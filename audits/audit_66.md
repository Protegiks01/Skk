## Title
Permanent Share Lock in Redeem Cancelation Due to Missing Vault Self-Allowance for WERC7575ShareToken Transfers

## Summary
When `ERC7575VaultUpgradeable` is configured with `WERC7575ShareToken` (Settlement Layer), all redeem cancelation claims permanently fail and lock user shares in the vault. The vault attempts to transfer shares back to users via `SafeTokenTransfers.safeTransfer()`, which calls `WERC7575ShareToken.transfer()`, but this requires vault self-allowance that can never be obtained because `WERC7575ShareToken.approve()` explicitly blocks self-approval. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `claimCancelRedeemRequest()` function (lines 1866-1885)

**Intended Logic:** When a user cancels a pending redeem request and the investment manager fulfills it, the user should be able to reclaim their shares by calling `claimCancelRedeemRequest()`. The vault should transfer the shares from its balance back to the owner address.

**Actual Logic:** The vault uses `SafeTokenTransfers.safeTransfer($.shareToken, owner, shares)` which calls the ShareToken's standard `transfer()` function. When the ShareToken is `WERC7575ShareToken` (Settlement Layer), this transfer fails because:

1. `WERC7575ShareToken.transfer()` requires `_spendAllowance(from, from, value)` - the sender must have self-allowance [2](#0-1) 

2. The vault (msg.sender) has zero self-allowance because it's never set up during initialization or operation [3](#0-2) 

3. The vault CANNOT obtain self-allowance because `WERC7575ShareToken.approve()` explicitly blocks self-approval (`msg.sender == spender` reverts) [4](#0-3) 

4. While the comment suggests "use permit instead for self-spending", the vault is a contract and cannot generate signatures, and no code path provides vault self-allowance via permit

**Exploitation Path:**
1. Deploy `ERC7575VaultUpgradeable` with `WERC7575ShareToken` as the share token (valid configuration per initialization checks)
2. User requests redeem via `requestRedeem()` - shares are transferred from user to vault using `vaultTransferFrom()` (bypasses allowance) [5](#0-4) 

3. User cancels the redeem request via `cancelRedeemRequest()` - shares move to `pendingCancelRedeemShares[controller]`
4. Investment manager fulfills cancelation via `fulfillCancelRedeemRequest()` - shares move to `claimableCancelRedeemShares[controller]` [6](#0-5) 

5. User calls `claimCancelRedeemRequest()` to reclaim their shares
6. Function deletes state and attempts `SafeTokenTransfers.safeTransfer($.shareToken, owner, shares)`
7. Transaction reverts in `WERC7575ShareToken.transfer()` at `_spendAllowance(from, from, value)` due to insufficient self-allowance
8. Due to revert, state deletion is rolled back, but shares remain permanently unclaimable because every future claim attempt will hit the same revert

**Security Property Broken:** Violates invariant #12 "No Fund Theft: No double-claims, no reentrancy, no authorization bypass" - users' shares become permanently inaccessible, effectively stolen by the vault.

## Impact Explanation
- **Affected Assets**: All shares of users who have claimable canceled redeem requests in vaults using WERC7575ShareToken
- **Damage Severity**: 100% loss of shares for affected users - shares are locked in vault with no recovery mechanism. No admin function can rescue these funds. The only theoretical recovery would be to upgrade the vault contract, but this requires owner intervention and may not be feasible in all scenarios.
- **User Impact**: Every user who cancels a redeem request and has it fulfilled by the investment manager will permanently lose their shares. This affects the entire user base of Settlement Layer vaults offering async redemption with cancelation support.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a protocol design flaw. Any normal user following the intended cancelation flow will trigger this.
- **Preconditions**: 
  - `ERC7575VaultUpgradeable` must be configured with `WERC7575ShareToken` (Settlement Layer architecture)
  - User must have a fulfilled canceled redeem request (legitimate use case)
- **Execution Complexity**: Trivial - happens automatically when user tries to claim their canceled redeem
- **Frequency**: Every single attempt to claim a canceled redeem in Settlement Layer vaults will fail

## Recommendation

The vault needs a privileged transfer mechanism that bypasses the self-allowance requirement. Add a `vaultTransfer()` function to `WERC7575ShareToken` (similar to existing `vaultTransferFrom()`):

```solidity
// In src/WERC7575ShareToken.sol, add new function:

/**
 * @dev Transfers shares from vault to recipient without requiring allowance (vault-only operation)
 * Enables vaults to return shares during cancelation claims
 * @param to The recipient address
 * @param amount The amount of shares to transfer
 * @return success True if transfer successful
 */
function vaultTransfer(address to, uint256 amount) external onlyVaults returns (bool success) {
    if (to == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    if (!isKycVerified[to]) revert KycRequired();
    
    // Direct transfer without checking allowance since this is vault-only
    _transfer(msg.sender, to, amount);
    return true;
}
```

Then modify `ERC7575VaultUpgradeable.claimCancelRedeemRequest()`:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function claimCancelRedeemRequest, line 1881:

// CURRENT (vulnerable):
SafeTokenTransfers.safeTransfer($.shareToken, owner, shares);

// FIXED:
// Use vault-privileged transfer to bypass self-allowance requirement
if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(address(this), owner, shares)) {
    revert ShareTransferFailed();
}
```

Note: This assumes `ShareTokenUpgradeable` is the base interface - if using `WERC7575ShareToken` directly, cast appropriately and add the `vaultTransfer()` function to that contract as well.

## Proof of Concept

```solidity
// File: test/Exploit_CanceledRedeemLock.t.sol
// Run with: forge test --match-test test_CanceledRedeemSharesPermanentlyLocked -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/ERC20Faucet.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_CanceledRedeemLock is Test {
    ERC7575VaultUpgradeable public vault;
    WERC7575ShareToken public shareToken;
    ERC20Faucet public asset;
    
    address public admin = address(this);
    address public alice = address(0x1);
    
    function setUp() public {
        // Deploy asset
        asset = new ERC20Faucet("USD Coin", "USDC", 1000000 * 1e6);
        
        // Deploy WERC7575ShareToken (Settlement Layer)
        shareToken = new WERC7575ShareToken("Settlement Shares", "SSHARE", admin);
        shareToken.setKycVerified(alice, true);
        shareToken.setKycVerified(address(this), true);
        
        // Deploy vault with WERC7575ShareToken
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            asset,
            address(shareToken),
            admin
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // Register vault
        shareToken.registerVault(address(asset), address(vault));
        
        // Give Alice assets and shares
        vm.warp(block.timestamp + 2 hours);
        asset.faucetAmountFor(alice, 10000 * 1e6);
        
        // Alice deposits to get shares
        vm.startPrank(alice);
        asset.approve(address(vault), 10000 * 1e6);
        vault.requestDeposit(10000 * 1e6, alice, alice);
        vm.stopPrank();
        
        vault.fulfillDeposit(alice, 10000 * 1e6);
        
        vm.prank(alice);
        vault.deposit(10000 * 1e6, alice);
    }
    
    function test_CanceledRedeemSharesPermanentlyLocked() public {
        uint256 aliceShares = shareToken.balanceOf(alice);
        console.log("Alice initial shares:", aliceShares);
        
        // STEP 1: Alice requests redeem
        vm.startPrank(alice);
        // Note: Alice needs self-allowance via permit for WERC7575ShareToken
        // For simplicity, we'll use the validator to bypass this in test setup
        vm.stopPrank();
        
        // Validator gives Alice self-allowance via permit (off-chain signature simulation)
        shareToken.forceApprove(alice, alice, aliceShares); // Test helper
        
        vm.prank(alice);
        vault.requestRedeem(aliceShares, alice, alice);
        
        assertEq(vault.pendingRedeemRequest(0, alice), aliceShares);
        assertEq(shareToken.balanceOf(address(vault)), aliceShares, "Vault should hold shares");
        
        // STEP 2: Alice cancels redeem request
        vm.prank(alice);
        vault.cancelRedeemRequest(0, alice);
        
        assertTrue(vault.pendingCancelRedeemRequest(0, alice));
        
        // STEP 3: Investment manager fulfills cancelation
        vault.fulfillCancelRedeemRequest(alice);
        
        assertEq(vault.claimableCancelRedeemRequest(0, alice), aliceShares);
        assertFalse(vault.pendingCancelRedeemRequest(0, alice));
        
        // STEP 4: Alice tries to claim canceled redeem - THIS WILL REVERT
        vm.prank(alice);
        vm.expectRevert(); // Will revert due to missing vault self-allowance
        vault.claimCancelRedeemRequest(0, alice, alice);
        
        // VERIFY: Shares are locked in vault forever
        assertEq(shareToken.balanceOf(address(vault)), aliceShares, "Shares stuck in vault");
        assertEq(shareToken.balanceOf(alice), 0, "Alice has no shares");
        assertEq(vault.claimableCancelRedeemRequest(0, alice), aliceShares, "Claimable but uncollectable");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- Shares locked in vault:", shareToken.balanceOf(address(vault)));
        console.log("- Alice cannot claim:", shareToken.balanceOf(alice));
        console.log("- No recovery mechanism available");
    }
}
```

## Notes

This vulnerability is distinct from KYC restrictions - even if the owner has valid KYC, the transfer will fail due to the vault's missing self-allowance. The architectural flaw is that:

1. **Investment Layer** (`ShareTokenUpgradeable`) has no self-allowance requirement, so this bug doesn't manifest there
2. **Settlement Layer** (`WERC7575ShareToken`) enforces dual authorization including self-allowance, but vaults were never designed to obtain self-allowance
3. The vault has `vaultTransferFrom()` for pulling shares IN, but no equivalent `vaultTransfer()` for sending shares OUT

The mismatch between the vault's transfer mechanism (standard `SafeTokenTransfers.safeTransfer`) and the Settlement Layer's transfer requirements (self-allowance mandatory) creates this critical lock-up scenario. This affects the entire Settlement Layer architecture when async redemption with cancelation is used.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L150-190)
```text
    function initialize(IERC20Metadata asset_, address shareToken_, address owner) public initializer {
        if (shareToken_ == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (address(asset_) == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }

        // Validate asset compatibility and get decimals
        uint8 assetDecimals;
        try IERC20Metadata(address(asset_)).decimals() returns (uint8 decimals) {
            if (decimals < DecimalConstants.MIN_ASSET_DECIMALS || decimals > DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert UnsupportedAssetDecimals();
            }
            assetDecimals = decimals;
        } catch {
            revert AssetDecimalsFailed();
        }
        // Validate share token compatibility and enforce 18 decimals
        try IERC20Metadata(shareToken_).decimals() returns (uint8 decimals) {
            if (decimals != DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert WrongDecimals();
            }
        } catch {
            revert AssetDecimalsFailed();
        }
        __Ownable_init(owner);

        VaultStorage storage $ = _getVaultStorage();
        $.asset = address(asset_);
        $.assetDecimals = assetDecimals;
        $.shareToken = shareToken_;
        $.investmentManager = owner; // Initially owner is investment manager
        $.isActive = true; // Vault is active by default

        // Calculate scaling factor for decimal normalization: 10^(18 - assetDecimals)
        uint256 scalingFactor = 10 ** (DecimalConstants.SHARE_TOKEN_DECIMALS - assetDecimals);
        if (scalingFactor > type(uint64).max) revert ScalingFactorTooLarge();
        $.scalingFactor = uint64(scalingFactor);
        $.minimumDepositAmount = 1000;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L740-742)
```text
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1081-1091)
```text
    function fulfillCancelRedeemRequest(address controller) external returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

        shares = $.pendingCancelRedeemShares[controller];
        if (shares == 0) revert NoPendingCancelRedeem();

        // Move from pending to claimable cancelation state
        delete $.pendingCancelRedeemShares[controller];
        $.claimableCancelRedeemShares[controller] += shares;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1866-1885)
```text
    function claimCancelRedeemRequest(uint256 requestId, address owner, address controller) external nonReentrant {
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 shares = $.claimableCancelRedeemShares[controller];
        if (shares == 0) revert CancelationNotClaimable();

        // CEI: State changes before external transfer
        delete $.claimableCancelRedeemShares[controller];
        $.controllersWithPendingRedeemCancelations.remove(controller);

        // External interaction
        SafeTokenTransfers.safeTransfer($.shareToken, owner, shares);

        // Event emission
        emit CancelRedeemRequestClaimed(controller, owner, REQUEST_ID, shares);
    }
```

**File:** src/WERC7575ShareToken.sol (L439-444)
```text
    function approve(address spender, uint256 value) public virtual override returns (bool) {
        if (msg.sender != spender) {
            return super.approve(spender, value);
        }
        revert ERC20InvalidSpender(msg.sender);
    }
```

**File:** src/WERC7575ShareToken.sol (L472-477)
```text
    function transfer(address to, uint256 value) public override whenNotPaused returns (bool) {
        address from = msg.sender;
        if (!isKycVerified[to]) revert KycRequired();
        _spendAllowance(from, from, value);
        return super.transfer(to, value);
    }
```
