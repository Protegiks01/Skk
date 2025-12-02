## Title
Self-Transfer DOS in SafeTokenTransfers Causes Permanent Fund Lock for Cancellation Claims and Withdrawals

## Summary
The `SafeTokenTransfers.safeTransfer()` function validates that the recipient's balance increases by exactly the transfer amount. However, when the recipient is the vault itself (self-transfer), all ERC20 tokens result in no net balance change, causing the validation to fail and revert with `TransferAmountMismatch`. This creates a DOS condition in critical functions including `claimCancelDepositRequest()`, `claimCancelRedeemRequest()`, `redeem()`, and `withdraw()` when users accidentally or programmatically set the receiver to the vault address.

## Impact
**Severity**: Medium

## Finding Description

**Location:** 
- `src/SafeTokenTransfers.sol` (lines 49-54)
- `src/ERC7575VaultUpgradeable.sol` - `claimCancelDepositRequest()` (line 1707), `claimCancelRedeemRequest()` (line 1881), `redeem()` (line 916), `withdraw()` (line 961)
- `src/WERC7575Vault.sol` - `_withdraw()` (line 409) [1](#0-0) 

**Intended Logic:** The `SafeTokenTransfers.safeTransfer()` function is designed to prevent fee-on-transfer token exploits by validating that the recipient receives exactly the specified amount. The balance check ensures `balanceAfter == balanceBefore + amount`.

**Actual Logic:** When a vault transfers tokens to itself (`recipient == address(this)`), the ERC20 transfer logic performs `_balances[vault] -= amount; _balances[vault] += amount;`, resulting in no net balance change. The SafeTokenTransfers check expects `balanceAfter == balanceBefore + amount`, but in reality `balanceAfter == balanceBefore`, causing the validation to fail and revert.

**Exploitation Path:**

1. **User creates and cancels a deposit/redeem request:**
   - User calls `requestDeposit(assets, controller, owner)` to deposit assets
   - User calls `cancelDepositRequest()` to cancel the pending request
   - Investment Manager calls `fulfillCancelDepositRequest()` to make the cancelation claimable

2. **User attempts to claim with vault as receiver:** [2](#0-1) 
   
   User (or a buggy smart contract integration) calls `claimCancelDepositRequest(0, vaultAddress, controller)` where `receiver = vaultAddress`

3. **Transaction reverts with TransferAmountMismatch:**
   - Line 1707 executes: `SafeTokenTransfers.safeTransfer($.asset, receiver, assets)`
   - Since `receiver == address(this)`, the vault transfers to itself
   - `balanceBefore = X`, transfer occurs, `balanceAfter = X` (no change)
   - Check fails: `X != X + assets` → reverts with `TransferAmountMismatch`

4. **DOS Condition Created:**
   - If the user is an EOA, they can retry with the correct receiver (temporary DOS)
   - If the caller is a smart contract that always sets `receiver = vault`, funds are permanently locked (permanent DOS)
   - Same vulnerability exists in `claimCancelRedeemRequest()`, `redeem()`, `withdraw()` functions [3](#0-2) [4](#0-3) [5](#0-4) 

**Security Property Broken:** 
- Violates user fund accessibility - users should always be able to claim their canceled deposits/redeems and withdraw their funds
- Breaks ERC-7540/ERC-7887 compliance by preventing legitimate claim operations
- Creates unexpected revert conditions not documented in the protocol

## Impact Explanation

**Affected Assets**: All assets supported by the protocol (USDC, DAI, or any ERC20 configured as vault assets) and share tokens

**Damage Severity**: 
- **Temporary DOS (Low-Medium Impact)**: EOA users who accidentally set receiver to vault address experience transaction failure but can retry with correct parameters
- **Permanent DOS (High Impact)**: Smart contract integrations with immutable receiver logic that always sets `receiver = address(vault)` experience permanent fund lock, as they cannot change the receiver parameter

**User Impact**: 
- All users attempting to claim canceled requests or withdraw funds
- Particularly severe for smart contract integrations (wallets, DAOs, protocols) that may have fixed receiver logic
- Affects functions: `claimCancelDepositRequest()`, `claimCancelRedeemRequest()`, `redeem()`, `withdraw()` in ERC7575VaultUpgradeable and `withdraw()`/`redeem()` in WERC7575Vault

## Likelihood Explanation

**Attacker Profile**: This is not a traditional attack vector but rather a protocol design flaw that creates a DOS footgun:
- Unprivileged users (EOAs or contracts) acting as controllers
- Smart contract integrations with buggy receiver parameter logic
- User errors in transaction construction

**Preconditions**: 
- User has claimable cancelation assets/shares OR claimable redeem assets/shares
- User (or their smart contract) sets `receiver` parameter to the vault's own address
- No other preconditions required - affects any ERC20 token (not just fee-on-transfer tokens)

**Execution Complexity**: 
- Single transaction with incorrect receiver parameter
- No sophisticated attack required - simple user error or integration bug triggers the condition

**Frequency**: 
- Uncommon for EOA users (requires explicit user error)
- Higher risk for smart contract integrations where receiver logic may be hardcoded incorrectly
- Permanent DOS for contracts that cannot update their receiver parameter

## Recommendation

Add validation in all affected functions to prevent self-transfers:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function claimCancelDepositRequest, line ~1691:

function claimCancelDepositRequest(uint256 requestId, address receiver, address controller) external nonReentrant {
    if (requestId != REQUEST_ID) revert InvalidRequestId();
    VaultStorage storage $ = _getVaultStorage();
    if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
        revert InvalidCaller();
    }
    
    // ADD THIS CHECK:
    if (receiver == address(this)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(this));
    }

    uint256 assets = $.claimableCancelDepositAssets[controller];
    if (assets == 0) revert CancelationNotClaimable();
    
    // ... rest of function
}
```

Apply the same validation to:
- `claimCancelRedeemRequest()` (line 1866)
- `redeem()` (line 885)  
- `withdraw()` (line 927)
- `WERC7575Vault._withdraw()` (line 397)

**Alternative Fix**: Modify `SafeTokenTransfers.safeTransfer()` to handle self-transfers:

```solidity
// In src/SafeTokenTransfers.sol, function safeTransfer, line 49:

function safeTransfer(address token, address recipient, uint256 amount) internal {
    // Short-circuit self-transfers - they should be no-ops
    if (recipient == address(this)) {
        // Validate the vault has sufficient balance
        if (IERC20Metadata(token).balanceOf(address(this)) < amount) {
            revert InsufficientBalance();
        }
        return; // No actual transfer needed
    }
    
    uint256 balanceBefore = IERC20Metadata(token).balanceOf(recipient);
    IERC20Metadata(token).safeTransfer(recipient, amount);
    uint256 balanceAfter = IERC20Metadata(token).balanceOf(recipient);
    if (balanceAfter != balanceBefore + amount) revert TransferAmountMismatch();
}
```

**Recommended Approach**: Implement the validation at the function level (first fix) rather than in SafeTokenTransfers, as self-transfers should not be a valid use case for withdrawal/claim operations. This makes the intent explicit and prevents accidental misuse.

## Proof of Concept

```solidity
// File: test/Exploit_SelfTransferDOS.t.sol
// Run with: forge test --match-test test_SelfTransferDOS_ClaimCancelDeposit -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockAsset is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {
        _mint(msg.sender, 1_000_000e6);
    }
    
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

contract Exploit_SelfTransferDOS is Test {
    ERC7575VaultUpgradeable vault;
    WERC7575ShareToken shareToken;
    MockAsset asset;
    
    address user = address(0x1);
    address investmentManager = address(0x2);
    address owner = address(0x3);
    
    function setUp() public {
        // Deploy contracts
        asset = new MockAsset();
        shareToken = new WERC7575ShareToken();
        vault = new ERC7575VaultUpgradeable();
        
        // Initialize (simplified - actual initialization would be more complex)
        shareToken.initialize(owner, "SukukFi Share", "SKFI");
        vault.initialize(address(asset), address(shareToken), investmentManager, owner);
        
        // Setup: Give user some assets
        asset.transfer(user, 10_000e6);
        
        // Register vault
        vm.prank(owner);
        shareToken.registerVault(address(vault), address(asset));
    }
    
    function test_SelfTransferDOS_ClaimCancelDeposit() public {
        // SETUP: User deposits assets
        vm.startPrank(user);
        uint256 depositAmount = 1_000e6;
        asset.approve(address(vault), depositAmount);
        vault.requestDeposit(depositAmount, user, user);
        
        // User cancels the deposit
        vault.cancelDepositRequest(0, user);
        vm.stopPrank();
        
        // Investment Manager fulfills the cancelation
        vm.prank(investmentManager);
        vault.fulfillCancelDepositRequest(0, user, depositAmount);
        
        // EXPLOIT: User attempts to claim with vault as receiver (accidental or bug)
        vm.prank(user);
        vm.expectRevert(SafeTokenTransfers.TransferAmountMismatch.selector);
        vault.claimCancelDepositRequest(0, address(vault), user); // receiver = vault address
        
        // VERIFY: Transaction reverted, user cannot claim funds
        // Funds are locked until user calls with correct receiver
        assertEq(vault.claimableCancelDepositAssets(user), depositAmount, "Assets still claimable but inaccessible with self-transfer");
        
        // Demonstrate that with correct receiver, it works fine
        vm.prank(user);
        vault.claimCancelDepositRequest(0, user, user); // receiver = user (correct)
        assertEq(asset.balanceOf(user), 10_000e6, "User successfully claimed with correct receiver");
    }
}
```

## Notes

This vulnerability is distinct from the "Self-transfers skipped in batch operations" known issue listed in KNOWN_ISSUES.md, which refers to batch transfer optimizations. This finding specifically addresses the SafeTokenTransfers balance validation check that affects individual claim and withdrawal operations where the vault inadvertently transfers to itself.

The issue affects **all ERC20 tokens**, not just those with non-standard behavior. Even standard implementations like OpenZeppelin's ERC20 will cause the balance check to fail during self-transfers because the net balance change is zero (decrease + increase = no change).

For smart contract integrations that cannot update their receiver parameter post-deployment, this creates a **permanent DOS condition**, effectively locking user funds until the contract is upgraded or replaced.

### Citations

**File:** src/SafeTokenTransfers.sol (L49-54)
```text
    function safeTransfer(address token, address recipient, uint256 amount) internal {
        uint256 balanceBefore = IERC20Metadata(token).balanceOf(recipient);
        IERC20Metadata(token).safeTransfer(recipient, amount);
        uint256 balanceAfter = IERC20Metadata(token).balanceOf(recipient);
        if (balanceAfter != balanceBefore + amount) revert TransferAmountMismatch();
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L885-918)
```text
    function redeem(uint256 shares, address receiver, address controller) public nonReentrant returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (shares == 0) revert ZeroShares();

        uint256 availableShares = $.claimableRedeemShares[controller];
        if (shares > availableShares) revert InsufficientClaimableShares();

        // Calculate proportional assets for the requested shares
        uint256 availableAssets = $.claimableRedeemAssets[controller];
        assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);

        if (assets == availableAssets) {
            // Remove from active redeem requesters if no more claimable assets and the potential dust
            $.activeRedeemRequesters.remove(controller);
            delete $.claimableRedeemAssets[controller];
            delete $.claimableRedeemShares[controller];
        } else {
            $.claimableRedeemAssets[controller] -= assets;
            $.claimableRedeemShares[controller] -= shares;
        }
        $.totalClaimableRedeemAssets -= assets;
        $.totalClaimableRedeemShares -= shares; // Decrement shares that are being burned

        // Burn the shares as per ERC7540 spec - shares are burned when request is claimed
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);

        emit Withdraw(msg.sender, receiver, controller, assets, shares);
        if (assets > 0) {
            SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
        }
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L927-962)
```text
    function withdraw(uint256 assets, address receiver, address controller) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (assets == 0) revert ZeroAssets();

        uint256 availableAssets = $.claimableRedeemAssets[controller];
        if (assets > availableAssets) revert InsufficientClaimableAssets();

        // Calculate proportional shares for the requested assets
        uint256 availableShares = $.claimableRedeemShares[controller];
        shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);

        if (shares == availableShares) {
            // Remove from active redeem requesters if no more claimable assets and the potential dust
            $.activeRedeemRequesters.remove(controller);
            delete $.claimableRedeemAssets[controller];
            delete $.claimableRedeemShares[controller];
        } else {
            $.claimableRedeemAssets[controller] -= assets;
            $.claimableRedeemShares[controller] -= shares;
        }

        $.totalClaimableRedeemAssets -= assets;
        $.totalClaimableRedeemShares -= shares; // Decrement shares that are being burned

        // Burn the shares as per ERC7540 spec - shares are burned when request is claimed
        if (shares > 0) {
            ShareTokenUpgradeable($.shareToken).burn(address(this), shares);
        }

        emit Withdraw(msg.sender, receiver, controller, assets, shares);

        SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1691-1711)
```text
    function claimCancelDepositRequest(uint256 requestId, address receiver, address controller) external nonReentrant {
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 assets = $.claimableCancelDepositAssets[controller];
        if (assets == 0) revert CancelationNotClaimable();

        // CEI: State changes before external transfer
        delete $.claimableCancelDepositAssets[controller];
        $.totalCancelDepositAssets -= assets;
        $.controllersWithPendingDepositCancelations.remove(controller);

        // External interaction
        SafeTokenTransfers.safeTransfer($.asset, receiver, assets);

        // Event emission
        emit CancelDepositRequestClaimed(controller, receiver, REQUEST_ID, assets);
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
