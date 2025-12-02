## Title
Vault Unregistration Fails to Validate Outstanding Share Redemptions, Permanently Locking User Funds

## Summary
The `unregisterVault()` function in WERC7575ShareToken only validates that the vault has no assets remaining, but fails to check whether users have pending or claimable share redemptions. This allows a vault to be unregistered while users still have active redemption requests, permanently preventing them from burning their shares since the vault will no longer be authorized to call `burn()`.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/WERC7575ShareToken.sol`, function `unregisterVault()` (lines 256-285) [1](#0-0) 

**Intended Logic:** The function should prevent vault unregistration when users still have claims on shares or assets, as stated in the comment "SAFETY: This function now includes outstanding shares validation to prevent user fund loss."

**Actual Logic:** The function only checks:
1. `totalAssets()` on the vault - but this excludes invested assets and can be 0 even with active redemptions
2. `balanceOf(vaultAddress)` for the asset token - but this can be 0 when assets are invested in an investment vault

The function does NOT check:
- Whether the vault holds shares from redemption requests
- Whether users have pending redemption requests (`pendingRedeemShares`)  
- Whether users have claimable redemption requests (`totalClaimableRedeemShares`)

**Exploitation Path:**

1. **Setup**: User Alice deposits 10,000 USDC into the USDC vault and receives shares. The investment manager invests most assets (e.g., 9,500 USDC) into an investment vault, leaving minimal balance in the main vault.

2. **Redemption Request**: Alice calls `requestRedeem()` to redeem her shares. [2](#0-1) 
The vault transfers Alice's shares from her to itself and records `pendingRedeemShares[alice]`.

3. **Vault Unregistration**: The vault's asset balance is near zero (invested). Owner calls `unregisterVault(USDC)`:
   - Check 1: `totalAssets()` returns 0 (balance minus reserved assets) ✓
   - Check 2: `balanceOf(vaultAddress)` returns 0 or minimal amount ✓
   - Unregistration succeeds, `_vaultToAsset[vault]` is deleted

4. **Fulfillment**: Investment manager calls `fulfillRedeem()` to fulfill Alice's request - this succeeds as it only updates internal state.

5. **Permanent Lock**: Alice calls `withdraw()` or `redeem()` to claim her assets. The vault attempts to burn the shares: [3](#0-2) [4](#0-3) 

6. **Failure**: The `burn()` function has the `onlyVaults` modifier: [5](#0-4) [6](#0-5) 
Since `_vaultToAsset[msg.sender]` is now `address(0)`, the transaction reverts with `Unauthorized()`. Alice's shares are permanently locked in the vault.

**Security Property Broken:** 
- Invariant #7: "Only registered vaults can mint/burn shares" - after unregistration, shares exist but the vault cannot burn them
- Invariant #12: "No Fund Theft" - users lose access to their funds permanently

## Impact Explanation

- **Affected Assets**: All user shares minted by the unregistered vault, representing potentially millions of dollars in USDC/DAI/other assets across all users with active redemption requests

- **Damage Severity**: 100% permanent loss of funds for affected users. There is no recovery mechanism since:
  - The vault cannot be re-registered (would need a new vault contract)
  - The old vault cannot call `burn()` (permanently unauthorized)
  - Shares cannot be transferred out of the vault contract
  - Users cannot cancel requests after fulfillment

- **User Impact**: Any user with pending or claimable redemption requests at the time of unregistration loses all their funds. This includes users who have already waited for fulfillment and are simply trying to claim.

## Likelihood Explanation

- **Attacker Profile**: Not an attack - this is a logic error that occurs during routine vault management. The owner believes unregistration is safe because both checks pass.

- **Preconditions**: 
  - Vault has invested most assets into an investment vault (common operation)
  - Users have redemption requests (pending or claimable)
  - Vault's direct asset balance is low/zero due to investments
  - Owner calls `unregisterVault()` thinking it's safe (checks pass)

- **Execution Complexity**: Occurs naturally during normal operations. No complex timing or special conditions required.

- **Frequency**: Can occur whenever a vault with active redemptions is unregistered while assets are invested, which is a reasonable operational scenario.

## Recommendation

Add validation to check that the vault holds no shares and has no active redemption requests before allowing unregistration:

```solidity
// In src/WERC7575ShareToken.sol, function unregisterVault, after line 279:

// CURRENT (vulnerable):
// Only checks asset balances, not share holdings or redemption state

// FIXED:
function unregisterVault(address asset) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    if (!_assetToVault.contains(asset)) revert AssetNotRegistered();

    address vaultAddress = _assetToVault.get(asset);

    // SAFETY CHECK 1: Validate that vault has no outstanding assets
    try IERC7575Vault(vaultAddress).totalAssets() returns (uint256 totalAssets) {
        if (totalAssets != 0) revert CannotUnregisterVaultAssetBalance();
    } catch {
        revert("ShareToken: cannot verify vault has no outstanding assets");
    }
    
    // SAFETY CHECK 2: Verify vault's direct asset balance is zero
    try ERC20(asset).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
        if (vaultBalance != 0) revert CannotUnregisterVaultAssetBalance();
    } catch {
        revert("ShareToken: cannot verify vault asset balance");
    }

    // SAFETY CHECK 3: Verify vault holds no shares from redemptions
    // Check if vault holds any shares that need to be burned
    uint256 vaultShareBalance = balanceOf(vaultAddress);
    if (vaultShareBalance != 0) {
        revert("ShareToken: vault holds shares from active redemptions");
    }

    // SAFETY CHECK 4: Verify no active redemption requests exist
    // Query vault for pending/claimable redemption state
    try IVaultMetrics(vaultAddress).getActiveRedeemRequestersCount() returns (uint256 activeCount) {
        if (activeCount != 0) {
            revert("ShareToken: vault has active redemption requests");
        }
    } catch {
        // If we can't verify redemption state, reject unregistration for safety
        revert("ShareToken: cannot verify vault has no active redemptions");
    }

    // All checks passed - safe to unregister
    _assetToVault.remove(asset);
    delete _vaultToAsset[vaultAddress];

    emit VaultUpdate(asset, address(0));
}
```

Additionally, add a helper function to the vault contract:

```solidity
// In src/ERC7575VaultUpgradeable.sol:

function getActiveRedeemRequestersCount() external view returns (uint256) {
    VaultStorage storage $ = _getVaultStorage();
    return $.activeRedeemRequesters.length();
}
```

## Proof of Concept

```solidity
// File: test/Exploit_VaultUnregistrationShareLock.t.sol
// Run with: forge test --match-test test_VaultUnregistrationLocksShares -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/mocks/MockERC20.sol";

contract Exploit_VaultUnregistrationShareLock is Test {
    WERC7575ShareToken shareToken;
    ERC7575VaultUpgradeable vault;
    MockERC20 usdc;
    
    address owner = address(1);
    address alice = address(2);
    address investmentManager = address(3);
    address investmentVault = address(4);
    
    function setUp() public {
        // Deploy contracts
        vm.startPrank(owner);
        usdc = new MockERC20("USDC", "USDC", 6);
        shareToken = new WERC7575ShareToken("Shares", "SHR");
        vault = new ERC7575VaultUpgradeable();
        vault.initialize(usdc, address(shareToken), owner);
        
        // Register vault
        shareToken.registerVault(address(usdc), address(vault));
        
        // Setup KYC and investment manager
        shareToken.setKycVerified(alice, true);
        shareToken.setKycVerified(address(vault), true);
        vault.setInvestmentManager(investmentManager);
        vault.setInvestmentVault(investmentVault);
        vm.stopPrank();
        
        // Give alice USDC and shares
        usdc.mint(alice, 10000e6);
        vm.prank(alice);
        usdc.approve(address(vault), 10000e6);
    }
    
    function test_VaultUnregistrationLocksShares() public {
        // SETUP: Alice deposits and requests redemption
        vm.startPrank(alice);
        vault.deposit(10000e6, alice);
        uint256 aliceShares = shareToken.balanceOf(alice);
        
        // Alice requests redemption - shares transfer to vault
        vault.requestRedeem(aliceShares, alice, alice);
        vm.stopPrank();
        
        assertEq(shareToken.balanceOf(address(vault)), aliceShares, "Vault should hold Alice's shares");
        
        // Simulate investment: move assets out (vault balance becomes 0)
        vm.prank(address(vault));
        usdc.transfer(investmentVault, 10000e6);
        
        // EXPLOIT: Owner unregisters vault (checks pass because balance is 0)
        vm.prank(owner);
        shareToken.unregisterVault(address(usdc));
        
        // Vault is now unregistered
        assertEq(shareToken.vault(address(usdc)), address(0), "Vault should be unregistered");
        
        // Investment manager fulfills redemption
        vm.prank(investmentVault);
        usdc.transfer(address(vault), 10000e6); // Return assets
        
        vm.prank(investmentManager);
        vault.fulfillRedeem(alice, aliceShares);
        
        // VERIFY: Alice cannot claim - burn() will revert
        vm.startPrank(alice);
        vm.expectRevert(); // Unauthorized error from onlyVaults modifier
        vault.redeem(aliceShares, alice, alice);
        vm.stopPrank();
        
        // Alice's shares are permanently locked in the vault
        assertEq(shareToken.balanceOf(address(vault)), aliceShares, "Shares still locked in vault");
        console.log("Vulnerability confirmed: Alice's %d shares are permanently locked", aliceShares);
    }
}
```

## Notes

This vulnerability represents a critical gap in the validation logic of `unregisterVault()`. The function was designed with safety in mind (as evidenced by the SAFETY comment), but the checks are insufficient. The function validates asset balances but not share holdings or redemption state, creating a scenario where shares become permanently unburnable after unregistration.

The root cause is that the multi-asset architecture separates asset holdings (in vaults) from share holdings (in ShareToken), and the unregistration validation only checks one side of this relationship. When assets are invested in external vaults, the main vault's balance can legitimately be zero while users still have active redemption claims represented by shares held in the vault.

The recommended fix adds explicit validation of both share holdings and active redemption state before allowing unregistration, ensuring the bijection invariant between registered vaults and burnable shares is maintained throughout the vault lifecycle.

### Citations

**File:** src/WERC7575ShareToken.sol (L200-203)
```text
    modifier onlyVaults() {
        if (_vaultToAsset[msg.sender] == address(0)) revert Unauthorized();
        _;
    }
```

**File:** src/WERC7575ShareToken.sol (L256-285)
```text
    function unregisterVault(address asset) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (!_assetToVault.contains(asset)) revert AssetNotRegistered();

        address vaultAddress = _assetToVault.get(asset);

        // SAFETY CHECK: Validate that vault has no outstanding assets that users could claim
        // In this architecture, we check vault's total assets rather than share supply
        // since shares are managed by this ShareToken contract, not the vault
        try IERC7575Vault(vaultAddress).totalAssets() returns (uint256 totalAssets) {
            if (totalAssets != 0) revert CannotUnregisterVaultAssetBalance();
        } catch {
            // If we can't verify the vault has no assets, we can't safely unregister
            // This prevents unregistration if the vault is malicious or has interface issues
            revert("ShareToken: cannot verify vault has no outstanding assets");
        }
        // Additional safety: Check if vault still has any assets to prevent user fund loss
        // This is a double-check using ERC20 interface in case totalAssets() is manipulated
        try ERC20(asset).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
            if (vaultBalance != 0) revert CannotUnregisterVaultAssetBalance();
        } catch {
            // If we can't check the asset balance in vault, err on the side of caution
            revert("ShareToken: cannot verify vault asset balance");
        }
        // Remove vault registration and authorization (automatically removes from enumerable collection)
        _assetToVault.remove(asset);
        delete _vaultToAsset[vaultAddress]; // Also clear reverse mapping for authorization

        emit VaultUpdate(asset, address(0));
    }
```

**File:** src/WERC7575ShareToken.sol (L376-382)
```text
    function burn(address from, uint256 amount) external onlyVaults whenNotPaused {
        if (from == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        if (!isKycVerified[from]) revert KycRequired();
        _burn(from, amount);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L740-742)
```text
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L912-912)
```text
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);
```

**File:** src/ERC7575VaultUpgradeable.sol (L956-956)
```text
            ShareTokenUpgradeable($.shareToken).burn(address(this), shares);
```
