## Title
Accidentally Sent Assets Cause Permanent DOS on Vault Unregistration Despite No User Funds at Risk

## Summary
The `unregisterVault()` function in `ShareTokenUpgradeable.sol` checks the raw token balance of the vault address to determine if unregistration is safe. This check does not distinguish between user-owned funds (tracked through pending deposits, claimable redemptions, and cancelations) and accidentally sent tokens. When tokens are accidentally transferred directly to a vault address after all legitimate user operations are complete, the vault cannot be unregistered permanently, despite no user funds being at risk and no recovery mechanism existing.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol`, function `unregisterVault()`, lines 282-327 [1](#0-0) 

**Intended Logic:** The function is designed to safely unregister a vault only when no user funds remain, preventing accidental removal of a vault that still holds user assets or has pending operations.

**Actual Logic:** The function performs comprehensive checks for all protocol-tracked user funds (lines 292-309), then adds a final safety check at line 318 that verifies the raw token balance is zero. However, this raw balance check cannot distinguish between:
- Protocol-tracked user funds (already verified to be zero in previous checks)
- Accidentally sent tokens (sent via direct ERC20 transfer, not through protocol operations) [2](#0-1) 

The comment at lines 316-317 acknowledges this scenario: "If this happens, there is either a bug in the vault or assets were sent to the vault without directly" but treats it as a permanent blocking condition rather than a recoverable situation.

**Exploitation Path:**
1. A vault completes all user operations: all deposits claimed, all redemptions processed, all cancelations fulfilled, vault deactivated
2. All protocol-tracked metrics are zero: `totalPendingDepositAssets = 0`, `totalClaimableRedeemAssets = 0`, `totalCancelDepositAssets = 0`, `activeDepositRequestersCount = 0`, `activeRedeemRequestersCount = 0`
3. A user accidentally sends tokens directly to the vault address via `ERC20.transfer(vaultAddress, amount)` (common user mistake)
4. Owner attempts to call `shareToken.unregisterVault(asset)` to clean up the completed vault
5. Transaction reverts at line 318 with `CannotUnregisterVaultAssetBalance()` because `balanceOf(vaultAddress) != 0`
6. No recovery mechanism exists in the protocol to remove the accidentally sent tokens
7. The vault remains permanently registered despite being functionally complete with no user funds at risk

**Security Property Broken:** While not explicitly stated as an invariant, the protocol should allow cleanup of vaults that have completed all user operations. The current implementation creates a permanent DOS condition based on external actions (accidental transfers) that don't involve user funds.

## Impact Explanation
- **Affected Assets**: Any ERC20 asset vault that receives accidentally sent tokens after completing operations
- **Damage Severity**: 
  - Loss of vault management functionality (cannot unregister)
  - Registry pollution with permanently stuck vaults
  - Potential gas cost increase for operations iterating over all registered vaults
  - Accidentally sent tokens are permanently locked (no recovery)
- **User Impact**: 
  - Protocol owners lose ability to clean up and manage vault registry
  - Users who accidentally send tokens lose those funds permanently
  - Any operation iterating over registered vaults (e.g., `getCirculatingSupplyAndAssets()`) continues to include the stuck vault

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is triggered by innocent user mistakes (sending tokens to wrong address)
- **Preconditions**: 
  - Vault has completed all user operations and is ready for unregistration
  - User accidentally sends tokens directly to vault address (common mistake)
- **Execution Complexity**: Single accidental transaction triggers permanent DOS
- **Frequency**: This can happen to any vault at any time - accidental token transfers are common in DeFi

## Recommendation

**Option 1: Check only protocol-tracked state (recommended)**
The function should rely on the comprehensive protocol-tracked metrics (lines 292-309) rather than the raw balance check. The protocol already tracks all user funds through its state variables.

```solidity
// In src/ShareTokenUpgradeable.sol, function unregisterVault, lines 314-320:

// CURRENT (vulnerable):
// 2. Final safety: Check raw asset balance in vault contract
// This catches any remaining assets including investments and edge cases
// If this happens, there is either a bug in the vault
// or assets were sent to the vault without directly
if (IERC20(asset).balanceOf(vaultAddress) != 0) {
    revert CannotUnregisterVaultAssetBalance();
}

// FIXED (remove raw balance check - rely on protocol-tracked state):
// Remove this check entirely - the comprehensive state checks above
// (lines 292-309) already verify no user funds are at risk.
// Accidentally sent tokens should not prevent unregistration.
// Note: Consider adding a separate rescue function for accidentally sent tokens.
```

**Option 2: Add rescue function for accidentally sent tokens**
Add an owner-only function to recover accidentally sent tokens from vaults:

```solidity
// In src/ERC7575VaultUpgradeable.sol:

/**
 * @dev Rescues accidentally sent tokens from the vault (only owner)
 * Can only be called when vault is inactive and all user operations are complete
 * @param token The token address to rescue
 * @param to The recipient address
 * @param amount The amount to rescue
 */
function rescueTokens(address token, address to, uint256 amount) external onlyOwner {
    VaultStorage storage $ = _getVaultStorage();
    
    // Ensure vault is inactive
    if ($.isActive) revert VaultMustBeInactive();
    
    // Ensure no user operations pending
    if ($.totalPendingDepositAssets != 0) revert CannotRescueWithPendingDeposits();
    if ($.totalClaimableRedeemAssets != 0) revert CannotRescueWithClaimableRedemptions();
    if ($.totalCancelDepositAssets != 0) revert CannotRescueWithPendingCancelations();
    
    // Calculate max rescuable amount (total balance minus reserved user funds)
    uint256 balance = IERC20Metadata(token).balanceOf(address(this));
    uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;
    uint256 maxRescuable = balance > reservedAssets ? balance - reservedAssets : 0;
    
    if (amount > maxRescuable) revert InsufficientRescuableBalance();
    
    SafeERC20.safeTransfer(IERC20Metadata(token), to, amount);
    
    emit TokensRescued(token, to, amount);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_AccidentalTransferBlocksUnregistration.t.sol
// Run with: forge test --match-test test_AccidentalTransferBlocksUnregistration -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "../src/ERC20Faucet.sol";
import {IERC7575Errors} from "../src/interfaces/IERC7575Errors.sol";

contract Exploit_AccidentalTransferBlocksUnregistration is Test {
    WERC7575ShareToken public shareToken;
    WERC7575Vault public vault;
    ERC20Faucet public usdc;
    
    address public owner = address(this);
    address public user = address(0x1);
    address public accidentalSender = address(0x2);
    
    function setUp() public {
        // Deploy USDC (6 decimals)
        usdc = new ERC20Faucet("USD Coin", "USDC", 1_000_000 * 10 ** 6);
        vm.mockCall(address(usdc), abi.encodeWithSignature("decimals()"), abi.encode(uint8(6)));
        
        // Deploy share token
        shareToken = new WERC7575ShareToken("Multi-Asset Share Token", "MAST");
        
        // Deploy vault
        vault = new WERC7575Vault(address(usdc), shareToken);
        
        // Register vault
        shareToken.registerVault(address(usdc), address(vault));
        
        // KYC users
        shareToken.setKycVerified(user, true);
        
        // Fund users
        usdc.transfer(user, 1000 * 10 ** 6);
        usdc.transfer(accidentalSender, 100 * 10 ** 6);
    }
    
    function test_AccidentalTransferBlocksUnregistration() public {
        // SETUP: User completes a full deposit/redeem cycle
        vm.startPrank(user);
        usdc.approve(address(vault), 100 * 10 ** 6);
        vault.deposit(100 * 10 ** 6, user);
        
        // Redeem all shares
        uint256 shares = shareToken.balanceOf(user);
        shareToken.approve(address(shareToken), shares); // Self-allowance
        vault.redeem(shares, user, user);
        vm.stopPrank();
        
        // Owner deactivates vault to prepare for unregistration
        vault.setVaultActive(false);
        
        // Verify vault is clean: no pending operations, no user funds
        assertEq(vault.totalAssets(), 0, "Vault should have zero assets");
        assertFalse(vault.isVaultActive(), "Vault should be inactive");
        
        // At this point, vault should be unregisterable
        // BUT someone accidentally sends tokens directly to vault address
        vm.prank(accidentalSender);
        usdc.transfer(address(vault), 10 * 10 ** 6); // Accidental transfer
        
        // EXPLOIT: Owner tries to unregister the vault
        // This should succeed since no user funds are at risk
        // But it fails permanently due to the accidental transfer
        
        vm.expectRevert(IERC7575Errors.CannotUnregisterVaultAssetBalance.selector);
        shareToken.unregisterVault(address(usdc));
        
        // VERIFY: Vault cannot be unregistered despite:
        // 1. All user operations complete
        // 2. Vault inactive
        // 3. No pending deposits, redemptions, or cancelations
        // 4. The accidentally sent tokens are NOT user funds
        
        // Confirm vault is still registered
        assertTrue(shareToken.isVault(address(vault)), "Vault is permanently stuck in registry");
        
        // Confirm the accidentally sent tokens are permanently locked
        assertEq(usdc.balanceOf(address(vault)), 10 * 10 ** 6, "Accidentally sent tokens are locked");
        
        // NO RECOVERY MECHANISM EXISTS - the vault cannot be unregistered
        // and the accidentally sent tokens cannot be recovered
    }
}
```

**Notes:**

1. **Root Cause**: The vulnerability stems from using `balanceOf()` as a safety check without distinguishing between protocol-tracked funds and externally sent tokens. The comprehensive state checks at lines 292-309 already verify no user funds are at risk.

2. **Why Previous Checks Are Sufficient**: The function already validates:
   - Vault is inactive (line 294)
   - No pending deposits (lines 295-297)
   - No claimable redemptions (lines 298-300)
   - No pending cancelations (lines 301-303)
   - No active requesters (lines 304-309)
   
   These checks comprehensively cover all protocol-tracked user funds. The raw balance check at line 318 is redundant for user protection but creates a DOS vector for accidental transfers.

3. **Comparison with Test Cases**: The existing test at `test/VaultDeactivation.t.sol` (lines 182-183) validates that vaults with user funds cannot be unregistered, which is correct behavior. However, it doesn't test the scenario where accidentally sent tokens (not user funds) block unregistration. [3](#0-2) 

4. **No Rescue Function**: A codebase search confirms no rescue/recovery function exists to remove accidentally sent tokens, making this DOS permanent.

5. **Impact on Multi-Asset System**: The `getCirculatingSupplyAndAssets()` function iterates over all registered vaults. Permanently stuck vaults continue consuming gas and polluting the registry. [4](#0-3)

### Citations

**File:** src/ShareTokenUpgradeable.sol (L282-327)
```text
    function unregisterVault(address asset) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();

        (bool exists, address vaultAddress) = $.assetToVault.tryGet(asset);
        if (!exists) revert AssetNotRegistered();

        // COMPREHENSIVE SAFETY CHECK: Ensure vault has no user funds at risk
        // This covers pending deposits, claimable redemptions, ERC7887 cancelations, and any remaining assets

        // 1. Check vault metrics for pending requests, active users, and ERC7887 cancelation assets
        try IVaultMetrics(vaultAddress).getVaultMetrics() returns (IVaultMetrics.VaultMetrics memory metrics) {
            if (metrics.isActive) revert CannotUnregisterActiveVault();
            if (metrics.totalPendingDepositAssets != 0) {
                revert CannotUnregisterVaultPendingDeposits();
            }
            if (metrics.totalClaimableRedeemAssets != 0) {
                revert CannotUnregisterVaultClaimableRedemptions();
            }
            if (metrics.totalCancelDepositAssets != 0) {
                revert CannotUnregisterVaultAssetBalance();
            }
            if (metrics.activeDepositRequestersCount != 0) {
                revert CannotUnregisterVaultActiveDepositRequesters();
            }
            if (metrics.activeRedeemRequestersCount != 0) {
                revert CannotUnregisterVaultActiveRedeemRequesters();
            }
        } catch {
            // If we can't get vault metrics, we can't safely verify no pending requests
            revert CannotUnregisterActiveVault();
        }
        // 2. Final safety: Check raw asset balance in vault contract
        // This catches any remaining assets including investments and edge cases
        // If this happens, there is either a bug in the vault
        // or assets were sent to the vault without directly
        if (IERC20(asset).balanceOf(vaultAddress) != 0) {
            revert CannotUnregisterVaultAssetBalance();
        }

        // Remove vault registration (automatically removes from enumerable collection)
        $.assetToVault.remove(asset);
        delete $.vaultToAsset[vaultAddress];

        emit VaultUpdate(asset, address(0));
    }
```

**File:** src/ShareTokenUpgradeable.sol (L369-390)
```text
    function getCirculatingSupplyAndAssets() external view returns (uint256 circulatingSupply, uint256 totalNormalizedAssets) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        uint256 totalClaimableShares = 0;
        uint256 length = $.assetToVault.length();

        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Get both claimable shares and normalized assets in a single call for gas efficiency
            (uint256 vaultClaimableShares, uint256 vaultNormalizedAssets) = IERC7575Vault(vaultAddress).getClaimableSharesAndNormalizedAssets();
            totalClaimableShares += vaultClaimableShares;
            totalNormalizedAssets += vaultNormalizedAssets;
        }

        // Add invested assets from the investment ShareToken (if configured)
        totalNormalizedAssets += _calculateInvestmentAssets();

        // Get total supply
        uint256 supply = totalSupply();
        // Calculate circulating supply: total supply minus vault-held shares for redemption claims
        circulatingSupply = totalClaimableShares > supply ? 0 : supply - totalClaimableShares;
    }
```

**File:** test/VaultDeactivation.t.sol (L182-184)
```text
        // Cannot remove vault yet (has outstanding assets)
        vm.expectRevert(IERC7575Errors.CannotUnregisterVaultAssetBalance.selector);
        shareToken.unregisterVault(address(usdc));
```
