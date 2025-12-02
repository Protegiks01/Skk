## Title
Vault Unregistration Bypasses Redeem Cancelation Share Tracking, Breaking ShareToken Conversion Ratios

## Summary
The `unregisterVault()` function in ShareTokenUpgradeable fails to check for pending or claimable redeem cancelation shares before allowing vault unregistration. This occurs because redeem cancelations lack an aggregate tracking variable (unlike deposit cancelations which have `totalCancelDepositAssets`), and users with canceled redeems are removed from `activeRedeemRequesters`. When a vault holding cancelation shares is unregistered, ShareToken's `getCirculatingSupplyAndAssets()` calculation excludes the unregistered vault, inflating the circulating supply and breaking conversion ratios system-wide.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` (unregisterVault function, lines 282-327) and `src/ERC7575VaultUpgradeable.sol` (cancelRedeemRequest function, lines 1745-1764)

**Intended Logic:** The `unregisterVault()` function should prevent vault unregistration when there are any outstanding user requests or shares held by the vault for claims. The function performs comprehensive safety checks via `getVaultMetrics()` to ensure no pending operations exist.

**Actual Logic:** The safety checks only validate deposit cancelations through `totalCancelDepositAssets` but completely miss redeem cancelations because:
1. There is no `totalCancelRedeemShares` aggregate tracking variable
2. When users cancel redeem requests, they're removed from `activeRedeemRequesters` 
3. The `VaultMetrics` struct doesn't include any field for redeem cancelation shares [1](#0-0) [2](#0-1) 

**Exploitation Path:**

1. **User cancels redeem request:** User calls `cancelRedeemRequest()` which moves shares from `pendingRedeemShares` to `pendingCancelRedeemShares` and removes the user from `activeRedeemRequesters` [3](#0-2) 

2. **Investment manager fulfills cancelation:** Manager calls `fulfillCancelRedeemRequest()` which moves shares from pending to claimable cancelation state [4](#0-3) 

3. **Owner unregisters vault:** The `unregisterVault()` function checks `activeRedeemRequestersCount` which is now 0 (user was removed in step 1), and checks other metrics that don't include redeem cancelation shares [5](#0-4) 

4. **Vault is removed from registry:** The vault is successfully unregistered even though it holds claimable cancelation shares for users [6](#0-5) 

5. **ShareToken accounting breaks:** The `getCirculatingSupplyAndAssets()` function only loops through registered vaults, so the unregistered vault's shares are not subtracted from total supply, inflating the circulating supply [7](#0-6) 

6. **Conversion ratios become inaccurate:** The inflated circulating supply breaks the share-to-asset conversion calculations used by all vaults sharing this ShareToken [8](#0-7) 

**Security Property Broken:** Violates Invariant #10 (Conversion Accuracy) - convertToShares/convertToAssets calculations use incorrect circulating supply, causing conversions that don't satisfy `convertToShares(convertToAssets(x)) ≈ x`

## Impact Explanation
- **Affected Assets**: All assets in vaults sharing the same ShareToken (multi-asset system)
- **Damage Severity**: With inflated circulating supply, users depositing receive more shares than deserved (diluting existing holders), while users redeeming receive fewer assets than deserved (direct financial loss). The magnitude depends on the ratio of cancelation shares to total supply.
- **User Impact**: All users performing deposits or redemptions in ANY vault sharing the ShareToken are affected. Each deposit/redeem transaction uses the broken conversion ratio, accumulating losses over time. Users with canceled redeems can still claim their shares directly from the unregistered vault, but the systemic accounting is permanently broken until the vault is re-registered or the ShareToken is upgraded.

## Likelihood Explanation
- **Attacker Profile**: Any user can create the precondition by requesting a redeem, canceling it, and not claiming. The owner then unknowingly unregisters the vault thinking it's safe (seeing `activeRedeemRequestersCount = 0`).
- **Preconditions**: 
  - At least one user must have canceled a redeem request without claiming
  - Owner must set vault to inactive and wait for normal requests to clear
  - Owner must call `unregisterVault()` without manually checking for cancelation shares
- **Execution Complexity**: Single user transaction to set up (cancel redeem), followed by owner action (unregister). No complex timing or multi-block requirements.
- **Frequency**: Can be set up once per vault, permanent impact until fixed. Multiple users can create the condition, increasing likelihood.

## Recommendation

Add tracking for redeem cancelation shares and include checks in `unregisterVault()`:

```solidity
// In src/ERC7575VaultUpgradeable.sol, VaultStorage struct, after line 119:

// Add aggregate tracking for redeem cancelation shares
uint256 totalCancelRedeemShares; // Total shares in pending or claimable redeem cancelation state

// In src/ERC7575VaultUpgradeable.sol, cancelRedeemRequest function, after line 1757:

// Increment total when moving to cancelation
$.totalCancelRedeemShares += pendingShares;

// In src/ERC7575VaultUpgradeable.sol, fulfillCancelRedeemRequest function, line 1089:
// No change needed - shares stay in cancelation tracking

// In src/ERC7575VaultUpgradeable.sol, claimCancelRedeemRequest function, after line 1877:

// Decrement total when shares are claimed
$.totalCancelRedeemShares -= shares;

// In src/interfaces/IVaultMetrics.sol, VaultMetrics struct, after line 9:

uint256 totalCancelRedeemShares; // Add to metrics struct

// In src/ERC7575VaultUpgradeable.sol, getVaultMetrics function, after line 2044:

totalCancelRedeemShares: $.totalCancelRedeemShares, // Include in returned metrics

// In src/ShareTokenUpgradeable.sol, unregisterVault function, after line 302:

if (metrics.totalCancelRedeemShares != 0) {
    revert CannotUnregisterVaultCancelRedeemShares(); // New error, add to interface
}
```

This ensures vault unregistration is blocked when redeem cancelation shares exist, maintaining accurate ShareToken accounting.

## Proof of Concept

```solidity
// File: test/Exploit_VaultUnregisterWithCancelation.t.sol
// Run with: forge test --match-test test_UnregisterVaultWithPendingCancelation -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "./mocks/MockERC20.sol";

contract Exploit_VaultUnregisterWithCancelation is Test {
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable vault;
    MockERC20 asset;
    
    address owner = address(0x1);
    address user = address(0x2);
    address investmentManager = address(0x3);
    
    function setUp() public {
        // Deploy contracts
        asset = new MockERC20("USDC", "USDC", 6);
        shareToken = new ShareTokenUpgradeable();
        vault = new ERC7575VaultUpgradeable();
        
        // Initialize
        shareToken.initialize("Share", "SHR", owner);
        vault.initialize(asset, address(shareToken), owner);
        
        // Register vault
        vm.prank(owner);
        shareToken.registerVault(address(asset), address(vault));
        
        // Setup investment manager
        vm.prank(owner);
        vault.setInvestmentManager(investmentManager);
        
        // Fund user
        asset.mint(user, 10000e6);
        vm.prank(user);
        asset.approve(address(vault), type(uint256).max);
    }
    
    function test_UnregisterVaultWithPendingCancelation() public {
        // SETUP: User requests and fulfills deposit, then requests redeem
        vm.startPrank(user);
        vault.requestDeposit(1000e6, user, user);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        vault.fulfillDeposit(user, 1000e6);
        
        vm.startPrank(user);
        vault.mint(1000e18, user, user); // Claim shares
        
        // Approve shares for redeem
        shareToken.approve(address(shareToken), 500e18);
        vault.requestRedeem(500e18, user, user);
        vm.stopPrank();
        
        // User cancels redeem - shares move to cancelation state
        vm.prank(user);
        vault.cancelRedeemRequest(0, user);
        
        // Investment manager fulfills cancelation
        vm.prank(investmentManager);
        vault.fulfillCancelRedeemRequest(user);
        
        // EXPLOIT: Owner unregisters vault (checks pass incorrectly)
        vm.startPrank(owner);
        vault.setVaultActive(false);
        
        // Verify vault passes unregister checks despite holding cancelation shares
        (uint256 circSupplyBefore, uint256 assetsBefore) = shareToken.getCirculatingSupplyAndAssets();
        
        shareToken.unregisterVault(address(asset));
        vm.stopPrank();
        
        // VERIFY: Circulating supply is now inflated (doesn't subtract vault's 500 shares)
        (uint256 circSupplyAfter, uint256 assetsAfter) = shareToken.getCirculatingSupplyAndAssets();
        
        // Cancelation shares should be subtracted but aren't
        assertGt(circSupplyAfter, circSupplyBefore, "Circulating supply should increase due to missing subtraction");
        
        // User can still claim but conversion ratio is broken
        assertEq(vault.claimableCancelRedeemRequest(0, user), 500e18, "User should have 500 claimable shares");
    }
}
```

## Notes

The vulnerability stems from an architectural inconsistency: deposit cancelations use `totalCancelDepositAssets` for aggregate tracking (checked in unregisterVault), but redeem cancelations lack an equivalent `totalCancelRedeemShares` variable. This asymmetry creates a blind spot in the safety checks.

The issue affects the entire multi-asset vault system because `getCirculatingSupplyAndAssets()` is used for all share/asset conversions across all vaults sharing the ShareToken. Even if only one vault is improperly unregistered, the conversion ratios for deposits and redemptions in ALL vaults become inaccurate.

Users with canceled redeems are not at risk - they can still claim their shares directly from the unregistered vault contract. The financial harm falls on OTHER users who perform subsequent deposits/redemptions at incorrect conversion rates.

### Citations

**File:** src/interfaces/IVaultMetrics.sol (L6-20)
```text
    struct VaultMetrics {
        uint256 totalPendingDepositAssets;
        uint256 totalClaimableRedeemAssets;
        uint256 totalCancelDepositAssets; // ERC7887 cancelation assets
        uint64 scalingFactor;
        uint256 totalAssets;
        uint256 availableForInvestment;
        uint256 activeDepositRequestersCount;
        uint256 activeRedeemRequestersCount;
        bool isActive;
        address asset;
        address shareToken;
        address investmentManager;
        address investmentVault;
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

**File:** src/ERC7575VaultUpgradeable.sol (L1745-1764)
```text
    function cancelRedeemRequest(uint256 requestId, address controller) external nonReentrant {
        VaultStorage storage $ = _getVaultStorage();
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 pendingShares = $.pendingRedeemShares[controller];
        if (pendingShares == 0) revert NoPendingCancelRedeem();

        // Move from pending to pending cancelation
        delete $.pendingRedeemShares[controller];
        $.pendingCancelRedeemShares[controller] = pendingShares;

        // Block new redeem requests
        $.controllersWithPendingRedeemCancelations.add(controller);
        $.activeRedeemRequesters.remove(controller);

        emit CancelRedeemRequest(controller, controller, REQUEST_ID, msg.sender, pendingShares);
    }
```

**File:** src/ShareTokenUpgradeable.sol (L293-309)
```text
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
```

**File:** src/ShareTokenUpgradeable.sol (L322-324)
```text
        // Remove vault registration (automatically removes from enumerable collection)
        $.assetToVault.remove(asset);
        delete $.vaultToAsset[vaultAddress];
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

**File:** src/ShareTokenUpgradeable.sol (L701-711)
```text
    function convertNormalizedAssetsToShares(uint256 normalizedAssets, Math.Rounding rounding) external view returns (uint256 shares) {
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = this.getCirculatingSupplyAndAssets();

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;
        totalNormalizedAssets += VIRTUAL_ASSETS;

        // shares = normalizedAssets * circulatingSupply / totalNormalizedAssets
        shares = Math.mulDiv(normalizedAssets, circulatingSupply, totalNormalizedAssets, rounding);
    }
```
