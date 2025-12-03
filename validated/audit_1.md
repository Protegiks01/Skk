## Audit Report

### Title
Vault Unregistration Bypasses Redeem Cancelation Share Tracking, Breaking ShareToken Conversion Ratios

### Summary
The `unregisterVault()` function fails to validate redeem cancelation shares before allowing vault unregistration due to missing aggregate tracking. When a vault holding cancelation shares is unregistered, the shares are excluded from `getCirculatingSupplyAndAssets()` calculations, permanently inflating circulating supply and breaking conversion ratios across all vaults sharing the ShareToken.

### Impact
**Severity**: Medium - Accounting error causing systematic conversion ratio miscalculation

This vulnerability creates system-wide accounting corruption. When an unregistered vault holds redeem cancelation shares, those shares remain physically held by the vault contract but are no longer subtracted from total supply during circulating supply calculations. This inflates the circulating supply metric used by `convertNormalizedAssetsToShares()` for ALL deposit and redeem operations across ALL vaults sharing the affected ShareToken. Users depositing will receive more shares than deserved (diluting existing shareholders), while users redeeming will receive fewer assets than entitled. The magnitude scales with the ratio of untracked cancelation shares to total supply, and the effect persists until the vault is re-registered or the ShareToken is upgraded.

### Finding Description

**Location:** `src/ShareTokenUpgradeable.sol` (unregisterVault, lines 282-327; getCirculatingSupplyAndAssets, lines 369-390) and `src/ERC7575VaultUpgradeable.sol` (cancelRedeemRequest, lines 1745-1764)

**Intended Logic:** 
The `unregisterVault()` function should prevent vault unregistration when any user funds or claims remain outstanding. The function performs comprehensive safety checks via `getVaultMetrics()` to validate no pending operations exist before allowing unregistration.

**Actual Logic:**
The safety checks exhibit architectural asymmetry between deposit and redeem cancelations:

- **Deposit cancelations:** Tracked via aggregate `totalCancelDepositAssets` variable [1](#0-0) , which is checked during unregistration [2](#0-1) 

- **Redeem cancelations:** Tracked only via individual mappings `pendingCancelRedeemShares` and `claimableCancelRedeemShares` [3](#0-2)  with NO aggregate tracking variable

The `VaultMetrics` struct returned by `getVaultMetrics()` includes `totalCancelDepositAssets` [4](#0-3)  but has no corresponding field for redeem cancelation shares.

**Exploitation Path:**

1. **User cancels redeem request:** Calling `cancelRedeemRequest()` moves shares from `pendingRedeemShares` to `pendingCancelRedeemShares` and crucially removes the user from `activeRedeemRequesters` [5](#0-4) 

2. **Investment manager fulfills cancelation:** Calling `fulfillCancelRedeemRequest()` moves shares to `claimableCancelRedeemShares` [6](#0-5)  where they remain vault-held but untracked

3. **Owner unregisters vault:** The `unregisterVault()` checks pass because `activeRedeemRequestersCount` is zero and no aggregate redeem cancelation check exists [7](#0-6) 

4. **Vault removed from registry:** Successfully unregistered despite holding claimable cancelation shares [8](#0-7) 

5. **Circulating supply calculation corrupted:** The `getCirculatingSupplyAndAssets()` function only iterates through registered vaults [9](#0-8) , so unregistered vault's shares are not subtracted from total supply, inflating circulating supply

6. **Conversion ratios broken system-wide:** All deposits and redemptions use the inflated circulating supply in `convertNormalizedAssetsToShares()` [10](#0-9) , affecting every user across all vaults

**Security Property Broken:**
Violates Invariant #10 from README: "convertToShares(convertToAssets(x)) ≈ x - Rounding accuracy". The inflated circulating supply causes systematic conversion inaccuracy beyond acceptable rounding tolerance.

### Likelihood Explanation

**Attacker Profile:** Any user can establish the precondition by requesting redeem, canceling it, and not claiming. The owner then unknowingly unregisters the vault believing it safe based on `activeRedeemRequestersCount = 0`.

**Preconditions:**
1. At least one user has canceled redeem request without claiming
2. Owner sets vault inactive and waits for normal operations to clear
3. Owner calls `unregisterVault()` relying on automated safety checks

**Execution Complexity:** Minimal - natural protocol operations without complex timing requirements or multi-block coordination.

**Frequency:** Can occur once per vault with permanent impact until remediation. Multiple users creating the condition increases likelihood.

**Overall Likelihood:** Medium - Requires natural sequence of user operations followed by routine administrative action.

### Recommendation

Implement aggregate tracking for redeem cancelation shares with corresponding safety checks:

**1. Add aggregate tracker to VaultStorage:**
```solidity
// After line 119 in src/ERC7575VaultUpgradeable.sol
uint256 totalCancelRedeemShares;
```

**2. Update cancelRedeemRequest to increment tracker:**
```solidity
// After line 1757 in src/ERC7575VaultUpgradeable.sol
$.totalCancelRedeemShares += pendingShares;
```

**3. Update claimCancelRedeemRequest to decrement tracker:**
```solidity
// After line 1877 in src/ERC7575VaultUpgradeable.sol
$.totalCancelRedeemShares -= shares;
```

**4. Add field to VaultMetrics struct:**
```solidity
// In VaultMetrics struct definition
uint256 totalCancelRedeemShares;
```

**5. Include in getVaultMetrics return value:**
```solidity
// In getVaultMetrics function after line 2045
totalCancelRedeemShares: $.totalCancelRedeemShares,
```

**6. Add validation check in unregisterVault:**
```solidity
// After line 302 in src/ShareTokenUpgradeable.sol
if (metrics.totalCancelRedeemShares != 0) {
    revert CannotUnregisterVaultCancelRedeemShares();
}
```

This establishes parity with deposit cancelation tracking and prevents unregistration while redeem cancelation shares remain outstanding.

### Notes

The vulnerability stems from architectural asymmetry: deposit cancelations use `totalCancelDepositAssets` for aggregate tracking (verified in unregistration), while redeem cancelations lack equivalent `totalCancelRedeemShares` tracking. This creates a blind spot in safety validation.

The impact extends beyond the single unregistered vault because `getCirculatingSupplyAndAssets()` provides conversion ratios for ALL vaults sharing the ShareToken in the multi-asset system. Users with canceled redeems retain claim rights on the unregistered vault, but OTHER users suffer from broken conversion ratios during subsequent deposits/redemptions across all vaults.

The issue is NOT mentioned in KNOWN_ISSUES.md Section 4, which discusses that request cancellation is intentional user protection but does not address the unregistration validation gap. This represents a genuine oversight in the comprehensive safety check implementation rather than intentional design.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L116-117)
```text
        mapping(address controller => uint256 shares) pendingCancelRedeemShares;
        mapping(address controller => uint256 shares) claimableCancelRedeemShares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L119-119)
```text
        uint256 totalCancelDepositAssets;
```

**File:** src/ERC7575VaultUpgradeable.sol (L1088-1090)
```text
        // Move from pending to claimable cancelation state
        delete $.pendingCancelRedeemShares[controller];
        $.claimableCancelRedeemShares[controller] += shares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L1756-1761)
```text
        delete $.pendingRedeemShares[controller];
        $.pendingCancelRedeemShares[controller] = pendingShares;

        // Block new redeem requests
        $.controllersWithPendingRedeemCancelations.add(controller);
        $.activeRedeemRequesters.remove(controller);
```

**File:** src/ERC7575VaultUpgradeable.sol (L2042-2056)
```text
        metrics = VaultMetrics({
            totalPendingDepositAssets: $.totalPendingDepositAssets,
            totalClaimableRedeemAssets: $.totalClaimableRedeemAssets,
            totalCancelDepositAssets: $.totalCancelDepositAssets,
            scalingFactor: $.scalingFactor,
            totalAssets: totalAssets(),
            availableForInvestment: totalAssets(),
            activeDepositRequestersCount: $.activeDepositRequesters.length(),
            activeRedeemRequestersCount: $.activeRedeemRequesters.length(),
            isActive: $.isActive,
            asset: $.asset,
            shareToken: $.shareToken,
            investmentManager: $.investmentManager,
            investmentVault: $.investmentVault
        });
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

**File:** src/ShareTokenUpgradeable.sol (L374-380)
```text
        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Get both claimable shares and normalized assets in a single call for gas efficiency
            (uint256 vaultClaimableShares, uint256 vaultNormalizedAssets) = IERC7575Vault(vaultAddress).getClaimableSharesAndNormalizedAssets();
            totalClaimableShares += vaultClaimableShares;
            totalNormalizedAssets += vaultNormalizedAssets;
```

**File:** src/ShareTokenUpgradeable.sol (L701-710)
```text
    function convertNormalizedAssetsToShares(uint256 normalizedAssets, Math.Rounding rounding) external view returns (uint256 shares) {
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = this.getCirculatingSupplyAndAssets();

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;
        totalNormalizedAssets += VIRTUAL_ASSETS;

        // shares = normalizedAssets * circulatingSupply / totalNormalizedAssets
        shares = Math.mulDiv(normalizedAssets, circulatingSupply, totalNormalizedAssets, rounding);
```
