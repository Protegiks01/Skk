# Audit Report

## Title
Asymmetric Tracking of Vault-Held Shares Causes Circulating Supply Inflation and Distorted Conversion Ratios

## Summary
The protocol implements asymmetric tracking between deposit and redemption flows: redemption shares held by vaults are tracked in a global counter (`totalClaimableRedeemShares`) and excluded from circulating supply, but deposit shares minted to vaults have no global counter and remain incorrectly included in circulating supply calculations. This causes systematic over-issuance of shares during deposit fulfillments and violates Invariant #10 conversion accuracy.

## Impact
**Severity**: Medium (potentially High given systematic dilution impact)

During the window between deposit fulfillment and user claim, circulating supply is inflated by the amount of vault-held deposit shares. This inflated value is used in `convertNormalizedAssetsToShares()` which is called by `_convertToShares()` during `fulfillDeposit()` operations. [1](#0-0)  Users receive more shares than they should during deposit fulfillments, diluting existing shareholders. The magnitude scales with the amount of unclaimed fulfilled deposits across all vaults.

## Finding Description

**Location:** `src/ShareTokenUpgradeable.sol` (lines 369-390, 701-737), `src/ERC7575VaultUpgradeable.sol` (lines 90-115, 430-445, 822-841, 1188-1196, 1531-1538)

**Intended Logic:** 
Per the conversion function documentation at lines 690-692 of ShareTokenUpgradeable.sol, both assets and shares should "exclude reserved redemption assets" and "exclude vault-held shares for redemption claims" to ensure "both numerator and denominator represent the same economic scope". All vault-held shares reserved for user claims (whether deposits or redemptions) should be excluded from circulating supply to maintain accurate conversion ratios and satisfy Invariant #10: "convertToShares(convertToAssets(x)) ≈ x".

**Actual Logic:**
The implementation creates an asymmetry:

1. **Redemption Flow** (symmetric tracking):
   - Global counter exists: [2](#0-1) 
   - Updated on fulfillment: [3](#0-2) 
   - Decremented on claim: [4](#0-3) 

2. **Deposit Flow** (asymmetric tracking):
   - NO global counter exists, only per-user mapping: [5](#0-4) 
   - Shares minted to vault on fulfillment: [6](#0-5) 
   - No global counter to decrement on claim

3. **Circulating Supply Calculation**:
   - Returns only redemption shares: [7](#0-6) 
   - Excludes only redemption shares from totalSupply: [8](#0-7) 

4. **Conversion Impact**:
   - Inflated circulating supply used in conversions: [9](#0-8) 
   - Affects actual minting via `_convertToShares()`: [10](#0-9) 

**Exploitation Path:**
1. **Normal Operation**: User calls `requestDeposit()` with 1000 assets
2. **Fulfillment**: Investment Manager calls `fulfillDeposit()` which:
   - Calculates shares using `_convertToShares(1000)` with INFLATED circulating supply
   - Mints more shares than correct (e.g., 100 instead of 90 if 10% of supply is unclaimed deposits)
   - Stores shares in vault without updating global counter
3. **Systematic Impact**: Every deposit fulfillment during vulnerability window issues ~10% excess shares (assuming 10% of supply is unclaimed deposits)
4. **Dilution**: Existing shareholders' ownership percentage decreases with each fulfillment
5. **Duration**: Window persists as long as users delay claiming (no forced claim mechanism)

**Security Property Broken:**
Violates README Invariant #10: "convertToShares(convertToAssets(x)) ≈ x - Rounding accuracy"

## Impact Explanation

**Affected Assets**: All share tokens across all vaults during periods of unclaimed fulfilled deposits

**Damage Severity**:
- Systematic over-issuance of shares during deposit fulfillments (inflated numerator in conversion)
- Dilution of existing shareholders (indirect value loss)
- Incorrect preview functions affecting user decisions
- Impact magnitude proportional to `unclaimedDepositShares / totalSupply` ratio
- In active systems with delayed claims, could represent 5-20% over-issuance

**User Impact**: All existing shareholders suffer dilution; new depositors receive excess shares

**Trigger Conditions**: Automatically occurs during normal `fulfillDeposit()` operations whenever unclaimed fulfilled deposits exist

## Likelihood Explanation

**Attacker Profile**: No attacker needed - occurs automatically during normal protocol operations

**Preconditions**:
1. Deposits have been fulfilled but not yet claimed (expected in async vault systems)
2. Investment Manager calls `fulfillDeposit()` for new deposits
3. No special timing or conditions required

**Execution Complexity**: Zero - happens automatically as part of normal fulfillment flow

**Economic Cost**: None - protocol bears the cost via dilution

**Frequency**: Continuous during any period with unclaimed fulfilled deposits (expected to be common)

**Overall Likelihood**: HIGH - Natural consequence of normal async deposit operations

## Recommendation

**Primary Fix - Add Global Deposit Share Tracking:**

Add to VaultStorage after line 100 in `src/ERC7575VaultUpgradeable.sol`:
```solidity
uint256 totalClaimableDepositShares; // Shares held by vault for fulfilled deposits
```

Update `fulfillDeposit()` after line 438:
```solidity
$.totalClaimableDepositShares += shares;
```

Update `fulfillDeposits()` after line 480:
```solidity
$.totalClaimableDepositShares += shareAmounts;
```

Update `deposit()` after line 579 and `mint()` after line 655:
```solidity
$.totalClaimableDepositShares -= shares;
```

Update `getClaimableSharesAndNormalizedAssets()` at line 1533:
```solidity
totalClaimableShares = $.totalClaimableRedeemShares + $.totalClaimableDepositShares;
```

**Additional Mitigations**:
- Add invariant test: `circulatingSupply + totalClaimableRedeemShares + totalClaimableDepositShares == totalSupply()`
- Document the symmetric tracking requirement in comments

## Proof of Concept

The provided PoC demonstrates the vulnerability window:
1. User deposits, Investment Manager fulfills → shares minted to vault
2. Before claim: circulating supply includes these vault-held shares (INCORRECT)
3. Conversion during this window uses inflated supply → wrong ratios
4. After claim: shares transferred to user, vulnerability window closes for those shares

Expected behavior: Circulating supply should exclude ALL vault-held shares immediately upon fulfillment, not only after claim.

## Notes

This vulnerability stems from incomplete implementation when adding the redemption tracking feature. While `totalClaimableRedeemShares` was properly implemented with global tracking, the symmetric `totalClaimableDepositShares` was never added, creating an asymmetry that inflates circulating supply calculations.

The impact is systematic but timing-dependent - greatest when many users delay claiming. This represents an accounting error that affects core protocol functionality (share issuance calculations) and could lead to material dilution in active systems. While not a direct theft vector, the systematic over-issuance of shares dilutes existing shareholders, which constitutes indirect value loss meriting Medium severity (potentially High given the systematic nature and dilution impact on all shareholders).

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L100-100)
```text
        uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
```

**File:** src/ERC7575VaultUpgradeable.sol (L103-103)
```text
        mapping(address controller => uint256 shares) claimableDepositShares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L433-433)
```text
        shares = _convertToShares(assets, Math.Rounding.Floor);
```

**File:** src/ERC7575VaultUpgradeable.sol (L438-442)
```text
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming

        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);
```

**File:** src/ERC7575VaultUpgradeable.sol (L837-837)
```text
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned
```

**File:** src/ERC7575VaultUpgradeable.sol (L909-909)
```text
        $.totalClaimableRedeemShares -= shares; // Decrement shares that are being burned
```

**File:** src/ERC7575VaultUpgradeable.sol (L1188-1196)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        // First normalize assets to 18 decimals using scaling factor
        // Use Math.mulDiv to prevent overflow for large amounts
        uint256 normalizedAssets = Math.mulDiv(assets, $.scalingFactor, 1);

        // Use optimized ShareToken conversion method (single call instead of multiple)
        shares = ShareTokenUpgradeable($.shareToken).convertNormalizedAssetsToShares(normalizedAssets, rounding);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1531-1533)
```text
    function getClaimableSharesAndNormalizedAssets() external view returns (uint256 totalClaimableShares, uint256 totalNormalizedAssets) {
        VaultStorage storage $ = _getVaultStorage();
        totalClaimableShares = $.totalClaimableRedeemShares;
```

**File:** src/ShareTokenUpgradeable.sol (L386-389)
```text
        // Get total supply
        uint256 supply = totalSupply();
        // Calculate circulating supply: total supply minus vault-held shares for redemption claims
        circulatingSupply = totalClaimableShares > supply ? 0 : supply - totalClaimableShares;
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
