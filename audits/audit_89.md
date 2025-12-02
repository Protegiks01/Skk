## Title
Circulating Supply Inflated by Claimable Deposit Shares Leading to Distorted Conversion Ratios

## Summary
The `getCirculatingSupplyAndAssets()` function in `ShareTokenUpgradeable` incorrectly calculates circulating supply by only subtracting `totalClaimableRedeemShares` from `totalSupply()`, but fails to account for shares minted to vaults during deposit fulfillment. This causes circulating supply inflation and distorts all asset-to-share conversion ratios throughout the protocol.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` (lines 369-390), `src/ERC7575VaultUpgradeable.sol` (lines 430-445, 822-841, 1531-1538)

**Intended Logic:** The circulating supply should exclude ALL shares held by vaults that are reserved for user claims, whether from deposits or redemptions. The conversion functions should use this accurate circulating supply to maintain correct asset-to-share exchange rates.

**Actual Logic:** The code implements asymmetric tracking:
1. For redemptions: A global counter `totalClaimableRedeemShares` tracks all redemption shares held by vaults [1](#0-0) 
2. For deposits: Only per-user mapping `claimableDepositShares[controller]` exists with NO global counter [2](#0-1) 
3. `getClaimableSharesAndNormalizedAssets()` only returns `totalClaimableRedeemShares` [3](#0-2) 
4. Circulating supply calculation subtracts ONLY redemption shares, missing deposit shares [4](#0-3) 

**Exploitation Path:**
1. Users call `requestDeposit()` submitting assets to vaults
2. Investment manager calls `fulfillDeposit()` which mints shares to the vault [5](#0-4) 
3. These shares increase `totalSupply()` and vault balances, but are NOT tracked in any global counter
4. When `getCirculatingSupplyAndAssets()` is called, it subtracts only `totalClaimableRedeemShares` from `totalSupply()`, leaving the deposit shares in the circulating supply calculation [6](#0-5) 
5. Any user calling `convertNormalizedAssetsToShares()` or `convertSharesToNormalizedAssets()` receives incorrect conversion rates [7](#0-6) 
6. All vault operations using `_convertToShares()` and `_convertToAssets()` are affected [8](#0-7) 

**Security Property Broken:** Invariant #10 "Conversion Accuracy: convertToShares(convertToAssets(x)) ≈ x (within rounding tolerance)" is violated because the inflated circulating supply causes systematic conversion errors.

## Impact Explanation
- **Affected Assets**: All users interacting with the protocol during periods when fulfilled deposits have not yet been claimed
- **Damage Severity**: 
  - Users converting assets to shares receive MORE shares than they should (inflated numerator in line 710)
  - Users converting shares to assets receive FEWER assets than they should (inflated denominator in line 736)
  - Impact scales with the amount of unfulfilled claimable deposits across all vaults
  - ERC4626 preview functions return incorrect values affecting user decisions
- **User Impact**: All users performing conversions during the vulnerability window (between deposit fulfillment and claim), which can be prolonged as users are not forced to claim immediately

## Likelihood Explanation
- **Attacker Profile**: No special permissions needed - any user is affected during normal protocol operations
- **Preconditions**: 
  - Deposits have been fulfilled but not yet claimed (common scenario in async vault systems)
  - Users attempt conversions or vault operations during this period
- **Execution Complexity**: Occurs automatically during normal protocol flow, no special setup required
- **Frequency**: Continuously active whenever there are unclaimed fulfilled deposits, which is expected to be common in an async deposit system

## Recommendation

**In `src/ERC7575VaultUpgradeable.sol`, add global tracking for claimable deposit shares:**

```solidity
// In VaultStorage struct (after line 100):

// CURRENT (vulnerable):
uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
// ERC7540 mappings with descriptive names
mapping(address controller => uint256 assets) pendingDepositAssets;
mapping(address controller => uint256 shares) claimableDepositShares;

// FIXED:
uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
uint256 totalClaimableDepositShares; // Shares held by vault for fulfilled but unclaimed deposits
// ERC7540 mappings with descriptive names
mapping(address controller => uint256 assets) pendingDepositAssets;
mapping(address controller => uint256 shares) claimableDepositShares;
```

**In `fulfillDeposit()` function (after line 438):**

```solidity
// CURRENT (vulnerable):
$.claimableDepositShares[controller] += shares;
$.claimableDepositAssets[controller] += assets;
// Mint shares to this vault
ShareTokenUpgradeable($.shareToken).mint(address(this), shares);

// FIXED:
$.claimableDepositShares[controller] += shares;
$.claimableDepositAssets[controller] += assets;
$.totalClaimableDepositShares += shares; // Track global deposit shares
// Mint shares to this vault
ShareTokenUpgradeable($.shareToken).mint(address(this), shares);
```

**In `fulfillDeposits()` function (after line 476):**

```solidity
// CURRENT (vulnerable):
shares[i] = shareAmount;
}
$.totalPendingDepositAssets -= assetAmounts;
ShareTokenUpgradeable($.shareToken).mint(address(this), shareAmounts);

// FIXED:
shares[i] = shareAmount;
}
$.totalPendingDepositAssets -= assetAmounts;
$.totalClaimableDepositShares += shareAmounts; // Track global deposit shares
ShareTokenUpgradeable($.shareToken).mint(address(this), shareAmounts);
```

**In claim functions (deposit/mint), decrement the global counter:**

```solidity
// In deposit() and mint() functions, after updating per-user mappings:

// FIXED (add after line 579 in deposit() and line 655 in mint()):
$.totalClaimableDepositShares -= shares; // Decrement global counter when shares are claimed
```

**In `getClaimableSharesAndNormalizedAssets()` function:**

```solidity
// CURRENT (vulnerable):
function getClaimableSharesAndNormalizedAssets() external view returns (uint256 totalClaimableShares, uint256 totalNormalizedAssets) {
    VaultStorage storage $ = _getVaultStorage();
    totalClaimableShares = $.totalClaimableRedeemShares;
    // ... rest of function

// FIXED:
function getClaimableSharesAndNormalizedAssets() external view returns (uint256 totalClaimableShares, uint256 totalNormalizedAssets) {
    VaultStorage storage $ = _getVaultStorage();
    totalClaimableShares = $.totalClaimableRedeemShares + $.totalClaimableDepositShares; // Include both deposit and redeem shares
    // ... rest of function
```

## Proof of Concept

```solidity
// File: test/Exploit_CirculatingSupplyInflation.t.sol
// Run with: forge test --match-test test_CirculatingSupplyInflation -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575Vault.sol";

contract Exploit_CirculatingSupplyInflation is Test {
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable vault;
    IERC20 asset;
    address alice = address(0xa11ce);
    address bob = address(0xb0b);
    address investmentManager = address(0x1234);
    
    function setUp() public {
        // Deploy contracts and setup (simplified)
        // Assume proper initialization with asset, shareToken, vault
    }
    
    function test_CirculatingSupplyInflation() public {
        // SETUP: Alice deposits 1000 assets
        uint256 depositAmount = 1000e18;
        vm.startPrank(alice);
        asset.approve(address(vault), depositAmount);
        vault.requestDeposit(depositAmount, alice, alice);
        vm.stopPrank();
        
        // Investment manager fulfills the deposit, minting shares to vault
        vm.prank(investmentManager);
        uint256 sharesMinted = vault.fulfillDeposit(alice, depositAmount);
        
        // EXPLOIT: Check circulating supply BEFORE Alice claims
        (uint256 circulatingSupplyBefore, ) = shareToken.getCirculatingSupplyAndAssets();
        uint256 totalSupplyBefore = shareToken.totalSupply();
        
        // The circulating supply should exclude the shares held by vault for Alice
        // But it doesn't! It only excludes redemption shares, not deposit shares
        uint256 expectedCirculatingSupply = totalSupplyBefore - sharesMinted;
        
        // VERIFY: Circulating supply is INFLATED
        assertTrue(circulatingSupplyBefore > expectedCirculatingSupply, 
            "Vulnerability confirmed: Circulating supply is inflated by claimable deposit shares");
        
        // This inflation affects conversion ratios
        uint256 assetsToConvert = 100e18;
        uint256 inflatedShares = shareToken.convertNormalizedAssetsToShares(assetsToConvert, Math.Rounding.Floor);
        
        // Alice claims her shares
        vm.prank(alice);
        vault.deposit(depositAmount, alice, alice);
        
        // After claim, check again
        (uint256 circulatingSupplyAfter, ) = shareToken.getCirculatingSupplyAndAssets();
        uint256 correctShares = shareToken.convertNormalizedAssetsToShares(assetsToConvert, Math.Rounding.Floor);
        
        // VERIFY: Conversion ratio was distorted during the vulnerability window
        assertTrue(inflatedShares > correctShares,
            "Vulnerability confirmed: Conversion ratio was distorted by inflated circulating supply");
    }
}
```

## Notes

This vulnerability stems from an **asymmetric implementation** between deposit and redemption tracking. The code properly implements `totalClaimableRedeemShares` for redemptions [9](#0-8)  but lacks an equivalent `totalClaimableDepositShares` for deposits. 

When deposits are fulfilled, shares are minted to vaults [5](#0-4)  and stored per-user [10](#0-9) , but no global aggregation occurs. This causes `getCirculatingSupplyAndAssets()` to return an inflated circulating supply that includes these vault-held deposit shares.

The inflated circulating supply directly affects all conversion operations in the protocol [11](#0-10) , causing users to receive incorrect amounts during the window between deposit fulfillment and claim. This is a systematic accounting error that violates the protocol's conversion accuracy invariant and can lead to financial losses for users.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L100-100)
```text
        uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
```

**File:** src/ERC7575VaultUpgradeable.sol (L103-103)
```text
        mapping(address controller => uint256 shares) claimableDepositShares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L438-438)
```text
        $.claimableDepositShares[controller] += shares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L441-442)
```text
        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);
```

**File:** src/ERC7575VaultUpgradeable.sol (L837-837)
```text
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned
```

**File:** src/ERC7575VaultUpgradeable.sol (L1188-1216)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        // First normalize assets to 18 decimals using scaling factor
        // Use Math.mulDiv to prevent overflow for large amounts
        uint256 normalizedAssets = Math.mulDiv(assets, $.scalingFactor, 1);

        // Use optimized ShareToken conversion method (single call instead of multiple)
        shares = ShareTokenUpgradeable($.shareToken).convertNormalizedAssetsToShares(normalizedAssets, rounding);
    }

    /**
     * @dev Internal function to convert shares to assets with specified rounding
     * @param shares Amount of shares to convert
     * @param rounding Rounding mode (Floor = favor vault, Ceil = favor user)
     * @return assets Amount of assets equivalent to shares
     */
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        uint256 scaling = $.scalingFactor;
        // Use optimized ShareToken conversion method (single call instead of multiple)
        uint256 normalizedAssets = ShareTokenUpgradeable($.shareToken).convertSharesToNormalizedAssets(shares, rounding);

        // Then denormalize back to original asset decimals
        if (scaling == 1) {
            return normalizedAssets;
        } else {
            return Math.mulDiv(normalizedAssets, 1, scaling, rounding);
        }
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1531-1533)
```text
    function getClaimableSharesAndNormalizedAssets() external view returns (uint256 totalClaimableShares, uint256 totalNormalizedAssets) {
        VaultStorage storage $ = _getVaultStorage();
        totalClaimableShares = $.totalClaimableRedeemShares;
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

**File:** src/ShareTokenUpgradeable.sol (L701-737)
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

    /**
     *  OPTIMIZED CONVERSION: Shares to normalized assets with mathematical consistency
     *
     * MATHEMATICAL CONSISTENCY:
     * This function uses the same circulating supply approach as convertNormalizedAssetsToShares
     * to ensure consistent conversion ratios in both directions during ERC7540 async operations.
     *
     * See convertNormalizedAssetsToShares documentation for detailed explanation of the
     * mathematical consistency fix.
     *
     * @param shares Amount of shares to convert
     * @param rounding Rounding mode for the conversion
     * @return normalizedAssets Amount of normalized assets (18 decimals) equivalent to the shares
     */
    function convertSharesToNormalizedAssets(uint256 shares, Math.Rounding rounding) external view returns (uint256 normalizedAssets) {
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = this.getCirculatingSupplyAndAssets();

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;
        totalNormalizedAssets += VIRTUAL_ASSETS;

        // normalizedAssets = shares * totalNormalizedAssets / circulatingSupply
        normalizedAssets = Math.mulDiv(shares, totalNormalizedAssets, circulatingSupply, rounding);
    }
```
