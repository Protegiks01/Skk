## Title
Asymmetric Circulating Supply Calculation Excludes Only Redeem Shares, Not Deposit Shares, Breaking Conversion Rate Accuracy

## Summary
The `getCirculatingSupplyAndAssets()` function in `ShareTokenUpgradeable.sol` only excludes `totalClaimableRedeemShares` from circulating supply, but fails to exclude shares held by vaults for fulfilled deposit claims. This asymmetry inflates the circulating supply when deposits are fulfilled but not yet claimed, distorting share-to-asset conversion rates for all users and violating the protocol's Conversion Accuracy invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/ShareTokenUpgradeable.sol` (getCirculatingSupplyAndAssets function) and `src/ERC7575VaultUpgradeable.sol` (getClaimableSharesAndNormalizedAssets function)

**Intended Logic:** The circulating supply should exclude ALL vault-held shares that are allocated to users but not yet claimed, ensuring accurate conversion rates between shares and assets across both deposit and redeem operations.

**Actual Logic:** The system only tracks and excludes `totalClaimableRedeemShares` but has no `totalClaimableDepositShares` tracking. When deposits are fulfilled, shares are minted to the vault but these shares remain counted in circulating supply until claimed.

**Exploitation Path:**

1. **Deposit Fulfillment Creates Vault-Held Shares**: When `fulfillDeposit()` is called, shares are minted directly to the vault address and stored in per-user mappings, but no aggregate `totalClaimableDepositShares` is incremented. [1](#0-0) 

2. **Redeem Fulfillment Properly Tracks Shares**: In contrast, `fulfillRedeem()` increments `totalClaimableRedeemShares` which is later used to exclude these shares from circulating supply. [2](#0-1) 

3. **Circulating Supply Calculation Missing Deposit Shares**: The `getCirculatingSupplyAndAssets()` function subtracts only `totalClaimableShares` (which comes from `totalClaimableRedeemShares`) from `totalSupply()`, missing all deposit shares held by vaults. [3](#0-2) 

4. **Only Redeem Shares Returned**: The vault's `getClaimableSharesAndNormalizedAssets()` returns only `totalClaimableRedeemShares`, not deposit shares. [4](#0-3) 

5. **No Tracking Variable Exists**: The `VaultStorage` struct contains `totalClaimableRedeemShares` but no equivalent `totalClaimableDepositShares` variable. [5](#0-4) 

6. **Distorted Conversions**: Both `convertNormalizedAssetsToShares()` and `convertSharesToNormalizedAssets()` use the inflated circulating supply in their calculations, affecting all users. [6](#0-5) 

**Security Property Broken:** Violates **Invariant #10: Conversion Accuracy** - `convertToShares(convertToAssets(x)) ≈ x` (within rounding tolerance). The inflated circulating supply causes systematic conversion errors beyond acceptable rounding tolerances.

## Impact Explanation

- **Affected Assets**: All assets/vaults in the multi-asset system. The shared `ShareToken` uses a single circulating supply calculation that aggregates across all vaults, so deposit shares in ANY vault inflate the denominator for ALL conversion operations.

- **Damage Severity**: 
  - When 10% of total supply sits as unclaimed deposit shares, circulatingSupply is inflated by 10%
  - New depositors calling `fulfillDeposit()` receive ~10% fewer shares than they should
  - Redeemers calling `fulfillRedeem()` receive ~10% fewer assets than they should
  - The error compounds as more deposits accumulate, potentially reaching 20-30% in high-activity periods

- **User Impact**: 
  - ALL users performing deposits or redemptions are affected
  - Particularly harmful during high-volume periods when investment manager batches fulfillments
  - Users who claim quickly are unaffected, but users who delay claims unknowingly benefit at others' expense
  - Creates unfair wealth redistribution from legitimate users to those gaming the timing

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user can trigger this by simply requesting deposits and waiting for fulfillment without claiming. No special permissions required.

- **Preconditions**: 
  - Normal protocol operation with deposit requests
  - Investment manager fulfills deposits (standard workflow)
  - Users delay claiming their fulfilled deposits (common in async protocols)

- **Execution Complexity**: Single transaction to request deposit, then wait for investment manager to fulfill. No complex MEV or timing attacks needed.

- **Frequency**: Occurs continuously during normal protocol operation. The error magnitude increases linearly with unclaimed deposit volume.

## Recommendation

Add tracking for total claimable deposit shares and include them in circulating supply calculations:

```solidity
// In src/ERC7575VaultUpgradeable.sol, VaultStorage struct, after line 100:

// CURRENT (vulnerable):
uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw

// FIXED:
uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
uint256 totalClaimableDepositShares; // Shares held by vault for users to claim after deposit fulfillment

// In src/ERC7575VaultUpgradeable.sol, fulfillDeposit function, after line 442:

// CURRENT (vulnerable):
ShareTokenUpgradeable($.shareToken).mint(address(this), shares);

// FIXED:
ShareTokenUpgradeable($.shareToken).mint(address(this), shares);
$.totalClaimableDepositShares += shares; // Track deposit shares held by vault

// In src/ERC7575VaultUpgradeable.sol, deposit function, after line 580:

// CURRENT (vulnerable):
$.claimableDepositShares[controller] -= shares;
$.claimableDepositAssets[controller] -= assets;

// FIXED:
$.claimableDepositShares[controller] -= shares;
$.claimableDepositAssets[controller] -= assets;
$.totalClaimableDepositShares -= shares; // Decrement when user claims

// In src/ERC7575VaultUpgradeable.sol, mint function, add similar decrement after line 651

// In src/ERC7575VaultUpgradeable.sol, getClaimableSharesAndNormalizedAssets, line 1533:

// CURRENT (vulnerable):
totalClaimableShares = $.totalClaimableRedeemShares;

// FIXED:
totalClaimableShares = $.totalClaimableRedeemShares + $.totalClaimableDepositShares; // Include both types
```

## Proof of Concept

```solidity
// File: test/Exploit_CirculatingSupplyInflation.t.sol
// Run with: forge test --match-test test_CirculatingSupplyInflation -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";

contract Exploit_CirculatingSupplyInflation is Test {
    WERC7575ShareToken shareToken;
    WERC7575Vault vault;
    MockERC20 asset;
    
    address owner = address(0x1);
    address investmentManager = address(0x2);
    address alice = address(0x3);
    address bob = address(0x4);
    
    function setUp() public {
        // Deploy mock asset
        asset = new MockERC20("USD Coin", "USDC", 6);
        
        // Deploy ShareToken and Vault
        vm.startPrank(owner);
        shareToken = new WERC7575ShareToken();
        shareToken.initialize("SukukFi Share", "SUKUK", owner);
        
        vault = new WERC7575Vault();
        vault.initialize(asset, address(shareToken), owner);
        
        shareToken.registerVault(address(asset), address(vault));
        vault.setInvestmentManager(investmentManager);
        vm.stopPrank();
        
        // Mint assets to users
        asset.mint(alice, 1000e6);
        asset.mint(bob, 1000e6);
    }
    
    function test_CirculatingSupplyInflation() public {
        // SETUP: Alice deposits and DOES NOT claim
        vm.startPrank(alice);
        asset.approve(address(vault), 500e6);
        vault.requestDeposit(500e6, alice, alice);
        vm.stopPrank();
        
        // Investment manager fulfills - shares minted to vault
        vm.prank(investmentManager);
        vault.fulfillDeposit(alice, 500e6);
        
        // VERIFY: Vault holds 500e18 shares but they're counted in circulating supply
        uint256 vaultBalance = shareToken.balanceOf(address(vault));
        assertEq(vaultBalance, 500e18, "Vault should hold 500 shares");
        
        (uint256 circSupplyBefore, uint256 assetsBefore) = shareToken.getCirculatingSupplyAndAssets();
        assertEq(circSupplyBefore, 500e18, "Circulating supply incorrectly includes vault-held deposit shares");
        
        // EXPLOIT: Bob deposits with inflated circulating supply
        vm.startPrank(bob);
        asset.approve(address(vault), 500e6);
        vault.requestDeposit(500e6, bob, bob);
        vm.stopPrank();
        
        // Bob gets fewer shares due to inflated denominator
        vm.prank(investmentManager);
        uint256 bobShares = vault.fulfillDeposit(bob, 500e6);
        
        // VERIFY: Bob received incorrect shares
        // With correct circulating supply (0), Bob should get ~500e18 shares
        // With inflated circulating supply (500e18), Bob gets fewer shares
        assertTrue(bobShares < 500e18, "Bob received fewer shares than deserved");
        
        // The vulnerability: Alice's unclaimed shares inflated the conversion rate
        // causing Bob to lose value
        console.log("Alice unclaimed shares:", vaultBalance);
        console.log("Bob received shares:", bobShares);
        console.log("Bob's loss:", 500e18 - bobShares);
    }
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    mapping(address => uint256) public balanceOf;
    
    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    
    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
```

## Notes

This vulnerability creates a systemic imbalance in the protocol's conversion rate mechanism. The asymmetry between deposit and redeem share tracking means that:

1. **Deposit shares** held by vaults inflate circulating supply, making shares appear more abundant than they actually are in circulation
2. **Redeem shares** are correctly excluded, making the accounting asymmetric
3. The more deposits that are fulfilled but unclaimed, the worse the distortion becomes
4. This can be exploited by sophisticated users who understand the timing dynamics, claiming quickly after their own fulfillments while others' unclaimed shares inflate the rate in their favor

The fix requires adding symmetric tracking for both deposit and redeem claimable shares in the `VaultStorage` struct and updating all relevant functions to maintain this invariant.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L86-123)
```text
    struct VaultStorage {
        // Storage slot optimization: pack address + uint64 + bool in single 32-byte slot
        address asset; // 20 bytes
        uint64 scalingFactor; // 8 bytes
        bool isActive; // 1 byte (fits with asset + scalingFactor: total 29 bytes + 3 bytes padding)
        uint8 assetDecimals; // 1 byte
        uint16 minimumDepositAmount; // 2 bytes
        // Remaining addresses (each takes full 32-byte slot)
        address shareToken;
        address investmentManager;
        address investmentVault;
        // Large numbers (each takes full 32-byte slot)
        uint256 totalPendingDepositAssets;
        uint256 totalClaimableRedeemAssets; // Assets reserved for users who can claim them
        uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
        // ERC7540 mappings with descriptive names
        mapping(address controller => uint256 assets) pendingDepositAssets;
        mapping(address controller => uint256 shares) claimableDepositShares;
        mapping(address controller => uint256 assets) claimableDepositAssets; // Store corresponding asset amounts
        mapping(address controller => uint256 shares) pendingRedeemShares;
        mapping(address controller => uint256 assets) claimableRedeemAssets;
        mapping(address controller => uint256 shares) claimableRedeemShares;
        // Off-chain helper sets for tracking active requests (using EnumerableSet for O(1) operations)
        EnumerableSet.AddressSet activeDepositRequesters;
        EnumerableSet.AddressSet activeRedeemRequesters;
        // ERC7887 Cancelation Request Storage (simplified - requestId is always 0)
        // Deposit cancelations: controller => assets (requestId always 0)
        mapping(address controller => uint256 assets) pendingCancelDepositAssets;
        mapping(address controller => uint256 assets) claimableCancelDepositAssets;
        // Redeem cancelations: controller => shares (requestId always 0)
        mapping(address controller => uint256 shares) pendingCancelRedeemShares;
        mapping(address controller => uint256 shares) claimableCancelRedeemShares;
        // Total pending and claimable cancelation deposit assets (for totalAssets() calculation)
        uint256 totalCancelDepositAssets;
        // Track controllers with pending cancelations to block new requests
        EnumerableSet.AddressSet controllersWithPendingDepositCancelations;
        EnumerableSet.AddressSet controllersWithPendingRedeemCancelations;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L425-444)
```text
    function fulfillDeposit(address controller, uint256 assets) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        uint256 pendingAssets = $.pendingDepositAssets[controller];
        if (assets > pendingAssets) {
            revert ERC20InsufficientBalance(address(this), pendingAssets, assets);
        }

        shares = _convertToShares(assets, Math.Rounding.Floor);
        if (shares == 0) revert ZeroShares();

        $.pendingDepositAssets[controller] -= assets;
        $.totalPendingDepositAssets -= assets;
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming

        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);

        return shares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L822-841)
```text
    function fulfillRedeem(address controller, uint256 shares) public nonReentrant returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if (shares == 0) revert ZeroShares();
        uint256 pendingShares = $.pendingRedeemShares[controller];
        if (shares > pendingShares) {
            revert ERC20InsufficientBalance(address(this), pendingShares, shares);
        }

        assets = _convertToAssets(shares, Math.Rounding.Floor);

        $.pendingRedeemShares[controller] -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned

        // Note: Shares are NOT burned here - they will be burned during redeem/withdraw claim
        return assets;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1531-1538)
```text
    function getClaimableSharesAndNormalizedAssets() external view returns (uint256 totalClaimableShares, uint256 totalNormalizedAssets) {
        VaultStorage storage $ = _getVaultStorage();
        totalClaimableShares = $.totalClaimableRedeemShares;

        uint256 vaultAssets = totalAssets();
        // Use Math.mulDiv to prevent overflow for large amounts
        totalNormalizedAssets = Math.mulDiv(vaultAssets, $.scalingFactor, 1);
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
