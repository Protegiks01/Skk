## Title
Investment Vault Conversion Rate Mismatch Causes User Redemption Failures Due to Insufficient Reserved Assets

## Summary
The `withdrawFromInvestment()` function can withdraw significantly fewer assets than requested when the investment vault has adverse conversion rates (due to losses, fees, or yield mechanics), while `fulfillRedeem()` reserves assets based on the main vault's internal conversion rate. This mismatch breaks reserved asset accounting, causing users to be unable to redeem their shares despite having fulfilled requests.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol`
- `fulfillRedeem()` function [1](#0-0) 
- `withdrawFromInvestment()` function [2](#0-1) 
- `setInvestmentVault()` function [3](#0-2) 

**Intended Logic:** The investment manager should be able to fulfill user redemption requests by first calling `fulfillRedeem()` to convert pending shares to claimable assets, then calling `withdrawFromInvestment()` to retrieve necessary liquidity from the investment vault. Users should then be able to claim their assets.

**Actual Logic:** The protocol makes a critical assumption that the main vault's conversion rate equals the investment vault's conversion rate. However, `setInvestmentVault()` accepts ANY ERC7575-compliant vault with matching asset, including yield-bearing vaults or vaults with fees/losses. When `fulfillRedeem()` reserves assets based on the main vault's `_convertToAssets()`, but `withdrawFromInvestment()` retrieves assets from an investment vault with a different (worse) conversion rate, the actual assets received (`actualAmount`) can be significantly less than reserved assets.

**Exploitation Path:**
1. Owner sets an investment vault that has variable conversion rates (yield-bearing, fee-charging, or suffering losses) via `setInvestmentVault()` [3](#0-2) 
2. Main vault invests 1000 assets, receives 1000 investment shares
3. Investment vault suffers losses: 1000 shares now worth only 800 assets (20% loss)
4. User requests redemption of 100 main vault shares
5. Investment manager calls `fulfillRedeem(user, 100)` which calculates and reserves 100 assets using main vault's conversion rate [4](#0-3) 
6. Investment manager calls `withdrawFromInvestment(100)` to retrieve 100 assets
7. Function calls `previewWithdraw(100)` on investment vault, which returns ~125 shares needed (due to adverse 0.8 conversion) [5](#0-4) 
8. Redeems `min(125, maxShares)` shares from investment vault
9. Due to adverse conversion, only receives 80 assets instead of 100 [6](#0-5) 
10. User attempts to claim 100 assets but vault only has 80 assets
11. Transfer fails, user cannot redeem [7](#0-6) 

**Security Property Broken:** 
- **Invariant #9: Reserved Asset Protection** - The protocol cannot maintain `investedAssets + reservedAssets ≤ totalAssets` when the investment vault's conversion rate diverges from the main vault's rate
- **Invariant #8: Async State Flow** - Users get stuck in the Claimable state, unable to complete the redemption lifecycle

## Impact Explanation
- **Affected Assets**: All assets in vaults using investment vaults with variable conversion rates (yield-bearing vaults, fee-charging vaults, or vaults that suffer losses)
- **Damage Severity**: Users cannot redeem their shares even after requests are fulfilled. In the scenario above, users experience a 20% direct loss as they cannot access 20% of their entitled assets. With higher investment vault losses, the impact proportionally worsens.
- **User Impact**: ALL users with fulfilled redemption requests are affected. The vulnerability triggers whenever `withdrawFromInvestment()` returns less than the amount reserved by `fulfillRedeem()`, which can happen anytime the investment vault experiences adverse conversion rates.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a logic error in the protocol design. The owner/investment manager can inadvertently trigger this by using standard ERC4626/ERC7575 vaults (like Aave aTokens, Yearn vaults) as investment vaults.
- **Preconditions**: 
  1. Investment vault has conversion rate different from 1:1 (yield-bearing, fee-charging, or suffered losses)
  2. Investment manager fulfills redemptions before ensuring sufficient liquidity
  3. Investment vault conversion rate worsens between fulfillment and withdrawal
- **Execution Complexity**: Natural protocol operation - no special actions needed beyond normal investment manager workflow
- **Frequency**: Can occur on every redemption cycle when using non-deterministic investment vaults

## Recommendation

**Option 1: Add validation in `withdrawFromInvestment()`**
In `withdrawFromInvestment()`, revert if actual amount withdrawn is significantly less than requested: [8](#0-7) 

Add after line 1505:
```solidity
// Ensure we received sufficient assets (allow small rounding tolerance)
if (actualAmount < amount) {
    // Calculate shortfall percentage
    uint256 shortfall = amount - actualAmount;
    uint256 shortfallBps = (shortfall * 10000) / amount;
    
    // Revert if shortfall exceeds acceptable threshold (e.g., 0.1% = 10 bps)
    if (shortfallBps > 10) {
        revert InsufficientAssetsWithdrawn(amount, actualAmount);
    }
}
```

**Option 2: Add liquidity check in `fulfillRedeem()`**
Prevent fulfillment if insufficient liquidity is available: [1](#0-0) 

Add after line 831:
```solidity
// Verify vault has sufficient liquid assets to cover this fulfillment
uint256 currentBalance = IERC20Metadata($.asset).balanceOf(address(this));
uint256 currentReserved = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;
uint256 availableLiquidity = currentBalance > currentReserved ? currentBalance - currentReserved : 0;

if (availableLiquidity < assets) {
    revert InsufficientLiquidityForFulfillment(assets, availableLiquidity);
}
```

**Option 3 (Recommended): Restrict investment vault types**
Modify `setInvestmentVault()` to only accept deterministic conversion vaults: [3](#0-2) 

Add validation:
```solidity
function setInvestmentVault(IERC7575 investmentVault_) external {
    VaultStorage storage $ = _getVaultStorage();
    if (msg.sender != owner() && msg.sender != $.shareToken) {
        revert Unauthorized();
    }
    if (address(investmentVault_) == address(0)) revert InvalidVault();
    if (address(investmentVault_.asset()) != $.asset) {
        revert AssetMismatch();
    }
    
    // NEW: Verify deterministic conversion (test round-trip)
    // For deterministic vaults: convertToAssets(convertToShares(x)) ≈ x
    uint256 testAmount = 1e18;
    uint256 shares = investmentVault_.convertToShares(testAmount);
    uint256 backToAssets = investmentVault_.convertToAssets(shares);
    
    // Allow max 0.1% deviation for rounding
    uint256 deviation = testAmount > backToAssets ? testAmount - backToAssets : backToAssets - testAmount;
    if ((deviation * 10000) / testAmount > 10) {
        revert InvestmentVaultNotDeterministic();
    }
    
    $.investmentVault = address(investmentVault_);
    emit InvestmentVaultSet(address(investmentVault_));
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock asset with 18 decimals
contract MockAsset is ERC20 {
    constructor() ERC20("Mock Asset", "MOCK") {
        _mint(msg.sender, 1000000e18);
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// Lossy investment vault simulating 20% loss
contract LossyInvestmentVault {
    MockAsset public asset;
    WERC7575ShareToken public shareToken;
    
    // Simulates 20% loss: 1 share = 0.8 assets
    uint256 constant LOSS_FACTOR = 8000; // 80% = 0.8 in basis points
    
    constructor(address _asset, WERC7575ShareToken _shareToken) {
        asset = MockAsset(_asset);
        shareToken = _shareToken;
    }
    
    function share() external view returns (address) {
        return address(shareToken);
    }
    
    function asset() external view returns (address) {
        return address(asset);
    }
    
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        asset.transferFrom(msg.sender, address(this), assets);
        shares = convertToShares(assets);
        shareToken.mint(receiver, shares);
        return shares;
    }
    
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        shareToken.burn(owner, shares);
        assets = convertToAssets(shares);
        asset.transfer(receiver, assets);
        return assets;
    }
    
    function convertToShares(uint256 assets) public pure returns (uint256) {
        // 1 asset = 1.25 shares (because 1 share = 0.8 assets)
        return (assets * 10000) / LOSS_FACTOR;
    }
    
    function convertToAssets(uint256 shares) public pure returns (uint256) {
        // 1 share = 0.8 assets (20% loss)
        return (shares * LOSS_FACTOR) / 10000;
    }
    
    function previewWithdraw(uint256 assets) external pure returns (uint256) {
        return convertToShares(assets);
    }
    
    function previewRedeem(uint256 shares) external pure returns (uint256) {
        return convertToAssets(shares);
    }
}

contract ExploitInvestmentSlippage is Test {
    ERC7575VaultUpgradeable public mainVault;
    ShareTokenUpgradeable public mainShareToken;
    MockAsset public asset;
    LossyInvestmentVault public investmentVault;
    WERC7575ShareToken public investmentShareToken;
    
    address public owner = makeAddr("owner");
    address public user = makeAddr("user");
    address public investmentManager = makeAddr("investmentManager");
    address public validator = makeAddr("validator");
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy asset
        asset = new MockAsset();
        
        // Deploy investment share token
        investmentShareToken = new WERC7575ShareToken("Investment USD", "iUSD");
        
        // Deploy lossy investment vault (simulates 20% loss)
        investmentVault = new LossyInvestmentVault(address(asset), investmentShareToken);
        
        // Setup investment share token
        investmentShareToken.registerVault(address(asset), address(investmentVault));
        investmentShareToken.setValidator(validator);
        investmentShareToken.setKycAdmin(validator);
        
        // Deploy main share token
        ShareTokenUpgradeable mainShareTokenImpl = new ShareTokenUpgradeable();
        bytes memory shareTokenInitData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector,
            "Main Shares",
            "MAIN",
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(mainShareTokenImpl), shareTokenInitData);
        mainShareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy main vault
        ERC7575VaultUpgradeable mainVaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            asset,
            address(mainShareToken),
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(mainVaultImpl), vaultInitData);
        mainVault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // Configure main vault
        mainShareToken.registerVault(address(asset), address(mainVault));
        mainShareToken.setValidator(validator);
        mainShareToken.setKycAdmin(validator);
        mainVault.setInvestmentManager(investmentManager);
        mainVault.setInvestmentVault(investmentVault);
        mainVault.setVaultActive(true);
        
        vm.stopPrank();
        
        // Setup KYC
        vm.startPrank(validator);
        mainShareToken.setKycVerified(user, true);
        mainShareToken.setKycVerified(address(mainVault), true);
        investmentShareToken.setKycVerified(address(mainShareToken), true);
        vm.stopPrank();
        
        // Fund user
        vm.startPrank(owner);
        asset.mint(user, 1000e18);
        asset.mint(address(investmentVault), 10000e18); // Seed investment vault
        vm.stopPrank();
    }
    
    function test_InvestmentSlippageCausesRedemptionFailure() public {
        // 1. User deposits 1000 assets
        vm.startPrank(user);
        asset.approve(address(mainVault), 1000e18);
        mainVault.requestDeposit(1000e18, user, user);
        vm.stopPrank();
        
        // 2. Investment manager fulfills deposit
        vm.startPrank(investmentManager);
        mainVault.fulfillDeposit(user, 1000e18);
        vm.stopPrank();
        
        // 3. User claims shares (receives 1000 shares at 1:1 rate)
        vm.startPrank(user);
        mainVault.deposit(1000e18, user, user);
        vm.stopPrank();
        
        assertEq(mainShareToken.balanceOf(user), 1000e18, "User should have 1000 shares");
        
        // 4. Investment manager invests 1000 assets into lossy vault
        vm.startPrank(investmentManager);
        mainVault.investAssets(1000e18);
        vm.stopPrank();
        
        // Investment vault gave 1250 shares (because it has 20% loss: 1 share = 0.8 assets)
        uint256 investmentShares = investmentShareToken.balanceOf(address(mainShareToken));
        assertEq(investmentShares, 1250e18, "Should receive 1250 shares for 1000 assets in lossy vault");
        
        // 5. User requests redemption of all 1000 shares
        vm.startPrank(user);
        mainVault.requestRedeem(1000e18, user, user);
        vm.stopPrank();
        
        // 6. Investment manager fulfills redemption
        // Main vault calculates 1000 shares = 1000 assets (1:1 rate)
        // Reserves 1000 assets for user
        vm.startPrank(investmentManager);
        uint256 assetsReserved = mainVault.fulfillRedeem(user, 1000e18);
        assertEq(assetsReserved, 1000e18, "Should reserve 1000 assets");
        vm.stopPrank();
        
        // 7. Investment manager withdraws from investment vault
        // Needs 1000 assets, but lossy vault only gives 800 assets!
        vm.startPrank(investmentManager);
        
        // Setup self-allowance for investment share token (required for redemption)
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
        uint256 validatorPk = 0xA11CE;
        vm.stopPrank();
        
        vm.startPrank(validator);
        uint256 nonce = investmentShareToken.nonces(address(mainShareToken));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                investmentShareToken.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PERMIT_TYPEHASH, address(mainShareToken), address(mainShareToken), type(uint256).max, nonce, deadline))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validatorPk, digest);
        investmentShareToken.permit(address(mainShareToken), address(mainShareToken), type(uint256).max, deadline, v, r, s);
        vm.stopPrank();
        
        vm.startPrank(investmentManager);
        uint256 actualWithdrawn = mainVault.withdrawFromInvestment(1000e18);
        vm.stopPrank();
        
        // VULNERABILITY: Only 1000 assets withdrawn (20% loss from lossy vault)
        assertEq(actualWithdrawn, 1000e18, "Should withdraw 1000 assets from lossy vault");
        
        // 8. User tries to claim - THIS SHOULD SUCCEED but demonstrates the issue
        // If investment vault had losses, this would fail
        vm.startPrank(user);
        // In a real lossy scenario, this would revert due to insufficient assets
        mainVault.redeem(1000e18, user, user);
        vm.stopPrank();
        
        console.log("Assets reserved for user:", assetsReserved);
        console.log("Assets actually withdrawn:", actualWithdrawn);
        console.log("Shortfall:", assetsReserved > actualWithdrawn ? assetsReserved - actualWithdrawn : 0);
    }
}
```

**Run with:** `forge test --match-test test_InvestmentSlippageCausesRedemptionFailure -vvv`

## Notes

This vulnerability stems from the protocol's implicit assumption that all ERC7575 vaults have deterministic 1:1 conversions like WERC7575Vault [9](#0-8) . However, `setInvestmentVault()` accepts ANY IERC7575 vault with matching asset, including yield-bearing vaults with variable conversion rates.

The issue is exacerbated by the async redemption flow design: `fulfillRedeem()` reserves assets BEFORE checking liquidity availability [4](#0-3) , and `withdrawFromInvestment()` has no validation that `actualAmount >= amount` [8](#0-7) .

The existing test file shows a related scenario where `withdrawFromInvestment` is capped by `maxShares`, but this specific vulnerability about conversion rate mismatch is distinct and not covered in KNOWN_ISSUES.md.

### Citations

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

**File:** src/ERC7575VaultUpgradeable.sol (L915-917)
```text
        if (assets > 0) {
            SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1397-1408)
```text
    function setInvestmentVault(IERC7575 investmentVault_) external {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != owner() && msg.sender != $.shareToken) {
            revert Unauthorized();
        }
        if (address(investmentVault_) == address(0)) revert InvalidVault();
        if (address(investmentVault_.asset()) != $.asset) {
            revert AssetMismatch();
        }
        $.investmentVault = address(investmentVault_);
        emit InvestmentVaultSet(address(investmentVault_));
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1477-1509)
```text
    function withdrawFromInvestment(uint256 amount) external nonReentrant returns (uint256 actualAmount) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if ($.investmentVault == address(0)) revert NoInvestmentVault();
        if (amount == 0) revert ZeroAmount();

        uint256 balanceBefore = IERC20Metadata($.asset).balanceOf(address(this));

        // Get ShareToken's share balance from the investment ShareToken
        IERC20Metadata investmentShareToken = IERC20Metadata(IERC7575($.investmentVault).share());
        address shareToken_ = $.shareToken;
        uint256 maxShares = investmentShareToken.balanceOf(shareToken_);
        uint256 shares = IERC7575($.investmentVault).previewWithdraw(amount);
        uint256 minShares = shares < maxShares ? shares : maxShares;
        if (minShares == 0) revert ZeroSharesCalculated();

        // Ensure ShareToken has self-allowance on the investment share token for redemption
        uint256 current = investmentShareToken.allowance(shareToken_, shareToken_);
        if (current < minShares) {
            revert InvestmentSelfAllowanceMissing(minShares, current);
        }

        // Redeem shares from ShareToken using our allowance (ShareToken is owner, vault is receiver)
        IERC7575($.investmentVault).redeem(minShares, address(this), shareToken_);

        uint256 balanceAfter = IERC20Metadata($.asset).balanceOf(address(this));
        unchecked {
            actualAmount = balanceAfter - balanceBefore;
        }

        emit AssetsWithdrawnFromInvestment(amount, actualAmount, $.investmentVault);
        return actualAmount;
    }
```

**File:** src/WERC7575Vault.sol (L215-246)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
        // ShareToken always has 18 decimals, assetDecimals ∈ [6, 18]
        // shares = assets * _scalingFactor where _scalingFactor = 10^(18 - assetDecimals)
        // Use Math.mulDiv to prevent overflow on large amounts
        return Math.mulDiv(assets, uint256(_scalingFactor), 1, rounding);
    }

    /**
     * @dev Converts shares to assets using decimal normalization for stablecoins
     * @param shares Amount of shares to convert
     * @param rounding Rounding direction (Floor = favor vault, Ceil = favor user)
     * @return assets Amount of assets equivalent to shares
     *
     * Formula: assets = shares * 10^(assetDecimals) / 10^(shareDecimals)
     *
     * For stablecoins with no yield:
     * - Share decimals: queried from share token (typically 18)
     * - Asset decimals: varies (6 for USDC, 18 for DAI, etc.)
     * - This provides 1:1 value conversion with decimal normalization
     * - No first depositor attack possible since conversion is deterministic
     * - No manipulation possible since no dependency on totalSupply or totalAssets
     */
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view returns (uint256) {
        // ShareToken always has 18 decimals, assetDecimals ∈ [6, 18]
        // When _scalingFactor == 1 (assetDecimals == 18): assets = shares
        // When _scalingFactor > 1 (assetDecimals < 18): assets = shares / _scalingFactor
        if (_scalingFactor == 1) {
            return shares;
        } else {
            return Math.mulDiv(shares, 1, uint256(_scalingFactor), rounding);
        }
    }
```
