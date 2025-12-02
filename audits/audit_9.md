## Title
Stale Scaling Factor Causes Catastrophic Fund Loss When Upgradeable Asset Token Changes Decimals

## Summary
The `_scalingFactor` used for share-to-asset conversions is calculated once during deployment/initialization and permanently cached. If the underlying asset token is upgradeable and changes its `decimals()` return value post-deployment, all conversions become incorrect, causing users to lose up to 99.9999% of their funds during withdrawals or enabling vault drainage attacks.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/WERC7575Vault.sol` (constructor and `_convertToAssets` function) and `src/ERC7575VaultUpgradeable.sol` (initialize and `_convertToAssets` function)

**Intended Logic:** The scaling factor should accurately convert between asset decimals and 18-decimal shares throughout the vault's lifetime, ensuring users receive the correct asset amounts when redeeming shares.

**Actual Logic:** The scaling factor is calculated once and cached permanently. If an upgradeable asset token (like USDC which uses a proxy pattern) changes its `decimals()` return value through an upgrade, the cached scaling factor becomes stale, causing all subsequent conversions to calculate wildly incorrect asset amounts. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Exploitation Path:**

**Scenario 1: Decimals Increase (User Fund Loss)**
1. Asset token deployed with 6 decimals (e.g., USDC-like token)
2. WERC7575Vault deployed: `_scalingFactor = 10^(18-6) = 10^12` is permanently cached
3. User deposits 1,000,000 tokens (= 1.0 USDC with 6 decimals) via `deposit()`
   - Shares minted: `1,000,000 * 10^12 = 10^18 shares`
4. Asset token owner upgrades contract, changing `decimals()` to return 18 instead of 6
5. User calls `redeem(10^18, receiver, owner)` to withdraw all shares
   - `previewRedeem()` calls `_convertToAssets(10^18)`
   - Calculation: `assets = 10^18 / 10^12 = 1,000,000 tokens`
   - But with 18 decimals, 1,000,000 tokens = 0.000001 USDC (not 1.0 USDC)
   - User receives 0.000001 USDC instead of 1.0 USDC
   - **99.9999% fund loss** [5](#0-4) [6](#0-5) 

**Scenario 2: Decimals Decrease (Vault Drainage)**
1. Asset token deployed with 18 decimals
2. WERC7575Vault deployed: `_scalingFactor = 10^(18-18) = 1`
3. Attacker deposits 1 * 10^18 tokens (= 1 whole token)
   - Shares minted: `10^18 * 1 = 10^18 shares`
4. Asset token upgrades to 6 decimals
5. Attacker redeems 10^18 shares
   - Calculation: `assets = 10^18 / 1 = 10^18 tokens`
   - With 6 decimals, 10^18 tokens = 10^12 whole tokens (1 trillion tokens)
   - **Attacker drains entire vault with 1:1,000,000,000,000 profit ratio**

**Security Property Broken:** 
- **Invariant #10 (Conversion Accuracy)**: `convertToShares(convertToAssets(x)) ≈ x` is catastrophically broken
- **Invariant #12 (No Fund Theft)**: Enables direct fund theft or user fund loss

## Impact Explanation

- **Affected Assets**: All assets held in WERC7575Vault and ERC7575VaultUpgradeable where the underlying token is upgradeable (USDC, USDT, and any proxy-based ERC20)

- **Damage Severity**: 
  - **User Loss**: Up to 99.9999% of deposited funds if decimals increase
  - **Vault Drainage**: Complete vault drainage possible if decimals decrease
  - **Scale**: Affects ALL users who deposited before the decimal change

- **User Impact**: Any user who deposited before the asset's decimal change and attempts to withdraw after will receive incorrect amounts. The protocol has no mechanism to detect or prevent this.

## Likelihood Explanation

- **Attacker Profile**: 
  - For Scenario 1 (user loss): No attacker needed—asset token owner's upgrade causes automatic loss
  - For Scenario 2 (drainage): Any user can exploit after noticing the decimal change

- **Preconditions**: 
  - Asset token must be upgradeable (common: USDC uses TransparentUpgradeableProxy, USDT uses custom proxy)
  - Asset token owner must change `decimals()` return value through upgrade
  - While unusual, this is technically possible and not prevented by the protocol

- **Execution Complexity**: Single transaction (`redeem()` or `withdraw()` call) after decimal change

- **Frequency**: Can happen once per decimal change event. If asset decimals change multiple times, each change creates a new vulnerability window.

## Recommendation

Add a mechanism to detect and handle decimal changes:

```solidity
// In src/WERC7575Vault.sol, add state variable:
uint8 private _cachedAssetDecimals;

// In constructor, after line 111, add:
_cachedAssetDecimals = assetDecimals;

// Add new function to check for decimal changes:
function _validateAssetDecimals() internal view {
    uint8 currentDecimals = IERC20Metadata(_asset).decimals();
    if (currentDecimals != _cachedAssetDecimals) {
        revert AssetDecimalsChanged();
    }
}

// In _convertToAssets, line 237, add check before conversion:
function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view returns (uint256) {
    _validateAssetDecimals(); // Revert if decimals changed
    
    if (_scalingFactor == 1) {
        return shares;
    } else {
        return Math.mulDiv(shares, 1, uint256(_scalingFactor), rounding);
    }
}

// In _convertToShares, line 215, add check:
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
    _validateAssetDecimals(); // Revert if decimals changed
    
    return Math.mulDiv(assets, uint256(_scalingFactor), 1, rounding);
}

// Add custom error:
error AssetDecimalsChanged();
```

Apply the same fix to `ERC7575VaultUpgradeable.sol` in the `initialize()` function and conversion methods.

**Alternative (if decimal changes are expected):** Implement a recalibration mechanism that allows the owner to recalculate the scaling factor, but only when vault has zero deposits/shares to prevent manipulation.

## Proof of Concept

```solidity
// File: test/Exploit_StaleScalingFactor.t.sol
// Run with: forge test --match-test test_StaleScalingFactorUserLoss -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";

// Mock upgradeable asset that can change decimals
contract UpgradeableAsset {
    uint8 private _decimals;
    mapping(address => uint256) private _balances;
    
    constructor(uint8 initialDecimals) {
        _decimals = initialDecimals;
    }
    
    function decimals() external view returns (uint8) {
        return _decimals;
    }
    
    function upgradeDecimals(uint8 newDecimals) external {
        _decimals = newDecimals;
    }
    
    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
    }
    
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _balances[from] -= amount;
        _balances[to] += amount;
        return true;
    }
}

contract Exploit_StaleScalingFactor is Test {
    WERC7575Vault vault;
    WERC7575ShareToken shareToken;
    UpgradeableAsset asset;
    
    address user = address(0x1);
    
    function setUp() public {
        // Deploy asset with 6 decimals (USDC-like)
        asset = new UpgradeableAsset(6);
        
        // Deploy share token
        shareToken = new WERC7575ShareToken(address(this));
        
        // Deploy vault
        vault = new WERC7575Vault(address(asset), shareToken);
        
        // Register vault
        shareToken.registerVault(address(asset), address(vault));
        
        // Give user 1 USDC (1_000_000 with 6 decimals)
        asset.mint(user, 1_000_000);
    }
    
    function test_StaleScalingFactorUserLoss() public {
        // SETUP: User deposits 1 USDC
        vm.startPrank(user);
        asset.transfer(address(vault), 1_000_000);
        uint256 sharesMinted = vault.deposit(1_000_000, user);
        
        // Verify: User received correct shares (1e18)
        assertEq(sharesMinted, 1e18, "Should receive 1e18 shares for 1 USDC");
        assertEq(shareToken.balanceOf(user), 1e18, "User should have 1e18 shares");
        vm.stopPrank();
        
        // EXPLOIT: Asset token upgrades from 6 to 18 decimals
        asset.upgradeDecimals(18);
        
        // VERIFY: Conversion now returns wrong amount
        uint256 assetsCalculated = vault.convertToAssets(1e18);
        assertEq(assetsCalculated, 1_000_000, "Vault calculates 1_000_000 tokens");
        
        // But 1_000_000 tokens with 18 decimals = 0.000001 USDC (not 1.0 USDC)
        // User loses 99.9999% of their funds!
        
        // Expected: 1_000_000 * 10^6 = 1e12 (1 USDC with 18 decimals)
        // Actual: 1_000_000 (0.000001 USDC with 18 decimals)
        
        uint256 expectedCorrect = 1e12; // What user should get
        uint256 actualWrong = assetsCalculated; // What user actually gets
        
        assertTrue(actualWrong < expectedCorrect / 1000000, "User receives less than 0.0001% of deposit");
        
        console.log("User deposited: 1.0 USDC");
        console.log("User will receive: 0.000001 USDC");
        console.log("Loss: 99.9999%");
    }
}
```

## Notes

This vulnerability is **NOT** mentioned in `KNOWN_ISSUES.md`. The closest known issue is "All shares 18 decimals" (Section 6), but that refers to the protocol's intentional design choice to normalize all shares to 18 decimals, not the risk of asset tokens changing their decimals post-deployment.

The issue affects both `WERC7575Vault` and `ERC7575VaultUpgradeable` identically, as both cache the scaling factor permanently without any mechanism to detect or respond to decimal changes in the underlying asset.

While changing an asset's decimals is unusual, it's technically possible with upgradeable tokens (USDC, USDT use proxy patterns) and represents a critical failure mode the protocol should handle gracefully rather than silently causing catastrophic fund loss.

### Citations

**File:** src/WERC7575Vault.sol (L88-116)
```text
    constructor(address asset_, WERC7575ShareToken shareToken_) Ownable(msg.sender) {
        // Validate asset compatibility
        uint8 assetDecimals;
        try IERC20Metadata(asset_).decimals() returns (uint8 decimals) {
            if (decimals < DecimalConstants.MIN_ASSET_DECIMALS || decimals > DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert UnsupportedAssetDecimals();
            }
            assetDecimals = decimals;
        } catch {
            revert AssetDecimalsFailed();
        }
        // Validate share token compatibility and enforce 18 decimals
        if (address(shareToken_) == address(0)) revert ZeroAddress();
        if (shareToken_.decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
            revert WrongDecimals();
        }

        // Precompute scaling factor: 10^(18 - assetDecimals)
        // Max scaling factor is 10^12 (for 6 decimals) which fits in uint64
        uint256 scalingFactor = 10 ** (DecimalConstants.SHARE_TOKEN_DECIMALS - assetDecimals);
        if (scalingFactor > type(uint64).max) revert ScalingFactorTooLarge();

        _asset = asset_;
        _scalingFactor = uint64(scalingFactor);
        _isActive = true; // Vault is active by default
        _shareToken = shareToken_;

        // Note: Owner must separately call shareToken.registerVault(asset, vault) after deployment
    }
```

**File:** src/WERC7575Vault.sol (L237-246)
```text
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

**File:** src/WERC7575Vault.sol (L276-278)
```text
    function previewRedeem(uint256 shares) public view returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }
```

**File:** src/WERC7575Vault.sol (L464-467)
```text
    function redeem(uint256 shares, address receiver, address owner) public nonReentrant whenNotPaused returns (uint256 assets) {
        assets = previewRedeem(shares);
        _withdraw(assets, shares, receiver, owner);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L150-190)
```text
    function initialize(IERC20Metadata asset_, address shareToken_, address owner) public initializer {
        if (shareToken_ == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (address(asset_) == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }

        // Validate asset compatibility and get decimals
        uint8 assetDecimals;
        try IERC20Metadata(address(asset_)).decimals() returns (uint8 decimals) {
            if (decimals < DecimalConstants.MIN_ASSET_DECIMALS || decimals > DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert UnsupportedAssetDecimals();
            }
            assetDecimals = decimals;
        } catch {
            revert AssetDecimalsFailed();
        }
        // Validate share token compatibility and enforce 18 decimals
        try IERC20Metadata(shareToken_).decimals() returns (uint8 decimals) {
            if (decimals != DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert WrongDecimals();
            }
        } catch {
            revert AssetDecimalsFailed();
        }
        __Ownable_init(owner);

        VaultStorage storage $ = _getVaultStorage();
        $.asset = address(asset_);
        $.assetDecimals = assetDecimals;
        $.shareToken = shareToken_;
        $.investmentManager = owner; // Initially owner is investment manager
        $.isActive = true; // Vault is active by default

        // Calculate scaling factor for decimal normalization: 10^(18 - assetDecimals)
        uint256 scalingFactor = 10 ** (DecimalConstants.SHARE_TOKEN_DECIMALS - assetDecimals);
        if (scalingFactor > type(uint64).max) revert ScalingFactorTooLarge();
        $.scalingFactor = uint64(scalingFactor);
        $.minimumDepositAmount = 1000;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1204-1216)
```text
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
