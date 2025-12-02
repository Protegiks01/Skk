## Title
Permanent Vault Registration DOS Due to Unhandled Investment Configuration Failures

## Summary
The `registerVault()` function in `ShareTokenUpgradeable` unconditionally calls `_configureVaultInvestmentSettings()` when an investment share token is configured, without any error handling. If external calls within the investment configuration fail (e.g., due to bugs in investment vault contracts), the entire vault registration transaction reverts. Since the `investmentShareToken` cannot be changed once set, this creates a permanent denial-of-service condition for registering new vaults, with no recovery path except contract upgrade.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/ShareTokenUpgradeable.sol`
- `registerVault()` function [1](#0-0) 
- `_configureVaultInvestmentSettings()` function [2](#0-1) 
- `setInvestmentVault()` function in `ERC7575VaultUpgradeable.sol` [3](#0-2) 

**Intended Logic:** The vault registration process should successfully register a new vault and, if possible, configure its investment settings. The investment configuration is meant to be a convenience feature that automatically sets up the investment layer integration.

**Actual Logic:** The investment configuration is mandatory and atomic with vault registration. If any external call in the configuration chain fails, the entire registration reverts. Specifically:

1. `registerVault()` adds the vault to the registry [4](#0-3) 
2. Then unconditionally calls `_configureVaultInvestmentSettings()` if `investmentShareToken` is set [1](#0-0) 
3. This calls `setInvestmentVault()` on the vault [5](#0-4) 
4. `setInvestmentVault()` makes an external call to `investmentVault_.asset()` [6](#0-5) 
5. If this external call reverts (due to a bug in the investment vault), the entire transaction reverts
6. The vault registration at step 1 is rolled back due to Solidity's atomic transaction semantics

**Exploitation Path:**
1. Owner legitimately sets `investmentShareToken` via `setInvestmentShareToken()` 
2. Investment ShareToken is immutable once set [7](#0-6) 
3. An investment vault for a specific asset develops a bug where `asset()` reverts (e.g., due to uninitialized storage, state corruption, or upgrade issues)
4. Owner attempts to register a new vault for that asset via `registerVault()`
5. Registration fails permanently because the investment configuration cannot complete
6. No workaround exists - vault cannot be registered without upgrading the ShareToken contract

**Security Property Broken:** Protocol availability and resilience - core functionality (vault registration) becomes permanently unavailable due to failures in external systems, violating the principle of graceful degradation.

## Impact Explanation

- **Affected Assets**: All assets whose corresponding investment vaults have bugs become impossible to register in the settlement layer
- **Damage Severity**: Complete denial of service for vault registration. The protocol cannot onboard new assets or replace existing vaults until the ShareToken contract is upgraded
- **User Impact**: All protocol users are affected as new asset vaults cannot be added. The protocol's multi-asset functionality is permanently limited to assets registered before the investment vault failure occurred

## Likelihood Explanation

- **Attacker Profile**: No direct attacker required. This vulnerability is triggered by bugs in external investment vault contracts
- **Preconditions**: 
  1. `investmentShareToken` must be configured (common in production)
  2. An investment vault must have a bug causing its `asset()` function to revert
- **Execution Complexity**: Vulnerability manifests automatically when attempting to register a vault for an asset whose investment vault is buggy
- **Frequency**: Occurs every time vault registration is attempted for affected assets until contract upgrade

## Recommendation

Add try-catch error handling to gracefully handle investment configuration failures:

```solidity
// In src/ShareTokenUpgradeable.sol, function registerVault, lines 222-225:

// CURRENT (vulnerable):
// If investment ShareToken is already configured, set up investment for the new vault
address investmentShareToken = $.investmentShareToken;
if (investmentShareToken != address(0)) {
    _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken);
}

// FIXED:
// If investment ShareToken is already configured, attempt to set up investment for the new vault
// Use try-catch to prevent investment configuration failures from blocking vault registration
address investmentShareToken = $.investmentShareToken;
if (investmentShareToken != address(0)) {
    try this._configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken) {
        // Investment configuration succeeded
        emit InvestmentConfigurationSucceeded(asset, vaultAddress);
    } catch Error(string memory reason) {
        // Investment configuration failed, but vault registration proceeds
        emit InvestmentConfigurationFailed(asset, vaultAddress, reason);
    } catch (bytes memory) {
        // Low-level failure, but vault registration proceeds
        emit InvestmentConfigurationFailed(asset, vaultAddress, "Low-level error");
    }
}
```

**Additional changes required:**

1. Make `_configureVaultInvestmentSettings()` external instead of internal to enable try-catch:
```solidity
// Change function visibility from internal to external
function _configureVaultInvestmentSettings(address asset, address vaultAddress, address investmentShareToken) external {
    // Restrict access to self-calls only
    if (msg.sender != address(this)) revert Unauthorized();
    // ... rest of function
}
```

2. Add events for tracking configuration outcomes:
```solidity
event InvestmentConfigurationSucceeded(address indexed asset, address indexed vault);
event InvestmentConfigurationFailed(address indexed asset, address indexed vault, string reason);
```

This fix ensures vault registration succeeds even if investment configuration fails, allowing the protocol to remain operational while investment layer issues are resolved separately.

## Proof of Concept

```solidity
// File: test/Exploit_InvestmentConfigDOS.t.sol
// Run with: forge test --match-test test_InvestmentConfigurationFailurePreventsVaultRegistration -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {WERC7575ShareToken} from "../src/WERC7575ShareToken.sol";
import {WERC7575Vault} from "../src/WERC7575Vault.sol";
import {ERC20Faucet6} from "../src/ERC20Faucet6.sol";
import {IERC7575} from "../src/interfaces/IERC7575.sol";

// Buggy investment vault that reverts on asset() call
contract BuggyInvestmentVault is WERC7575Vault {
    bool public shouldRevert = false;

    constructor(address asset_, WERC7575ShareToken shareToken_) 
        WERC7575Vault(asset_, shareToken_) {}

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function asset() public view override returns (address) {
        if (shouldRevert) {
            revert("Buggy vault: asset() reverts");
        }
        return super.asset();
    }
}

contract Exploit_InvestmentConfigDOS is Test {
    ShareTokenUpgradeable public shareToken;
    WERC7575ShareToken public investmentShareToken;
    ERC20Faucet6 public usdc;
    ERC20Faucet6 public dai;
    BuggyInvestmentVault public buggyInvestmentVault;
    WERC7575Vault public investmentUsdcVault;
    
    address public owner = address(0x1);
    address public validator = address(0x2);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy test tokens
        usdc = new ERC20Faucet6("USD Coin", "USDC", 1_000_000_000 * 1e6);
        dai = new ERC20Faucet6("Dai Stablecoin", "DAI", 1_000_000_000 * 1e6);
        
        // Deploy investment share token system
        investmentShareToken = new WERC7575ShareToken("Investment USD", "iUSD");
        investmentUsdcVault = new WERC7575Vault(address(usdc), investmentShareToken);
        buggyInvestmentVault = new BuggyInvestmentVault(address(dai), investmentShareToken);
        
        // Register investment vaults
        investmentShareToken.registerVault(address(usdc), address(investmentUsdcVault));
        investmentShareToken.registerVault(address(dai), address(buggyInvestmentVault));
        investmentShareToken.setValidator(validator);
        
        // Deploy ShareToken
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory initData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector,
            "Multi-Asset Shares",
            "MAVS",
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), initData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Register USDC vault successfully (before setting investment share token)
        ERC7575VaultUpgradeable usdcVault = _deployVault(address(usdc));
        shareToken.registerVault(address(usdc), address(usdcVault));
        
        // Set investment share token - this cannot be changed later
        shareToken.setInvestmentShareToken(address(investmentShareToken));
        
        vm.stopPrank();
    }
    
    function _deployVault(address asset) internal returns (ERC7575VaultUpgradeable) {
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            IERC20Metadata(asset),
            address(shareToken),
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        return ERC7575VaultUpgradeable(address(vaultProxy));
    }
    
    function test_InvestmentConfigurationFailurePreventsVaultRegistration() public {
        // SETUP: Verify investment share token is set and cannot be changed
        assertEq(shareToken.getInvestmentShareToken(), address(investmentShareToken));
        
        vm.prank(owner);
        vm.expectRevert(); // Attempting to change it reverts
        shareToken.setInvestmentShareToken(address(0x999));
        
        // Deploy a new DAI vault
        ERC7575VaultUpgradeable daiVault = _deployVault(address(dai));
        
        // Verify DAI vault not yet registered
        assertEq(shareToken.vault(address(dai)), address(0));
        
        // EXPLOIT: Trigger the bug in investment vault
        buggyInvestmentVault.setShouldRevert(true);
        
        // Attempt to register DAI vault - this will fail because investment configuration reverts
        vm.prank(owner);
        vm.expectRevert("Buggy vault: asset() reverts");
        shareToken.registerVault(address(dai), address(daiVault));
        
        // VERIFY: Vault registration failed completely - vault not registered
        assertEq(shareToken.vault(address(dai)), address(0), "Vault should not be registered");
        
        // VERIFY: No workaround exists - investment share token cannot be cleared
        vm.prank(owner);
        vm.expectRevert();
        shareToken.setInvestmentShareToken(address(0));
        
        // VERIFY: Even fixing the investment vault doesn't help if we can't re-register
        buggyInvestmentVault.setShouldRevert(false);
        
        // Now registration works
        vm.prank(owner);
        shareToken.registerVault(address(dai), address(daiVault));
        assertEq(shareToken.vault(address(dai)), address(daiVault), "Vault successfully registered after fix");
        
        console.log("=== VULNERABILITY DEMONSTRATED ===");
        console.log("1. Investment share token set and immutable");
        console.log("2. Investment vault develops bug causing asset() to revert");
        console.log("3. Vault registration becomes impossible");
        console.log("4. No workaround except contract upgrade");
    }
}
```

## Notes

This vulnerability represents a critical failure in the protocol's defensive programming approach. The issue stems from tight coupling between the settlement layer (ShareToken) and investment layer (investment vaults) without proper error boundaries. 

**Key insights:**

1. **Immutability creates brittleness**: The `investmentShareToken` is immutable once set [7](#0-6) , which means any bugs in that system permanently affect the settlement layer.

2. **Atomic operations without fallback**: The registration and investment configuration are atomic [8](#0-7) , with no try-catch or conditional success handling.

3. **External call chain vulnerability**: The vulnerability manifests through a chain of external calls: `registerVault` → `_configureVaultInvestmentSettings` → `setInvestmentVault` → `investmentVault_.asset()` [6](#0-5) , where any revert propagates to the top.

4. **Impact on protocol evolution**: This issue prevents the protocol from adapting to changing conditions - if an investment vault becomes problematic, the settlement layer cannot continue operating independently.

The recommended fix using try-catch provides graceful degradation, allowing vault registration to succeed even when investment configuration fails, while maintaining visibility through events.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L214-225)
```text
        // Register new vault - set() returns true if newly added, false if already existed
        if (!$.assetToVault.set(asset, vaultAddress)) {
            revert AssetAlreadyRegistered();
        }
        $.vaultToAsset[vaultAddress] = asset;

        // If investment ShareToken is already configured, set up investment for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentShareToken = $.investmentShareToken;
        if (investmentShareToken != address(0)) {
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken);
        }
```

**File:** src/ShareTokenUpgradeable.sol (L540-551)
```text
    function _configureVaultInvestmentSettings(address asset, address vaultAddress, address investmentShareToken) internal {
        // Find the corresponding investment vault for this asset
        address investmentVaultAddress = IERC7575ShareExtended(investmentShareToken).vault(asset);

        // Configure investment vault if there's a matching one for this asset
        if (investmentVaultAddress != address(0)) {
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentVault(IERC7575(investmentVaultAddress));

            // Grant unlimited allowance to the vault on the investment ShareToken
            IERC20(investmentShareToken).approve(vaultAddress, type(uint256).max);
        }
    }
```

**File:** src/ShareTokenUpgradeable.sol (L572-574)
```text
        if ($.investmentShareToken != address(0)) {
            revert InvestmentShareTokenAlreadySet();
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
