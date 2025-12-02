## Title
Permanent DOS of Vault Unregistration Due to Reverting totalAssets() or balanceOf() Calls

## Summary
The `unregisterVault()` function uses try-catch blocks to verify vault safety before unregistration, but any revert in the vault's `totalAssets()` or the asset's `balanceOf()` call permanently blocks unregistration. This prevents the owner from removing buggy or upgraded vaults, creating an irrecoverable DOS on critical vault management functionality. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` - `unregisterVault()` function (lines 256-285)

**Intended Logic:** The function should validate that a vault has no outstanding assets before allowing unregistration, protecting user funds by preventing removal of vaults that still hold user assets.

**Actual Logic:** The function uses two try-catch blocks that revert if either external call fails. If a vault's `totalAssets()` function reverts (lines 265-271) or the asset's `balanceOf()` call reverts (lines 274-278), the catch blocks revert with string errors, permanently preventing unregistration. There is no emergency override or alternative mechanism to force unregistration. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. Owner registers a vault that is initially functional and passes all validation checks
2. The vault contract is upgradeable (common for institutional DeFi) and is later upgraded by its admin to a version with a bug in `totalAssets()`, or the vault's `totalAssets()` depends on an external oracle/contract that becomes faulty
3. The `totalAssets()` function now reverts (e.g., due to division by zero, uninitialized storage, failed external call, or malicious logic)
4. Owner attempts to unregister the vault using `unregisterVault(asset)`, but the try-catch at line 265 catches the revert and re-reverts with "ShareToken: cannot verify vault has no outstanding assets"
5. The vault remains permanently registered in `_assetToVault` and `_vaultToAsset` mappings, continuing to have mint/burn privileges and occupying one of the limited `MAX_VAULTS_PER_SHARE_TOKEN` slots [4](#0-3) 

**Security Property Broken:** Violates the principle that protocol administrators should maintain ultimate control over system components. The owner cannot remove a problematic vault despite having the appropriate role and permissions.

## Impact Explanation
- **Affected Assets**: The ShareToken contract's vault management system. A single buggy vault can occupy one of the limited vault slots indefinitely
- **Damage Severity**: 
  - Permanent loss of vault management capability for the affected asset
  - Buggy vault remains authorized to mint/burn shares, potentially causing accounting issues
  - One of `MAX_VAULTS_PER_SHARE_TOKEN` slots permanently consumed
  - If the vault has other bugs beyond `totalAssets()`, users may be unable to withdraw funds while the vault cannot be deauthorized
- **User Impact**: All users of the ShareToken system are affected if a buggy vault cannot be removed, as it retains minting/burning privileges that could cause systemic issues [5](#0-4) 

## Likelihood Explanation
- **Attacker Profile**: Not a traditional attacker scenario. This occurs when:
  - A vault's implementation is upgraded to a buggy version by its admin
  - External dependencies (oracles, price feeds) used by vault's `totalAssets()` fail
  - Asset contract has non-standard ERC20 implementation where `balanceOf()` can revert
- **Preconditions**: 
  - Vault must be registered in the system
  - Vault's `totalAssets()` or asset's `balanceOf(vault)` must revert
- **Execution Complexity**: Not an active exploit, but a systemic weakness. Occurs naturally when vaults are upgraded or external dependencies fail
- **Frequency**: Can occur whenever registered vaults undergo upgrades or depend on external contracts that may become faulty

## Recommendation

Add an emergency override function that allows the owner to force unregister a vault without safety checks when necessary. Additionally, modify the try-catch blocks to be more permissive:

```solidity
// In src/WERC7575ShareToken.sol:

// ADD NEW FUNCTION (after unregisterVault):
/**
 * @dev Emergency function to force unregister a vault without safety checks
 * @param asset The asset token address to force unregister vault for
 * 
 * WARNING: This bypasses all safety checks. Use only when a vault is buggy
 * and cannot be unregistered through normal means. Ensure vault has no
 * outstanding user assets before calling.
 */
function forceUnregisterVault(address asset) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    if (!_assetToVault.contains(asset)) revert AssetNotRegistered();
    
    address vaultAddress = _assetToVault.get(asset);
    
    // Remove vault registration (no safety checks)
    _assetToVault.remove(asset);
    delete _vaultToAsset[vaultAddress];
    
    emit VaultUpdate(asset, address(0));
}

// ALTERNATIVELY, modify existing function to be more permissive:
function unregisterVault(address asset) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    if (!_assetToVault.contains(asset)) revert AssetNotRegistered();

    address vaultAddress = _assetToVault.get(asset);

    // TRY to verify vault has no assets, but allow unregistration even if verification fails
    // after warning in logs
    bool safetyChecksPassed = true;
    
    try IERC7575Vault(vaultAddress).totalAssets() returns (uint256 totalAssets) {
        if (totalAssets != 0) {
            revert CannotUnregisterVaultAssetBalance();
        }
    } catch {
        // Log warning but allow unregistration to proceed
        // Owner takes responsibility for ensuring safety
        safetyChecksPassed = false;
    }
    
    try ERC20(asset).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
        if (vaultBalance != 0) {
            revert CannotUnregisterVaultAssetBalance();
        }
    } catch {
        safetyChecksPassed = false;
    }
    
    // Proceed with unregistration even if checks failed
    // Owner is trusted and may need to remove buggy vaults
    _assetToVault.remove(asset);
    delete _vaultToAsset[vaultAddress];
    
    emit VaultUpdate(asset, address(0));
    
    if (!safetyChecksPassed) {
        // Emit warning event that safety checks could not be completed
        emit VaultUnregisteredWithoutSafetyChecks(asset, vaultAddress);
    }
}
```

The recommended approach is to add a separate `forceUnregisterVault()` function to make the intent explicit when bypassing safety checks, while keeping the normal `unregisterVault()` function strict for the standard case.

## Proof of Concept

```solidity
// File: test/Exploit_UnregisterVaultDOS.t.sol
// Run with: forge test --match-test test_UnregisterVaultDOS -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "../src/ERC20Faucet.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Malicious/Buggy vault that reverts on totalAssets()
contract BuggyVault {
    address public asset;
    address public share;
    
    constructor(address _asset, address _share) {
        asset = _asset;
        share = _share;
    }
    
    // This function always reverts, simulating a bug or malicious behavior
    function totalAssets() external view returns (uint256) {
        revert("Buggy implementation");
    }
}

contract Exploit_UnregisterVaultDOS is Test {
    WERC7575ShareToken public shareToken;
    WERC7575Vault public normalVault;
    BuggyVault public buggyVault;
    ERC20Faucet public usdc;
    
    address public owner = address(this);
    
    function setUp() public {
        // Deploy asset
        usdc = new ERC20Faucet("USD Coin", "USDC", 1_000_000 * 10 ** 6);
        vm.mockCall(address(usdc), abi.encodeWithSignature("decimals()"), abi.encode(uint8(6)));
        
        // Deploy share token
        shareToken = new WERC7575ShareToken("Multi-Asset Share Token", "MAST");
    }
    
    function test_UnregisterVaultDOS() public {
        // SETUP: Register a normal vault initially
        normalVault = new WERC7575Vault(address(usdc), shareToken);
        shareToken.registerVault(address(usdc), address(normalVault));
        
        // Verify vault is registered
        assertEq(shareToken.vault(address(usdc)), address(normalVault));
        
        // SIMULATE: Vault gets upgraded to buggy implementation
        // In reality, this would happen through a proxy upgrade, but for testing
        // we unregister and re-register with buggy vault to simulate the scenario
        
        // First unregister the normal vault (this works because totalAssets doesn't revert)
        shareToken.unregisterVault(address(usdc));
        
        // Now register the buggy vault (simulating an upgrade to buggy implementation)
        buggyVault = new BuggyVault(address(usdc), address(shareToken));
        shareToken.registerVault(address(usdc), address(buggyVault));
        
        // EXPLOIT: Try to unregister the buggy vault - this will fail permanently
        vm.expectRevert("ShareToken: cannot verify vault has no outstanding assets");
        shareToken.unregisterVault(address(usdc));
        
        // VERIFY: Vault remains registered despite owner wanting to remove it
        assertEq(shareToken.vault(address(usdc)), address(buggyVault), 
            "Buggy vault remains registered - permanent DOS on unregistration");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- Buggy vault with reverting totalAssets() cannot be unregistered");
        console.log("- Owner has no way to remove the vault");
        console.log("- Vault retains mint/burn privileges indefinitely");
    }
}
```

## Notes

This vulnerability demonstrates a critical weakness in the vault management system where external dependencies (vault implementations) can permanently DOS administrative functions. While the owner is trusted, they should not be prevented from managing their system due to buggy external contracts.

The issue is particularly concerning because:

1. **Upgradeable vaults are common** in institutional DeFi, and upgrades can introduce bugs
2. **External dependencies** like oracles or price feeds used by `totalAssets()` can fail
3. **No recovery mechanism** exists - the vault stays registered forever
4. **Authorization persists** - the buggy vault can still call mint/burn functions via the `onlyVaults` modifier [6](#0-5) 

The recommended fix of adding a `forceUnregisterVault()` function provides an escape hatch while maintaining safety checks for normal operations. This balances security (keeping safety checks) with operational resilience (allowing recovery from buggy external contracts).

### Citations

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

**File:** src/ShareTokenUpgradeable.sol (L200-203)
```text
        if (IERC7575(vaultAddress).asset() != asset) revert AssetMismatch();

        // Validate that vault's share token matches this ShareToken
        if (IERC7575(vaultAddress).share() != address(this)) {
```

**File:** src/ShareTokenUpgradeable.sol (L400-414)
```text
    function mint(address account, uint256 amount) external onlyVaults {
        _mint(account, amount);
    }

    /**
     * @dev Burn shares from an account. Only callable by authorized vaults.
     */
    /**
     * @dev Burns shares from an account (only registered vaults)
     * @param account The account to burn shares from
     * @param amount The amount of shares to burn
     */
    function burn(address account, uint256 amount) external onlyVaults {
        _burn(account, amount);
    }
```
