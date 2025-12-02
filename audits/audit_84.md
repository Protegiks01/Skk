## Title
Vault Owner Can Permanently Block Vault Unregistration Through `isActive` Griefing

## Summary
The `unregisterVault()` function in `ShareTokenUpgradeable` requires vaults to have `isActive == false` before they can be unregistered. However, only the vault owner (not the ShareToken owner) can control the `isActive` flag via `setVaultActive()`. This creates a griefing vulnerability where a malicious or uncooperative vault owner can permanently block the ShareToken owner from unregistering their vault, preventing protocol maintenance and registry cleanup.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol`, function `unregisterVault()`, lines 282-327 [1](#0-0) 

**Intended Logic:** The ShareToken owner should have the ability to unregister vaults for protocol maintenance and cleanup, as documented in the trusted roles section stating "Owner Powers: Registers/unregisters vaults".

**Actual Logic:** The unregistration process has a critical dependency on vault owner cooperation. At line 294, the function checks `if (metrics.isActive) revert CannotUnregisterActiveVault()`, but the ShareToken owner has no mechanism to force vault deactivation. [2](#0-1) 

The `isActive` flag is controlled exclusively by the vault owner through `setVaultActive()`: [3](#0-2) 

**Exploitation Path:**
1. **Vault Deployment**: A third-party deploys `ERC7575VaultUpgradeable` with their own address as owner via the `initialize()` function's `owner` parameter
2. **Registration**: ShareToken owner registers this vault via `registerVault(asset, vaultAddress)` to enable multi-asset functionality
3. **Later Maintenance Need**: ShareToken owner decides to unregister the vault (e.g., vault is outdated, better vault available, or security concerns)
4. **Griefing Attack**: Vault owner refuses to call `setVaultActive(false)` or actively calls `setVaultActive(true)` whenever unregistration is attempted
5. **Permanent Block**: ShareToken owner's `unregisterVault()` call reverts with `CannotUnregisterActiveVault`, and there is no override mechanism
6. **Protocol Impact**: Old/abandoned vaults cannot be removed from the registry, accumulating technical debt

**Security Property Broken:** Violates Invariant #11 ("No role escalation - access control boundaries enforced"). The vault owner can effectively veto the ShareToken owner's documented administrative power to unregister vaults, creating an unintended privilege escalation where a non-trusted role blocks a trusted role's function.

## Impact Explanation
- **Affected Assets**: The entire ShareToken vault registry system
- **Damage Severity**: Protocol maintenance is permanently blocked. The ShareToken owner cannot clean up the vault registry, remove deprecated vaults, or respond to security issues in registered vaults without vault owner cooperation
- **User Impact**: All users of the ShareToken system are affected indirectly, as the protocol cannot evolve or remove problematic vaults from its registry

## Likelihood Explanation
- **Attacker Profile**: Any vault owner who deployed their own vault and had it registered by the ShareToken owner. This is realistic given the "decentralized vault deployment" architecture mentioned in documentation
- **Preconditions**: 
  - Vault owner is a different entity from ShareToken owner (architecturally allowed)
  - Vault has been registered in the ShareToken
  - ShareToken owner attempts to unregister the vault
- **Execution Complexity**: Single transaction - vault owner simply refuses to call `setVaultActive(false)` or actively calls `setVaultActive(true)`
- **Frequency**: Can be maintained indefinitely with zero cost (just don't deactivate the vault)

## Recommendation
Add an emergency override mechanism that allows the ShareToken owner to force-unregister vaults in exceptional circumstances, or implement a timelock mechanism where unregistration is scheduled and becomes executable after a delay period:

```solidity
// In src/ShareTokenUpgradeable.sol, add new state variable:
mapping(address => uint256) private _unregistrationScheduled;
uint256 public constant UNREGISTRATION_DELAY = 7 days;

// Modified unregisterVault function:
function unregisterVault(address asset) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    ShareTokenStorage storage $ = _getShareTokenStorage();
    
    (bool exists, address vaultAddress) = $.assetToVault.tryGet(asset);
    if (!exists) revert AssetNotRegistered();

    // Check if vault metrics show active state
    try IVaultMetrics(vaultAddress).getVaultMetrics() returns (IVaultMetrics.VaultMetrics memory metrics) {
        if (metrics.isActive) {
            // If vault is still active, schedule unregistration
            if (_unregistrationScheduled[asset] == 0) {
                _unregistrationScheduled[asset] = block.timestamp + UNREGISTRATION_DELAY;
                emit UnregistrationScheduled(asset, _unregistrationScheduled[asset]);
                return;
            }
            // If scheduled time has passed, allow force unregistration
            if (block.timestamp < _unregistrationScheduled[asset]) {
                revert UnregistrationNotYetExecutable();
            }
            // Continue with forced unregistration after timelock
        }
        
        // Existing safety checks for pending deposits, claimable redemptions, etc.
        if (metrics.totalPendingDepositAssets != 0) {
            revert CannotUnregisterVaultPendingDeposits();
        }
        // ... rest of checks ...
    } catch {
        revert CannotUnregisterActiveVault();
    }
    
    // Clear schedule and proceed with unregistration
    delete _unregistrationScheduled[asset];
    $.assetToVault.remove(asset);
    delete $.vaultToAsset[vaultAddress];
    emit VaultUpdate(asset, address(0));
}
```

This gives vault owners a 7-day window to deactivate their vault voluntarily, but allows ShareToken owner to proceed with unregistration after the timelock expires, preventing permanent griefing.

## Proof of Concept
```solidity
// File: test/Exploit_VaultUnregisterGriefing.t.sol
// Run with: forge test --match-test test_VaultOwnerBlocksUnregistration -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ERC20Faucet6} from "../src/ERC20Faucet6.sol";
import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {IERC7575Errors} from "../src/interfaces/IERC7575Errors.sol";

contract Exploit_VaultUnregisterGriefing is Test {
    ShareTokenUpgradeable public shareToken;
    ERC7575VaultUpgradeable public vault;
    ERC20Faucet6 public usdc;
    
    address public shareTokenOwner = address(0x1);
    address public maliciousVaultOwner = address(0x2);
    
    function setUp() public {
        // Deploy USDC token
        usdc = new ERC20Faucet6("USD Coin", "USDC", 1_000_000 * 1e6);
        
        // Deploy ShareToken (owned by shareTokenOwner)
        vm.startPrank(shareTokenOwner);
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory shareTokenInitData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector,
            "Multi-Asset Vault Shares",
            "MAVS",
            shareTokenOwner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), shareTokenInitData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        vm.stopPrank();
        
        // Deploy vault with DIFFERENT owner (maliciousVaultOwner)
        vm.startPrank(maliciousVaultOwner);
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            IERC20Metadata(address(usdc)),
            address(shareToken),
            maliciousVaultOwner  // Vault owner is different from ShareToken owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        vm.stopPrank();
        
        // ShareToken owner registers the vault
        vm.prank(shareTokenOwner);
        shareToken.registerVault(address(usdc), address(vault));
    }
    
    function test_VaultOwnerBlocksUnregistration() public {
        // SETUP: Verify vault is registered and active
        assertEq(shareToken.vault(address(usdc)), address(vault));
        assertTrue(vault.isVaultActive());
        
        // EXPLOIT: ShareToken owner wants to unregister the vault
        // But malicious vault owner keeps it active
        vm.prank(shareTokenOwner);
        vm.expectRevert(IERC7575Errors.CannotUnregisterActiveVault.selector);
        shareToken.unregisterVault(address(usdc));
        
        // VERIFY: Even if we try multiple times, vault owner can keep blocking
        // Malicious vault owner actively keeps vault active
        vm.prank(maliciousVaultOwner);
        vault.setVaultActive(true);  // Keep it active
        
        vm.prank(shareTokenOwner);
        vm.expectRevert(IERC7575Errors.CannotUnregisterActiveVault.selector);
        shareToken.unregisterVault(address(usdc));
        
        // VERIFY: ShareToken owner has NO way to force unregistration
        // The vault remains in the registry indefinitely
        assertEq(
            shareToken.vault(address(usdc)),
            address(vault),
            "Vulnerability confirmed: Vault owner can permanently block unregistration"
        );
        
        console.log("Griefing attack successful:");
        console.log("- ShareToken owner cannot unregister vault");
        console.log("- Vault owner controls isActive flag");
        console.log("- No override mechanism exists");
        console.log("- Protocol maintenance is blocked");
    }
}
```

## Notes

This vulnerability arises from the architectural tension between "decentralized vault deployment" (allowing third parties to deploy vaults) and centralized vault registry control (ShareToken owner decides which vaults to authorize). The current implementation gives vault owners the power to veto ShareToken owner's unregistration attempts, which violates the documented trust model where the ShareToken Owner role should have administrative control over vault registration/unregistration.

The vulnerability is particularly concerning because:
1. Vault owners are not listed as trusted roles in KNOWN_ISSUES.md - only "Owners" (ShareToken owner), Validator, KYC Admin, Revenue Admin, and Investment Manager are trusted
2. The ShareToken owner's documented power to "unregister vaults" is effectively nullified without vault owner cooperation
3. There is no emergency override, timelock, or governance mechanism to resolve disputes
4. The attack requires zero ongoing cost - the vault owner simply doesn't deactivate

While the tests show the same entity controlling both the ShareToken and vaults, the code architecture explicitly supports separate ownership through the `initialize()` function's `owner` parameter, making this a realistic attack scenario in production deployments with third-party vault integrations.

### Citations

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

**File:** src/ERC7575VaultUpgradeable.sol (L1414-1417)
```text
    function setVaultActive(bool _isActive) external onlyOwner {
        VaultStorage storage $ = _getVaultStorage();
        $.isActive = _isActive;
        emit VaultActiveStateChanged(_isActive);
```
