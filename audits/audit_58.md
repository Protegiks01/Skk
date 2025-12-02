## Title
Premature Removal from activeDepositRequesters Breaks Tracking System for Users with Pending Deposits

## Summary
In `ERC7575VaultUpgradeable.deposit()` and `mint()`, controllers are removed from `activeDepositRequesters` when they claim all their claimable amounts, without checking if they still have pending deposit amounts. This causes users with pending deposits to be excluded from tracking functions after claiming, breaking the investment manager's ability to identify users requiring fulfillment.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `deposit()` function (lines 557-589) and `mint()` function (lines 633-665) [1](#0-0) 

**Intended Logic:** The `activeDepositRequesters` set should track all controllers who have active deposit requests in either Pending or Claimable states. This allows the investment manager and off-chain systems to identify which users need attention.

**Actual Logic:** When a user claims all their claimable assets (line 574: `availableAssets == assets`), they are immediately removed from `activeDepositRequesters` (line 575), even if they still have pending deposit amounts that haven't been fulfilled yet. When those pending amounts are later fulfilled by the investment manager, the user will have claimable amounts but won't be tracked in `activeDepositRequesters`.

**Exploitation Path:**
1. Alice calls `requestDeposit(10000 USDC)` → `pendingDepositAssets[alice] = 10000`, alice added to `activeDepositRequesters`
2. Investment manager calls `fulfillDeposit(alice, 6000)` → `pendingDepositAssets[alice] = 4000`, `claimableDepositAssets[alice] = 6000`
3. Alice calls `deposit(6000, receiver, alice)` to claim all available assets → Since `availableAssets (6000) == assets (6000)`, alice is removed from `activeDepositRequesters` at line 575
4. Alice still has `pendingDepositAssets[alice] = 4000` but is NOT in `activeDepositRequesters`
5. Investment manager calls `fulfillDeposit(alice, 4000)` → `claimableDepositAssets[alice] = 4000` but alice is STILL not in `activeDepositRequesters`
6. `getActiveDepositRequesters()` returns empty array (or doesn't include alice), causing investment manager's off-chain systems to miss alice's claimable deposits [2](#0-1) 

Note that `fulfillDeposit()` does NOT re-add the controller to `activeDepositRequesters` - it only modifies the pending/claimable mappings.

**Security Property Broken:** The tracking system for active deposit requesters becomes inconsistent with actual state. The `activeDepositRequesters` set no longer accurately reflects controllers with pending or claimable amounts, violating the documented purpose of these "off-chain helper sets for tracking active requests" (line 108). [3](#0-2) 

## Impact Explanation
- **Affected Assets**: All users with partial fulfillment scenarios are at risk of being excluded from tracking
- **Damage Severity**: Users may experience indefinite delays in deposit fulfillment if the investment manager relies on `getActiveDepositRequesters()` to identify who needs fulfillment. While funds are not lost, operational functionality is broken.
- **User Impact**: Any user who claims their deposits in batches (partial claims before all pending amounts are fulfilled) will be prematurely removed from tracking. This affects helper functions used by off-chain systems: [4](#0-3) [5](#0-4) 

## Likelihood Explanation
- **Attacker Profile**: Any regular user in normal operation (no malicious intent required)
- **Preconditions**: Investment manager fulfills deposits in multiple batches, user claims between fulfillments
- **Execution Complexity**: Single transaction - normal `deposit()` or `mint()` call
- **Frequency**: Occurs whenever a user claims all claimable amounts while pending amounts remain - common in async vault operations with partial fulfillments

## Recommendation

The fix should check both claimable AND pending amounts before removing from the set:

```solidity
// In src/ERC7575VaultUpgradeable.sol, deposit() function, lines 573-581:

// CURRENT (vulnerable):
// Remove from active deposit requesters if no more claimable assets
if (availableAssets == assets) {
    $.activeDepositRequesters.remove(controller);
    delete $.claimableDepositShares[controller];
    delete $.claimableDepositAssets[controller];
} else {
    $.claimableDepositShares[controller] -= shares;
    $.claimableDepositAssets[controller] -= assets;
}

// FIXED:
// Remove from active deposit requesters only if no more claimable AND no pending assets
if (availableAssets == assets) {
    delete $.claimableDepositShares[controller];
    delete $.claimableDepositAssets[controller];
    
    // Only remove from set if no pending deposits remain
    if ($.pendingDepositAssets[controller] == 0) {
        $.activeDepositRequesters.remove(controller);
    }
} else {
    $.claimableDepositShares[controller] -= shares;
    $.claimableDepositAssets[controller] -= assets;
}
```

Apply the same fix to `mint()` function at lines 649-657: [6](#0-5) 

## Proof of Concept

```solidity
// File: test/Exploit_PrematureRemovalFromActiveRequesters.t.sol
// Run with: forge test --match-test test_PrematureRemovalFromActiveRequesters -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "./MockAsset.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_PrematureRemovalFromActiveRequesters is Test {
    ERC7575VaultUpgradeable public vault;
    ShareTokenUpgradeable public shareToken;
    MockAsset public asset;
    
    address public owner = makeAddr("owner");
    address public alice = makeAddr("alice");
    address public investmentManager = makeAddr("investmentManager");
    
    function setUp() public {
        vm.startPrank(owner);
        
        asset = new MockAsset();
        
        // Deploy ShareToken with proxy
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory shareTokenInitData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector, 
            "Test Shares", 
            "TST", 
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), shareTokenInitData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy Vault with proxy
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            asset,
            address(shareToken),
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // Configure
        shareToken.registerVault(address(asset), address(vault));
        vault.setInvestmentManager(investmentManager);
        
        vm.stopPrank();
        
        // Fund alice
        asset.mint(alice, 10000e18);
    }
    
    function test_PrematureRemovalFromActiveRequesters() public {
        // SETUP: Alice makes a deposit request
        vm.startPrank(alice);
        asset.approve(address(vault), 10000e18);
        vault.requestDeposit(10000e18, alice, alice);
        vm.stopPrank();
        
        // Verify alice is in activeDepositRequesters
        address[] memory requesters = vault.getActiveDepositRequesters();
        assertEq(requesters.length, 1, "Alice should be in active requesters");
        assertEq(requesters[0], alice, "Alice should be the active requester");
        
        // EXPLOIT Step 1: Investment manager fulfills partial deposit (6000)
        vm.prank(investmentManager);
        vault.fulfillDeposit(alice, 6000e18);
        
        // Alice now has: 4000 pending, 6000 claimable
        assertEq(vault.pendingDepositRequest(0, alice), 4000e18, "Should have 4000 pending");
        assertEq(vault.claimableDepositRequest(0, alice), 6000e18, "Should have 6000 claimable");
        
        // EXPLOIT Step 2: Alice claims all claimable (6000)
        vm.prank(alice);
        vault.deposit(6000e18, alice, alice);
        
        // VERIFY: Alice is REMOVED from activeDepositRequesters despite having 4000 pending
        requesters = vault.getActiveDepositRequesters();
        assertEq(requesters.length, 0, "Vulnerability: Alice removed despite having pending deposits!");
        assertEq(vault.pendingDepositRequest(0, alice), 4000e18, "Alice still has 4000 pending");
        
        // EXPLOIT Step 3: Investment manager fulfills remaining deposit (4000)
        vm.prank(investmentManager);
        vault.fulfillDeposit(alice, 4000e18);
        
        // VERIFY: Alice now has claimable amount but is STILL not in activeDepositRequesters
        assertEq(vault.claimableDepositRequest(0, alice), 4000e18, "Alice has 4000 claimable");
        requesters = vault.getActiveDepositRequesters();
        assertEq(requesters.length, 0, "Vulnerability confirmed: Alice has claimable deposits but not tracked!");
        
        // Impact: If investment manager relies on getActiveDepositRequesters() to know 
        // who needs attention, Alice will be missed and experience indefinite delays
    }
}
```

## Notes

This vulnerability specifically addresses the security question asked: the removal from `activeDepositRequesters` happens when all claimable amounts are claimed (not on the "final claim" in terms of total deposits), without verifying that no pending amounts remain. The issue manifests when users perform partial claims across multiple fulfillment batches, breaking the integrity of the tracking system that off-chain systems and the investment manager rely upon for operational decisions.

The vulnerability does not cause direct loss of funds but represents an accounting error that breaks core tracking functionality, qualifying as Medium severity under Code4rena's criteria for "accounting errors breaking functionality."

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L108-110)
```text
        // Off-chain helper sets for tracking active requests (using EnumerableSet for O(1) operations)
        EnumerableSet.AddressSet activeDepositRequesters;
        EnumerableSet.AddressSet activeRedeemRequesters;
```

**File:** src/ERC7575VaultUpgradeable.sol (L425-444)
```text
    function fulfillDeposit(address controller, uint256 assets) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        uint256 pendingAssets = $.pendingDepositAssets[controller];
        if (assets > pendingAssets) {
            revert ERC20InsufficientBalance(address(this), pendingAssets, assets);
        }

        shares = _convertToShares(assets, Math.Rounding.Floor);
        if (shares == 0) revert ZeroShares();

        $.pendingDepositAssets[controller] -= assets;
        $.totalPendingDepositAssets -= assets;
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming

        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);

        return shares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L573-581)
```text
        // Remove from active deposit requesters if no more claimable assets
        if (availableAssets == assets) {
            $.activeDepositRequesters.remove(controller);
            delete $.claimableDepositShares[controller];
            delete $.claimableDepositAssets[controller];
        } else {
            $.claimableDepositShares[controller] -= shares;
            $.claimableDepositAssets[controller] -= assets;
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L649-657)
```text
        // Remove from active deposit requesters if no more claimable shares
        if (availableShares == shares) {
            $.activeDepositRequesters.remove(controller);
            delete $.claimableDepositShares[controller];
            delete $.claimableDepositAssets[controller];
        } else {
            $.claimableDepositShares[controller] -= shares;
            $.claimableDepositAssets[controller] -= assets;
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1910-1916)
```text
    function getActiveDepositRequesters() external view returns (address[] memory) {
        VaultStorage storage $ = _getVaultStorage();
        if ($.activeDepositRequesters.length() > 100) {
            revert TooManyRequesters();
        }
        return $.activeDepositRequesters.values();
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L2042-2050)
```text
        metrics = VaultMetrics({
            totalPendingDepositAssets: $.totalPendingDepositAssets,
            totalClaimableRedeemAssets: $.totalClaimableRedeemAssets,
            totalCancelDepositAssets: $.totalCancelDepositAssets,
            scalingFactor: $.scalingFactor,
            totalAssets: totalAssets(),
            availableForInvestment: totalAssets(),
            activeDepositRequestersCount: $.activeDepositRequesters.length(),
            activeRedeemRequestersCount: $.activeRedeemRequesters.length(),
```
