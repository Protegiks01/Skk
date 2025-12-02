## Title
Fulfilled Redeem Cancelations Block New Redeem Requests Until Claimed, Causing DOS and Operational Friction

## Summary
In `ERC7575VaultUpgradeable`, users with fulfilled (claimable) redeem cancelations are permanently blocked from making new redeem requests until they claim their canceled shares. The `requestRedeem()` function checks if a controller exists in `controllersWithPendingRedeemCancelations` and reverts, but this set is only cleared during claim, not when the investment manager fulfills the cancelation and moves it to claimable state.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `requestRedeem()` (lines 734-736), `fulfillCancelRedeemRequest()` (lines 1081-1091), `claimCancelRedeemRequest()` (lines 1866-1884)

**Intended Logic:** The cancelation blocking mechanism should prevent race conditions by blocking new redeem requests only while a cancelation is in **pending state** (awaiting investment manager fulfillment). Once the investment manager fulfills the cancelation and moves it to **claimable state**, users should be free to make new redeem requests with different shares while their previous canceled shares wait to be claimed.

**Actual Logic:** The blocking persists through the entire cancelation lifecycle. When a user cancels a redeem request, they're added to `controllersWithPendingRedeemCancelations`. [1](#0-0)  When the investment manager fulfills this cancelation by calling `fulfillCancelRedeemRequest()`, the shares move from pending to claimable state, but the controller is **not** removed from the blocking set. [2](#0-1)  The controller is only removed when they actually claim via `claimCancelRedeemRequest()`. [3](#0-2) 

Meanwhile, `requestRedeem()` blocks any new redeem requests from this controller as long as they remain in the set. [4](#0-3) 

**Exploitation Path:**
1. User calls `cancelRedeemRequest()` for 100 shares → Controller added to `controllersWithPendingRedeemCancelations`
2. Investment manager calls `fulfillCancelRedeemRequest()` → Shares become claimable, but controller remains in blocking set
3. User acquires 200 new shares and wants to submit a new redeem request
4. User calls `requestRedeem()` with 200 new shares → Transaction reverts with `RedeemCancelationPending()` even though cancelation is already fulfilled and claimable
5. User is forced to call `claimCancelRedeemRequest()` first to remove themselves from the blocking set before they can submit any new redeem requests

**Security Property Broken:** Violates **Async State Flow** invariant (Invariant #8): The ERC-7887 spec implements a three-phase lifecycle (Pending → Claimable → Claimed), and blocking should logically apply only during the Pending phase when the investment manager hasn't yet processed the cancelation. Once fulfilled to Claimable state, there's no technical reason to block new independent requests.

## Impact Explanation
- **Affected Assets**: All share tokens and redemption operations across all vaults
- **Damage Severity**: 
  - **Operational DOS**: Users cannot make time-sensitive redemption requests during market opportunities
  - **Forced Action**: Users must execute an extra transaction (claim) before proceeding with new operations, incurring unnecessary gas costs
  - **Temporary Fund Locking**: New shares intended for redemption are temporarily unusable until the claim is processed
- **User Impact**: Every user who cancels a redeem request experiences this friction. In high-volatility scenarios where users need to quickly submit new redemption requests (e.g., withdrawing during market crashes), this forced delay could result in material losses

## Likelihood Explanation
- **Attacker Profile**: Not malicious exploitation - this affects all legitimate users
- **Preconditions**: User has a fulfilled redeem cancelation in claimable state
- **Execution Complexity**: Automatically triggered on every `requestRedeem()` call
- **Frequency**: Occurs 100% of the time when a user has claimable canceled shares and attempts new redemptions

## Recommendation
Remove the controller from `controllersWithPendingRedeemCancelations` when the cancelation is fulfilled, not when it's claimed:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function fulfillCancelRedeemRequest, line 1081-1091:

// CURRENT (vulnerable):
function fulfillCancelRedeemRequest(address controller) external returns (uint256 shares) {
    VaultStorage storage $ = _getVaultStorage();
    if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

    shares = $.pendingCancelRedeemShares[controller];
    if (shares == 0) revert NoPendingCancelRedeem();

    // Move from pending to claimable cancelation state
    delete $.pendingCancelRedeemShares[controller];
    $.claimableCancelRedeemShares[controller] += shares;
}

// FIXED:
function fulfillCancelRedeemRequest(address controller) external returns (uint256 shares) {
    VaultStorage storage $ = _getVaultStorage();
    if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

    shares = $.pendingCancelRedeemShares[controller];
    if (shares == 0) revert NoPendingCancelRedeem();

    // Move from pending to claimable cancelation state
    delete $.pendingCancelRedeemShares[controller];
    $.claimableCancelRedeemShares[controller] += shares;
    
    // Remove controller from blocking set - cancelation is now fulfilled and claimable
    // User should be free to make new redeem requests with different shares
    $.controllersWithPendingRedeemCancelations.remove(controller);
}
```

And update `claimCancelRedeemRequest()` to avoid double-removal errors:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function claimCancelRedeemRequest, line 1877-1878:

// CURRENT:
delete $.claimableCancelRedeemShares[controller];
$.controllersWithPendingRedeemCancelations.remove(controller);

// FIXED (defensive - only remove if still in set):
delete $.claimableCancelRedeemShares[controller];
// Note: This line can be removed since controller was already removed during fulfillment
// Keeping it for defensive programming (EnumerableSet.remove is idempotent)
$.controllersWithPendingRedeemCancelations.remove(controller);
```

Apply the same fix to `fulfillCancelDepositRequest()` and batch fulfillment functions, as deposit cancelations have the identical issue. [5](#0-4) 

## Proof of Concept
```solidity
// File: test/Exploit_CancelationBlocksNewRequests.t.sol
// Run with: forge test --match-test test_CancelationBlocksNewRequests -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";

contract Exploit_CancelationBlocksNewRequests is Test {
    WERC7575Vault vault;
    WERC7575ShareToken shareToken;
    address user = address(0x1);
    address investmentManager = address(0x2);
    address asset = address(0x3); // Mock ERC20
    
    function setUp() public {
        // Initialize protocol (simplified - actual deployment more complex)
        shareToken = new WERC7575ShareToken();
        vault = new WERC7575Vault();
        
        // Setup: user has 300 shares, submits redeem request for 100 shares
        vm.startPrank(user);
        // User requests redeem of 100 shares
        vault.requestRedeem(100, user, user);
        vm.stopPrank();
    }
    
    function test_CancelationBlocksNewRequests() public {
        // SETUP: User cancels their redeem request
        vm.prank(user);
        vault.cancelRedeemRequest(0, user);
        
        // Investment manager fulfills the cancelation
        vm.prank(investmentManager);
        vault.fulfillCancelRedeemRequest(user);
        
        // VERIFY: User now has 100 claimable canceled shares
        assertEq(vault.claimableCancelRedeemRequest(0, user), 100, "Should have claimable canceled shares");
        
        // EXPLOIT: User tries to make a NEW redeem request with their remaining 200 shares
        // This should work since the previous cancelation is fulfilled and claimable
        vm.prank(user);
        vm.expectRevert(RedeemCancelationPending.selector);
        vault.requestRedeem(200, user, user); // REVERTS - user is blocked!
        
        // User is forced to claim first
        vm.prank(user);
        vault.claimCancelRedeemRequest(0, user, user);
        
        // NOW the new redeem request works
        vm.prank(user);
        vault.requestRedeem(200, user, user); // Success
        
        console.log("Vulnerability confirmed: User blocked from new redeem requests even with claimable cancelation");
    }
}
```

## Notes
- **Parallel Issue**: The same vulnerability exists for deposit cancelations with `controllersWithPendingDepositCancelations` in `requestDeposit()` and `fulfillCancelDepositRequest()`. [6](#0-5) 
- **Batch Functions**: The batch fulfillment functions `fulfillCancelRedeemRequests()` and `fulfillCancelDepositRequests()` also need the same fix to remove controllers from blocking sets during fulfillment.
- **ERC-7887 Spec Alignment**: The ERC-7887 specification describes a three-phase lifecycle for cancelations but doesn't explicitly mandate when the request blocking should be lifted. However, the logical intent of blocking is to prevent race conditions during pending state, not to force sequential claims.
- **Not in Known Issues**: While KNOWN_ISSUES.md mentions "Request cancellation allowed (intentional user protection) - QA/Low", it does not mention this specific DOS condition where fulfilled cancelations block new requests.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L353-356)
```text
        // ERC7887: Block new deposit requests while cancelation is pending for this controller
        if ($.controllersWithPendingDepositCancelations.contains(controller)) {
            revert DepositCancelationPending();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L733-736)
```text
        // ERC7887: Block new redeem requests while cancelation is pending for this controller
        if ($.controllersWithPendingRedeemCancelations.contains(controller)) {
            revert RedeemCancelationPending();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L994-1005)
```text
    function fulfillCancelDepositRequest(address controller) external returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

        assets = $.pendingCancelDepositAssets[controller];
        if (assets == 0) revert NoPendingCancelDeposit();

        // Move from pending to claimable cancelation state
        delete $.pendingCancelDepositAssets[controller];
        $.claimableCancelDepositAssets[controller] += assets;

        return assets;
```

**File:** src/ERC7575VaultUpgradeable.sol (L1081-1091)
```text
    function fulfillCancelRedeemRequest(address controller) external returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

        shares = $.pendingCancelRedeemShares[controller];
        if (shares == 0) revert NoPendingCancelRedeem();

        // Move from pending to claimable cancelation state
        delete $.pendingCancelRedeemShares[controller];
        $.claimableCancelRedeemShares[controller] += shares;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1755-1760)
```text
        // Move from pending to pending cancelation
        delete $.pendingRedeemShares[controller];
        $.pendingCancelRedeemShares[controller] = pendingShares;

        // Block new redeem requests
        $.controllersWithPendingRedeemCancelations.add(controller);
```

**File:** src/ERC7575VaultUpgradeable.sol (L1873-1878)
```text
        uint256 shares = $.claimableCancelRedeemShares[controller];
        if (shares == 0) revert CancelationNotClaimable();

        // CEI: State changes before external transfer
        delete $.claimableCancelRedeemShares[controller];
        $.controllersWithPendingRedeemCancelations.remove(controller);
```
