## Title
Permanent DOS: Cancellation Request Blocks Deposits Forever if Investment Manager Never Fulfills

## Summary
Users who call `cancelDepositRequest()` to protect themselves from Investment Manager delays become permanently blocked from making new deposit requests if the Investment Manager never fulfills the cancellation. The blocking mechanism has no timeout, no escape hatch, and creates a paradox where the user protection feature can trap users in a worse state than before.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - Functions `cancelDepositRequest()` (lines 1574-1595), `requestDeposit()` (lines 341-371), `fulfillCancelDepositRequest()` (lines 994-1006), and `claimCancelDepositRequest()` (lines 1691-1711)

**Intended Logic:** 
The ERC-7887 cancellation mechanism is documented as a "user protection feature" that allows users to cancel pending requests and reclaim their assets when the Investment Manager delays fulfillment. [1](#0-0) 

The blocking of new requests during cancellation is specified by ERC-7887 to prevent race conditions. [2](#0-1) 

**Actual Logic:**
When a user calls `cancelDepositRequest()`, they are added to `controllersWithPendingDepositCancelations` which blocks ALL future deposit requests. [3](#0-2) 

The blocking check in `requestDeposit()` permanently prevents new deposits for any controller in this set. [4](#0-3) 

The ONLY way to be removed from the blocking set is in `claimCancelDepositRequest()`, which requires claimable assets. [5](#0-4) 

However, claimable assets only exist after the Investment Manager calls `fulfillCancelDepositRequest()`, which is restricted to the Investment Manager role. [6](#0-5) 

**Exploitation Path:**
1. User has pending deposit assets and calls `cancelDepositRequest()` to reclaim them due to Investment Manager delays
2. User is added to `controllersWithPendingDepositCancelations`, blocking all new deposit requests
3. Assets are moved from `pendingDepositAssets` to `pendingCancelDepositAssets`
4. Investment Manager never calls `fulfillCancelDepositRequest()` (unresponsive, malicious, or busy)
5. User attempts `requestDeposit()` with new assets → reverts with `DepositCancelationPending()` 
6. User attempts `claimCancelDepositRequest()` → reverts with `CancelationNotClaimable()` (no claimable assets)
7. User is permanently trapped: cannot make new deposits, cannot reclaim original assets, no escape mechanism

**Security Property Broken:** 
This violates the protocol's availability guarantees and creates an unintended DOS condition. Per the KNOWN_ISSUES document, "DOS requiring non-trivial cost that blocks core functionality" constitutes a valid Medium finding, while "Unintended availability impact from bug (not intentional control)" is explicitly in scope. [7](#0-6) 

## Impact Explanation
- **Affected Assets**: User's original pending deposit assets remain stuck in `pendingCancelDepositAssets` indefinitely
- **Damage Severity**: User loses all ability to participate in the vault system through deposits. If they have no other pending or claimable positions, they are completely locked out of the deposit functionality
- **User Impact**: Any user who calls `cancelDepositRequest()` becomes vulnerable. The "user protection" feature becomes a trap that makes their situation worse than before cancellation

**The Paradox:**
- **Before cancellation**: Assets in pending state, user can still make additional deposit requests (assuming different controller or first request)
- **After cancellation**: Assets in pending cancellation state, user is BLOCKED from ALL new deposit requests for that controller
- The user protection feature intended to help users escape Investment Manager delays instead creates a worse, inescapable situation

## Likelihood Explanation
- **Attacker Profile**: Not an attack - any normal user trying to protect themselves becomes a victim
- **Preconditions**: User has pending deposit assets and calls `cancelDepositRequest()` when Investment Manager is delayed
- **Execution Complexity**: Single transaction by the user (`cancelDepositRequest()`), then Investment Manager simply doesn't fulfill
- **Frequency**: Can occur anytime Investment Manager is unresponsive or overloaded. The longer the delay, the more users will attempt cancellation and trigger this issue

## Recommendation

Add a timeout mechanism or emergency escape hatch to prevent permanent blocking:

```solidity
// In src/ERC7575VaultUpgradeable.sol, add to VaultStorage struct:
mapping(address controller => uint256 timestamp) public cancelDepositRequestTimestamp;
uint256 public constant CANCEL_TIMEOUT = 7 days;

// In cancelDepositRequest(), line 1591, add:
$.cancelDepositRequestTimestamp[controller] = block.timestamp;

// In requestDeposit(), replace lines 354-356 with:
if ($.controllersWithPendingDepositCancelations.contains(controller)) {
    // Allow new deposits if cancellation has timed out
    uint256 cancelTime = $.cancelDepositRequestTimestamp[controller];
    if (block.timestamp < cancelTime + CANCEL_TIMEOUT) {
        revert DepositCancelationPending();
    }
    // Timeout expired - allow new deposit and clean up stale cancellation state
    $.controllersWithPendingDepositCancelations.remove(controller);
    delete $.pendingCancelDepositAssets[controller];
    delete $.cancelDepositRequestTimestamp[controller];
}

// Alternative: Add emergency admin function to manually unblock users:
function emergencyUnblockController(address controller) external onlyOwner {
    VaultStorage storage $ = _getVaultStorage();
    // Return any pending cancellation assets to pending state
    uint256 assets = $.pendingCancelDepositAssets[controller];
    if (assets > 0) {
        delete $.pendingCancelDepositAssets[controller];
        $.pendingDepositAssets[controller] = assets;
        $.totalCancelDepositAssets -= assets;
        $.totalPendingDepositAssets += assets;
    }
    $.controllersWithPendingDepositCancelations.remove(controller);
    $.activeDepositRequesters.add(controller);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_PermanentDepositBlocking.t.sol
// Run with: forge test --match-test test_PermanentDepositBlocking -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";
import "./mocks/MockERC20.sol";

contract Exploit_PermanentDepositBlocking is Test {
    WERC7575Vault vault;
    WERC7575ShareToken shareToken;
    MockERC20 asset;
    
    address user = address(0x1);
    address investmentManager = address(0x2);
    
    function setUp() public {
        // Deploy protocol
        asset = new MockERC20("USD Coin", "USDC", 6);
        shareToken = new WERC7575ShareToken();
        vault = new WERC7575Vault();
        
        // Initialize
        shareToken.initialize(address(this), address(this), address(this));
        vault.initialize(address(asset), address(shareToken), address(this));
        shareToken.registerVault(address(vault), address(asset));
        vault.setVaultActive(true);
        vault.setInvestmentManager(investmentManager);
        
        // Setup user with assets
        asset.mint(user, 1000e6);
        vm.prank(user);
        asset.approve(address(vault), type(uint256).max);
    }
    
    function test_PermanentDepositBlocking() public {
        // SETUP: User makes initial deposit request
        vm.prank(user);
        vault.requestDeposit(100e6, user, user);
        
        assertEq(vault.pendingDepositRequest(0, user), 100e6, "Should have pending deposit");
        
        // USER ACTION: Cancel deposit to protect themselves from Investment Manager delay
        vm.prank(user);
        vault.cancelDepositRequest(0, user);
        
        assertEq(vault.pendingCancelDepositRequest(0, user), true, "Cancel should be pending");
        assertEq(vault.pendingDepositRequest(0, user), 0, "Original deposit should be gone");
        
        // EXPLOIT: User tries to make NEW deposit request with additional funds
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("DepositCancelationPending()"));
        vault.requestDeposit(200e6, user, user);
        
        // VERIFY: User is permanently blocked - cannot deposit, cannot claim
        
        // Cannot make new deposits
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("DepositCancelationPending()"));
        vault.requestDeposit(50e6, user, user);
        
        // Cannot claim cancellation (not fulfilled yet)
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("CancelationNotClaimable()"));
        vault.claimCancelDepositRequest(0, user, user);
        
        // Even after time passes, still blocked (no timeout mechanism)
        vm.warp(block.timestamp + 365 days);
        
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("DepositCancelationPending()"));
        vault.requestDeposit(50e6, user, user);
        
        // Only Investment Manager can unblock by fulfilling (but if unresponsive, user is trapped forever)
        assertEq(vault.pendingCancelDepositRequest(0, user), true, "User still blocked after 1 year");
    }
}
```

## Notes

This vulnerability is distinct from the KNOWN_ISSUES item "No Fulfillment Deadlines" (QA/Low) because:

1. **Different Scope**: KNOWN_ISSUES documents that "Investment Manager can delay fulfillments indefinitely" for normal operations, but does NOT mention that cancellation creates permanent blocking

2. **Perverse Incentive**: The cancellation feature is explicitly documented as "user protection" [1](#0-0)  but actually creates a WORSE outcome for users when Investment Manager is unresponsive

3. **Meets Medium Criteria**: Per KNOWN_ISSUES Section 8, "DOS requiring non-trivial cost that blocks core functionality" is explicitly listed as a valid Medium finding [7](#0-6) 

4. **No Escape Mechanism**: Unlike normal pending states where users can wait indefinitely, the cancellation blocking has no timeout and no admin override, creating permanent unavailability

The root issue is architectural: ERC-7887 requires blocking during cancellation to prevent race conditions, but the protocol lacks safeguards (timeouts, emergency overrides) to handle Investment Manager unavailability in the cancellation flow.

### Citations

**File:** KNOWN_ISSUES.md (L228-257)
```markdown
### Request Cancellation Allowed
Users (or their approved operators) can cancel **pending** deposit/redeem requests and reclaim their assets/shares.

**Functions**:
- `cancelDepositRequest(address controller)` - Returns assets to user
- `cancelRedeemRequest(address controller)` - Returns shares to user

**Severity: QA/Low** or INVALID - Intentional user protection feature

**Why Intentional**:
- User protection - allows exit if Investment Manager delays too long
- **Custom extension beyond ERC-7540** (ERC-7540 deliberately excludes cancellation, deferring to future EIP)
- Design choice to provide user escape mechanism
- Only controller or their approved operator can cancel (access control working as intended)
- Only PENDING requests can be cancelled (not CLAIMABLE/fulfilled ones)

**NOT a Medium**:
- This IS the intended function - user has control over their pending requests
- No assets at risk - assets/shares returned to rightful owner
- Access control is intentional (controller or operator only)
- Not a "missing access control" - it's controlled access working correctly

**What WOULD Be a Bug** (High/Medium severity):
- ✅ Anyone can cancel other users' requests (broken access control)
- ✅ Cancellation doesn't return assets/shares (loss of funds)
- ✅ Can cancel CLAIMABLE requests (allowing double-claim)
- ✅ Reentrancy allows theft during cancellation

**Note**: Future versions may add additional cancellation features or restrictions, but current implementation is intentional.

```

**File:** KNOWN_ISSUES.md (L496-507)
```markdown

### What WOULD Be Medium DOS

**These would be valid Medium findings**:

- ✅ Griefing attack causing permanent lock of user funds (external requirements but realistic path)
- ✅ DOS requiring non-trivial cost that blocks core functionality (e.g., preventing all withdrawals)
- ✅ Unintended availability impact from bug (not intentional control)

**Key Distinction**: C4 Medium is "availability COULD BE IMPACTED" (broken/degraded from intended state), NOT "availability IS CONTROLLED by design."

Our intentional controls are the INTENDED state, not impacted state.
```

**File:** src/interfaces/IERC7887.sol (L31-42)
```text
     * @dev Submits a request to cancel a pending deposit request
     * Transitions the deposit request assets from pending state into pending cancelation state
     *
     * - MUST revert unless `msg.sender` is either equal to `controller` or an operator approved by `controller`
     * - MUST block new deposit requests for this controller while cancelation is pending
     * - MUST emit `CancelDepositRequest` event
     * - Can only cancel deposits in Pending state, not Claimable state
     *
     * @param requestId The requestId from the original deposit request (identifies which deposit to cancel)
     * @param controller Address that made the original deposit request
     */
    function cancelDepositRequest(uint256 requestId, address controller) external;
```

**File:** src/ERC7575VaultUpgradeable.sol (L353-356)
```text
        // ERC7887: Block new deposit requests while cancelation is pending for this controller
        if ($.controllersWithPendingDepositCancelations.contains(controller)) {
            revert DepositCancelationPending();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L994-1006)
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
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1574-1595)
```text
    function cancelDepositRequest(uint256 requestId, address controller) external nonReentrant {
        VaultStorage storage $ = _getVaultStorage();
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 pendingAssets = $.pendingDepositAssets[controller];
        if (pendingAssets == 0) revert NoPendingCancelDeposit();

        // Move from pending to pending cancelation
        delete $.pendingDepositAssets[controller];
        $.totalPendingDepositAssets -= pendingAssets;
        $.pendingCancelDepositAssets[controller] = pendingAssets;
        $.totalCancelDepositAssets += pendingAssets;

        // Block new deposit requests
        $.controllersWithPendingDepositCancelations.add(controller);
        $.activeDepositRequesters.remove(controller);

        emit CancelDepositRequest(controller, controller, REQUEST_ID, msg.sender, pendingAssets);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1691-1711)
```text
    function claimCancelDepositRequest(uint256 requestId, address receiver, address controller) external nonReentrant {
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 assets = $.claimableCancelDepositAssets[controller];
        if (assets == 0) revert CancelationNotClaimable();

        // CEI: State changes before external transfer
        delete $.claimableCancelDepositAssets[controller];
        $.totalCancelDepositAssets -= assets;
        $.controllersWithPendingDepositCancelations.remove(controller);

        // External interaction
        SafeTokenTransfers.safeTransfer($.asset, receiver, assets);

        // Event emission
        emit CancelDepositRequestClaimed(controller, receiver, REQUEST_ID, assets);
    }
```
