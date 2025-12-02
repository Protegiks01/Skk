## Title
Operator-Initiated Redemptions Bypass Critical Self-Allowance Compliance Gate

## Summary
In `ERC7575VaultUpgradeable.requestRedeem()`, approved operators can initiate redemption requests without consuming or checking the user's self-allowance (validator-issued permit). This bypasses the protocol's dual authorization invariant and critical compliance control mechanism designed to prevent fund movements during pending settlements.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol` - `requestRedeem()` function (lines 715-751)

**Intended Logic:** Per the protocol's dual authorization invariant (#3 and #4 from README), all transfers must check self-allowance to ensure validator approval. The self-allowance mechanism is documented as essential for "ensuring the settlement platform (WRAPX) controls when users can withdraw funds, preventing withdrawals during pending settlements or disputes." [1](#0-0) 

**Actual Logic:** When an operator is approved via `setOperator()`, the authorization check passes at line 723, causing the `spendAllowance()` call to be skipped entirely. Subsequently, `vaultTransferFrom()` is called which performs a direct `_transfer()` without any allowance validation: [2](#0-1) 

This means the user's self-allowance is never checked or spent when an operator initiates a redemption.

**Exploitation Path:**
1. User approves an operator via `shareToken.setOperator(operator, true)` 
2. User does NOT obtain a validator-signed permit (no self-allowance set)
3. Operator calls `vault.requestRedeem(shares, controller, owner)` 
4. Authorization check passes due to operator approval (line 723)
5. `spendAllowance()` is skipped (lines 724-726 not executed)
6. `vaultTransferFrom()` transfers shares from user to vault without checking self-allowance (line 740)
7. User's shares are now locked in pending redemption WITHOUT validator approval

**Security Property Broken:** 
- Invariant #3: "Dual Authorization: transfer requires self-allowance[user] (permit enforcement)"
- Invariant #4: "TransferFrom Dual Check: requires both self-allowance AND caller allowance"

The operator path bypasses BOTH allowance types - neither caller allowance nor self-allowance is checked.

## Impact Explanation

- **Affected Assets**: All share tokens held by users who have approved operators
- **Damage Severity**: Users can lock their shares in pending redemption requests during periods when the validator has intentionally NOT granted self-allowance (e.g., during active settlements, disputes, or compliance holds). This undermines the protocol's regulatory compliance mechanism.
- **User Impact**: Any user with approved operators can have their shares moved into redemption limbo without platform oversight, potentially interfering with settlement processes that require those shares to remain in the user's account.

## Likelihood Explanation

- **Attacker Profile**: Any operator approved by a user (legitimate or malicious)
- **Preconditions**: 
  - User has approved an operator
  - User has NOT obtained self-allowance (validator has not issued permit)
  - User holds shares that validator intends to keep locked
- **Execution Complexity**: Single transaction - operator calls `requestRedeem()`
- **Frequency**: Can be executed at any time by approved operators

## Recommendation

The `requestRedeem()` function should check self-allowance regardless of whether the caller is an operator, maintaining consistency with the synchronous vault implementation: [3](#0-2) 

## Proof of Concept

```solidity
// File: test/Exploit_OperatorBypassSelfAllowance.t.sol
// Run with: forge test --match-test test_OperatorBypassSelfAllowance -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";

contract Exploit_OperatorBypassSelfAllowance is Test {
    ERC7575VaultUpgradeable vault;
    WERC7575ShareToken shareToken;
    address alice = address(0x1);
    address operator = address(0x2);
    address validator = address(0x3);
    
    function setUp() public {
        // Deploy and initialize protocol
        // [deployment code omitted for brevity]
        
        // Alice has shares but NO self-allowance (no validator permit)
        // Alice approves operator
        vm.prank(alice);
        vault.setOperator(operator, true);
    }
    
    function test_OperatorBypassSelfAllowance() public {
        // SETUP: Alice has 1000 shares, no self-allowance
        uint256 shares = 1000e18;
        uint256 aliceAllowance = shareToken.allowance(alice, alice);
        assertEq(aliceAllowance, 0, "Alice should have no self-allowance");
        
        // EXPLOIT: Operator initiates redemption WITHOUT self-allowance check
        vm.prank(operator);
        vault.requestRedeem(shares, alice, alice);
        
        // VERIFY: Shares moved to vault, bypassing validator approval
        assertEq(shareToken.balanceOf(alice), 0, "Alice shares moved");
        assertEq(shareToken.balanceOf(address(vault)), shares, "Vault holds shares");
        assertEq(vault.pendingRedeemRequest(0, alice), shares, "Redemption pending");
        
        // Alice's shares are now locked without validator consent
        // This breaks the compliance control mechanism
    }
}
```

## Notes

**Architectural Inconsistency:** The synchronous `WERC7575Vault._withdraw()` function explicitly calls `spendSelfAllowance(owner, shares)` even when operators are involved, but the asynchronous `ERC7575VaultUpgradeable.requestRedeem()` does not. This inconsistency suggests the bypass was unintentional rather than a deliberate design choice. [4](#0-3) 

**Why This Matters:** The self-allowance (permit) mechanism serves a fundamentally different purpose than operator approval:
- **Operator approval** = User delegates authority to a third party
- **Self-allowance** = Validator (platform) authorizes fund movement for compliance

Operator approval represents user consent, but self-allowance represents regulatory/platform consent. An operator should still need validator approval (self-allowance) to initiate redemptions.

**Not Listed in KNOWN_ISSUES.md:** This bypass is not documented as intentional behavior in KNOWN_ISSUES.md (lines 84-130 cover dual allowance requirements but don't exempt operators).

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

**File:** src/WERC7575Vault.sol (L397-411)
```text
    function _withdraw(uint256 assets, uint256 shares, address receiver, address owner) internal {
        if (receiver == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (owner == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        if (assets == 0) revert ZeroAssets();
        if (shares == 0) revert ZeroShares();

        _shareToken.spendSelfAllowance(owner, shares);
        _shareToken.burn(owner, shares);
        SafeTokenTransfers.safeTransfer(_asset, receiver, assets);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }
```
