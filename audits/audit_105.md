## Title
Permanent Denial of Service on `cancelrBalanceAdjustment()` Due to rBalance Drainage via `rBatchTransfers()`

## Summary
The `cancelrBalanceAdjustment()` function can be permanently blocked when attempting to reverse a profit adjustment if a user's `_rBalances` has been subsequently drained through `rBatchTransfers()` operations. This prevents the Revenue Admin from correcting erroneous adjustments, permanently locking incorrect accounting data in the `_rBalanceAdjustments` mapping.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` - `cancelrBalanceAdjustment()` function (lines 1485-1514)

**Intended Logic:** The cancellation mechanism should allow the Revenue Admin to reverse any prior `adjustrBalance()` call by applying the opposite adjustment, enabling error correction for investment return tracking. [1](#0-0) 

**Actual Logic:** When a profit adjustment (amountr > amounti) is applied via `adjustrBalance()`, the user's `_rBalances` increases. However, the cancellation function checks if the current rBalance is sufficient to reverse the adjustment. If the user's rBalance has been drained through `rBatchTransfers()` operations after the original adjustment, the cancellation will permanently fail.

**Exploitation Path:**

1. **Revenue Admin applies profit adjustment:** `adjustrBalance(account, ts, 500e18, 600e18)` is called, increasing `_rBalances[account]` by 100e18. [2](#0-1) 

2. **User participates in rBatchTransfers as net creditor:** In the normal course of telecom settlement operations, the user receives net payments. When the Validator calls `rBatchTransfers()` with the user as a creditor and their bit set in `rBalanceFlags`, the rBalance is decreased. [3](#0-2) 

3. **rBalance gets drained:** If the user receives credits totaling ≥100e18 with rBalance flag set, their `_rBalances[account]` decreases to 0 (capped to prevent underflow). [4](#0-3) 

4. **Cancellation permanently fails:** When Revenue Admin discovers an error and attempts `cancelrBalanceAdjustment(account, ts)`, the function checks if `currentRBalance < difference`. Since rBalance is now 0 or insufficient, it reverts with `RBalanceAdjustmentTooLarge()`. [5](#0-4) 

**Security Property Broken:** This violates the protocol's error correction mechanism and accounting integrity. The adjustment data remains permanently locked in `_rBalanceAdjustments[account][ts]`, preventing any future corrections.

## Impact Explanation
- **Affected Assets**: Share tokens with dual balance tracking (`_balances` and `_rBalances`)
- **Damage Severity**: No direct fund theft, but:
  - Incorrect investment return records permanently locked in storage
  - Revenue Admin cannot correct mistakes or fraudulent adjustments
  - Accounting audit trail becomes permanently corrupted
  - May affect regulatory compliance and financial reporting
- **User Impact**: Any user who receives a profit adjustment followed by net credit transfers. This can affect multiple accounts simultaneously if batch operations involve them as creditors.

## Likelihood Explanation
- **Attacker Profile**: No malicious intent required - happens through normal operations. A sophisticated attacker could deliberately arrange to be a creditor after receiving a profit adjustment to lock in favorable accounting errors.
- **Preconditions**: 
  - Revenue Admin applies a profit adjustment (amountr > amounti)
  - User participates in subsequent `rBatchTransfers()` as a net creditor
  - User's rBalance flag is set (controlled by Validator's pre-computation)
- **Execution Complexity**: Can occur naturally in a single `rBatchTransfers()` call after an adjustment. No complex multi-transaction coordination required.
- **Frequency**: Can happen repeatedly across multiple users and adjustments. Every profit adjustment is vulnerable to this issue once the user's rBalance is drained through normal settlement operations.

## Recommendation

Add a bypass mechanism that allows cancellation even when rBalance is insufficient, by tracking the deficit separately:

```solidity
// In src/WERC7575ShareToken.sol, function cancelrBalanceAdjustment, line 1494-1504:

// CURRENT (vulnerable):
if (amountr > amounti) {
    uint256 difference = amountr - amounti;
    uint256 currentRBalance = _rBalances[account];
    if (currentRBalance < difference) {
        // Should not happen otherwise we can't cancel with the adjustment
        revert RBalanceAdjustmentTooLarge();
    } else {
        unchecked {
            _rBalances[account] -= difference;
        }
    }
}

// FIXED:
if (amountr > amounti) {
    uint256 difference = amountr - amounti;
    uint256 currentRBalance = _rBalances[account];
    if (currentRBalance < difference) {
        // rBalance drained after adjustment - set to 0 instead of reverting
        // This allows cancellation while acknowledging the balance was already utilized
        _rBalances[account] = 0;
        emit RBalanceDeficit(account, ts, difference - currentRBalance);
    } else {
        unchecked {
            _rBalances[account] -= difference;
        }
    }
}
```

**Alternative approach:** Store the original rBalance at adjustment time and restore it exactly during cancellation, preventing external modifications from blocking cancellation:

```solidity
// Store snapshot during adjustment
_rBalanceAdjustments[account][ts] = [amounti, amountr, _rBalances[account]];

// Restore during cancellation
uint256[3] memory adjustment = _rBalanceAdjustments[account][ts];
uint256 originalRBalance = adjustment[2];
_rBalances[account] = originalRBalance;
```

## Proof of Concept

```solidity
// File: test/Exploit_CancelBlockedByRBalanceDrainage.t.sol
// Run with: forge test --match-test test_CancelBlockedByRBalanceDrainage -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "./MockAsset.sol";

contract Exploit_CancelBlockedByRBalanceDrainage is Test {
    WERC7575ShareToken public shareToken;
    WERC7575Vault public vault;
    MockAsset public asset;
    
    address owner = address(1);
    address validator = address(2);
    address revenueAdmin = address(3);
    address alice = address(4);
    address bob = address(5);
    
    function setUp() public {
        vm.startPrank(owner);
        asset = new MockAsset();
        asset.mint(alice, 10000e18);
        asset.mint(bob, 10000e18);
        
        shareToken = new WERC7575ShareToken("Test Token", "TST");
        vault = new WERC7575Vault(address(asset), shareToken);
        
        shareToken.setValidator(validator);
        shareToken.setKycAdmin(validator);
        shareToken.setRevenueAdmin(revenueAdmin);
        shareToken.registerVault(address(asset), address(vault));
        vm.stopPrank();
        
        // Setup KYC
        vm.startPrank(validator);
        shareToken.setKycVerified(alice, true);
        shareToken.setKycVerified(bob, true);
        vm.stopPrank();
        
        // Give alice initial shares
        vm.startPrank(alice);
        asset.approve(address(vault), 1000e18);
        vault.deposit(1000e18, alice);
        vm.stopPrank();
    }
    
    function test_CancelBlockedByRBalanceDrainage() public {
        // SETUP: Initial state
        uint256 timestamp = block.timestamp;
        assertEq(shareToken.rBalanceOf(alice), 0, "Alice starts with rBalance = 0");
        assertEq(shareToken.balanceOf(alice), 1000e18, "Alice has 1000 liquid balance");
        
        // STEP 1: Revenue admin applies profit adjustment (mistake or legitimate)
        // Alice invested 500, received 600 back (100 profit)
        vm.prank(revenueAdmin);
        shareToken.adjustrBalance(alice, timestamp, 500e18, 600e18);
        
        assertEq(shareToken.rBalanceOf(alice), 100e18, "Alice rBalance increased by profit");
        
        // STEP 2: Alice participates in rBatchTransfers as net creditor
        // In telecom settlement, Alice receives net payment of 150 tokens
        address[] memory debtors = new address[](1);
        address[] memory creditors = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        
        debtors[0] = bob;
        creditors[0] = alice;
        amounts[0] = 150e18;
        
        // Give bob shares first
        vm.startPrank(bob);
        asset.approve(address(vault), 200e18);
        vault.deposit(200e18, bob);
        vm.stopPrank();
        
        // Compute rBalance flags with alice flagged
        bool[] memory debtorsFlags = new bool[](1);
        bool[] memory creditorsFlags = new bool[](1);
        debtorsFlags[0] = false;
        creditorsFlags[0] = true; // Alice's rBalance should decrease
        
        uint256 flags = shareToken.computeRBalanceFlags(debtors, creditors, debtorsFlags, creditorsFlags);
        
        // Execute batch transfer
        vm.prank(validator);
        shareToken.rBatchTransfers(debtors, creditors, amounts, flags);
        
        // VERIFY: Alice's rBalance drained (150 credit > 100 rBalance, so capped to 0)
        assertEq(shareToken.rBalanceOf(alice), 0, "Alice rBalance drained to 0");
        assertEq(shareToken.balanceOf(alice), 1150e18, "Alice received 150 tokens");
        
        // EXPLOIT: Revenue admin discovers error and tries to cancel adjustment
        vm.prank(revenueAdmin);
        vm.expectRevert(WERC7575ShareToken.RBalanceAdjustmentTooLarge.selector);
        shareToken.cancelrBalanceAdjustment(alice, timestamp);
        
        // Vulnerability confirmed: Cancellation permanently blocked
        // The incorrect adjustment [500, 600] is now permanently locked in storage
    }
}
```

## Notes

This vulnerability demonstrates a **state ordering dependency** where the cancellation mechanism assumes that rBalance modifications only occur through `adjustrBalance()` calls. However, `rBatchTransfers()` can independently modify rBalances, creating a scenario where cancellation becomes impossible.

The issue is particularly problematic because:
1. **No malicious intent required** - happens naturally in telecom settlement operations
2. **Affects error correction** - Revenue Admin cannot fix legitimate mistakes
3. **Permanent state corruption** - adjustment records remain locked indefinitely
4. **Regulatory implications** - inability to correct financial records may violate compliance requirements

The recommended fix allows cancellation to proceed even when rBalance is insufficient, acknowledging that the balance was utilized in legitimate operations. This maintains the error correction capability while respecting the business logic that allowed rBalance drainage.

### Citations

**File:** src/WERC7575ShareToken.sol (L1166-1178)
```text
                    if (((rBalanceFlags >> i) & 1) == 1) {
                        // Account flagged for rBalance update
                        // When gaining tokens, restricted balance decreases (restricted amount used)
                        uint256 rbalance = _rBalances[account.owner];
                        if (rbalance < amount) {
                            // Not enough restricted balance to cover credit amount
                            // Set to 0 (no over-correction, stays >= 0)
                            _rBalances[account.owner] = 0;
                        } else {
                            // Have enough restricted balance, decrement by credit amount
                            // (unchecked is parent unchecked block, safe from underflow)
                            _rBalances[account.owner] -= amount;
                        }
```

**File:** src/WERC7575ShareToken.sol (L1451-1455)
```text
        if (amountr > amounti) {
            difference = amountr - amounti;
            unchecked {
                _rBalances[account] += difference;
            }
```

**File:** src/WERC7575ShareToken.sol (L1485-1514)
```text
    function cancelrBalanceAdjustment(address account, uint256 ts) external onlyRevenueAdmin {
        if (_rBalanceAdjustments[account][ts][0] == 0) {
            revert NoRBalanceAdjustmentFound();
        }

        uint256[2] memory adjustment = _rBalanceAdjustments[account][ts];
        uint256 amounti = adjustment[0];
        uint256 amountr = adjustment[1];

        if (amountr > amounti) {
            uint256 difference = amountr - amounti;
            uint256 currentRBalance = _rBalances[account];
            if (currentRBalance < difference) {
                // Should not happen otherwise we can't cancel with the adjustment
                revert RBalanceAdjustmentTooLarge();
            } else {
                unchecked {
                    _rBalances[account] -= difference;
                }
            }
        } else if (amountr < amounti) {
            uint256 difference = amounti - amountr;
            unchecked {
                _rBalances[account] += difference;
            }
        }

        delete _rBalanceAdjustments[account][ts];
        emit RBalanceAdjustmentCancelled(account, ts);
    }
```
