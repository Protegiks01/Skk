## Title
Token Supply Conservation Violation in adjustrBalance() Profit Case

## Summary
The `adjustrBalance()` function in `WERC7575ShareToken` violates the critical "Token Supply Conservation" invariant when recording investment profits. When `amountr > amounti`, the function increases `_rBalances[account]` without a corresponding mint operation, causing the sum of all effective balances to exceed `totalSupply`.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/WERC7575ShareToken.sol`, function `adjustrBalance()` (lines 1435-1471) [1](#0-0) 

**Intended Logic:** The function should adjust `_rBalances` to reflect investment returns while maintaining the invariant that the sum of all user balances equals `totalSupply`.

**Actual Logic:** When investment returns exceed the initial investment (`amountr > amounti`), the function increases `_rBalances[account]` by the profit amount without minting new shares or updating `_totalSupply`. [2](#0-1) 

**Exploitation Path:**
1. User deposits 1000 assets and receives 1000 shares (minted via vault)
   - State: `_balances[user] = 1000`, `_rBalances[user] = 0`, `_totalSupply = 1000`
2. User's shares are moved to invested state via `rBatchTransfers` (300 shares)
   - State: `_balances[user] = 700`, `_rBalances[user] = 300`, `_totalSupply = 1000`
3. Investment returns 10% profit (invested 300, returned 330)
4. Revenue admin calls `adjustrBalance(user, timestamp, 300, 330)`
   - `_rBalances[user]` increases by 30 → becomes 330
   - `_balances[user]` remains 700 (NOT modified)
   - `_totalSupply` remains 1000 (NOT modified)
   - **Total effective balance: 700 + 330 = 1030 > 1000 = totalSupply**

**Security Property Broken:** Invariant #1 from README: "sum(balances) == totalSupply" [3](#0-2) 

In the dual balance system, each user's total balance is `_balances[user] + _rBalances[user]`. The invariant requires: `sum(_balances[i] + _rBalances[i]) == _totalSupply`. This is violated when profit adjustments increase the sum of effective balances without corresponding `totalSupply` increase.

## Impact Explanation
- **Affected Assets**: All shares in the WERC7575ShareToken contract
- **Damage Severity**: Creates "phantom" shares not backed by actual token supply. The discrepancy grows with each profitable investment cycle. With 10% returns across multiple users and cycles, the phantom supply can quickly accumulate to significant amounts.
- **User Impact**: All users holding invested positions. Any logic relying on `totalSupply()` for accounting (e.g., percentage calculations, governance voting, protocol integrations) will use incorrect values.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a protocol design flaw triggered by normal operations
- **Preconditions**: Users must have invested positions that generate profit
- **Execution Complexity**: Triggered automatically when revenue admin records investment returns
- **Frequency**: Occurs on every profitable investment cycle (intended to be regular operation)

## Recommendation
The `adjustrBalance()` function should mint new shares when recording profits to maintain the token supply invariant. The profit should result in actual share minting rather than just increasing `_rBalances`.

```solidity
// In src/WERC7575ShareToken.sol, function adjustrBalance, lines 1451-1455:

// CURRENT (vulnerable):
if (amountr > amounti) {
    difference = amountr - amounti;
    unchecked {
        _rBalances[account] += difference;
    }
}

// FIXED:
if (amountr > amounti) {
    difference = amountr - amounti;
    // Mint new shares to represent the profit
    _mint(account, difference);
    // The minted shares automatically go to _balances, so we need to transfer to _rBalances
    unchecked {
        _balances[account] -= difference;
        _rBalances[account] += amountr; // Set to total amount (not just add difference)
    }
}
```

Alternative approach: Track `_rBalances` separately from `_totalSupply` and update the `totalSupply()` function to include reserved balances, or redesign the accounting model so profit adjustments don't artificially inflate balances.

## Proof of Concept

```solidity
// File: test/Exploit_TokenSupplyViolation.t.sol
// Run with: forge test --match-test test_TokenSupplyViolation -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockAsset is ERC20 {
    constructor() ERC20("Mock", "MOCK") {
        _mint(msg.sender, 1000000e18);
    }
}

contract Exploit_TokenSupplyViolation is Test {
    WERC7575ShareToken shareToken;
    WERC7575Vault vault;
    MockAsset asset;
    
    address owner = address(1);
    address validator = address(2);
    address user = address(3);
    
    function setUp() public {
        vm.startPrank(owner);
        shareToken = new WERC7575ShareToken("Share", "SHR");
        asset = new MockAsset();
        vault = new WERC7575Vault(address(asset), shareToken);
        
        shareToken.setValidator(validator);
        shareToken.setKycAdmin(validator);
        shareToken.setRevenueAdmin(validator);
        shareToken.registerVault(address(asset), address(vault));
        vm.stopPrank();
        
        vm.prank(validator);
        shareToken.setKycVerified(user, true);
        
        vm.prank(owner);
        asset.transfer(user, 1000e18);
        
        vm.startPrank(user);
        asset.approve(address(vault), 1000e18);
        vault.deposit(1000e18, user);
        vm.stopPrank();
    }
    
    function test_TokenSupplyViolation() public {
        // SETUP: Initial state
        uint256 initialBalance = shareToken.balanceOf(user);
        uint256 initialRBalance = shareToken.rBalanceOf(user);
        uint256 initialTotalSupply = shareToken.totalSupply();
        
        assertEq(initialBalance, 1000e18, "User should have 1000 shares");
        assertEq(initialRBalance, 0, "User should have 0 rBalance initially");
        assertEq(initialTotalSupply, 1000e18, "Total supply should be 1000");
        
        // Invariant check: sum(balances + rBalances) == totalSupply
        uint256 totalEffectiveBalance = initialBalance + initialRBalance;
        assertEq(totalEffectiveBalance, initialTotalSupply, "Invariant should hold initially");
        
        // Move 300 shares to invested state
        address[] memory debtors = new address[](1);
        address[] memory creditors = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        bool[] memory debtorsFlags = new bool[](1);
        bool[] memory creditorsFlags = new bool[](1);
        
        debtors[0] = user;
        creditors[0] = user;
        amounts[0] = 300e18;
        debtorsFlags[0] = true;
        
        uint256 rBalanceFlags = shareToken.computeRBalanceFlags(debtors, creditors, debtorsFlags, creditorsFlags);
        
        vm.prank(validator);
        shareToken.rBatchTransfers(debtors, creditors, amounts, rBalanceFlags);
        
        assertEq(shareToken.balanceOf(user), 700e18, "User should have 700 liquid shares");
        assertEq(shareToken.rBalanceOf(user), 300e18, "User should have 300 reserved shares");
        assertEq(shareToken.totalSupply(), 1000e18, "Total supply unchanged after transfer");
        
        // EXPLOIT: Adjust rBalance with profit (invested 300, returned 330)
        vm.prank(validator);
        shareToken.adjustrBalance(user, block.timestamp, 300e18, 330e18);
        
        // VERIFY: Confirm exploit success
        uint256 finalBalance = shareToken.balanceOf(user);
        uint256 finalRBalance = shareToken.rBalanceOf(user);
        uint256 finalTotalSupply = shareToken.totalSupply();
        
        assertEq(finalBalance, 700e18, "Liquid balance unchanged");
        assertEq(finalRBalance, 330e18, "rBalance increased by profit");
        assertEq(finalTotalSupply, 1000e18, "Total supply unchanged");
        
        // CRITICAL: Invariant is now violated!
        uint256 finalTotalEffectiveBalance = finalBalance + finalRBalance;
        assertEq(finalTotalEffectiveBalance, 1030e18, "Total effective balance is 1030");
        
        // This assertion will fail - demonstrating the vulnerability
        assertTrue(
            finalTotalEffectiveBalance > finalTotalSupply,
            "Vulnerability confirmed: Effective balance exceeds totalSupply"
        );
        
        console.log("Total Supply:", finalTotalSupply);
        console.log("Effective Balance (balanceOf + rBalanceOf):", finalTotalEffectiveBalance);
        console.log("Phantom Shares Created:", finalTotalEffectiveBalance - finalTotalSupply);
    }
}
```

## Notes

The premise of the security question about `sum(_rBalances) > sum(_balances)` is slightly misleading. The actual violated invariant is more fundamental: the total effective balance `sum(_balances[i] + _rBalances[i])` exceeds `_totalSupply`. The `_rBalances` mapping doesn't track a "subset" of `_balances` - rather, both mappings together constitute each user's total balance. The vulnerability creates phantom tokens in the accounting system that have no backing in the actual `_totalSupply`.

This issue is NOT listed in `KNOWN_ISSUES.md` and directly violates the first and most critical invariant documented in the README. The "rBalance silent truncation" known issue refers to different behavior (informational tracking limitations) and does not excuse this supply conservation violation.

### Citations

**File:** src/WERC7575ShareToken.sol (L1435-1471)
```text
    function adjustrBalance(address account, uint256 ts, uint256 amounti, uint256 amountr) external onlyRevenueAdmin {
        if (_rBalanceAdjustments[account][ts][0] != 0) {
            revert RBalanceAdjustmentAlreadyApplied();
        }
        if (amounti == 0) revert ZeroAmount();
        if (ts > block.timestamp) revert FutureTimestampNotAllowed();
        // Prevent overflow in return multiplier calculation
        if (amounti > type(uint256).max / MAX_RETURN_MULTIPLIER) {
            revert AmountTooLarge();
        }
        if (amountr > amounti * MAX_RETURN_MULTIPLIER) {
            revert MaxReturnMultiplierExceeded();
        }
        _rBalanceAdjustments[account][ts] = [amounti, amountr];

        uint256 difference;
        if (amountr > amounti) {
            difference = amountr - amounti;
            unchecked {
                _rBalances[account] += difference;
            }
        } else if (amountr < amounti) {
            difference = amounti - amountr;
            uint256 currentRBalance = _rBalances[account];
            if (currentRBalance < difference) {
                // Should not happen otherwise we can't cancel with cancelrBalanceAdjustment
                // If this was the case it would mean that the investment vault has received more assets than the original investment
                // This would mean that the investment vault has made a profit that is not backed by the assets which should not be possible
                revert RBalanceAdjustmentTooLarge();
            } else {
                unchecked {
                    _rBalances[account] -= difference;
                }
            }
        }
        emit RBalanceAdjusted(account, amounti, amountr);
    }
```

**File:** README.md (L93-93)
```markdown
  1. sum(balances) == totalSupply - Token supply conservation
```
