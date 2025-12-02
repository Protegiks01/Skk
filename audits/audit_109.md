## Title
Double-Spending of Self-Allowance in transferFrom() When Caller Equals Owner

## Summary
The `transferFrom()` function spends self-allowance twice when `msg.sender == from`, violating the intended dual-authorization model. This causes users to consume double the expected allowance per transfer, prematurely exhausting their validator-approved permits and requiring twice as many validator signatures for the same transfer capacity.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` - `transferFrom()` function (lines 488-492) [1](#0-0) 

**Intended Logic:** The `transferFrom()` function is documented to enforce dual-authorization: self-allowance (platform permission via validator) AND caller allowance (owner delegation). These are intended to be two DIFFERENT allowances checked independently. [2](#0-1) 

**Actual Logic:** When a user calls `transferFrom(user, recipient, amount)` where `msg.sender == user`, the self-allowance `allowance[user][user]` is spent TWICE:

1. **First deduction** (line 490): `_spendAllowance(from, from, value)` explicitly spends self-allowance
2. **Second deduction** (line 491): `super.transferFrom()` inherits OpenZeppelin's ERC20 implementation, which internally calls `_spendAllowance(from, msg.sender, value)`. Since `msg.sender == from`, this becomes `_spendAllowance(from, from, value)` again, deducting from the same allowance a second time.

**Exploitation Path:**
1. User obtains self-allowance of 100 via validator-signed permit: `allowance[user][user] = 100`
2. User calls `transferFrom(user, recipient, 50)` with `msg.sender == user`
3. Line 490 executes: `allowance[user][user]` decremented by 50 → becomes 50
4. Line 491 executes `super.transferFrom()` which internally decrements `allowance[user][user]` by 50 again → becomes 0
5. User has consumed entire allowance (100) for a single 50-token transfer
6. Second transfer attempt immediately reverts with `ERC20InsufficientAllowance` despite expecting 50 remaining allowance

**Security Property Broken:** 
- **Invariant #4 (TransferFrom Dual Check)**: "requires both self-allowance AND caller allowance" - When `msg.sender == from`, both checks target the SAME allowance, causing double consumption rather than dual authorization
- Breaks expected allowance accounting: transfers consume 2x the expected allowance

## Impact Explanation
- **Affected Assets**: All share tokens held by users who call `transferFrom()` on their own addresses
- **Damage Severity**: Users lose 50% of their effective transfer capacity. Validator-signed permits (the scarce authorization resource in this compliance-focused system) are exhausted at double the expected rate.
- **User Impact**: Any user who calls `transferFrom(address(this), recipient, amount)` instead of `transfer(recipient, amount)` will consume double allowance. This is particularly problematic for:
  - Smart contract integrations that use `transferFrom()` uniformly
  - Users unfamiliar with the protocol's non-standard transfer mechanics
  - Automated systems that might route through `transferFrom()` for consistency

## Likelihood Explanation
- **Attacker Profile**: Any user or integrated contract calling `transferFrom()` with `msg.sender == from`
- **Preconditions**: User has obtained self-allowance via validator permit and calls `transferFrom()` instead of `transfer()`
- **Execution Complexity**: Single transaction - no special timing or conditions required
- **Frequency**: Occurs on every `transferFrom()` call where `msg.sender == from`

## Recommendation

**Option 1: Prevent Self-TransferFrom (Recommended)**
```solidity
// In src/WERC7575ShareToken.sol, function transferFrom, line 488:

function transferFrom(address from, address to, uint256 value) public override whenNotPaused returns (bool) {
    if (!isKycVerified[to]) revert KycRequired();
    
    // FIXED: Prevent double-spending by requiring caller != from
    // Users should use transfer() for self-initiated transfers
    if (msg.sender == from) {
        revert("WERC7575ShareToken: use transfer() for self-initiated transfers");
    }
    
    _spendAllowance(from, from, value);
    return super.transferFrom(from, to, value);
}
```

**Option 2: Skip Second Allowance Check for Self-TransferFrom**
```solidity
function transferFrom(address from, address to, uint256 value) public override whenNotPaused returns (bool) {
    if (!isKycVerified[to]) revert KycRequired();
    _spendAllowance(from, from, value);
    
    // FIXED: When caller == from, use transfer() internally to avoid double-spending
    if (msg.sender == from) {
        return super.transfer(to, value);
    }
    
    return super.transferFrom(from, to, value);
}
```

## Proof of Concept
```solidity
// File: test/Exploit_DoubleSelfAllowanceSpending.t.sol
// Run with: forge test --match-test test_DoubleSelfAllowanceSpending -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "../src/ERC20Faucet.sol";

contract Exploit_DoubleSelfAllowanceSpending is Test {
    WERC7575ShareToken shareToken;
    WERC7575Vault vault;
    ERC20Faucet token;
    
    address validator;
    address user;
    address recipient;
    
    function setUp() public {
        validator = makeAddr("validator");
        user = makeAddr("user");
        recipient = makeAddr("recipient");
        
        token = new ERC20Faucet("Test", "TST", 1000000e18);
        shareToken = new WERC7575ShareToken("Share", "SHR");
        vault = new WERC7575Vault(address(token), shareToken);
        
        shareToken.registerVault(address(token), address(vault));
        shareToken.setValidator(validator);
        shareToken.setKycAdmin(validator);
        
        vm.startPrank(validator);
        shareToken.setKycVerified(user, true);
        shareToken.setKycVerified(recipient, true);
        vm.stopPrank();
        
        // Mint shares to user
        vm.prank(address(vault));
        shareToken.mint(user, 1000e18);
    }
    
    function test_DoubleSelfAllowanceSpending() public {
        // SETUP: User gets 100 self-allowance via validator permit
        bytes32 permitHash = keccak256(abi.encodePacked("mock_permit"));
        vm.prank(validator);
        // Simulate permit: validator signs to give user self-allowance of 100e18
        vm.store(address(shareToken), 
                 keccak256(abi.encode(user, keccak256(abi.encode(user, uint256(1))))), 
                 bytes32(uint256(100e18)));
        
        uint256 initialAllowance = shareToken.allowance(user, user);
        assertEq(initialAllowance, 100e18, "Initial self-allowance should be 100");
        
        // EXPLOIT: User calls transferFrom(user, recipient, 50e18) with msg.sender == user
        vm.prank(user);
        shareToken.transferFrom(user, recipient, 50e18);
        
        // VERIFY: Self-allowance consumed TWICE (should be 50e18 remaining, actually 0)
        uint256 remainingAllowance = shareToken.allowance(user, user);
        assertEq(remainingAllowance, 0, "Vulnerability confirmed: allowance consumed twice");
        
        // Expected: 50e18 remaining after single 50e18 transfer
        // Actual: 0 remaining (100 - 50 - 50 = 0)
        
        // User cannot make a second transfer despite expecting 50e18 remaining
        vm.prank(user);
        vm.expectRevert(); // Reverts due to insufficient allowance
        shareToken.transferFrom(user, recipient, 50e18);
    }
}
```

## Notes

This vulnerability is distinct from the documented "TransferFrom Requires Dual Allowances" known issue. The KNOWN_ISSUES documentation describes the intended dual-authorization model where self-allowance AND caller allowance are BOTH required, implying these are separate allowances. However, when `msg.sender == from`, the implementation incorrectly treats them as the same allowance and spends it twice, which is not the documented behavior.

The intended use pattern appears to be:
- `transfer()`: When user is moving their own tokens (`msg.sender == from`)  
- `transferFrom()`: When third party is moving someone else's tokens (`msg.sender != from`)

However, nothing in the code enforces this distinction, and users calling `transferFrom()` on themselves face unexpected double allowance consumption. This is particularly problematic in an institutional setting where validator signatures are a controlled, compliance-critical resource.

### Citations

**File:** src/WERC7575ShareToken.sol (L488-492)
```text
    function transferFrom(address from, address to, uint256 value) public override whenNotPaused returns (bool) {
        if (!isKycVerified[to]) revert KycRequired();
        _spendAllowance(from, from, value);
        return super.transferFrom(from, to, value);
    }
```

**File:** KNOWN_ISSUES.md (L104-116)
```markdown
### TransferFrom Requires Dual Allowances
```solidity
function transferFrom(address from, address to, uint256 value) public override {
    _spendAllowance(from, from, value);        // Self-allowance
    super.transferFrom(from, to, value);       // Caller allowance
}
```

**Severity: QA/Low** - Spec deviation

**Why Intentional**: Dual-authorization model (platform permission + owner delegation)

**NOT a Medium**: No assets at risk. Intentional security model.
```
