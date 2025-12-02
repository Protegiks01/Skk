## Title
KYC Revocation Creates Permanent Fund Lock - Users Cannot Redeem Shares After KYC Removal

## Summary
When the KYC Admin revokes a user's KYC status, the user can still transfer shares to KYC-verified recipients but cannot redeem or withdraw their shares from the WERC7575Vault. This asymmetric enforcement creates a permanent fund lock if KYC is never reinstated, violating users' ability to exit the protocol.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` (lines 376-382, 472-477) and `src/WERC7575Vault.sol` (line 408)

**Intended Logic:** The KYC system should prevent non-KYC'd addresses from holding or transferring shares. When KYC is revoked, users should either: (1) have their shares frozen completely, or (2) be allowed to exit their positions by redeeming to receive underlying assets.

**Actual Logic:** The KYC enforcement is asymmetric:
- The `transfer()` function only checks the **recipient's** KYC status [1](#0-0) 
- The `burn()` function checks the **sender's** KYC status [2](#0-1) 
- During vault redemption, `burn(owner, shares)` is called where `owner` is the user's address [3](#0-2) 

**Exploitation Path:**
1. Alice deposits 10,000 USDC into WERC7575Vault and receives 10,000e18 shares (KYC verified)
2. KYC Admin legitimately revokes Alice's KYC status (e.g., compliance issue, expired documentation)
3. Alice can still `transfer()` her shares to Bob (KYC-verified recipient) - transfer succeeds
4. Alice attempts to `redeem()` or `withdraw()` her shares to recover her USDC - transaction reverts with `KycRequired()` because `burn()` checks sender KYC
5. Alice's 10,000 USDC is permanently locked in the vault unless KYC Admin reinstates her verification

**Security Property Broken:** 
- Violates **Invariant #5 (KYC Gating)** asymmetrically - users can transfer out but cannot redeem
- Violates **Invariant #12 (No Fund Theft)** - users lose access to their own funds through no fault of their own
- Creates an unintended fund lock scenario not documented in KNOWN_ISSUES.md

## Impact Explanation
- **Affected Assets**: All user shares and underlying assets (USDC, USDT, DAI, etc.) in WERC7575Vault
- **Damage Severity**: 100% of user's vault position becomes inaccessible. For institutional users, this could represent millions of dollars
- **User Impact**: Any user whose KYC is revoked (for legitimate compliance reasons like expired documentation, jurisdiction changes, or regulatory updates) loses access to their entire vault position. The only recovery path requires the KYC Admin to reinstate verification, which may never occur due to regulatory constraints.

## Likelihood Explanation
- **Attacker Profile**: No malicious attacker needed - this is a legitimate operational scenario. KYC revocations occur regularly in institutional finance for compliance reasons
- **Preconditions**: 
  - User must have existing shares in vault (common)
  - KYC Admin revokes user's KYC status (legitimate operational action)
- **Execution Complexity**: Single transaction - user attempts normal `redeem()` or `withdraw()` and discovers funds are locked
- **Frequency**: Occurs on every redemption attempt by any user with revoked KYC status

## Recommendation
Modify the `burn()` function to allow burning from non-KYC'd addresses when called by registered vaults, since the vault's redemption flow is the legitimate exit path for users: [2](#0-1) 

**Recommended Fix:**
```solidity
// In src/WERC7575ShareToken.sol, function burn, line 376-382:

// CURRENT (vulnerable):
function burn(address from, uint256 amount) external onlyVaults whenNotPaused {
    if (from == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    if (!isKycVerified[from]) revert KycRequired();
    _burn(from, amount);
}

// FIXED:
function burn(address from, uint256 amount) external onlyVaults whenNotPaused {
    if (from == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    // Remove KYC check on burn - vaults handle the redemption flow
    // Users with revoked KYC can exit by redeeming to underlying assets
    // but still cannot receive new shares (mint() enforces KYC on recipient)
    _burn(from, amount);
}
```

**Alternative Fix (if stricter KYC is required):**
If the protocol requires that non-KYC'd users cannot participate at all, then the `transfer()` function should also check the sender's KYC status to prevent an asymmetric trap:

```solidity
// In src/WERC7575ShareToken.sol, function transfer, line 472-477:

// CURRENT (asymmetric):
function transfer(address to, uint256 value) public override whenNotPaused returns (bool) {
    address from = msg.sender;
    if (!isKycVerified[to]) revert KycRequired();
    _spendAllowance(from, from, value);
    return super.transfer(to, value);
}

// FIXED (symmetric enforcement):
function transfer(address to, uint256 value) public override whenNotPaused returns (bool) {
    address from = msg.sender;
    if (!isKycVerified[from]) revert KycRequired(); // Check sender KYC
    if (!isKycVerified[to]) revert KycRequired();   // Check recipient KYC
    _spendAllowance(from, from, value);
    return super.transfer(to, value);
}
```

## Proof of Concept
```solidity
// File: test/Exploit_KycRevocationFundLock.t.sol
// Run with: forge test --match-test test_KycRevocationLocksUserFunds -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "./MockAsset.sol";

contract Exploit_KycRevocationFundLock is Test {
    WERC7575ShareToken public shareToken;
    WERC7575Vault public vault;
    MockAsset public asset;
    
    address owner = address(1);
    address alice = address(2);
    address bob = address(3);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy mock USDC (6 decimals)
        asset = new MockAsset();
        asset.mint(alice, 10_000e18);
        asset.mint(bob, 10_000e18);
        
        // Deploy share token and vault
        shareToken = new WERC7575ShareToken("Share Token", "SHARE");
        vault = new WERC7575Vault(address(asset), shareToken);
        
        // Setup roles and register vault
        shareToken.setValidator(owner);
        shareToken.setKycAdmin(owner);
        shareToken.registerVault(address(asset), address(vault));
        
        // KYC verify Alice and Bob
        shareToken.setKycVerified(alice, true);
        shareToken.setKycVerified(bob, true);
        
        vm.stopPrank();
        
        // Alice approves and deposits
        vm.startPrank(alice);
        asset.approve(address(vault), 10_000e18);
        uint256 shares = vault.deposit(10_000e18, alice);
        
        // Verify Alice received shares
        assertEq(shareToken.balanceOf(alice), shares);
        console.log("Alice deposited 10,000 USDC and received", shares, "shares");
        vm.stopPrank();
    }
    
    function test_KycRevocationLocksUserFunds() public {
        // SETUP: Alice has 10,000 shares, fully KYC'd
        uint256 aliceShares = shareToken.balanceOf(alice);
        assertGt(aliceShares, 0, "Alice should have shares");
        assertTrue(shareToken.isKycVerified(alice), "Alice should be KYC verified");
        
        // STEP 1: KYC Admin revokes Alice's KYC (legitimate compliance action)
        vm.prank(owner);
        shareToken.setKycVerified(alice, false);
        console.log("\n[KYC REVOKED] Alice's KYC status revoked by admin");
        
        // STEP 2: Alice can still TRANSFER shares to KYC-verified Bob (asymmetric behavior)
        vm.prank(owner);
        shareToken.permit(alice, alice, 1000e18, block.timestamp + 1 hours, 0, "", "");
        
        vm.prank(alice);
        shareToken.transfer(bob, 1000e18);
        console.log("[TRANSFER SUCCESS] Alice transferred 1000 shares to Bob despite revoked KYC");
        assertEq(shareToken.balanceOf(bob), 1000e18, "Bob should receive shares");
        
        // STEP 3: Alice attempts to REDEEM remaining shares - this should fail
        vm.prank(owner);
        shareToken.permit(alice, alice, aliceShares - 1000e18, block.timestamp + 1 hours, 0, "", "");
        
        vm.prank(alice);
        vm.expectRevert(); // Should revert with KycRequired
        vault.redeem(aliceShares - 1000e18, alice, alice);
        console.log("[REDEMPTION BLOCKED] Alice cannot redeem shares - funds permanently locked");
        
        // STEP 4: Alice also cannot WITHDRAW
        vm.prank(alice);
        vm.expectRevert(); // Should revert with KycRequired
        vault.withdraw(9_000e18, alice, alice);
        console.log("[WITHDRAWAL BLOCKED] Alice cannot withdraw assets - funds permanently locked");
        
        // VERIFY: Alice's funds are locked unless KYC is reinstated
        uint256 lockedShares = shareToken.balanceOf(alice);
        uint256 lockedAssets = vault.convertToAssets(lockedShares);
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("Alice's locked shares:", lockedShares);
        console.log("Alice's locked assets:", lockedAssets);
        console.log("Alice can transfer but cannot exit vault - PERMANENT FUND LOCK");
        
        assertGt(lockedShares, 0, "Alice has locked shares");
        assertGt(lockedAssets, 0, "Alice has locked assets");
        assertFalse(shareToken.isKycVerified(alice), "Alice's KYC remains revoked");
    }
}
```

## Notes
- This vulnerability exists specifically in `WERC7575ShareToken` (Settlement Layer) used by `WERC7575Vault` (synchronous vault)
- The `ShareTokenUpgradeable` (Investment Layer) does NOT have KYC checks and is not affected
- The issue is not mentioned in `KNOWN_ISSUES.md` and represents a genuine operational risk for institutional users
- The recommended fix depends on protocol intent: either allow burns from non-KYC'd users (enabling exit), or enforce sender KYC on transfers (symmetric freezing)

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

**File:** src/WERC7575Vault.sol (L407-408)
```text
        _shareToken.spendSelfAllowance(owner, shares);
        _shareToken.burn(owner, shares);
```
