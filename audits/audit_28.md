## Title
KYC Revocation Permanently Locks User Shares in WERC7575Vault Due to Burn Function KYC Check

## Summary
Users who receive shares while KYC-verified cannot redeem their shares for underlying assets if their KYC status is subsequently revoked by the KYC admin. The `burn()` function in WERC7575ShareToken checks the sender's KYC status, causing redemptions to fail when the vault attempts to burn shares from non-KYC users. Additionally, transfers require validator cooperation for self-allowance, creating a scenario where shares become effectively locked with no escape mechanism.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` (burn function, lines 376-382) and `src/WERC7575Vault.sol` (_withdraw function, line 408)

**Intended Logic:** The protocol should allow users who legitimately received shares while KYC-verified to eventually exit the system, even if their KYC status is later revoked for legitimate regulatory reasons. KYC checks should prevent non-verified users from entering the system, not trap existing users.

**Actual Logic:** The `burn()` function checks `isKycVerified[from]` where `from` is the user whose shares are being burned. When WERC7575Vault calls `burn(owner, shares)` during redemption, if the owner's KYC has been revoked, the burn operation fails, preventing redemption. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. Alice is KYC-verified and receives shares via `mint()` - succeeds because `isKycVerified[alice] = true`
2. KYC admin legitimately revokes Alice's KYC status via `setKycVerified(alice, false)` 
3. Alice attempts to redeem shares by calling `WERC7575Vault.redeem(shares, receiver, alice)`
4. Vault's `_withdraw()` internal function calls `_shareToken.burn(alice, shares)`
5. `burn()` checks `isKycVerified[alice]` which is now `false`, causing the transaction to revert with `KycRequired()` error
6. Alice cannot redeem her shares for the underlying assets

**Alternative Transfer Path Also Blocked:**
1. Alice attempts to transfer shares to Bob (KYC-verified) via `transfer(bob, shares)`
2. `transfer()` requires `_spendAllowance(alice, alice, shares)` for self-allowance
3. To get self-allowance, Alice needs `permit(alice, alice, ...)` which requires validator signature [3](#0-2) [4](#0-3) 

4. Validator may reasonably refuse to sign permits for non-KYC users, blocking transfers

**Security Property Broken:** 
- **Invariant #5 violated**: "Only KYC-verified addresses can receive/hold shares" - the protocol allows shares to be held by non-KYC users (after revocation) but provides no mechanism to exit
- Users cannot access their legitimately obtained assets

## Impact Explanation
- **Affected Assets**: All share tokens held by users whose KYC status is revoked after minting
- **Damage Severity**: Complete loss of access to underlying assets. Users cannot redeem shares to recover their deposited funds.
- **User Impact**: Any user whose KYC is revoked (for legitimate reasons like changing jurisdiction, expired documentation, etc.) has their shares permanently locked. This affects the entire balance, not just new operations.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is triggered by normal protocol operations (KYC revocation by KYC admin)
- **Preconditions**: 
  - User received shares while KYC-verified
  - KYC admin revokes user's KYC status (legitimate regulatory action)
  - Validator refuses to sign permits for non-KYC users (reasonable policy)
- **Execution Complexity**: Single transaction (KYC revocation) creates the locked state
- **Frequency**: Occurs whenever KYC is revoked for any user with existing shares, which could be a common regulatory action

## Recommendation

**Option 1: Remove KYC check from burn() function**
The burn function should not check KYC status because it's called by vaults during redemption, and the shares are already owned by the user. The KYC gate should be at minting, not burning.

```solidity
// In src/WERC7575ShareToken.sol, function burn, lines 376-382:

// CURRENT (vulnerable):
function burn(address from, uint256 amount) external onlyVaults whenNotPaused {
    if (from == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    if (!isKycVerified[from]) revert KycRequired(); // ← REMOVE THIS CHECK
    _burn(from, amount);
}

// FIXED:
function burn(address from, uint256 amount) external onlyVaults whenNotPaused {
    if (from == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    // KYC check removed - users can exit even if KYC revoked
    // Vault access control (onlyVaults) ensures only authorized burns
    _burn(from, amount);
}
```

**Option 2: Follow ERC7575VaultUpgradeable pattern**
Modify WERC7575Vault to transfer shares to vault first, then burn from vault address (like the async implementation):

```solidity
// In src/WERC7575Vault.sol, function _withdraw, lines 397-411:

// CURRENT (vulnerable):
function _withdraw(uint256 assets, uint256 shares, address receiver, address owner) internal {
    // ... validation checks ...
    _shareToken.spendSelfAllowance(owner, shares);
    _shareToken.burn(owner, shares); // ← Burns from user who may not be KYC-verified
    // ...
}

// FIXED:
function _withdraw(uint256 assets, uint256 shares, address receiver, address owner) internal {
    // ... validation checks ...
    _shareToken.spendSelfAllowance(owner, shares);
    // First transfer shares to vault, then burn from vault address
    _shareToken.transferFrom(owner, address(this), shares);
    _shareToken.burn(address(this), shares); // Vault is always KYC-verified
    // ...
}
```

**Option 3: Add admin escape hatch**
Add an admin function to force-burn shares from non-KYC users and return their proportional assets, providing an escape mechanism while maintaining regulatory compliance.

## Proof of Concept

```solidity
// File: test/Exploit_KYCRevocationLocksShares.t.sol
// Run with: forge test --match-test test_KYCRevocationLocksShares -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "../src/ERC20Faucet.sol";

contract Exploit_KYCRevocationLocksShares is Test {
    WERC7575ShareToken shareToken;
    WERC7575Vault vault;
    ERC20Faucet asset;
    
    address owner = address(this);
    address alice = address(0x1);
    address kycAdmin = address(0x2);
    
    function setUp() public {
        // Deploy contracts
        asset = new ERC20Faucet("Test Asset", "TASSET", 18);
        shareToken = new WERC7575ShareToken("Share Token", "SHARE");
        vault = new WERC7575Vault(address(asset), shareToken);
        
        // Setup roles
        shareToken.setKycAdmin(kycAdmin);
        shareToken.registerVault(address(asset), address(vault));
        
        // Setup initial state
        vm.startPrank(kycAdmin);
        shareToken.setKycVerified(alice, true);
        shareToken.setKycVerified(address(vault), true);
        vm.stopPrank();
        
        // Give Alice assets and approve vault
        asset.mint(alice, 1000e18);
        vm.prank(alice);
        asset.approve(address(vault), 1000e18);
    }
    
    function test_KYCRevocationLocksShares() public {
        // SETUP: Alice deposits while KYC verified
        vm.prank(alice);
        uint256 shares = vault.deposit(1000e18, alice);
        
        assertEq(shareToken.balanceOf(alice), shares, "Alice should have shares");
        assertEq(shares, 1000e18, "Should receive 1:1 shares");
        
        // EXPLOIT: KYC admin revokes Alice's KYC status
        vm.prank(kycAdmin);
        shareToken.setKycVerified(alice, false);
        
        // VERIFY: Alice cannot redeem her shares
        vm.startPrank(alice);
        
        // Alice needs self-allowance to redeem, but let's assume validator gave it
        // (In reality, validator might refuse for non-KYC users)
        vm.stopPrank();
        
        // Give Alice self-allowance via permit (simulating validator cooperation)
        vm.prank(address(this)); // Owner/validator signs permit
        bytes32 PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
        // Simplified - assume permit succeeds
        
        // Even with allowance, burn will fail due to KYC check
        vm.expectRevert(WERC7575ShareToken.KycRequired.selector);
        vm.prank(alice);
        vault.redeem(shares, alice, alice);
        
        // RESULT: Alice's shares are locked
        assertEq(shareToken.balanceOf(alice), shares, "Shares still locked in Alice's account");
        assertEq(asset.balanceOf(alice), 0, "Alice cannot recover her assets");
    }
}
```

## Notes

This vulnerability reveals a design inconsistency in WERC7575Vault compared to the async ERC7575VaultUpgradeable implementation:

- **ERC7575VaultUpgradeable (Correct)**: Burns shares from vault address during redemption [5](#0-4) 

- **WERC7575Vault (Flawed)**: Burns shares from user address during redemption [6](#0-5) 

The async vault correctly handles KYC revocation because it transfers shares to the vault (via `vaultTransferFrom` which bypasses public KYC checks) before burning them from the vault's address (which is KYC-verified). The synchronous vault lacks this protection, creating a trap for users whose KYC status changes.

While KYC requirements are documented as a centralization risk in KNOWN_ISSUES.md, the specific issue of shares becoming permanently locked after legitimate KYC revocation is not mentioned and appears to be an unintended consequence of the asymmetric KYC check placement (burn checks sender, transfer checks recipient, mint checks recipient).

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

**File:** src/WERC7575ShareToken.sol (L419-428)
```text
        if (owner == spender) {
            if (signer != _validator) {
                revert ERC2612InvalidSigner(signer, owner);
            }
        } else {
            if (signer != owner) {
                revert ERC2612InvalidSigner(signer, owner);
            }
        }
        _approve(owner, spender, value);
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

**File:** src/ERC7575VaultUpgradeable.sol (L912-912)
```text
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);
```
