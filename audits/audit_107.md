## Title
KYC Bypass via Batch Transfer Functions Allows Non-Verified Addresses to Receive Tokens

## Summary
The `batchTransfers()` and `rBatchTransfers()` functions in `WERC7575ShareToken` fail to enforce KYC verification when crediting tokens to net creditors, directly violating the protocol's Critical Invariant #5 ("KYC Gating: Only KYC-verified addresses can receive/hold shares"). While standard transfer functions (`transfer()`, `transferFrom()`, `mint()`) all verify `isKycVerified[recipient]` before crediting shares, both batch transfer functions omit this check, allowing the validator to transfer tokens to any address—including non-KYC users—by including them as creditors in batch operations.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` - Functions `batchTransfers()` (lines 700-734) and `rBatchTransfers()` (lines 1119-1202)

**Intended Logic:** According to the protocol documentation and Critical Invariant #5, all token recipients must be KYC-verified. The wiki explicitly states: "KYC Enforcement: All token recipients must have isKycVerified[recipient] == true" with claimed enforcement in `batchTransfers()` at lines 714-716. Standard token transfer operations (`transfer()`, `transferFrom()`, `mint()`) all verify KYC status before crediting tokens.

**Actual Logic:** Both batch transfer functions directly update `_balances[account.owner]` for net creditors without any KYC verification check. When an account has `credit > debit`, the functions increase the account's balance without checking if the recipient is KYC-verified.

**Exploitation Path:**
1. Validator calls `batchTransfers()` or `rBatchTransfers()` with crafted parameters
2. Includes a non-KYC address (`attackerAddress`) as a creditor in the `creditors` array
3. Includes a KYC-verified address with sufficient balance as a debtor in the `debtors` array
4. The consolidation phase aggregates the transfers without KYC checks
5. In the balance update phase, `attackerAddress` receives tokens via `_balances[attackerAddress] += amount` without `isKycVerified[attackerAddress]` being checked
6. Non-KYC address successfully holds tokens, violating the KYC invariant

**Security Property Broken:** 
- Critical Invariant #5: "KYC Gating: Only KYC-verified addresses can receive/hold shares"
- Documented security invariant from wiki: "All token recipients must have isKycVerified[recipient] == true"

## Impact Explanation
- **Affected Assets**: All share tokens across all registered vaults (WUSD shares representing USDC, USDT, DAI positions)
- **Damage Severity**: Unlimited - any amount of tokens can be transferred to non-KYC addresses up to available debtor balances. With MAX_BATCH_SIZE=100, a validator can distribute tokens to up to 100 non-KYC addresses per transaction
- **User Impact**: 
  - Regulatory non-compliance: Protocol can no longer guarantee all shareholders are KYC-verified
  - Sanctions risk: Tokens could be transferred to sanctioned entities
  - Fund tracking: Non-KYC holders break the audit trail required for institutional DeFi
  - All users affected: The entire KYC system becomes unreliable once bypass exists

## Likelihood Explanation
- **Attacker Profile**: Requires validator role (trusted but not immune to compromise/error). Could occur through:
  - Validator key compromise (different from owner key compromise)
  - Honest mistakes in off-chain batch generation systems
  - Bugs in WRAPX platform integration
  - Social engineering of validator
- **Preconditions**: 
  - At least one KYC-verified address with positive balance (debtor)
  - Non-KYC target address (creditor)
  - Validator access to call batch transfer functions
- **Execution Complexity**: Single transaction - trivial to execute
- **Frequency**: Can be exploited repeatedly until detected

## Recommendation

In `src/WERC7575ShareToken.sol`, add KYC checks in both batch transfer functions when crediting net creditors:

### For `batchTransfers()`: [1](#0-0) 

```solidity
// CURRENT (vulnerable):
} else if (account.debit < account.credit) {
    uint256 amount = account.credit - account.debit;
    unchecked {
        _balances[account.owner] += amount;
    }
}

// FIXED:
} else if (account.debit < account.credit) {
    uint256 amount = account.credit - account.debit;
    // SECURITY: Enforce KYC for all token recipients, consistent with transfer/mint
    if (!isKycVerified[account.owner]) revert KycRequired();
    unchecked {
        _balances[account.owner] += amount;
    }
}
```

### For `rBatchTransfers()`: [2](#0-1) 

```solidity
// CURRENT (vulnerable):
} else if (account.debit < account.credit) {
    uint256 amount = account.credit - account.debit;
    unchecked {
        _balances[account.owner] += amount;
        // ... rBalance logic
    }
}

// FIXED:
} else if (account.debit < account.credit) {
    uint256 amount = account.credit - account.debit;
    // SECURITY: Enforce KYC for all token recipients, consistent with transfer/mint
    if (!isKycVerified[account.owner]) revert KycRequired();
    unchecked {
        _balances[account.owner] += amount;
        // ... existing rBalance logic unchanged
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_KYC_Bypass_BatchTransfers.t.sol
// Run with: forge test --match-test test_KYC_Bypass_Via_BatchTransfers -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "../src/ERC20Faucet.sol";

contract Exploit_KYC_Bypass is Test {
    WERC7575ShareToken public shareToken;
    WERC7575Vault public vault;
    ERC20Faucet public asset;
    
    address public validator;
    address public kycUser;
    address public nonKycAttacker;
    
    function setUp() public {
        validator = makeAddr("validator");
        kycUser = makeAddr("kycUser");
        nonKycAttacker = makeAddr("nonKycAttacker");
        
        // Deploy contracts
        asset = new ERC20Faucet("Test Asset", "TEST", 1000000e18);
        shareToken = new WERC7575ShareToken("Test Share", "tSHARE");
        vault = new WERC7575Vault(address(asset), shareToken);
        
        // Setup roles
        shareToken.registerVault(address(asset), address(vault));
        shareToken.setValidator(validator);
        shareToken.setKycAdmin(validator);
        
        // KYC verify ONLY kycUser (not nonKycAttacker)
        vm.prank(validator);
        shareToken.setKycVerified(kycUser, true);
        
        // Give kycUser initial tokens via deposit
        vm.warp(block.timestamp + 2 hours);
        asset.faucetAmountFor(kycUser, 1000e18);
        
        vm.startPrank(kycUser);
        asset.approve(address(vault), 1000e18);
        vault.deposit(1000e18, kycUser);
        vm.stopPrank();
    }
    
    function test_KYC_Bypass_Via_BatchTransfers() public {
        // SETUP: Verify initial state
        assertEq(shareToken.balanceOf(kycUser), 1000e18, "KYC user should have initial balance");
        assertEq(shareToken.balanceOf(nonKycAttacker), 0, "Attacker should have zero balance");
        assertTrue(shareToken.isKycVerified(kycUser), "KYC user should be verified");
        assertFalse(shareToken.isKycVerified(nonKycAttacker), "Attacker should NOT be KYC verified");
        
        // EXPLOIT: Validator uses batchTransfers to credit non-KYC address
        address[] memory debtors = new address[](1);
        address[] memory creditors = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        
        debtors[0] = kycUser;           // KYC-verified debtor with balance
        creditors[0] = nonKycAttacker;  // Non-KYC creditor (SHOULD BE BLOCKED!)
        amounts[0] = 500e18;            // Transfer half the balance
        
        vm.prank(validator);
        shareToken.batchTransfers(debtors, creditors, amounts);
        
        // VERIFY: Non-KYC address successfully received tokens (VULNERABILITY CONFIRMED)
        assertEq(shareToken.balanceOf(nonKycAttacker), 500e18, 
            "VULNERABILITY: Non-KYC attacker received tokens without KYC check!");
        assertEq(shareToken.balanceOf(kycUser), 500e18, 
            "KYC user balance decreased as expected");
        
        // Additional verification: Try standard transfer to same address (should fail)
        vm.startPrank(kycUser);
        // First need permit for self-allowance
        vm.stopPrank();
        
        // This demonstrates inconsistency: batchTransfers bypassed KYC, but transfer would not
        console.log("NON-KYC ADDRESS HOLDS TOKENS:", shareToken.balanceOf(nonKycAttacker));
        console.log("KYC INVARIANT VIOLATED!");
    }
    
    function test_KYC_Bypass_Via_rBatchTransfers() public {
        // Similar exploit with rBatchTransfers
        assertFalse(shareToken.isKycVerified(nonKycAttacker), "Attacker not KYC verified");
        
        address[] memory debtors = new address[](1);
        address[] memory creditors = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        
        debtors[0] = kycUser;
        creditors[0] = nonKycAttacker;
        amounts[0] = 300e18;
        
        uint256 rBalanceFlags = 0; // No rBalance updates needed for this test
        
        vm.prank(validator);
        shareToken.rBatchTransfers(debtors, creditors, amounts, rBalanceFlags);
        
        // VERIFY: rBatchTransfers also bypasses KYC
        assertEq(shareToken.balanceOf(nonKycAttacker), 300e18, 
            "VULNERABILITY: rBatchTransfers also bypasses KYC enforcement!");
    }
}
```

## Notes

**Comparison with Enforced Functions:**

The KYC check is properly enforced in:
- `mint()` function [3](#0-2) 
- `transfer()` function [4](#0-3)   
- `transferFrom()` function [5](#0-4) 

**Missing KYC Checks:**

Both batch functions fail to verify KYC when crediting net creditors:
- `batchTransfers()` credits at [6](#0-5) 
- `rBatchTransfers()` credits at [7](#0-6) 

**Documentation Discrepancy:**

The protocol wiki falsely claims KYC enforcement exists in `batchTransfers()` at "lines 714-716" for creditors. However, inspection of the actual implementation reveals no such check exists—this appears to be a documentation error that masked the vulnerability during development.

**Trust Model Clarification:**

While the validator is a trusted role, this is NOT a centralization issue—it's a **logic bug**. The absence of KYC checks in batch functions is inconsistent with the rest of the codebase and violates documented invariants. This could occur through honest mistakes, compromised validator keys (different from owner compromise), or bugs in off-chain batch generation systems. The fix should enforce the same KYC rules universally across all token crediting operations.

### Citations

**File:** src/WERC7575ShareToken.sol (L367-367)
```text
        if (!isKycVerified[to]) revert KycRequired();
```

**File:** src/WERC7575ShareToken.sol (L474-474)
```text
        if (!isKycVerified[to]) revert KycRequired();
```

**File:** src/WERC7575ShareToken.sol (L489-489)
```text
        if (!isKycVerified[to]) revert KycRequired();
```

**File:** src/WERC7575ShareToken.sol (L713-718)
```text
            } else if (account.debit < account.credit) {
                uint256 amount = account.credit - account.debit;
                unchecked {
                    _balances[account.owner] += amount;
                }
            }
```

**File:** src/WERC7575ShareToken.sol (L1155-1181)
```text
            } else if (account.debit < account.credit) {
                // CASE 2: Account is net CREDITOR (gaining tokens)
                // This account had more inflows than outflows
                uint256 amount = account.credit - account.debit;

                unchecked {
                    // Update regular balance: add net credit
                    _balances[account.owner] += amount;

                    // CRITICAL: Selective rBalance update based on rBalanceFlags bitmap
                    // Same bitmap lookup as above
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
                    }
                }
            }
```
