## Audit Report

### Title
Missing Total Claimable Deposit Assets Tracking Allows Over-Investment of Reserved Assets

### Summary
The `ERC7575VaultUpgradeable` contract lacks a `totalClaimableDepositAssets` state variable to track assets reserved for fulfilled but unclaimed deposits. This asymmetric accounting causes `totalAssets()` to incorrectly include these reserved assets as "available," allowing `investAssets()` to invest funds that must remain liquid for user claims, violating the Reserved Asset Protection invariant and contradicting documented design principles.

### Impact
**Severity**: High - Direct violation of core invariant causing systematic liquidity risk

The protocol can become insolvent when reserved assets are prematurely invested. When fulfilled deposits exist but haven't been claimed, the Investment Manager can unknowingly invest those reserved assets because `totalAssets()` incorrectly reports them as available. This creates a liquidity mismatch where the vault cannot honor redemption requests without first withdrawing from potentially illiquid investment positions, affecting all users and violating Invariant #9: "investedAssets + reservedAssets ≤ totalAssets."

### Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol`

**Intended Logic:** 
Per KNOWN_ISSUES.md line 217: "Cannot invest funds that are pending fulfillment or claimable (they're not yet/already owned by users)." The vault should track all categories of reserved assets and exclude them from `totalAssets()` calculations. The async deposit flow should maintain: Pending (excluded) → Claimable (excluded) → Claimed (included).

**Actual Logic:**
The storage struct tracks `totalClaimableRedeemAssets` for redeems but has NO equivalent `totalClaimableDepositAssets` for deposits: [1](#0-0) 

When `fulfillDeposit()` is called, assets transition from globally-tracked pending state to only per-controller claimable state with no global total: [2](#0-1) 

This contrasts with `fulfillRedeem()` which properly increments global totals: [3](#0-2) 

The `totalAssets()` function only excludes `totalPendingDepositAssets`, `totalClaimableRedeemAssets`, and `totalCancelDepositAssets`: [4](#0-3) 

Since `totalClaimableDepositAssets` doesn't exist, these assets are incorrectly included in available balance.

**Exploitation Path:**
1. **User deposits 1000 USDC**: Calls `requestDeposit(1000e6)`, assets transferred to vault, `totalPendingDepositAssets` = 1000, `totalAssets()` = 0 (correct)
2. **Manager fulfills**: Calls `fulfillDeposit(user, 1000e6)`, `totalPendingDepositAssets` = 0, `claimableDepositAssets[user]` = 1000, but `totalAssets()` = 1000 (incorrect - should still be 0)
3. **Manager over-invests**: Calls `investAssets(1000)`, check at line 1454-1456 passes because `totalAssets()` incorrectly reports 1000 as available: [5](#0-4) 

4. **Liquidity crisis**: Vault now has 0 USDC liquid but owes shares worth 1000 USDC. When users try to redeem, vault must first withdraw from investment vault, creating delays or failures if investment is illiquid.

**Security Guarantee Broken:**
README Invariant #9 (line 104): "investedAssets + reservedAssets ≤ totalAssets" - violated because reserved claimable deposit assets are incorrectly counted as part of totalAssets rather than being excluded.

### Impact Explanation

**Affected Assets**: All assets in any vault where deposit fulfillments occur before user claims (normal operation pattern)

**Damage Severity**:
- Investment Manager can invest 100% of claimable deposit assets, believing they're idle capital
- Vault becomes illiquid for redemptions, requiring emergency withdrawal from investment positions
- In worst case (investment vault insolvency/lock-up), results in permanent loss of user funds
- Systematic risk affecting entire vault, not isolated to individual users

**User Impact**: All depositors with fulfilled but unclaimed deposits have their reserved assets at risk. All redeemers face liquidity crisis when trying to claim assets that were prematurely invested.

**Trigger Conditions**: Occurs naturally during normal operations - any time Investment Manager calls `investAssets()` while fulfilled but unclaimed deposits exist.

### Likelihood Explanation

**Attacker Profile**: Not an attack - this is a logic error triggering during normal protocol operations by trusted Investment Manager

**Preconditions**:
1. Any fulfilled but unclaimed deposits exist in vault (normal state)
2. Investment Manager performs yield optimization by calling `investAssets()` (expected behavior)
3. No special timing or market conditions required

**Execution Complexity**: Single transaction in normal course of operations

**Economic Cost**: None - happens as part of expected Investment Manager duties

**Frequency**: Will occur repeatedly as vault operates normally - fulfillments occur, then Investment Manager deploys capital

**Overall Likelihood**: CRITICAL - Not "if" but "when" during normal operations

### Recommendation

**Primary Fix:**

Add `totalClaimableDepositAssets` tracking to match the existing `totalClaimableRedeemAssets` pattern:

1. Add to VaultStorage struct (after line 98):
```solidity
uint256 totalClaimableDepositAssets; // Track globally reserved deposit assets
```

2. Increment in `fulfillDeposit()` (after line 439):
```solidity
$.totalClaimableDepositAssets += assets;
```

3. Increment in `fulfillDeposits()` batch function (after line 476, before line 480):
```solidity
// Inside loop
totalClaimableAssets += assetAmount;
// After loop
$.totalClaimableDepositAssets += totalClaimableAssets;
```

4. Decrement in `deposit()` claim function (after lines 577 and 580):
```solidity
$.totalClaimableDepositAssets -= assets;
```

5. Decrement in `mint()` claim function similarly

6. Update `totalAssets()` calculation (line 1178):
```solidity
uint256 reservedAssets = $.totalPendingDepositAssets 
    + $.totalClaimableDepositAssets  // ADD THIS
    + $.totalClaimableRedeemAssets 
    + $.totalCancelDepositAssets;
```

**Additional Mitigations**:
- Add invariant test: `investAssets` amount must be ≤ `totalAssets() - totalClaimableDepositAssets`
- Add unit tests specifically covering totalAssets() calculation after fulfillment but before claim
- Consider adding view function `getReservedAssets()` for transparency

### Proof of Concept

The provided PoC demonstrates the core issue - after fulfillment, `totalAssets()` incorrectly returns 1000e6 when it should return 0:

```solidity
function test_OverInvestClaimableDeposits() public {
    // User requests deposit
    vault.requestDeposit(1000e6, user, user);
    assertEq(vault.totalAssets(), 0); // Correct - pending excluded
    
    // Investment manager fulfills
    vault.fulfillDeposit(user, 1000e6);
    assertEq(vault.totalAssets(), 1000e6); // BUG - should still be 0!
    
    // This proves Investment Manager can now invest reserved assets
    // because totalAssets() incorrectly reports them as available
}
```

The PoC correctly identifies that `totalAssets()` transitions from 0 (correct) to 1000e6 (incorrect) after fulfillment, when it should remain 0 until the user claims their shares.

---

## Notes

**Asymmetric Tracking Pattern Confirmed**: The codebase demonstrates clear asymmetry - redemptions track `totalClaimableRedeemAssets` globally but deposits do NOT track `totalClaimableDepositAssets`, despite both being reserved assets that should not be invested.

**Design Intent Violated**: KNOWN_ISSUES.md explicitly states reserved assets should not be invested (line 217), but this bug allows exactly that to happen during normal operations.

**Not in KNOWN_ISSUES.md**: This specific accounting bug is not listed as a known issue. In fact, it contradicts the documented design principle that claimable assets should not be invested.

**Severity Justification**: High severity is appropriate because:
1. Violates documented core invariant (#9)
2. Contradicts explicit design principle in KNOWN_ISSUES.md
3. Occurs naturally in normal operations (not requiring attack)
4. Creates systematic liquidity risk affecting all vault users
5. Can result in permanent loss if investment vault becomes insolvent

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L98-104)
```text
        uint256 totalPendingDepositAssets;
        uint256 totalClaimableRedeemAssets; // Assets reserved for users who can claim them
        uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
        // ERC7540 mappings with descriptive names
        mapping(address controller => uint256 assets) pendingDepositAssets;
        mapping(address controller => uint256 shares) claimableDepositShares;
        mapping(address controller => uint256 assets) claimableDepositAssets; // Store corresponding asset amounts
```

**File:** src/ERC7575VaultUpgradeable.sol (L436-439)
```text
        $.pendingDepositAssets[controller] -= assets;
        $.totalPendingDepositAssets -= assets;
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming
```

**File:** src/ERC7575VaultUpgradeable.sol (L833-837)
```text
        $.pendingRedeemShares[controller] -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned
```

**File:** src/ERC7575VaultUpgradeable.sol (L1174-1179)
```text
    function totalAssets() public view virtual returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        uint256 balance = IERC20Metadata($.asset).balanceOf(address(this));
        // Exclude pending deposits, pending/claimable cancelation deposits, and claimable withdrawals from total assets
        uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;
        return balance > reservedAssets ? balance - reservedAssets : 0;
```

**File:** src/ERC7575VaultUpgradeable.sol (L1454-1457)
```text
        uint256 availableBalance = totalAssets();
        if (amount > availableBalance) {
            revert ERC20InsufficientBalance(address(this), availableBalance, amount);
        }
```
