# Audit Report

## Title
Missing Global Accounting for Claimable Deposit Assets Allows Over-Investment and Redemption Failures

## Summary
The `totalAssets()` function in `ERC7575VaultUpgradeable` does not account for assets that have been fulfilled for deposit but not yet claimed by users. This missing global counter allows the Investment Manager to inadvertently over-invest these assets, causing redemption claims to fail when users attempt to withdraw.

## Impact
**Severity**: High

Users experience temporary but complete inability to redeem their shares due to vault insolvency. When deposits are fulfilled but not immediately claimed, those assets become invisible to the reserve calculation, allowing investment of funds that should remain liquid. This directly violates Invariant #9 ("investedAssets + reservedAssets ≤ totalAssets") and causes user fund freezing until the Investment Manager manually withdraws from investments.

## Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol`, lines 1174-1180, function `totalAssets()` [1](#0-0) 

**Intended Logic:**
According to KNOWN_ISSUES.md line 217, "Cannot invest funds that are pending fulfillment or claimable (they're not yet/already owned by users)". Reserved assets should include ALL assets involved in incomplete async operations to prevent over-investment.

**Actual Logic:**
The `totalAssets()` function only subtracts three reserved asset categories: `totalPendingDepositAssets`, `totalClaimableRedeemAssets`, and `totalCancelDepositAssets`. When `fulfillDeposit()` is called, assets transition from globally-tracked pending to per-user claimable storage with NO global counter updated. [2](#0-1) 

The VaultStorage struct confirms no `totalClaimableDepositAssets` field exists, only per-user `claimableDepositAssets` mapping.

**Exploitation Path:**

1. **Initial State**: Vault has 10,000 USDC backing existing shares, all invested.

2. **User Deposits**: Alice calls `requestDeposit(5,000 USDC)`. Vault balance: 5,000 USDC liquid. `totalPendingDepositAssets = 5,000`. `totalAssets() = 5,000 - 5,000 = 0` ✓

3. **Fulfillment**: Investment Manager calls `fulfillDeposit(Alice, 5,000)`. Code decrements `totalPendingDepositAssets` to 0 and sets `claimableDepositAssets[Alice] = 5,000` with no global counter. [3](#0-2) 

4. **Reserve Gap**: `totalAssets() = 5,000 - 0 = 5,000` (should be 0). The 5,000 USDC appears available for investment.

5. **Over-Investment**: Manager calls `investAssets(5,000)`, which checks `totalAssets() = 5,000` and allows transfer. Vault balance: 0 USDC. [4](#0-3) 

6. **Alice Claims Deposit**: Alice calls `deposit(5,000, Alice, Alice)` and receives shares (succeeds—shares were pre-minted). [5](#0-4) 

7. **Alice Requests Redemption**: Alice's shares transferred to vault. Manager fulfills redemption, setting `totalClaimableRedeemAssets = 5,000`. [6](#0-5) 

8. **Redemption Failure**: Alice calls `redeem()`. Function attempts `SafeTokenTransfers.safeTransfer($.asset, receiver, 5000)` but vault has 0 USDC—transaction reverts. [7](#0-6) 

**Security Guarantee Broken:**
- README Invariant #9: "investedAssets + reservedAssets ≤ totalAssets" - violated when claimable deposit assets excluded from reserves
- README Invariant #12: "No fund theft - no double-claims, no reentrancy, no bypass" - users cannot access rightfully owed funds

## Impact Explanation

**Affected Assets**: All vaults (USDC, USDT, DAI, etc.) where deposits are fulfilled faster than users claim them.

**Damage Severity**:
- Complete temporary loss of redemption access for affected users
- Vault becomes technically insolvent for redemptions (assets exist but are invested)
- Multi-user scenarios compound the issue—subsequent deposits/redemptions worsen the gap
- Duration depends on Investment Manager's withdrawal timing and investment vault liquidity

**User Impact**: Any user following normal async flow (deposit → fulfill → claim shares → later redeem) will encounter transaction revert on redemption claim. Funds locked until manual intervention.

**Trigger Conditions**: Fulfilled but unclaimed deposits + Investment Manager investing based on `totalAssets()` availability.

## Likelihood Explanation

**Attacker Profile**: No attacker required—this is an accounting logic error in normal protocol operation.

**Preconditions**:
1. Users have fulfilled but unclaimed deposits (normal in async vault systems with non-instant claims)
2. Investment Manager calls `investAssets()` relying on `totalAssets()` accuracy
3. Users later request redemptions

**Execution Complexity**: Trivial—occurs during standard vault operations without special timing or manipulation.

**Economic Cost**: None—happens naturally as users interact with the protocol.

**Frequency**: Can occur continuously whenever fulfilled deposits exist before investment operations.

**Overall Likelihood**: HIGH—Natural protocol flow triggers this condition regularly.

## Recommendation

**Primary Fix:**
Add global tracking for claimable deposit assets:

```solidity
// In VaultStorage struct (line ~100), add:
uint256 totalClaimableDepositAssets;

// In fulfillDeposit() (line ~439), add:
$.totalClaimableDepositAssets += assets;

// In deposit() claim functions (lines ~574-580), add:
$.totalClaimableDepositAssets -= assets;

// In totalAssets() (line 1178), modify:
uint256 reservedAssets = $.totalPendingDepositAssets 
                       + $.totalClaimableRedeemAssets 
                       + $.totalCancelDepositAssets
                       + $.totalClaimableDepositAssets; // NEW
```

**Additional Mitigations**:
- Add unit tests verifying reserve calculation with fulfilled-but-unclaimed deposits
- Add require check: `investAssets()` should validate total invested + reserved ≤ actual balance
- Consider adding view function `getReservedAssets()` for transparency

## Notes

This vulnerability is explicitly acknowledged in KNOWN_ISSUES.md lines 656-657 as an example of a valid HIGH severity finding: "Reserved asset calculation adds shares to assets without conversion → NEW bug. Accounting error. Can cause over-investment. **HIGH**"

The documentation at KNOWN_ISSUES.md line 217 confirms the intended behavior: "Cannot invest funds that are pending fulfillment or claimable (they're not yet/already owned by users)". The current implementation violates this documented design by allowing investment of claimable deposit assets.

The `_calculateReservedAssets()` function referenced in some documentation does not exist in the deployed code—the calculation is performed inline within `totalAssets()`. The actual impact affects redemption claims (not deposit claims), as deposit claims only transfer pre-minted shares without requiring liquid assets.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L98-107)
```text
        uint256 totalPendingDepositAssets;
        uint256 totalClaimableRedeemAssets; // Assets reserved for users who can claim them
        uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
        // ERC7540 mappings with descriptive names
        mapping(address controller => uint256 assets) pendingDepositAssets;
        mapping(address controller => uint256 shares) claimableDepositShares;
        mapping(address controller => uint256 assets) claimableDepositAssets; // Store corresponding asset amounts
        mapping(address controller => uint256 shares) pendingRedeemShares;
        mapping(address controller => uint256 assets) claimableRedeemAssets;
        mapping(address controller => uint256 shares) claimableRedeemShares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L436-442)
```text
        $.pendingDepositAssets[controller] -= assets;
        $.totalPendingDepositAssets -= assets;
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming

        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);
```

**File:** src/ERC7575VaultUpgradeable.sol (L585-588)
```text
        // Transfer shares from vault to receiver using ShareToken
        if (!IERC20Metadata($.shareToken).transfer(receiver, shares)) {
            revert ShareTransferFailed();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L831-837)
```text
        assets = _convertToAssets(shares, Math.Rounding.Floor);

        $.pendingRedeemShares[controller] -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned
```

**File:** src/ERC7575VaultUpgradeable.sol (L915-917)
```text
        if (assets > 0) {
            SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1174-1180)
```text
    function totalAssets() public view virtual returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        uint256 balance = IERC20Metadata($.asset).balanceOf(address(this));
        // Exclude pending deposits, pending/claimable cancelation deposits, and claimable withdrawals from total assets
        uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;
        return balance > reservedAssets ? balance - reservedAssets : 0;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1448-1457)
```text
    function investAssets(uint256 amount) external nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if ($.investmentVault == address(0)) revert NoInvestmentVault();
        if (amount == 0) revert ZeroAmount();

        uint256 availableBalance = totalAssets();
        if (amount > availableBalance) {
            revert ERC20InsufficientBalance(address(this), availableBalance, amount);
        }
```
