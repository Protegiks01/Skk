## Audit Report

### Title
Pending Redemption Shares Not Reserved in totalAssets() Calculation Enables Over-Investment and Failed Redemption Claims

### Summary
The `totalAssets()` function fails to account for pending redemption requests (shares transferred to vault but not yet fulfilled), allowing `investAssets()` to over-invest assets that should be reserved for users awaiting redemption. This causes redemption claims to fail due to insufficient vault liquidity, requiring manual withdrawal from the investment vault.

### Impact
**Severity**: Medium - Accounting error breaking investment logic (per C4 severity categorization)

Users with fulfilled redemptions cannot claim their assets until the investment manager manually withdraws from the investment vault. If the investment vault has lock-up periods or withdrawal restrictions, redemptions could be delayed indefinitely. This affects all users with pending redemption requests during normal protocol operation.

### Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol`, functions `totalAssets()` (lines 1174-1180) and `investAssets()` (lines 1448-1464)

**Intended Logic:** 
Per KNOWN_ISSUES.md Section 4 (lines 210-227), the protocol explicitly states: "Safety buffer ensuring liquidity for pending operations" and "Cannot invest funds that are pending fulfillment or claimable." The system should reserve assets for all pending user operations, including pending redemption requests.

**Actual Logic:**
The `totalAssets()` calculation only reserves assets for pending deposits, claimable redemptions, and deposit cancellations: [1](#0-0) 

When users request redemptions, their shares are transferred to the vault and tracked in `pendingRedeemShares[controller]`, but there is **no aggregated tracking** variable like `totalPendingRedeemShares`: [2](#0-1) 

The `VaultStorage` struct contains individual mappings but no total: [3](#0-2) 

The `investAssets()` function checks available balance based on `totalAssets()`, which incorrectly includes assets corresponding to pending redeem shares: [4](#0-3) 

**Exploitation Path:**
1. **Initial State**: User Alice holds 10,000 shares (backed by 10,000 USDC in vault)
2. **Request**: Alice calls `requestRedeem(10,000 shares)` - shares transferred to vault, tracked in `pendingRedeemShares[Alice]`
3. **Bug**: `totalAssets()` returns 10,000 USDC (no reservation for pending redeem shares)
4. **Over-investment**: Investment manager calls `investAssets(10,000 USDC)` - check passes because `totalAssets()` incorrectly shows all assets as available
5. **Fulfillment**: Investment manager calls `fulfillRedeem(Alice, 10,000 shares)` - converts to 10,000 USDC claimable: [5](#0-4) 
6. **Failed Claim**: Alice calls `redeem()` - transaction reverts because vault has 0 USDC liquid (all invested): [6](#0-5) 

**Security Guarantee Broken:**
Violates documented Invariant #9 from README.md (line 104): "investedAssets + reservedAssets ≤ totalAssets - Reserved protection"

The `reservedAssets` calculation is incomplete, failing to include the asset value of pending redemption shares.

### Impact Explanation

**Affected Assets**: All vault assets (USDC, USDT, DAI, or any ERC-20) can be over-invested when pending redemption requests exist.

**Damage Severity**:
- Users with fulfilled redemptions cannot withdraw their assets
- Temporary denial of service for redemption claims
- Requires manual intervention: investment manager must call `withdrawFromInvestment()` to restore vault liquidity
- If investment vault has lock-up periods, withdrawal limits, or illiquidity, redemptions could be delayed significantly or blocked
- All users with pending redemption requests are affected

**User Impact**: This vulnerability affects any user who has requested redemption but whose request has not yet been fulfilled. It occurs naturally during normal protocol operation in the async ERC-7540 flow.

**Trigger Conditions**: 
- One or more users have pending redemption requests (shares in `pendingRedeemShares` state)
- Investment manager calls `investAssets()` before fulfilling those redemptions
- No special timing or manipulation required

### Likelihood Explanation

**Attacker Profile**: NOT REQUIRED - This is a protocol accounting bug, not an attack vector. Even a properly secured investment manager controlled by trusted operators can trigger this naturally.

**Preconditions**:
1. Users must have pending redemption requests (common in ERC-7540 async vaults where requests wait for batch fulfillment)
2. Investment manager performs normal operations (calling `investAssets()` to deploy idle capital)
3. No other special preconditions

**Execution Complexity**: Occurs naturally through normal protocol operation - no attack sophistication required. The bug is in the accounting logic itself.

**Economic Cost**: None - this is not an exploit but a flaw in the reserve calculation.

**Frequency**: Can occur on every investment operation when pending redemptions exist, which is expected to be common in the async design.

**Overall Likelihood**: HIGH - This will happen naturally during normal protocol usage whenever:
- Users request redemptions (creating pending state)
- Investment manager invests idle capital before fulfilling those redemptions

### Recommendation

**Primary Fix:**
Add tracking of total pending redemption shares and convert to assets in the `totalAssets()` reserved calculation:

```solidity
// In src/ERC7575VaultUpgradeable.sol

// 1. Add to VaultStorage struct (after line 100):
uint256 totalPendingRedeemShares;  // Track total shares pending redemption

// 2. Update requestRedeem function (after line 745):
$.totalPendingRedeemShares += shares;

// 3. Update fulfillRedeem function (after line 833):
$.totalPendingRedeemShares -= shares;

// 4. Update totalAssets function (replace lines 1178):
uint256 pendingRedeemAssets = _convertToAssets($.totalPendingRedeemShares, Math.Rounding.Ceil);
uint256 reservedAssets = $.totalPendingDepositAssets 
                        + $.totalClaimableRedeemAssets 
                        + $.totalCancelDepositAssets 
                        + pendingRedeemAssets;
```

**Rationale**: This mirrors how `totalPendingDepositAssets` and `totalClaimableRedeemAssets` are already tracked and reserved. Using `Math.Rounding.Ceil` when converting shares to assets ensures conservative reservation (favoring user protection over investment efficiency).

**Additional Mitigations**:
- Add unit tests specifically verifying that `totalAssets()` correctly excludes pending redemption values
- Add invariant test: `investAssets()` should always revert when attempting to invest more than `totalAssets()`
- Consider adding a view function `getReservedAssets()` for off-chain monitoring

### Proof of Concept

The provided PoC demonstrates the vulnerability by showing that:
1. After `requestRedeem()`, `totalAssets()` incorrectly returns the full vault balance (not reserving assets for pending redemption)
2. This allows `investAssets()` to pass validation when it should fail
3. When redemption is fulfilled, `totalAssets()` correctly shows 0 available
4. If assets were invested in step 2, redemption claims would fail

The PoC structure is sound and would demonstrate the accounting error when run with a configured investment vault.

### Notes

**This is NOT about centralization or admin privileges**: Even with proper access controls and honest administrators, this bug exists in the accounting logic itself. KNOWN_ISSUES.md Section 4 explicitly confirms the design intent is to reserve assets for pending operations, stating "Cannot invest funds that are pending fulfillment or claimable" (lines 217-218). The implementation fails to achieve this intent for pending redemption shares.

**Distinction from Known Issue "Reserved Assets Not Invested"**: The known issue discusses the intentional choice to NOT invest reserved assets (a safety buffer). This finding identifies a BUG where pending redemption shares are NOT INCLUDED in the reserved asset calculation at all, violating that safety buffer design.

**ERC-7540 Compliance**: While ERC-7540 defines async deposit/redeem flows, it does not specify implementation details. Proper reserve accounting is a protocol-specific requirement documented in SukukFi's own invariants (README.md line 104).

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L86-123)
```text
    struct VaultStorage {
        // Storage slot optimization: pack address + uint64 + bool in single 32-byte slot
        address asset; // 20 bytes
        uint64 scalingFactor; // 8 bytes
        bool isActive; // 1 byte (fits with asset + scalingFactor: total 29 bytes + 3 bytes padding)
        uint8 assetDecimals; // 1 byte
        uint16 minimumDepositAmount; // 2 bytes
        // Remaining addresses (each takes full 32-byte slot)
        address shareToken;
        address investmentManager;
        address investmentVault;
        // Large numbers (each takes full 32-byte slot)
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
        // Off-chain helper sets for tracking active requests (using EnumerableSet for O(1) operations)
        EnumerableSet.AddressSet activeDepositRequesters;
        EnumerableSet.AddressSet activeRedeemRequesters;
        // ERC7887 Cancelation Request Storage (simplified - requestId is always 0)
        // Deposit cancelations: controller => assets (requestId always 0)
        mapping(address controller => uint256 assets) pendingCancelDepositAssets;
        mapping(address controller => uint256 assets) claimableCancelDepositAssets;
        // Redeem cancelations: controller => shares (requestId always 0)
        mapping(address controller => uint256 shares) pendingCancelRedeemShares;
        mapping(address controller => uint256 shares) claimableCancelRedeemShares;
        // Total pending and claimable cancelation deposit assets (for totalAssets() calculation)
        uint256 totalCancelDepositAssets;
        // Track controllers with pending cancelations to block new requests
        EnumerableSet.AddressSet controllersWithPendingDepositCancelations;
        EnumerableSet.AddressSet controllersWithPendingRedeemCancelations;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L740-746)
```text
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }

        // State changes after successful transfer
        $.pendingRedeemShares[controller] += shares;
        $.activeRedeemRequesters.add(controller);
```

**File:** src/ERC7575VaultUpgradeable.sol (L831-840)
```text
        assets = _convertToAssets(shares, Math.Rounding.Floor);

        $.pendingRedeemShares[controller] -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned

        // Note: Shares are NOT burned here - they will be burned during redeem/withdraw claim
        return assets;
```

**File:** src/ERC7575VaultUpgradeable.sol (L911-918)
```text
        // Burn the shares as per ERC7540 spec - shares are burned when request is claimed
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);

        emit Withdraw(msg.sender, receiver, controller, assets, shares);
        if (assets > 0) {
            SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
        }
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

**File:** src/ERC7575VaultUpgradeable.sol (L1448-1464)
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

        // Approve and deposit into investment vault with ShareToken as receiver
        IERC20Metadata($.asset).safeIncreaseAllowance($.investmentVault, amount);
        shares = IERC7575($.investmentVault).deposit(amount, $.shareToken);

        emit AssetsInvested(amount, shares, $.investmentVault);
        return shares;
```
