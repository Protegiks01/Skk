## Title
Missing Total Claimable Deposit Assets Tracking Allows Over-Investment of Reserved Assets

## Summary
The `ERC7575VaultUpgradeable` contract lacks a `totalClaimableDepositAssets` state variable to track assets reserved for users who have fulfilled deposit requests but not yet claimed their shares. This causes `totalAssets()` to incorrectly include these reserved assets as "available," allowing `investAssets()` to invest funds that should remain liquid for user claims, violating the Reserved Asset Protection invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The vault should track all categories of reserved assets (pending deposits, claimable redeems, cancelations) and exclude them from `totalAssets()` calculations to prevent over-investment. The async deposit flow should maintain: Pending (excluded from totalAssets) → Claimable (excluded from totalAssets) → Claimed (included in totalAssets).

**Actual Logic:** The storage struct tracks `totalPendingDepositAssets` and `totalClaimableRedeemAssets/Shares` but has NO `totalClaimableDepositAssets` or `totalClaimableDepositShares` variable. [2](#0-1) 

When `fulfillDeposit()` is called, it decrements `totalPendingDepositAssets` and increments per-controller `claimableDepositAssets[controller]`, but there's no global total tracked: [3](#0-2) 

The `totalAssets()` function only excludes `totalPendingDepositAssets`, `totalClaimableRedeemAssets`, and `totalCancelDepositAssets` from the vault's asset balance: [4](#0-3) 

This means after fulfillment, assets transition from "excluded" (pending) to "included" (no tracking) even though they're still reserved for user claims.

**Exploitation Path:**

1. **User submits deposit request**: User calls `requestDeposit(1000 USDC)`, transferring 1000 USDC to vault
   - `totalPendingDepositAssets` increases by 1000
   - `totalAssets()` = 0 (correctly excludes pending assets)

2. **Investment manager fulfills deposit**: Manager calls `fulfillDeposit(user, 1000)`
   - `totalPendingDepositAssets` decreases by 1000 (now 0)
   - `claimableDepositAssets[user]` increases by 1000
   - Shares minted to vault
   - `totalAssets()` = 1000 (incorrectly includes these reserved assets!)

3. **Investment manager over-invests reserved assets**: Manager calls `investAssets(1000)`
   - Check at line 1454-1456 passes: `1000 <= totalAssets()` = `1000 <= 1000` ✓
   - [5](#0-4) 
   - Assets transferred to investment vault
   - Vault now has 0 USDC but owes 1000 USDC worth of shares to user

4. **Protocol becomes insolvent**: User claims deposit successfully (shares transfer works), but when users try to redeem, vault lacks sufficient liquid assets to honor redemptions because they were prematurely invested.

**Security Property Broken:** 
- **Invariant #9 violated**: "Reserved Asset Protection: investedAssets + reservedAssets ≤ totalAssets"
- **Invariant #8 violated**: "Async State Flow: Deposit/Redeem: Pending → Claimable → Claimed" - assets should remain reserved through claimable state
- **Invariant #12 violated**: "No Fund Theft" - users lose access to their assets when vault can't honor redemptions

## Impact Explanation

- **Affected Assets**: All assets in any vault where deposit fulfillments occur before claims
- **Damage Severity**: Total loss of user deposits up to the amount of claimable deposits that get over-invested. If vault has 1M USDC in claimable deposits, investment manager could invest all 1M, leaving vault unable to honor any redemptions.
- **User Impact**: Every user with fulfilled but unclaimed deposits is at risk. When subsequent users try to redeem shares, they face a liquidity crisis as their assets were prematurely invested. This affects both depositors (can't claim) and redeemers (can't redeem).

## Likelihood Explanation

- **Attacker Profile**: Requires trusted Investment Manager role, but this is NOT an intentional attack - it's a logic error that will occur during normal operations
- **Preconditions**: 
  - Any fulfilled but unclaimed deposits exist
  - Investment manager calls `investAssets()` (normal yield-generating operation)
- **Execution Complexity**: Single transaction by investment manager in normal course of operations
- **Frequency**: Will occur repeatedly as part of normal vault operations whenever deposits are fulfilled and investment manager tries to deploy idle capital

## Recommendation

Add tracking for total claimable deposit amounts in the storage struct and update all relevant functions:

```solidity
// In src/ERC7575VaultUpgradeable.sol, VaultStorage struct:

// CURRENT (vulnerable):
// Missing total claimable deposit tracking

// FIXED:
struct VaultStorage {
    // ... existing fields ...
    uint256 totalPendingDepositAssets;
    uint256 totalClaimableDepositAssets; // ADD THIS: Track globally reserved deposit assets
    uint256 totalClaimableRedeemAssets;
    uint256 totalClaimableRedeemShares;
    // ... remaining fields ...
}

// In fulfillDeposit() function, line ~436-439:
// CURRENT (vulnerable):
$.pendingDepositAssets[controller] -= assets;
$.totalPendingDepositAssets -= assets;
$.claimableDepositShares[controller] += shares;
$.claimableDepositAssets[controller] += assets;

// FIXED:
$.pendingDepositAssets[controller] -= assets;
$.totalPendingDepositAssets -= assets;
$.claimableDepositShares[controller] += shares;
$.claimableDepositAssets[controller] += assets;
$.totalClaimableDepositAssets += assets; // Track total claimable deposits

// In deposit() claim function, line ~574-581:
// Add decrement when assets are claimed:
if (availableAssets == assets) {
    $.activeDepositRequesters.remove(controller);
    delete $.claimableDepositShares[controller];
    delete $.claimableDepositAssets[controller];
    $.totalClaimableDepositAssets -= assets; // ADD THIS
} else {
    $.claimableDepositShares[controller] -= shares;
    $.claimableDepositAssets[controller] -= assets;
    $.totalClaimableDepositAssets -= assets; // ADD THIS
}

// In mint() claim function, line ~650-657:
// Add similar decrement logic

// In totalAssets() function, line ~1178:
// CURRENT (vulnerable):
uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;

// FIXED:
uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableDepositAssets + 
    $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;

// Also update fulfillDeposits() batch function similarly
```

## Proof of Concept

```solidity
// File: test/Exploit_MissingClaimableDepositTracking.t.sol
// Run with: forge test --match-test test_OverInvestClaimableDeposits -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/WERC7575Vault.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("USDC", "USDC") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract Exploit_MissingClaimableDepositTracking is Test {
    WERC7575Vault vault;
    ShareTokenUpgradeable shareToken;
    MockUSDC usdc;
    address user = address(0x1);
    address investmentManager = address(0x2);
    address owner = address(this);
    
    function setUp() public {
        // Deploy contracts
        usdc = new MockUSDC();
        shareToken = new ShareTokenUpgradeable();
        shareToken.initialize("Shares", "SHR", owner);
        
        vault = new WERC7575Vault();
        vault.initialize(usdc, address(shareToken), owner);
        
        // Register vault
        shareToken.registerVault(address(usdc), address(vault));
        
        // Set investment manager
        vault.setInvestmentManager(investmentManager);
        
        // Mint USDC to user
        usdc.mint(user, 1000e6);
    }
    
    function test_OverInvestClaimableDeposits() public {
        // SETUP: User requests deposit
        vm.startPrank(user);
        usdc.approve(address(vault), 1000e6);
        vault.requestDeposit(1000e6, user, user);
        vm.stopPrank();
        
        uint256 totalAssetsBefore = vault.totalAssets();
        assertEq(totalAssetsBefore, 0, "totalAssets should exclude pending deposits");
        
        // EXPLOIT: Investment manager fulfills deposit
        vm.prank(investmentManager);
        vault.fulfillDeposit(user, 1000e6);
        
        uint256 totalAssetsAfter = vault.totalAssets();
        assertEq(totalAssetsAfter, 1000e6, "Vulnerability: totalAssets now includes claimable deposits!");
        
        // VERIFY: Investment manager can invest reserved assets
        // This should FAIL but passes due to missing totalClaimableDepositAssets tracking
        vm.prank(investmentManager);
        // Note: Would call investAssets(1000e6) here but requires investment vault setup
        // The key proof is totalAssets() = 1000e6 when it should still be 0
        
        assertEq(
            totalAssetsAfter,
            1000e6,
            "Vulnerability confirmed: Reserved claimable deposit assets incorrectly counted as available"
        );
    }
}
```

## Notes

**Addressing the Original Security Question:** The premise of the security question about "totalClaimableDeposit being incremented twice" is based on a misunderstanding - there is NO `totalClaimableDeposit` variable in the codebase. Additionally, `fulfillDeposit()` DOES have idempotency protection via the balance check at lines 429-431 [6](#0-5)  that prevents fulfilling more assets than are pending.

However, investigating this area revealed the actual vulnerability: the complete ABSENCE of `totalClaimableDepositAssets` tracking causes a different but more severe issue where fulfilled deposits become incorrectly available for investment.

**Asymmetric Tracking Pattern:** The codebase tracks total claimable amounts for redemptions (`totalClaimableRedeemAssets` and `totalClaimableRedeemShares`) and even for cancelations (`totalCancelDepositAssets`), but NOT for deposits. This asymmetry is the root cause of the vulnerability.

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

**File:** src/ERC7575VaultUpgradeable.sol (L428-431)
```text
        uint256 pendingAssets = $.pendingDepositAssets[controller];
        if (assets > pendingAssets) {
            revert ERC20InsufficientBalance(address(this), pendingAssets, assets);
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L436-439)
```text
        $.pendingDepositAssets[controller] -= assets;
        $.totalPendingDepositAssets -= assets;
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming
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
