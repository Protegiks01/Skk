## Title
Claimable Deposit Assets Not Reserved in totalAssets() Allows Over-Investment Causing Withdrawal Failures

## Summary
The `totalAssets()` function in `ERC7575VaultUpgradeable` fails to reserve assets from fulfilled-but-unclaimed deposits, causing the investment manager to over-invest based on inflated available balances. When users subsequently claim deposits and request redemptions, withdrawal transactions revert due to insufficient liquid assets, requiring emergency withdrawals from the investment vault.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol` - `totalAssets()` function (lines 1174-1180), `fulfillDeposit()` function (lines 425-444), and `VaultStorage` struct (lines 86-123)

**Intended Logic:** Per Invariant #9 from the README, the system should enforce "investedAssets + reservedAssets ≤ totalAssets - Reserved protection". [2](#0-1)  The `totalAssets()` function is designed to return only assets available for investment by excluding all assets reserved for pending user operations.

**Actual Logic:** The `reservedAssets` calculation only subtracts three aggregate totals: [1](#0-0) 

However, the `VaultStorage` struct contains NO `totalClaimableDepositAssets` variable to aggregate fulfilled deposits: [4](#0-3) 

Notice lines 98-99 track `totalPendingDepositAssets` and `totalClaimableRedeemAssets`, but lines 103-104 only have per-controller mappings `claimableDepositShares[controller]` and `claimableDepositAssets[controller]` with no aggregate total.

When `fulfillDeposit()` is called, assets transition from reserved to unreserved state: [5](#0-4) 

Line 437 decreases `totalPendingDepositAssets` (removing the reservation), but line 439 only stores assets in a per-controller mapping with no corresponding increase to any aggregate total that gets subtracted in `totalAssets()`.

**Exploitation Path:**

1. **Initial State**: Vault has 1000 USDC balance, no pending requests. `totalAssets() = 1000`

2. **User A deposits 1000 USDC**: Calls `requestDeposit(1000)`, transfers 1000 USDC to vault
   - `totalPendingDepositAssets = 1000`
   - Vault balance = 2000 USDC
   - `reservedAssets = 1000 + 0 + 0 = 1000`
   - `totalAssets() = 2000 - 1000 = 1000` ✅

3. **Manager fulfills deposit**: Calls `fulfillDeposit(UserA, 1000)`
   - Line 437: `totalPendingDepositAssets` goes from 1000 → 0
   - Line 439: `claimableDepositAssets[UserA] = 1000` (no aggregate total!)
   - Mints 1000 shares to vault
   - `reservedAssets = 0 + 0 + 0 = 0` ⚠️
   - `totalAssets() = 2000 - 0 = 2000` ⚠️ (artificially doubled!)

4. **Manager over-invests**: Calls `investAssets(2000)`
   - Check at line 1455 passes: `2000 <= totalAssets() = 2000` ✅ [6](#0-5) 
   - Transfers 2000 USDC to investment vault
   - Vault balance = 0 USDC

5. **User A claims deposit and redeems**: 
   - Calls `deposit(1000, UserA, UserA)` → receives 1000 shares (no asset transfer)
   - Calls `requestRedeem(1000)` → transfers 1000 shares to vault
   - Manager calls `fulfillRedeem(UserA, 1000)` → calculates 1000 USDC owed [7](#0-6) 
   - `totalClaimableRedeemAssets = 1000` (now properly reserved)

6. **Withdrawal fails**: User A calls `withdraw(1000, UserA, UserA)`
   - Line 916 attempts: `SafeTokenTransfers.safeTransfer($.asset, receiver, 1000)` [8](#0-7) 
   - **REVERTS**: Vault has 0 USDC balance but needs to transfer 1000 USDC
   - Manager must call `withdrawFromInvestment()` to restore liquidity

**Security Property Broken:** Violates Invariant #9 "Reserved Asset Protection: investedAssets + reservedAssets ≤ totalAssets". The issue is that `reservedAssets` calculation is incomplete, allowing over-investment.

## Impact Explanation

- **Affected Assets**: All assets (USDC, USDT, DAI) in any ERC7575VaultUpgradeable instance
- **Damage Severity**: Temporary denial-of-service for withdrawals. Users cannot claim fulfilled redemptions until the investment manager manually withdraws sufficient assets from the investment vault using `withdrawFromInvestment()`. In worst case, if the investment vault has lock-up periods or illiquidity, user funds become inaccessible for extended periods.
- **User Impact**: Any user with a fulfilled deposit can trigger this. Multiple users with fulfilled deposits amplify the issue. All users attempting to withdraw claimable redemptions are blocked until the manager rebalances liquidity.

## Likelihood Explanation

- **Attacker Profile**: Any normal user with a fulfilled deposit request. No special privileges required.
- **Preconditions**: 
  1. Vault must have fulfilled but unclaimed deposits (`claimableDepositAssets[user] > 0`)
  2. Investment manager invests based on inflated `totalAssets()` 
  3. User claims deposit and immediately requests redemption
  4. Manager fulfills redemption before withdrawing from investment
- **Execution Complexity**: Single sequence of standard user transactions. No timing precision or front-running required.
- **Frequency**: Can occur whenever the normal deposit→fulfill→claim→redeem flow happens with investment activity in between.

## Recommendation

Add a `totalClaimableDepositAssets` state variable to aggregate fulfilled deposits and include it in the `reservedAssets` calculation:

```solidity
// In src/ERC7575VaultUpgradeable.sol, VaultStorage struct around line 100:

// CURRENT (vulnerable):
struct VaultStorage {
    // ... existing fields ...
    uint256 totalPendingDepositAssets;
    uint256 totalClaimableRedeemAssets;
    uint256 totalClaimableRedeemShares;
    // ... mappings ...
}

// FIXED:
struct VaultStorage {
    // ... existing fields ...
    uint256 totalPendingDepositAssets;
    uint256 totalClaimableDepositAssets; // NEW: Track aggregate claimable deposits
    uint256 totalClaimableRedeemAssets;
    uint256 totalClaimableRedeemShares;
    // ... mappings ...
}

// In src/ERC7575VaultUpgradeable.sol, totalAssets() function around line 1178:

// CURRENT (vulnerable):
uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;

// FIXED:
uint256 reservedAssets = $.totalPendingDepositAssets 
    + $.totalClaimableDepositAssets  // Include claimable deposits
    + $.totalClaimableRedeemAssets 
    + $.totalCancelDepositAssets;

// In src/ERC7575VaultUpgradeable.sol, fulfillDeposit() function around line 437:

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
$.totalClaimableDepositAssets += assets; // Track in aggregate total

// In src/ERC7575VaultUpgradeable.sol, deposit() function around line 577-580:

// CURRENT (vulnerable):
if (availableAssets == assets) {
    $.activeDepositRequesters.remove(controller);
    delete $.claimableDepositShares[controller];
    delete $.claimableDepositAssets[controller];
} else {
    $.claimableDepositShares[controller] -= shares;
    $.claimableDepositAssets[controller] -= assets;
}

// FIXED:
if (availableAssets == assets) {
    $.activeDepositRequesters.remove(controller);
    delete $.claimableDepositShares[controller];
    delete $.claimableDepositAssets[controller];
    $.totalClaimableDepositAssets -= availableAssets; // Decrease aggregate
} else {
    $.claimableDepositShares[controller] -= shares;
    $.claimableDepositAssets[controller] -= assets;
    $.totalClaimableDepositAssets -= assets; // Decrease aggregate
}
```

Apply similar fixes to the `mint()` function and the batch `fulfillDeposits()` function to maintain consistency.

## Proof of Concept

```solidity
// File: test/Exploit_ClaimableDepositOverInvestment.t.sol
// Run with: forge test --match-test test_ClaimableDepositOverInvestment -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("USDC", "USDC") {
        _mint(msg.sender, 1000000 * 10**6);
    }
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

contract Exploit_ClaimableDepositOverInvestment is Test {
    WERC7575ShareToken shareToken;
    WERC7575Vault vault;
    WERC7575Vault investmentVault;
    MockUSDC usdc;
    
    address owner = address(1);
    address investmentManager = address(2);
    address validator = address(3);
    address userA = address(4);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy tokens
        usdc = new MockUSDC();
        
        // Deploy share token
        shareToken = new WERC7575ShareToken();
        shareToken.initialize(owner, validator, "WUSD", "WUSD");
        
        // Deploy main vault
        vault = new WERC7575Vault();
        vault.initialize(usdc, address(shareToken), owner);
        vault.setInvestmentManager(investmentManager);
        
        // Deploy investment vault
        investmentVault = new WERC7575Vault();
        investmentVault.initialize(usdc, address(shareToken), owner);
        
        // Register vaults
        shareToken.registerVault(address(usdc), address(vault));
        
        // Setup investment
        vault.setInvestmentVault(address(investmentVault));
        shareToken.registerInvestmentConfig(address(shareToken));
        
        // Setup KYC
        shareToken.grantRole(shareToken.KYC_ADMIN_ROLE(), owner);
        shareToken.addToKYCWhitelist(address(vault));
        shareToken.addToKYCWhitelist(address(investmentVault));
        shareToken.addToKYCWhitelist(userA);
        
        // Fund vault with initial 1000 USDC
        usdc.transfer(address(vault), 1000 * 10**6);
        
        // Fund user
        usdc.transfer(userA, 1000 * 10**6);
        
        vm.stopPrank();
    }
    
    function test_ClaimableDepositOverInvestment() public {
        // SETUP: UserA deposits 1000 USDC
        vm.startPrank(userA);
        usdc.approve(address(vault), 1000 * 10**6);
        vault.requestDeposit(1000 * 10**6, userA, userA);
        vm.stopPrank();
        
        // Initial state: totalAssets should be 1000 (original) because 1000 is pending
        assertEq(vault.totalAssets(), 1000 * 10**6, "Initial totalAssets should be 1000 USDC");
        
        // EXPLOIT Step 1: Manager fulfills deposit
        vm.prank(investmentManager);
        vault.fulfillDeposit(userA, 1000 * 10**6);
        
        // BUG: totalAssets jumps to 2000 because claimable deposits are not reserved!
        assertEq(vault.totalAssets(), 2000 * 10**6, "BUG: totalAssets incorrectly increased to 2000 USDC");
        
        // EXPLOIT Step 2: Manager over-invests based on inflated totalAssets
        vm.startPrank(investmentManager);
        usdc.approve(address(investmentVault), 2000 * 10**6);
        vault.investAssets(2000 * 10**6); // Invests ALL vault balance
        vm.stopPrank();
        
        // Vault now has 0 liquid USDC
        assertEq(usdc.balanceOf(address(vault)), 0, "Vault has 0 USDC after over-investment");
        
        // EXPLOIT Step 3: UserA claims deposit and immediately redeems
        vm.startPrank(userA);
        vault.deposit(1000 * 10**6, userA, userA); // Claims shares
        uint256 shares = shareToken.balanceOf(userA);
        shareToken.approve(address(vault), shares);
        vault.requestRedeem(shares, userA, userA);
        vm.stopPrank();
        
        // Manager fulfills redemption (can do this even without liquid assets!)
        vm.prank(investmentManager);
        vault.fulfillRedeem(userA, shares);
        
        // VERIFY: Withdrawal FAILS due to insufficient balance
        vm.startPrank(userA);
        vm.expectRevert(); // SafeERC20 will revert on insufficient balance
        vault.withdraw(1000 * 10**6, userA, userA);
        vm.stopPrank();
        
        console.log("VULNERABILITY CONFIRMED: User cannot withdraw despite fulfilled redemption");
        console.log("Vault balance:", usdc.balanceOf(address(vault)));
        console.log("Claimable redemption:", vault.claimableRedeemRequest(0, userA));
    }
}
```

## Notes

The root cause is the missing `totalClaimableDepositAssets` aggregate variable. The current implementation only tracks claimable deposits in per-controller mappings, which are invisible to the `totalAssets()` calculation. This creates a critical accounting gap in the async ERC-7540 deposit flow where assets transition from "pending" (properly reserved) to "claimable" (improperly unreserved), despite still being owed to users who can claim shares and immediately request redemption.

The vulnerability is particularly insidious because:
1. It doesn't require any malicious actors - normal user behavior triggers it
2. The investment manager is making rational decisions based on what appears to be available balance
3. The system appears to work correctly until the exact moment users try to withdraw
4. It violates the core safety invariant #9 that prevents over-investment

This is distinct from the known issue "No fulfillment deadlines" because the problem is not about timing delays by the manager, but rather incorrect accounting that allows mathematically impossible investment decisions.

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

**File:** src/ERC7575VaultUpgradeable.sol (L831-836)
```text
        assets = _convertToAssets(shares, Math.Rounding.Floor);

        $.pendingRedeemShares[controller] -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
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

**File:** src/ERC7575VaultUpgradeable.sol (L1454-1457)
```text
        uint256 availableBalance = totalAssets();
        if (amount > availableBalance) {
            revert ERC20InsufficientBalance(address(this), availableBalance, amount);
        }
```

**File:** README.md (L104-104)
```markdown
  9. investedAssets + reservedAssets ≤ totalAssets - Reserved protection
```
