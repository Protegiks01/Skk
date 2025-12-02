## Title
Missing Global Accounting for Claimable Deposit Assets Allows Over-Investment and Redemption Failures

## Summary
The `totalAssets()` function in `ERC7575VaultUpgradeable` does not account for assets that have been fulfilled for deposit but not yet claimed by users. This allows the Investment Manager to inadvertently invest these reserved assets via `investAssets()`, causing subsequent redemption claims to fail due to insufficient vault balance.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol` [1](#0-0) [2](#0-1) 

**Intended Logic:** 
According to the TECHNICAL_ARCHITECTURE.md documentation, reserved assets should include all assets that must remain in the vault for pending and claimable operations. The `totalAssets()` function should exclude all reserved assets to prevent over-investment.

**Actual Logic:** 
The `totalAssets()` function only subtracts three categories of reserved assets: [3](#0-2) 

However, when `fulfillDeposit()` is called, assets transition from `totalPendingDepositAssets` (which IS tracked globally) to per-user `claimableDepositAssets` (which is NOT tracked globally). There is no `totalClaimableDepositAssets` global counter. [4](#0-3) 

The VaultStorage struct confirms no global claimable deposit tracking exists: [5](#0-4) 

**Exploitation Path:**

1. **User deposits assets:** Alice calls `requestDeposit(5000 USDC)`. Assets enter pending state: `totalPendingDepositAssets = 5000`. Vault balance = 15,000 USDC.

2. **Investment Manager fulfills deposit:** Manager calls `fulfillDeposit(Alice, 5000)`. The code decrements `totalPendingDepositAssets` by 5000 (now 0) and mints shares to the vault. Assets are tracked only in `claimableDepositAssets[Alice] = 5000` with NO global counter updated. [6](#0-5) 

3. **totalAssets() no longer reserves these assets:** `totalAssets()` now returns 15,000 USDC because `totalPendingDepositAssets = 0`, `totalClaimableRedeemAssets = 0`, `totalCancelDepositAssets = 0`. The 5000 USDC that should be reserved for Alice's claim are treated as available.

4. **Investment Manager over-invests:** Manager calls `investAssets(15000)`, which checks `totalAssets()` returns 15,000 and allows the full investment. All 15,000 USDC (including Alice's 5000) are transferred to the investment vault. [7](#0-6) 

5. **Alice claims deposit (succeeds):** Alice calls `deposit(5000, Alice, Alice)` to claim her shares. This succeeds because shares were already minted to the vault in step 2. Alice receives ~5000 shares. [8](#0-7) 

6. **Alice requests redemption:** Alice calls `requestRedeem(~5000 shares)`. Shares transferred from Alice to vault.

7. **Manager fulfills redemption:** Manager calls `fulfillRedeem(Alice, ~5000 shares)`. This calculates assets = 5000 USDC and updates `totalClaimableRedeemAssets = 5000`. [9](#0-8) 

8. **Alice's redemption claim fails:** Alice calls `redeem(~5000 shares, Alice, Alice)`. The function burns shares and attempts to transfer 5000 USDC to Alice. **This reverts because the vault has 0 USDC** - all assets were invested in step 4. [10](#0-9) 

**Security Property Broken:** 
- **Invariant #9 - Reserved Asset Protection**: "investedAssets + reservedAssets ≤ totalAssets" is violated because claimable deposit assets are not counted in reservedAssets.
- **Invariant #12 - No Fund Theft**: Users cannot access their rightfully owed assets due to over-investment.

## Impact Explanation

- **Affected Assets**: All assets in vaults where deposits have been fulfilled but not yet claimed, then later redeemed. Affects USDC, USDT, DAI, and any other registered vault assets.
- **Damage Severity**: Complete temporary loss of user redemption access. The vault becomes insolvent for redemptions until the Investment Manager withdraws assets from the investment vault. In extreme cases with multiple users, the vault may be unable to fulfill all redemptions even after partial withdrawals.
- **User Impact**: Any user who deposits, gets fulfilled, claims their shares, then later requests redemption will have their redemption claim fail. This affects normal user flow and can lock funds indefinitely if the investment vault has losses or withdrawal restrictions.

## Likelihood Explanation

- **Attacker Profile**: No attacker needed - this is a logic bug in normal operation. The Investment Manager acts in good faith but the system provides incorrect information via `totalAssets()`.
- **Preconditions**: 
  - Users have deposits that are fulfilled but not yet claimed (common in async vault systems)
  - Investment Manager calls `investAssets()` based on `totalAssets()` availability
  - Users later want to redeem their shares
- **Execution Complexity**: Trivial - occurs during normal vault operations. No special timing or manipulation required.
- **Frequency**: Can happen continuously as long as there are fulfilled-but-unclaimed deposits followed by investment operations.

## Recommendation

Add global tracking for claimable deposit assets and include it in the reserved assets calculation:

```solidity
// In src/ERC7575VaultUpgradeable.sol, VaultStorage struct, add after line 100:
uint256 totalClaimableDepositAssets; // NEW: Track total assets reserved for deposit claims

// In fulfillDeposit() function, add after line 439:
$.totalClaimableDepositAssets += assets; // NEW: Increment global counter

// In fulfillDeposits() function, add after line 480:
$.totalClaimableDepositAssets += assetAmounts; // NEW: Increment global counter

// In deposit() function, modify lines 574-580:
if (availableAssets == assets) {
    $.activeDepositRequesters.remove(controller);
    delete $.claimableDepositShares[controller];
    delete $.claimableDepositAssets[controller];
    $.totalClaimableDepositAssets -= assets; // NEW: Decrement when fully claimed
} else {
    $.claimableDepositShares[controller] -= shares;
    $.claimableDepositAssets[controller] -= assets;
    $.totalClaimableDepositAssets -= assets; // NEW: Decrement proportionally
}

// In mint() function, modify lines 650-656 similarly:
if (availableShares == shares) {
    $.activeDepositRequesters.remove(controller);
    delete $.claimableDepositShares[controller];
    delete $.claimableDepositAssets[controller];
    $.totalClaimableDepositAssets -= assets; // NEW: Decrement when fully claimed
} else {
    $.claimableDepositShares[controller] -= shares;
    $.claimableDepositAssets[controller] -= assets;
    $.totalClaimableDepositAssets -= assets; // NEW: Decrement proportionally
}

// In totalAssets() function, modify line 1178:
uint256 reservedAssets = $.totalPendingDepositAssets 
                       + $.totalClaimableRedeemAssets 
                       + $.totalCancelDepositAssets
                       + $.totalClaimableDepositAssets; // NEW: Include claimable deposits
```

## Proof of Concept

```solidity
// File: test/Exploit_MissingClaimableDepositAccounting.t.sol
// Run with: forge test --match-test test_MissingClaimableDepositAccounting -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ERC20Faucet6} from "../src/ERC20Faucet6.sol";
import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {WERC7575ShareToken} from "../src/WERC7575ShareToken.sol";
import {WERC7575Vault} from "../src/WERC7575Vault.sol";

contract Exploit_MissingClaimableDepositAccounting is Test {
    ERC20Faucet6 public usdc;
    WERC7575ShareToken public investmentShareToken;
    WERC7575Vault public investmentUsdcVault;
    ShareTokenUpgradeable public shareToken;
    ERC7575VaultUpgradeable public usdcVault;
    
    address public owner = address(0x1);
    address public alice = address(0x2);
    address public investmentManager = address(0x3);
    address public validator = address(0x4);
    
    uint256 constant INITIAL_SUPPLY = 1_000_000 * 1e6;
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy USDC
        usdc = new ERC20Faucet6("USD Coin", "USDC", INITIAL_SUPPLY);
        
        // Deploy investment system
        investmentShareToken = new WERC7575ShareToken("Investment USD", "iUSD");
        investmentUsdcVault = new WERC7575Vault(address(usdc), investmentShareToken);
        investmentShareToken.registerVault(address(usdc), address(investmentUsdcVault));
        investmentShareToken.setValidator(validator);
        investmentShareToken.setKycAdmin(validator);
        
        // Deploy upgradeable ShareToken
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory initData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector,
            "Vault Shares",
            "VS",
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), initData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy USDC vault
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            IERC20Metadata(address(usdc)),
            address(shareToken),
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        usdcVault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // Register vault and configure investment
        shareToken.registerVault(address(usdc), address(usdcVault));
        shareToken.setInvestmentManager(investmentManager);
        shareToken.setInvestmentShareToken(address(investmentShareToken));
        
        vm.stopPrank();
        
        // Setup KYC
        vm.startPrank(validator);
        investmentShareToken.setKycVerified(address(shareToken), true);
        investmentShareToken.setKycVerified(alice, true);
        vm.stopPrank();
        
        // Fund alice
        usdc.transfer(alice, 10000 * 1e6);
    }
    
    function test_MissingClaimableDepositAccounting() public {
        // SETUP: Vault has initial balance
        vm.prank(owner);
        usdc.transfer(address(usdcVault), 10000 * 1e6);
        
        uint256 initialVaultBalance = usdc.balanceOf(address(usdcVault));
        console.log("Initial vault balance:", initialVaultBalance / 1e6, "USDC");
        
        // STEP 1: Alice deposits 5000 USDC
        vm.startPrank(alice);
        usdc.approve(address(usdcVault), 5000 * 1e6);
        usdcVault.requestDeposit(5000 * 1e6, alice, alice);
        vm.stopPrank();
        
        uint256 balanceAfterDeposit = usdc.balanceOf(address(usdcVault));
        uint256 totalAssetsAfterDeposit = usdcVault.totalAssets();
        console.log("After deposit - Vault balance:", balanceAfterDeposit / 1e6, "USDC");
        console.log("After deposit - totalAssets():", totalAssetsAfterDeposit / 1e6, "USDC");
        assertEq(totalAssetsAfterDeposit, 10000 * 1e6, "Pending deposit should be reserved");
        
        // STEP 2: Investment manager fulfills Alice's deposit
        vm.prank(investmentManager);
        usdcVault.fulfillDeposit(alice, 5000 * 1e6);
        
        uint256 totalAssetsAfterFulfill = usdcVault.totalAssets();
        console.log("After fulfill - totalAssets():", totalAssetsAfterFulfill / 1e6, "USDC");
        console.log("BUG: totalAssets jumped to 15000 USDC - claimable deposits not reserved!");
        assertEq(totalAssetsAfterFulfill, 15000 * 1e6, "BUG: Claimable deposits not reserved");
        
        // STEP 3: Investment manager invests all "available" assets
        vm.prank(investmentManager);
        usdcVault.investAssets(15000 * 1e6);
        
        uint256 balanceAfterInvest = usdc.balanceOf(address(usdcVault));
        console.log("After invest - Vault balance:", balanceAfterInvest / 1e6, "USDC");
        assertEq(balanceAfterInvest, 0, "All assets invested including Alice's");
        
        // STEP 4: Alice claims her deposit (succeeds - shares already minted)
        vm.prank(alice);
        usdcVault.deposit(5000 * 1e6, alice, alice);
        
        uint256 aliceShares = shareToken.balanceOf(alice);
        console.log("Alice received shares:", aliceShares / 1e18);
        assertTrue(aliceShares > 0, "Alice received shares");
        
        // STEP 5: Alice requests to redeem her shares
        vm.startPrank(alice);
        shareToken.approve(address(shareToken), aliceShares);
        usdcVault.requestRedeem(aliceShares, alice, alice);
        vm.stopPrank();
        
        // STEP 6: Investment manager fulfills redemption
        vm.prank(investmentManager);
        usdcVault.fulfillRedeem(alice, aliceShares);
        
        // STEP 7: Alice tries to claim her redemption - FAILS
        vm.prank(alice);
        vm.expectRevert(); // Will revert due to insufficient USDC balance
        usdcVault.redeem(aliceShares, alice, alice);
        
        console.log("EXPLOIT CONFIRMED: Alice cannot redeem her assets!");
        console.log("Vault has 0 USDC but owes Alice 5000 USDC");
    }
}
```

## Notes

The security question references a `_calculateReservedAssets()` function that doesn't exist in the actual codebase - the calculation is performed inline in `totalAssets()`. The question also mentions "deposit claims" reverting, but technically deposit claims (calling `deposit()` or `mint()`) only transfer already-minted shares and won't revert. The actual impact is that **redemption claims** will revert due to insufficient assets when users try to withdraw. This is still a critical vulnerability as it prevents users from accessing their funds and violates the "Reserved Asset Protection" invariant.

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
