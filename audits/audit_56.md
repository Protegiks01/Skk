## Title
Fulfillment Without Sufficient Balance Causes totalAssets() to Return Zero and Breaks All Conversion Rate Calculations

## Summary
The `fulfillRedeem()` function in `ERC7575VaultUpgradeable.sol` does not validate that the vault has sufficient balance to cover the assets it promises to claimable redeemers. When the investment manager invests assets and then fulfills large redemptions without first withdrawing from the investment vault, `totalClaimableRedeemAssets` can exceed the vault's actual balance, causing `totalAssets()` to return 0 and catastrophically breaking all share-to-asset conversion rates across the entire multi-vault system.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `fulfillRedeem()` function (lines 822-841) and `totalAssets()` function (lines 1174-1180)

**Intended Logic:** The vault should maintain sufficient balance to cover all reserved assets (pending deposits, claimable redemptions, and cancellation deposits). The `totalAssets()` calculation excludes reserved assets to represent only the freely available assets for investment and conversions. [1](#0-0) 

**Actual Logic:** When `fulfillRedeem()` is called, it converts shares to assets based on the current exchange rate and increases `totalClaimableRedeemAssets` without verifying the vault has sufficient balance to pay these assets. [2](#0-1) 

This creates a scenario where `totalClaimableRedeemAssets` exceeds the vault's actual token balance, causing the underflow protection in `totalAssets()` to return 0.

**Exploitation Path:**

1. **Initial State**: Vault has 1000 USDC balance, 1000 shares outstanding (1:1 ratio)

2. **Investment Manager invests 900 USDC**: Calls `investAssets(900)`, transferring 900 USDC to investment vault. Vault balance drops to 100 USDC, but total system value remains 1000 USDC (100 in vault + 900 invested). [3](#0-2) 

3. **Users request large redemptions**: Users request redemption of 800 shares (worth 800 USDC at current rate).

4. **Investment Manager fulfills redemptions WITHOUT withdrawing from investment**: Calls `fulfillRedeem(user, 800)` which:
   - Converts 800 shares to ~800 assets using current conversion rate (which includes invested assets in its calculation)
   - Sets `totalClaimableRedeemAssets += 800`
   - Vault balance is still only 100 USDC, but now owes 800 USDC

5. **totalAssets() returns 0**: 
   - `balance = 100 USDC`
   - `reservedAssets = 0 + 800 + 0 = 800`
   - `totalAssets() = max(100 - 800, 0) = 0`

6. **Conversion rates catastrophically break**: The ShareToken's `getCirculatingSupplyAndAssets()` now calculates:
   - `vaultNormalizedAssets = 0 * scalingFactor = 0` (from this vault's totalAssets)
   - `totalNormalizedAssets = 0 + 900e12 = 900e12` (only investment assets counted)
   - `circulatingSupply = 1000 - 800 = 200` (excluding claimable shares) [4](#0-3) 

7. **Financial damage occurs**:
   - **New depositor loses 78% of value**: Deposits 100 USDC, expects 100 shares, but gets only `100e12 * 200 / 900e12 ≈ 22 shares` due to broken conversion rate [5](#0-4) 

   - **Existing user steals 350% extra value**: Redeems 100 shares, expects 100 USDC, but gets `100 * 900e12 / 200 = 450e12 / 1e12 = 450 USDC` due to inflated conversion rate [6](#0-5) 

**Security Property Broken:** 
- **Invariant #9 - Reserved Asset Protection**: "investedAssets + reservedAssets ≤ totalAssets" is violated as reservedAssets (800) > totalAssets (0)
- **Invariant #10 - Conversion Accuracy**: "convertToShares(convertToAssets(x)) ≈ x" is catastrophically broken with 4.5x conversion rate errors

## Impact Explanation
- **Affected Assets**: All assets in all vaults within the multi-asset system, as the broken conversion rate affects the global ShareToken calculations
- **Damage Severity**: 
  - New depositors lose up to 78% of their deposit value (receive far fewer shares than entitled)
  - Existing redeemers can extract up to 4.5x more assets than their shares are worth
  - Total theft potential equals the difference between actual value and broken conversion rate across all affected transactions
- **User Impact**: All users interacting with any vault in the system after the vulnerability is triggered are affected. Both deposits and redemptions use the corrupted global conversion rate.

## Likelihood Explanation
- **Attacker Profile**: Does not require a malicious attacker. This occurs through normal protocol operations when the investment manager fulfills redemptions in the expected sequence (invest first, fulfill redemptions later without intermediate withdrawal).
- **Preconditions**: 
  - Vault has invested a significant portion of assets into investment vault
  - Users request redemptions totaling more than the remaining vault balance
  - Investment manager fulfills these redemptions without first calling `withdrawFromInvestment()`
- **Execution Complexity**: Single transaction by investment manager (normal duty, not malicious). The subsequent damage occurs automatically when any user deposits or redeems.
- **Frequency**: Can occur whenever the investment manager fulfills redemptions after investing assets, which is a routine operation in the protocol's intended workflow.

## Recommendation

Add balance validation in `fulfillRedeem()` to ensure the vault can cover the promised assets:

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

    // FIX: Validate vault has sufficient balance to cover the promised assets
    uint256 currentBalance = IERC20Metadata($.asset).balanceOf(address(this));
    uint256 totalReservedAfter = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + assets + $.totalCancelDepositAssets;
    if (currentBalance < totalReservedAfter) {
        revert InsufficientVaultBalance(currentBalance, totalReservedAfter);
    }

    $.pendingRedeemShares[controller] -= shares;
    $.claimableRedeemAssets[controller] += assets;
    $.claimableRedeemShares[controller] += shares;
    $.totalClaimableRedeemAssets += assets;
    $.totalClaimableRedeemShares += shares;

    return assets;
}

// Add custom error at contract level:
error InsufficientVaultBalance(uint256 available, uint256 required);
```

This forces the investment manager to call `withdrawFromInvestment()` before fulfilling redemptions if the vault lacks sufficient balance, maintaining the invariant that reserved assets never exceed available balance.

## Proof of Concept

```solidity
// File: test/Exploit_FulfillWithoutBalance.t.sol
// Run with: forge test --match-test test_FulfillWithoutBalance -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";

contract Exploit_FulfillWithoutBalance is Test {
    WERC7575Vault vault;
    WERC7575ShareToken shareToken;
    MockERC20 usdc;
    MockInvestmentVault investmentVault;
    
    address investmentManager = address(0x1);
    address user1 = address(0x2);
    address user2 = address(0x3);
    
    function setUp() public {
        // Deploy mock USDC (6 decimals)
        usdc = new MockERC20("USDC", "USDC", 6);
        
        // Deploy shareToken and vault
        shareToken = new WERC7575ShareToken();
        vault = new WERC7575Vault();
        
        // Initialize
        shareToken.initialize(address(this), address(this), address(this), "ShareToken", "SHARE");
        vault.initialize(address(shareToken), address(usdc), investmentManager, "Vault", "vUSDC");
        
        // Setup investment vault
        investmentVault = new MockInvestmentVault(address(usdc));
        vault.setInvestmentVault(address(investmentVault));
        
        // Mint initial USDC and deposit
        usdc.mint(address(vault), 1000e6);
        vault.fulfillDeposit(user1, 1000e6); // User1 gets 1000 shares
    }
    
    function test_FulfillWithoutBalance() public {
        // SETUP: Initial state
        assertEq(vault.totalAssets(), 1000e6, "Initial totalAssets should be 1000 USDC");
        assertEq(shareToken.balanceOf(user1), 1000e18, "User1 should have 1000 shares");
        
        // STEP 1: Investment manager invests 900 USDC
        vm.prank(investmentManager);
        vault.investAssets(900e6);
        
        assertEq(usdc.balanceOf(address(vault)), 100e6, "Vault balance should be 100 USDC after investment");
        assertEq(vault.totalAssets(), 100e6, "totalAssets reflects only vault balance");
        
        // STEP 2: User1 requests redemption of 800 shares
        vm.prank(user1);
        vault.requestRedeem(800e18, user1, user1);
        
        // STEP 3: Investment manager fulfills redemption WITHOUT withdrawing from investment
        vm.prank(investmentManager);
        vault.fulfillRedeem(user1, 800e18);
        
        // VERIFY: Vault balance (100) < claimableRedeemAssets (800)
        assertEq(vault.totalClaimableRedeemAssets(), 800e6, "Should owe 800 USDC");
        assertEq(usdc.balanceOf(address(vault)), 100e6, "Vault only has 100 USDC");
        
        // VERIFY: totalAssets() returns 0
        assertEq(vault.totalAssets(), 0, "VULNERABILITY: totalAssets() returns 0!");
        
        // VERIFY: Conversion rates are broken
        uint256 sharesBefore = shareToken.convertToShares(100e6);
        
        // User2 tries to deposit 100 USDC - gets far fewer shares than deserved
        usdc.mint(user2, 100e6);
        vm.startPrank(user2);
        usdc.approve(address(vault), 100e6);
        vault.deposit(100e6, user2);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        vault.fulfillDeposit(user2, 100e6);
        
        uint256 user2Shares = shareToken.balanceOf(user2);
        
        // User2 should get ~100 shares but gets much less due to broken conversion
        assertLt(user2Shares, 30e18, "User2 gets < 30 shares instead of 100 (>70% loss)");
        
        // Remaining user can redeem with inflated rate
        uint256 user1Remaining = shareToken.balanceOf(user1); // 200 shares left
        vm.prank(user1);
        vault.requestRedeem(user1Remaining, user1, user1);
        
        vm.prank(investmentManager);
        investmentVault.withdrawToVault(address(vault), 500e6); // Withdraw to cover redemption
        
        vm.prank(investmentManager);
        uint256 assetsForRemaining = vault.fulfillRedeem(user1, user1Remaining);
        
        // User1's remaining 200 shares are worth far more than they should be
        assertGt(assetsForRemaining, 400e6, "200 shares valued at >400 USDC (should be ~200)");
    }
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockInvestmentVault {
    address public asset;
    constructor(address _asset) { asset = _asset; }
    
    function deposit(uint256 amount, address) external returns (uint256) {
        MockERC20(asset).transferFrom(msg.sender, address(this), amount);
        return amount;
    }
    
    function withdrawToVault(address vault, uint256 amount) external {
        MockERC20(asset).transfer(vault, amount);
    }
    
    function share() external view returns (address) {
        return address(this);
    }
}
```

## Notes

This vulnerability demonstrates a critical flaw in the async redemption flow where the fulfillment step does not validate that promised assets can actually be delivered. The issue is particularly severe because:

1. **Systemic Impact**: The broken `totalAssets()` affects the global conversion rate calculation in `ShareTokenUpgradeable.getCirculatingSupplyAndAssets()`, impacting ALL vaults in the multi-asset system, not just the one that triggered the issue.

2. **Normal Operations Trigger It**: This isn't a malicious exploit - it occurs during routine protocol operations when the investment manager follows the natural workflow of investing assets and then fulfilling redemptions.

3. **Silent Failure**: The vault continues operating after `totalAssets()` returns 0, but with catastrophically incorrect conversion rates that directly steal from depositors and overpay redeemers.

4. **Protected by Design Intent**: The `totalAssets()` underflow protection (returning 0 instead of reverting) was meant to handle edge cases gracefully, but instead enables this vulnerability to persist silently.

The fix requires adding a simple balance check in `fulfillRedeem()` to maintain the critical invariant that reserved assets never exceed available vault balance.

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

**File:** src/ERC7575VaultUpgradeable.sol (L1448-1465)
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
    }
```

**File:** src/ShareTokenUpgradeable.sol (L369-390)
```text
    function getCirculatingSupplyAndAssets() external view returns (uint256 circulatingSupply, uint256 totalNormalizedAssets) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        uint256 totalClaimableShares = 0;
        uint256 length = $.assetToVault.length();

        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Get both claimable shares and normalized assets in a single call for gas efficiency
            (uint256 vaultClaimableShares, uint256 vaultNormalizedAssets) = IERC7575Vault(vaultAddress).getClaimableSharesAndNormalizedAssets();
            totalClaimableShares += vaultClaimableShares;
            totalNormalizedAssets += vaultNormalizedAssets;
        }

        // Add invested assets from the investment ShareToken (if configured)
        totalNormalizedAssets += _calculateInvestmentAssets();

        // Get total supply
        uint256 supply = totalSupply();
        // Calculate circulating supply: total supply minus vault-held shares for redemption claims
        circulatingSupply = totalClaimableShares > supply ? 0 : supply - totalClaimableShares;
    }
```

**File:** src/ShareTokenUpgradeable.sol (L701-711)
```text
    function convertNormalizedAssetsToShares(uint256 normalizedAssets, Math.Rounding rounding) external view returns (uint256 shares) {
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = this.getCirculatingSupplyAndAssets();

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;
        totalNormalizedAssets += VIRTUAL_ASSETS;

        // shares = normalizedAssets * circulatingSupply / totalNormalizedAssets
        shares = Math.mulDiv(normalizedAssets, circulatingSupply, totalNormalizedAssets, rounding);
    }
```

**File:** src/ShareTokenUpgradeable.sol (L727-737)
```text
    function convertSharesToNormalizedAssets(uint256 shares, Math.Rounding rounding) external view returns (uint256 normalizedAssets) {
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = this.getCirculatingSupplyAndAssets();

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;
        totalNormalizedAssets += VIRTUAL_ASSETS;

        // normalizedAssets = shares * totalNormalizedAssets / circulatingSupply
        normalizedAssets = Math.mulDiv(shares, totalNormalizedAssets, circulatingSupply, rounding);
    }
```
