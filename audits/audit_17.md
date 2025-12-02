## Title
Missing Zero-Assets Validation in redeem() Allows Share Burning Without Asset Transfer

## Summary
The `redeem()` function in `ERC7575VaultUpgradeable` lacks validation to prevent burning shares when proportional asset calculation rounds down to zero. Unlike the protected `mint()` function which reverts on zero asset calculations, `redeem()` will burn user shares even when they receive no assets in return, causing permanent loss of user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `redeem()` function (lines 885-918)

**Intended Logic:** When users claim their redeemed assets, they should receive a proportional amount of assets for their shares. The shares are burned and the equivalent asset value is transferred to the user, maintaining the principle that users receive fair value for their redeemed shares.

**Actual Logic:** The function calculates proportional assets using floor rounding, but fails to validate if the result is zero before burning shares. This allows shares to be burned without any asset transfer, effectively stealing user value. [1](#0-0) 

The shares are always burned regardless of the calculated asset amount: [2](#0-1) 

**Exploitation Path:**
1. User has fulfilled redemption with unfavorable ratio (e.g., `claimableRedeemAssets[user] = 99`, `claimableRedeemShares[user] = 990`)
2. User calls `redeem(1 share, receiver, controller)` to claim a small portion
3. Proportional calculation: `assets = (1 * 99) / 990 = 0.099...` → rounds down to 0
4. Line 912 burns 1 share from vault unconditionally
5. Lines 915-917 skip asset transfer because `assets == 0`
6. User permanently loses 1 share's worth of value with no compensation

**Security Property Broken:** 
- **Invariant #12 (No Fund Theft)**: User shares are destroyed without receiving corresponding asset value
- **Conversion Accuracy**: The system fails to maintain proportional value exchange when rounding causes zero asset calculations

**Inconsistency with mint() function:** The deposit claim function `mint()` explicitly protects against this scenario: [3](#0-2) 

This same protection is conspicuously absent from `redeem()`.

## Impact Explanation
- **Affected Assets**: All vault assets (USDC, DAI, or any ERC-20 token) are vulnerable
- **Damage Severity**: Users can lose partial or complete redemption value depending on the ratio of available assets to shares. With unfavorable ratios, even 1 share represents real economic value that is permanently destroyed
- **User Impact**: Any user performing partial redemption claims where the proportional calculation rounds to zero. This is particularly likely after multiple partial claims that create unfavorable ratios, or in vaults with poor exchange rates

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a user-facing bug that causes self-harm through normal protocol usage
- **Preconditions**: 
  - User has claimable redemption with ratio where `shares * availableAssets < availableShares`
  - User attempts to claim small portion of their redemption
  - Can occur naturally after partial claims or with low-value assets
- **Execution Complexity**: Single transaction calling `redeem()` with small share amount
- **Frequency**: Can happen repeatedly for any user with claimable redemptions in unfavorable ratio states

## Recommendation

Add zero-assets validation identical to the `mint()` function:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function redeem(), after line 897:

// CURRENT (vulnerable):
assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);

if (assets == availableAssets) {
    // Remove from active redeem requesters...

// FIXED:
assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);
if (assets == 0) revert ZeroAssetsCalculated(); // Add this validation

if (assets == availableAssets) {
    // Remove from active redeem requesters...
```

This change ensures consistency with the `mint()` function's protection and prevents users from losing shares when rounding causes zero asset calculations.

## Proof of Concept
```solidity
// File: test/Exploit_RedeemZeroAssets.t.sol
// Run with: forge test --match-test test_RedeemZeroAssets -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("USD Coin", "USDC") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract Exploit_RedeemZeroAssets is Test {
    ERC7575VaultUpgradeable vault;
    WERC7575ShareToken shareToken;
    MockUSDC usdc;
    
    address user = address(0x1);
    address investmentManager = address(0x2);
    
    function setUp() public {
        // Deploy contracts
        usdc = new MockUSDC();
        shareToken = new WERC7575ShareToken();
        vault = new ERC7575VaultUpgradeable();
        
        // Initialize vault with USDC
        vault.initialize(address(usdc), address(shareToken), investmentManager, "USDC Vault", 1000);
        
        // Setup: Create unfavorable ratio state
        // Simulate fulfilled redemption with poor ratio
        usdc.mint(address(vault), 99); // 99 USDC assets
        
        // Manually set claimable state (in real scenario, this comes from fulfillRedeem)
        vm.store(
            address(vault),
            keccak256(abi.encode(user, uint256(keccak256("erc7575.vault.storage")) + 12)), // claimableRedeemAssets slot
            bytes32(uint256(99))
        );
        vm.store(
            address(vault),
            keccak256(abi.encode(user, uint256(keccak256("erc7575.vault.storage")) + 13)), // claimableRedeemShares slot
            bytes32(uint256(990))
        );
        
        // Vault holds 990 shares that will be burned
        shareToken.mint(address(vault), 990);
    }
    
    function test_RedeemZeroAssets() public {
        // SETUP: User has claimable redemption with unfavorable 99:990 ratio
        uint256 sharesBefore = shareToken.balanceOf(address(vault));
        uint256 assetsBefore = usdc.balanceOf(user);
        
        assertEq(sharesBefore, 990, "Vault should hold 990 shares");
        assertEq(assetsBefore, 0, "User should have no assets initially");
        
        // EXPLOIT: User redeems 1 share, expecting proportional assets
        vm.prank(user);
        uint256 assetsReceived = vault.redeem(1, user, user);
        
        // VERIFY: Vulnerability confirmed
        uint256 sharesAfter = shareToken.balanceOf(address(vault));
        uint256 assetsAfter = usdc.balanceOf(user);
        
        assertEq(assetsReceived, 0, "Calculated assets rounded to 0");
        assertEq(sharesAfter, 989, "1 share was burned from vault");
        assertEq(assetsAfter, 0, "User received 0 assets");
        assertEq(sharesBefore - sharesAfter, 1, "User lost 1 share");
        assertEq(assetsAfter - assetsBefore, 0, "User gained 0 assets");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("User redeemed 1 share but received 0 assets");
        console.log("Share was burned but no value transferred");
    }
}
```

**Notes:**
- This vulnerability exists because `redeem()` lacks the zero-assets check that protects the symmetric `mint()` function
- The issue is exacerbated by Solidity's floor rounding in division operations
- Users have no way to detect this before calling `redeem()` since the calculation happens inside the function
- The `withdraw()` function has a related but opposite issue: it can transfer assets without burning shares when the shares calculation rounds to zero, but that's a separate vulnerability

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L646-647)
```text
        assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);
        if (assets == 0) revert ZeroAssetsCalculated();
```

**File:** src/ERC7575VaultUpgradeable.sol (L890-897)
```text
        if (shares == 0) revert ZeroShares();

        uint256 availableShares = $.claimableRedeemShares[controller];
        if (shares > availableShares) revert InsufficientClaimableShares();

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
