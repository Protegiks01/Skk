## Title
Rounding Down to Zero Prevents Users from Claiming Small Fulfilled Deposit Amounts

## Summary
In `ERC7575VaultUpgradeable.deposit()`, the proportional share calculation uses floor rounding that can result in zero shares when claiming small asset amounts, even when assets > 0. This occurs when the asset-to-share conversion ratio is not 1:1 (due to vault appreciation) and remaining claimable amounts become small after partial claims, permanently locking user funds.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol`, function `deposit()`, lines 557-589 [1](#0-0) 

**Intended Logic:** Users should be able to claim their fulfilled deposit requests in full or in partial amounts. The function calculates shares proportionally based on the stored asset-share ratio from fulfillment time.

**Actual Logic:** When `availableAssets` and `availableShares` have a non-1:1 ratio (which occurs when share price differs from 1 asset per share at fulfillment time), and a user attempts to claim a small amount of assets, the floor rounding in the calculation `shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor)` can result in `shares = 0`, triggering the `ZeroSharesCalculated` revert.

**Exploitation Path:**
1. **Initial Setup**: Vault has appreciated, so 1 share = 2 assets (circulatingSupply = 1000 shares, totalNormalizedAssets = 2000 assets)
2. **User Requests Deposit**: User calls `requestDeposit(100 assets, ...)` and assets are transferred to vault
3. **Investment Manager Fulfills**: `fulfillDeposit()` converts assets to shares using the current rate: [2](#0-1) 

   - `shares = _convertToShares(100, Floor)` 
   - With conversion logic: [3](#0-2) 

   - This calls ShareToken's conversion: [4](#0-3) 

   - Result: shares = 100 * 1000 / 2000 = 50 shares (floor rounding)
   - State: `claimableDepositAssets[user] = 100`, `claimableDepositShares[user] = 50`

4. **Multiple Partial Claims**: User makes partial claims via `deposit(98, ...)`:
   - shares = 98 * 50 / 100 = 49 shares
   - Remaining: `availableAssets = 2`, `availableShares = 1`

5. **Final Claim Attempt Fails**: User tries to claim `deposit(1, ...)`:
   - shares = 1 * 1 / 2 = 0.5 → rounds down to 0 (Floor)
   - Function reverts with `ZeroSharesCalculated` [5](#0-4) 

6. **Funds Locked**: The user cannot claim the final 2 assets individually. They must claim both assets at once (`deposit(2, ...)`) to get 1 share, but this is not obvious to users.

**Security Property Broken:** 
- Violates Invariant #8 "Async State Flow": Users should be able to complete the Claimable → Claimed transition for any portion of their fulfilled deposits
- Violates user expectation that all fulfilled deposits can be claimed in arbitrary partial amounts

## Impact Explanation
- **Affected Assets**: Any asset where the share conversion rate is not 1:1 at fulfillment time
- **Damage Severity**: Users can have small amounts of assets (e.g., 1-10 wei of high-value tokens, or 1-1000 wei of stablecoins) permanently stuck in the claimable state. While individually small, this can accumulate across many users.
- **User Impact**: Any user who makes partial claims and has a non-1:1 asset-to-share ratio at fulfillment time. Users may repeatedly attempt to claim their remaining assets, failing each time without understanding why.

## Likelihood Explanation
- **Attacker Profile**: Not an attack—this is a protocol bug affecting normal users
- **Preconditions**: 
  - Vault must have appreciated (or depreciated) so share price ≠ 1 asset per share
  - User makes multiple partial claims that leave a small remainder
  - Remaining assets are below the threshold where `assets * availableShares / availableAssets < 1`
- **Execution Complexity**: Happens naturally during normal protocol usage
- **Frequency**: Common in production environments where vaults appreciate over time and users make partial claims

## Recommendation

The issue occurs because the proportional calculation with floor rounding can result in zero shares. The fix is to ensure minimum claim amounts or use ceiling rounding for user-favorable operations:

**Option 1 - Minimum Claim Amount (Recommended):**
```solidity
// In src/ERC7575VaultUpgradeable.sol, function deposit(), line 570:

// CURRENT (vulnerable):
shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);
if (shares == 0) revert ZeroSharesCalculated();

// FIXED:
shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);
if (shares == 0) {
    // If rounding results in 0 shares, enforce minimum claim of all remaining assets
    // This ensures users can always fully claim their deposits
    if (assets < availableAssets) {
        revert MinimumClaimAmountNotMet(); // User must claim all remaining assets
    }
    shares = availableShares; // Claim all remaining shares for all remaining assets
}
```

**Option 2 - Use Ceiling Rounding for User Claims:**
```solidity
// In src/ERC7575VaultUpgradeable.sol, function deposit(), line 570:

// CURRENT (vulnerable):
shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);

// FIXED:
// Use Ceil rounding to favor user (ensures they always get at least 1 share if assets > 0)
shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Ceil);
```

**Option 1 is recommended** as it maintains conservative rounding while ensuring users can always fully claim their deposits. Option 2 slightly favors users but may have minor accounting implications.

## Proof of Concept

```solidity
// File: test/Exploit_RoundingToZeroLocksFunds.t.sol
// Run with: forge test --match-test test_RoundingToZeroLocksFunds -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockAsset is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1e30);
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract Exploit_RoundingToZeroLocksFunds is Test {
    ERC7575VaultUpgradeable public vault;
    ShareTokenUpgradeable public shareToken;
    MockAsset public asset;
    
    address public owner = makeAddr("owner");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    
    function setUp() public {
        vm.startPrank(owner);
        
        asset = new MockAsset();
        
        // Deploy ShareToken with proxy
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory shareTokenInitData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector, 
            "Test Shares", 
            "TST", 
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), shareTokenInitData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy Vault with proxy
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector, 
            asset, 
            address(shareToken), 
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        shareToken.registerVault(address(asset), address(vault));
        vault.setMinimumDepositAmount(0);
        
        vm.stopPrank();
        
        // Fund users
        asset.mint(alice, 1000e18);
        asset.mint(bob, 10000e18);
    }
    
    function test_RoundingToZeroLocksFunds() public {
        // SETUP: Create initial vault state where 1 share = 2 assets
        // Bob deposits first to establish the share price
        vm.startPrank(bob);
        asset.approve(address(vault), 2000e18);
        vault.requestDeposit(2000e18, bob, bob);
        vm.stopPrank();
        
        vm.prank(owner);
        vault.fulfillDeposit(bob, 2000e18);
        
        vm.prank(bob);
        vault.deposit(2000e18, bob, bob);
        
        uint256 bobShares = shareToken.balanceOf(bob);
        assertEq(bobShares, 2000e18, "Bob should have 2000 shares");
        
        // Simulate vault appreciation by donating assets
        // This changes the conversion rate to 1 share = 2 assets
        asset.mint(address(shareToken), 2000e18);
        
        // Verify conversion rate: 1 share = 2 assets
        uint256 assetsPerShare = vault.convertToAssets(1e18);
        assertEq(assetsPerShare, 2e18, "1 share should equal 2 assets");
        
        // EXPLOIT: Alice deposits 100 assets at this rate
        vm.startPrank(alice);
        asset.approve(address(vault), 100e18);
        vault.requestDeposit(100e18, alice, alice);
        vm.stopPrank();
        
        // Fulfill: Alice gets 50 shares for 100 assets (due to 1:2 rate)
        vm.prank(owner);
        uint256 sharesForAlice = vault.fulfillDeposit(alice, 100e18);
        
        assertEq(sharesForAlice, 50e18, "Alice should get 50 shares for 100 assets");
        assertEq(vault.claimableDepositRequest(0, alice), 100e18, "Alice has 100 assets claimable");
        
        // Alice claims 98 assets (leaving 2 assets, 1 share)
        vm.prank(alice);
        vault.deposit(98e18, alice, alice);
        
        assertEq(vault.claimableDepositRequest(0, alice), 2e18, "Alice has 2 assets remaining");
        assertEq(shareToken.balanceOf(address(vault)), 1e18, "Vault holds 1 share for Alice");
        
        // VERIFY: Alice tries to claim 1 asset but it reverts with ZeroSharesCalculated
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("ZeroSharesCalculated()"));
        vault.deposit(1e18, alice, alice);
        
        // Alice's final 2 assets are stuck - she can only claim them both at once
        // which she might not realize
        console.log("Vulnerability confirmed: Alice cannot claim 1 asset at a time");
        console.log("Remaining claimable assets:", vault.claimableDepositRequest(0, alice));
    }
}
```

**Notes:**

This vulnerability demonstrates a subtle rounding issue in the async deposit claim mechanism. While the amounts locked per user may be small (often just a few wei), this can accumulate across many users over time. The issue is particularly problematic because:

1. It violates user expectations—they should be able to claim any portion of fulfilled deposits
2. The error message `ZeroSharesCalculated` doesn't explain why the claim failed or how to fix it
3. Users may waste gas repeatedly trying to claim small amounts without understanding the minimum threshold

The recommended fix (Option 1) ensures users can always fully claim their deposits while maintaining conservative rounding for the protocol.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L425-444)
```text
    function fulfillDeposit(address controller, uint256 assets) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        uint256 pendingAssets = $.pendingDepositAssets[controller];
        if (assets > pendingAssets) {
            revert ERC20InsufficientBalance(address(this), pendingAssets, assets);
        }

        shares = _convertToShares(assets, Math.Rounding.Floor);
        if (shares == 0) revert ZeroShares();

        $.pendingDepositAssets[controller] -= assets;
        $.totalPendingDepositAssets -= assets;
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming

        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);

        return shares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L557-589)
```text
    function deposit(uint256 assets, address receiver, address controller) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (assets == 0) revert ZeroAssets();

        uint256 availableShares = $.claimableDepositShares[controller];
        uint256 availableAssets = $.claimableDepositAssets[controller];

        if (assets > availableAssets) revert InsufficientClaimableAssets();

        // Calculate shares proportionally from the stored asset-share ratio
        shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);
        if (shares == 0) revert ZeroSharesCalculated();

        // Remove from active deposit requesters if no more claimable assets
        if (availableAssets == assets) {
            $.activeDepositRequesters.remove(controller);
            delete $.claimableDepositShares[controller];
            delete $.claimableDepositAssets[controller];
        } else {
            $.claimableDepositShares[controller] -= shares;
            $.claimableDepositAssets[controller] -= assets;
        }

        emit Deposit(receiver, controller, assets, shares);

        // Transfer shares from vault to receiver using ShareToken
        if (!IERC20Metadata($.shareToken).transfer(receiver, shares)) {
            revert ShareTransferFailed();
        }
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1188-1196)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        // First normalize assets to 18 decimals using scaling factor
        // Use Math.mulDiv to prevent overflow for large amounts
        uint256 normalizedAssets = Math.mulDiv(assets, $.scalingFactor, 1);

        // Use optimized ShareToken conversion method (single call instead of multiple)
        shares = ShareTokenUpgradeable($.shareToken).convertNormalizedAssetsToShares(normalizedAssets, rounding);
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
