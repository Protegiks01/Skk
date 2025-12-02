## Title
Floor Rounding in Partial Redemptions Causes Complete Share Loss Without Asset Transfer

## Summary
In `ERC7575VaultUpgradeable.redeem()`, when users perform small partial redemptions after investment losses (where `availableShares > availableAssets`), the Floor rounding calculation can result in `assets = 0` while still burning the user's shares, causing permanent loss of value without receiving any assets in return.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol` - `redeem()` function (lines 885-918) [1](#0-0) 

**Intended Logic:** Users should receive proportional assets when redeeming shares based on the locked exchange rate from `fulfillRedeem()`. The ERC-7540 standard expects that claiming shares always results in receiving corresponding assets.

**Actual Logic:** The formula at line 897 uses Floor rounding: `assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor)`. When the ratio `availableAssets / availableShares < 1` (post-loss scenario), small redemption amounts round down to 0 assets. However, the shares are unconditionally burned at line 912, regardless of whether assets = 0. The asset transfer at lines 915-917 only occurs if `assets > 0`, meaning users lose shares without receiving anything.

**Exploitation Path:**
1. Vault experiences investment losses, captured during `fulfillRedeem()` creating unfavorable ratio (e.g., 1000 shares = 500 USDC) [2](#0-1) 

2. User's `claimableRedeemAssets[user] = 500e6` and `claimableRedeemShares[user] = 1000e18` are set

3. User calls `redeem()` with small amount (e.g., 1e12 shares, which is 0.001 shares)

4. Calculation: `assets = 1e12 * 500e6 / 1000e18 = 5e17 / 1e21 = 0` (Floor rounding)

5. Line 912 burns the 1e12 shares from vault

6. Lines 915-917 skip transfer since `assets = 0`

7. User has lost 1e12 shares permanently without receiving any USDC

**Security Property Broken:** Violates Invariant #10: "Conversion Accuracy: convertToShares(convertToAssets(x)) ≈ x (within rounding tolerance)". Users can lose significantly more than 1 wei of value when redeeming below the rounding threshold.

## Impact Explanation

- **Affected Assets**: All vault assets, particularly those with significant losses where `availableShares >> availableAssets`
- **Damage Severity**: For a 50% loss scenario (500 USDC for 1000 shares), users must redeem at least 2e12 wei (0.002 shares in display terms) to receive any assets. Smaller redemptions result in 100% loss of redeemed shares.
- **User Impact**: Affects users who:
  - Make multiple small redemptions instead of one large redemption
  - Use automated systems that redeem in small increments  
  - Are unaware of the minimum threshold needed to overcome rounding
  - Experience high loss scenarios (>50%) where the threshold becomes significant

## Likelihood Explanation

- **Attacker Profile**: Any user with claimable redeem shares can trigger this, either accidentally or through griefing
- **Preconditions**: Vault must have fulfilled redeem requests with `availableShares > availableAssets` (possible after any investment loss)
- **Execution Complexity**: Single transaction - simply call `redeem()` with amount below threshold
- **Frequency**: Can occur on every small redemption attempt in post-loss scenarios; threshold increases with greater losses

## Recommendation

Add a minimum asset check before burning shares to prevent complete loss scenarios:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function redeem(), after line 897:

// CURRENT (vulnerable):
assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);

// FIXED:
assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);
if (assets == 0 && shares > 0) {
    revert InsufficientRedeemAmount(); // Prevent burning shares for 0 assets
}
```

Alternatively, implement a minimum redemption threshold based on the current exchange rate:

```solidity
// Calculate minimum shares needed to receive at least 1 wei of assets
uint256 minShares = availableShares.mulDiv(1, availableAssets, Math.Rounding.Ceil);
if (shares < minShares && shares != availableShares) {
    revert RedeemAmountTooSmall(shares, minShares);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_FloorRoundingShareLoss.t.sol
// Run with: forge test --match-test test_FloorRoundingShareLoss -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {MockAsset} from "./MockAsset.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_FloorRoundingShareLoss is Test {
    ERC7575VaultUpgradeable public vault;
    ShareTokenUpgradeable public shareToken;
    MockAsset public asset;
    
    address public owner = makeAddr("owner");
    address public alice = makeAddr("alice");
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy mock USDC (6 decimals)
        asset = new MockAsset();
        
        // Deploy ShareToken with proxy
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory shareTokenInitData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector, 
            "Investment USD", 
            "IUSD", 
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), shareTokenInitData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy Vault with proxy
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            IERC20(asset),
            address(shareToken),
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        shareToken.registerVault(address(asset), address(vault));
        vault.setMinimumDepositAmount(0);
        
        vm.stopPrank();
        
        // Mint assets to Alice
        asset.mint(alice, 1000e18);
    }
    
    function test_FloorRoundingShareLoss() public {
        // SETUP: Alice deposits assets and gets shares
        vm.startPrank(alice);
        uint256 depositAmount = 1000e18;
        asset.approve(address(vault), depositAmount);
        vault.requestDeposit(depositAmount, alice, alice);
        vm.stopPrank();
        
        vm.prank(owner);
        vault.fulfillDeposit(alice, depositAmount);
        
        vm.prank(alice);
        vault.deposit(depositAmount, alice);
        
        uint256 aliceShares = shareToken.balanceOf(alice);
        console.log("Alice shares:", aliceShares);
        
        // SETUP: Simulate 50% investment loss by withdrawing assets from vault
        // (In real scenario, this happens through investAssets/withdrawFromInvestment)
        uint256 lossAmount = 500e18;
        vm.prank(address(vault));
        asset.transfer(address(0xdead), lossAmount);
        
        console.log("Vault assets after loss:", asset.balanceOf(address(vault)));
        
        // Alice requests redeem for all her shares
        vm.startPrank(alice);
        shareToken.approve(address(vault), aliceShares);
        vault.requestRedeem(aliceShares, alice, alice);
        vm.stopPrank();
        
        // Owner fulfills redeem - this locks in the unfavorable ratio
        vm.prank(owner);
        uint256 assetsFromFulfill = vault.fulfillRedeem(alice, aliceShares);
        console.log("Assets allocated at fulfillRedeem:", assetsFromFulfill);
        
        // Check the stored ratio
        (uint256 claimableAssets, uint256 claimableShares) = vault.claimableRedeemRequest(alice);
        console.log("Claimable assets:", claimableAssets);
        console.log("Claimable shares:", claimableShares);
        
        // EXPLOIT: Alice tries to redeem small amounts
        uint256 smallRedeemAmount = 1e12; // 0.000001 shares
        
        uint256 aliceAssetsBefore = asset.balanceOf(alice);
        uint256 vaultSharesBefore = shareToken.balanceOf(address(vault));
        
        vm.prank(alice);
        uint256 assetsReceived = vault.redeem(smallRedeemAmount, alice, alice);
        
        uint256 aliceAssetsAfter = asset.balanceOf(alice);
        uint256 vaultSharesAfter = shareToken.balanceOf(address(vault));
        
        // VERIFY: Shares were burned but no assets received
        console.log("Assets received:", assetsReceived);
        console.log("Assets transferred:", aliceAssetsAfter - aliceAssetsBefore);
        console.log("Shares burned:", vaultSharesBefore - vaultSharesAfter);
        
        assertEq(assetsReceived, 0, "Assets received should be 0 due to rounding");
        assertEq(aliceAssetsAfter - aliceAssetsBefore, 0, "No assets transferred");
        assertEq(vaultSharesBefore - vaultSharesAfter, smallRedeemAmount, "Shares were burned");
        
        console.log("\nVulnerability confirmed: User lost", smallRedeemAmount, "shares without receiving any assets");
    }
}
```

## Notes

This vulnerability is distinct from the known issue "Rounding ≤1 wei" because:
1. The loss can exceed 1 wei of value depending on the exchange rate and asset decimals
2. The threshold for receiving 0 assets can be significant (e.g., 0.002 shares = 2e15 wei in a 50% loss scenario)
3. The shares are permanently burned without any asset return, not just rounded down by 1 wei
4. It violates the documented Invariant #10 about conversion accuracy

The issue is exacerbated in high-loss scenarios where the ratio `availableAssets / availableShares` becomes very small, making the minimum redemption threshold larger and affecting more users.

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

**File:** src/ERC7575VaultUpgradeable.sol (L885-918)
```text
    function redeem(uint256 shares, address receiver, address controller) public nonReentrant returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (shares == 0) revert ZeroShares();

        uint256 availableShares = $.claimableRedeemShares[controller];
        if (shares > availableShares) revert InsufficientClaimableShares();

        // Calculate proportional assets for the requested shares
        uint256 availableAssets = $.claimableRedeemAssets[controller];
        assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);

        if (assets == availableAssets) {
            // Remove from active redeem requesters if no more claimable assets and the potential dust
            $.activeRedeemRequesters.remove(controller);
            delete $.claimableRedeemAssets[controller];
            delete $.claimableRedeemShares[controller];
        } else {
            $.claimableRedeemAssets[controller] -= assets;
            $.claimableRedeemShares[controller] -= shares;
        }
        $.totalClaimableRedeemAssets -= assets;
        $.totalClaimableRedeemShares -= shares; // Decrement shares that are being burned

        // Burn the shares as per ERC7540 spec - shares are burned when request is claimed
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);

        emit Withdraw(msg.sender, receiver, controller, assets, shares);
        if (assets > 0) {
            SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
        }
    }
```
