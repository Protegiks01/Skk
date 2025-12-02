## Title
Share Trapping via Zero-Asset Fulfillment in Low-Decimal Vaults

## Summary
In `ERC7575VaultUpgradeable.fulfillRedeem()`, when the investment manager fulfills redeem requests for small share amounts in low-decimal asset vaults (e.g., USDC with 6 decimals), the `_convertToAssets()` denormalization can round down to zero assets. The function lacks validation to prevent zero-asset fulfillments, allowing shares to enter the claimable state with 0 corresponding assets. Users cannot cancel claimable requests, and claiming burns their shares while transferring 0 assets, resulting in permanent loss of funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `fulfillRedeem()` function (lines 822-841), specifically the missing validation after `_convertToAssets()` call at line 831. [1](#0-0) 

**Intended Logic:** The `fulfillRedeem()` function should convert pending redeem shares to a proportional amount of assets that users can later claim. The conversion should maintain the economic value of shares through the async redemption lifecycle.

**Actual Logic:** When `_convertToAssets()` is called with small share amounts in low-decimal vaults (USDC = 6 decimals, `scalingFactor = 10^12`), the denormalization step divides `normalizedAssets` by `scalingFactor`. If `normalizedAssets < scalingFactor`, the floor rounding returns 0 assets. [2](#0-1) 

The function proceeds to update state with `assets = 0`: [3](#0-2) 

**Exploitation Path:**
1. **Setup**: USDC vault (6 decimals) with `scalingFactor = 10^12` established during initialization [4](#0-3) 

2. **Request**: User calls `requestRedeem(smallShares, controller, owner)` where the share value when converted results in `normalizedAssets < 10^12` [5](#0-4) 

3. **Fulfill with Zero**: Investment manager calls `fulfillRedeem(controller, smallShares)`. The conversion at line 831 returns `assets = 0` due to rounding down when `normalizedAssets / 10^12 < 1`. State is updated with `claimableRedeemAssets[controller] = 0` and `claimableRedeemShares[controller] = smallShares`.

4. **Cannot Cancel**: User cannot cancel the request because cancelation only works on pending requests, not claimable ones [6](#0-5) 

5. **Forced Loss**: User must claim via `redeem(shares, receiver, controller)`. The function calculates proportional assets (which is 0), burns the shares, but transfers 0 assets to the user [7](#0-6) 

**Security Property Broken:** 
- Invariant #10: "Conversion Accuracy: convertToShares(convertToAssets(x)) ≈ x" - violated as shares map to 0 assets
- Invariant #12: "No Fund Theft" - users lose shares with no asset recovery mechanism

## Impact Explanation
- **Affected Assets**: All low-decimal asset vaults (USDC, USDT = 6 decimals). Any user with small share amounts becomes vulnerable.
- **Damage Severity**: Complete loss of share value for affected redemptions. In a USDC vault, shares representing any value that normalizes to less than `10^12` (< 1 micro-USDC in 18-decimal representation) will round to 0 assets.
- **User Impact**: 
  - Users with dust share amounts from partial deposits/redeems
  - Users with shares in vaults that have experienced significant losses (unfavorable exchange rate)
  - Any redemption where `shares * totalNormalizedAssets / circulatingSupply < scalingFactor`
  - Once fulfilled with 0 assets, shares are permanently trapped in claimable state with no recovery path

## Likelihood Explanation
- **Attacker Profile**: Not an active attack - this is a protocol design flaw affecting normal users. However, a malicious investment manager could deliberately fulfill small-share redeems to trap user funds.
- **Preconditions**: 
  - Vault using low-decimal assets (USDC, USDT = 6 decimals)
  - User has requested redeem with share amount where conversion yields `normalizedAssets < 10^12`
  - Investment manager fulfills the request
- **Execution Complexity**: Single transaction by investment manager (trusted role, but issue affects user funds)
- **Frequency**: Can occur for any small-share redemption in 6-decimal vaults. Dust amounts naturally accumulate through normal protocol usage.

## Recommendation

Add validation in `fulfillRedeem()` to prevent zero-asset fulfillments:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function fulfillRedeem, after line 831:

// CURRENT (vulnerable):
assets = _convertToAssets(shares, Math.Rounding.Floor);

$.pendingRedeemShares[controller] -= shares;
$.claimableRedeemAssets[controller] += assets;

// FIXED:
assets = _convertToAssets(shares, Math.Rounding.Floor);

// Prevent zero-asset fulfillments that would trap user shares
if (assets == 0) revert ZeroAssetsCalculated();

$.pendingRedeemShares[controller] -= shares;
$.claimableRedeemAssets[controller] += assets;
```

**Alternative Solution**: Implement minimum redemption amounts per vault based on asset decimals, or allow users to cancel claimable requests if assets calculated to zero.

## Proof of Concept

```solidity
// File: test/Exploit_ZeroAssetRedeemTrap.t.sol
// Run with: forge test --match-test test_ZeroAssetRedeemTrap -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/WERC7575Vault.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {
        _mint(msg.sender, 1000000e6); // 1M USDC
    }
    
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

contract Exploit_ZeroAssetRedeemTrap is Test {
    WERC7575Vault vault;
    ShareTokenUpgradeable shareToken;
    MockUSDC usdc;
    
    address owner = address(1);
    address investmentManager = address(2);
    address victim = address(3);
    
    function setUp() public {
        // Deploy contracts
        usdc = new MockUSDC();
        
        // Deploy ShareToken implementation and proxy
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(
            address(shareTokenImpl),
            abi.encodeCall(ShareTokenUpgradeable.initialize, ("SukukFi Share", "SKFS", owner))
        );
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy Vault implementation and proxy
        WERC7575Vault vaultImpl = new WERC7575Vault();
        ERC1967Proxy vaultProxy = new ERC1967Proxy(
            address(vaultImpl),
            abi.encodeCall(WERC7575Vault.initialize, (usdc, address(shareToken), owner))
        );
        vault = WERC7575Vault(address(vaultProxy));
        
        // Setup: register vault, set investment manager
        vm.startPrank(owner);
        shareToken.registerVault(address(usdc), address(vault));
        vault.setInvestmentManager(investmentManager);
        vm.stopPrank();
        
        // Fund vault and victim
        usdc.transfer(address(vault), 1000000e6); // 1M USDC to vault
        usdc.transfer(victim, 1000e6); // 1000 USDC to victim
    }
    
    function test_ZeroAssetRedeemTrap() public {
        // SETUP: Victim deposits to get shares
        vm.startPrank(victim);
        usdc.approve(address(vault), 1000e6);
        vault.requestDeposit(1000e6, victim, victim);
        vm.stopPrank();
        
        // Investment manager fulfills deposit
        vm.prank(investmentManager);
        vault.fulfillDeposit(victim, 1000e6);
        
        // Victim claims shares
        vm.prank(victim);
        uint256 shares = vault.deposit(1000e6, victim, victim);
        
        console.log("Victim received shares:", shares);
        console.log("Share balance:", shareToken.balanceOf(victim));
        
        // EXPLOIT: Victim requests redeem with 1 wei of shares (dust amount)
        // Due to rounding, this will convert to 0 assets
        vm.startPrank(victim);
        shareToken.approve(address(vault), 1);
        vault.requestRedeem(1, victim, victim);
        vm.stopPrank();
        
        // Investment manager fulfills - THIS CALCULATES 0 ASSETS
        vm.prank(investmentManager);
        uint256 assetsCalculated = vault.fulfillRedeem(victim, 1);
        
        // VERIFY: Assets calculated to 0
        assertEq(assetsCalculated, 0, "Vulnerability confirmed: 0 assets calculated for non-zero shares");
        console.log("Assets calculated for 1 share:", assetsCalculated);
        
        // Check claimable state
        uint256 claimableAssets = vault.claimableRedeemRequest(0, victim);
        uint256 claimableShares = vault.claimableRedeemRequest(0, victim);
        console.log("Claimable assets:", claimableAssets); // 0
        console.log("Claimable shares:", claimableShares); // 1
        
        // Victim tries to claim - shares get burned, 0 assets received
        uint256 victimUSDCBefore = usdc.balanceOf(victim);
        vm.prank(victim);
        uint256 assetsReceived = vault.redeem(1, victim, victim);
        uint256 victimUSDCAfter = usdc.balanceOf(victim);
        
        // VERIFY: Shares burned, but 0 assets transferred
        assertEq(assetsReceived, 0, "Victim received 0 assets");
        assertEq(victimUSDCAfter - victimUSDCBefore, 0, "No USDC transferred");
        assertEq(shareToken.balanceOf(victim), shares - 1, "Share was burned");
        
        console.log("Assets received by victim:", assetsReceived);
        console.log("USDC transferred:", victimUSDCAfter - victimUSDCBefore);
        console.log("Victim's share balance after:", shareToken.balanceOf(victim));
    }
}
```

## Notes

The vulnerability stems from the interaction between:
1. The decimal normalization architecture (18-decimal shares for all asset types)
2. The lack of validation in `fulfillRedeem()` after asset conversion
3. The ERC-7887 cancellation model that only allows canceling pending (not claimable) requests

While the security question mentioned "causing ZeroAssets reverts and trapping shares," the actual vulnerability is more subtle - there is NO revert. The `fulfillRedeem()` function silently accepts 0 assets, and the later `redeem()` call also doesn't revert (it just transfers 0 assets per line 915-917). This makes the issue worse because shares are irrecoverably burned with no compensation.

The vulnerability is most severe for USDC vaults (6 decimals, `scalingFactor = 10^12`) where any `normalizedAssets < 1e12` rounds to 0. This can happen with:
- Dust share amounts (< 1e12 shares when total assets are low)
- Vaults with unfavorable exchange rates due to losses
- Normal protocol operation creating small residual balances

The error `ZeroAssetsCalculated` already exists in the codebase but is only used in the `mint()` function, not in `fulfillRedeem()` where it's critically needed.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L185-188)
```text
        // Calculate scaling factor for decimal normalization: 10^(18 - assetDecimals)
        uint256 scalingFactor = 10 ** (DecimalConstants.SHARE_TOKEN_DECIMALS - assetDecimals);
        if (scalingFactor > type(uint64).max) revert ScalingFactorTooLarge();
        $.scalingFactor = uint64(scalingFactor);
```

**File:** src/ERC7575VaultUpgradeable.sol (L715-750)
```text
    function requestRedeem(uint256 shares, address controller, address owner) external nonReentrant returns (uint256 requestId) {
        if (shares == 0) revert ZeroShares();
        VaultStorage storage $ = _getVaultStorage();

        // ERC7540 REQUIREMENT: Authorization check for redemption
        // Per spec: "Redeem Request approval of shares for a msg.sender NOT equal to owner may come
        // either from ERC-20 approval over the shares of owner or if the owner has approved the
        // msg.sender as an operator."
        bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
        if (!isOwnerOrOperator) {
            ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
        }

        uint256 ownerShares = IERC20Metadata($.shareToken).balanceOf(owner);
        if (ownerShares < shares) {
            revert ERC20InsufficientBalance(owner, ownerShares, shares);
        }

        // ERC7887: Block new redeem requests while cancelation is pending for this controller
        if ($.controllersWithPendingRedeemCancelations.contains(controller)) {
            revert RedeemCancelationPending();
        }

        // Pull-Then-Credit pattern: Transfer shares first before updating state
        // This ensures we only credit shares that have been successfully received
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }

        // State changes after successful transfer
        $.pendingRedeemShares[controller] += shares;
        $.activeRedeemRequesters.add(controller);

        // Event emission
        emit RedeemRequest(controller, owner, REQUEST_ID, msg.sender, shares);
        return REQUEST_ID;
```

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

**File:** src/ERC7575VaultUpgradeable.sol (L1204-1216)
```text
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        uint256 scaling = $.scalingFactor;
        // Use optimized ShareToken conversion method (single call instead of multiple)
        uint256 normalizedAssets = ShareTokenUpgradeable($.shareToken).convertSharesToNormalizedAssets(shares, rounding);

        // Then denormalize back to original asset decimals
        if (scaling == 1) {
            return normalizedAssets;
        } else {
            return Math.mulDiv(normalizedAssets, 1, scaling, rounding);
        }
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1745-1764)
```text
    function cancelRedeemRequest(uint256 requestId, address controller) external nonReentrant {
        VaultStorage storage $ = _getVaultStorage();
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 pendingShares = $.pendingRedeemShares[controller];
        if (pendingShares == 0) revert NoPendingCancelRedeem();

        // Move from pending to pending cancelation
        delete $.pendingRedeemShares[controller];
        $.pendingCancelRedeemShares[controller] = pendingShares;

        // Block new redeem requests
        $.controllersWithPendingRedeemCancelations.add(controller);
        $.activeRedeemRequesters.remove(controller);

        emit CancelRedeemRequest(controller, controller, REQUEST_ID, msg.sender, pendingShares);
    }
```
