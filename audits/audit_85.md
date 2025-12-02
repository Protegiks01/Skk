## Title
Protocol Upgrade DOS: Unclaimed Redemptions Permanently Block Vault Unregistration

## Summary
The protocol enforces a hard limit of 10 vaults per share token and requires vaults to have zero claimable redemptions before unregistration. When users fail to claim fulfilled redemptions (due to lost keys, inactivity, or intentional griefing), the vault becomes permanently stuck and cannot be unregistered, blocking the protocol's ability to add new asset types or upgrade vault implementations.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` (unregisterVault function, lines 282-327) and `src/ERC7575VaultUpgradeable.sol` (redemption claim functions)

**Intended Logic:** The protocol should allow owners to unregister old vaults and register new ones to support protocol upgrades and new asset types, with the 10-vault limit serving as a DOS mitigation mechanism.

**Actual Logic:** Once the 10-vault limit is reached and any vault has unclaimed redemptions, the protocol becomes permanently locked from adding new vaults because:
1. Only users can decrease `totalClaimableRedeemAssets` by claiming their redemptions
2. No admin function exists to force claims or bypass unregistration checks
3. ERC7887 cancellation only works on pending requests, not claimable ones [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. **Initial State**: Protocol has 10 vaults registered (MAX_VAULTS_PER_SHARE_TOKEN limit reached)
2. **User Redemption**: User in Vault A requests redemption via `requestRedeem()`
3. **Fulfillment**: Investment manager fulfills redemption via `fulfillRedeem()`, moving assets to claimable state and incrementing `totalClaimableRedeemAssets` [3](#0-2) 

4. **User Inactivity**: User never claims their fulfilled redemption (lost keys, forgotten, or malicious intent)
5. **Upgrade Attempt**: Protocol owner wants to add Vault 11 for a new asset type
6. **Unregistration Blocked**: Owner attempts `unregisterVault(assetA)` but it reverts because `totalClaimableRedeemAssets != 0` [4](#0-3) 

7. **Permanent DOS**: Protocol cannot unregister any vault with unclaimed redemptions, blocking all future vault additions

**Security Property Broken:** Violates the "No DOS requiring non-trivial cost" principle - a single user with even 1 wei of unclaimed redemption can permanently block protocol upgrades at zero cost to the attacker.

## Impact Explanation
- **Affected Assets**: All protocol operations requiring new vault registration (new asset types, vault upgrades, architectural changes)
- **Damage Severity**: Complete protocol upgrade blockage. The protocol cannot:
  - Add support for new asset types beyond the initial 10
  - Replace vault implementations with upgraded versions
  - Adapt to changing market conditions or regulatory requirements
  - Generate revenue from new asset classes
- **User Impact**: All users suffer from protocol stagnation. Even a single inactive user with a small unclaimed redemption affects the entire protocol's ability to evolve.

## Likelihood Explanation
- **Attacker Profile**: Any user (unprivileged) or passive attacker. Does not require malicious intent - natural user behavior (lost keys, inactivity, small amounts forgotten) triggers this issue.
- **Preconditions**: 
  - 10 vaults registered
  - At least 1 user with fulfilled but unclaimed redemption in any vault
- **Execution Complexity**: Trivial. User simply needs to not claim their redemption. No active attack required.
- **Frequency**: Very high likelihood over protocol lifetime:
  - Users commonly lose access to wallets
  - Small amounts (<$1) are frequently abandoned
  - Users become inactive, deceased, or simply forget
  - Malicious users can intentionally grief at zero cost (request redemption, let it be fulfilled, never claim)

## Recommendation

Add an emergency admin function to handle unclaimed redemptions after a reasonable timeout period:

```solidity
// In src/ERC7575VaultUpgradeable.sol, add new state variables:

struct VaultStorage {
    // ... existing fields ...
    
    // Emergency claim timeout (e.g., 180 days)
    uint256 constant EMERGENCY_CLAIM_TIMEOUT = 180 days;
    
    // Track when redemptions were fulfilled
    mapping(address controller => uint256 fulfillmentTimestamp) redeemFulfillmentTime;
}

// Add emergency claim function (only owner):

/**
 * @dev Emergency function to claim stale redemptions after timeout
 * @param controller Address with unclaimed redemption
 * @param receiver Address to receive the assets (e.g., treasury)
 */
function emergencyClaimStaleRedemption(address controller, address receiver) 
    external 
    onlyOwner 
    nonReentrant 
    returns (uint256 assets) 
{
    VaultStorage storage $ = _getVaultStorage();
    
    uint256 claimableAssets = $.claimableRedeemAssets[controller];
    if (claimableAssets == 0) revert NoClaimableAssets();
    
    // Require sufficient time has passed since fulfillment
    uint256 fulfillmentTime = $.redeemFulfillmentTime[controller];
    if (block.timestamp < fulfillmentTime + EMERGENCY_CLAIM_TIMEOUT) {
        revert EmergencyClaimTimeoutNotReached();
    }
    
    // Execute claim on behalf of inactive user
    uint256 claimableShares = $.claimableRedeemShares[controller];
    assets = claimableAssets;
    
    // Clear state
    delete $.claimableRedeemAssets[controller];
    delete $.claimableRedeemShares[controller];
    delete $.redeemFulfillmentTime[controller];
    $.activeRedeemRequesters.remove(controller);
    
    $.totalClaimableRedeemAssets -= assets;
    $.totalClaimableRedeemShares -= claimableShares;
    
    // Burn shares and transfer assets
    ShareTokenUpgradeable($.shareToken).burn(address(this), claimableShares);
    SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
    
    emit EmergencyRedemptionClaimed(controller, receiver, assets, claimableShares);
}

// Update fulfillRedeem to track timestamp:
function fulfillRedeem(address controller, uint256 shares) public nonReentrant returns (uint256 assets) {
    // ... existing logic ...
    
    // Track fulfillment time for emergency claims
    $.redeemFulfillmentTime[controller] = block.timestamp;
    
    // ... rest of function ...
}
```

**Alternative Solution**: Allow owner to increase MAX_VAULTS_PER_SHARE_TOKEN via governance:

```solidity
// In src/ShareTokenUpgradeable.sol:

struct ShareTokenStorage {
    // ... existing fields ...
    uint256 maxVaultsPerShareToken; // Make it mutable instead of constant
}

function setMaxVaults(uint256 newMax) external onlyOwner {
    require(newMax >= $.assetToVault.length(), "Cannot decrease below current count");
    require(newMax <= 50, "Max 50 vaults for gas safety");
    $.maxVaultsPerShareToken = newMax;
    emit MaxVaultsUpdated(newMax);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_VaultUnregistrationDOS.t.sol
// Run with: forge test --match-test test_VaultUnregistrationDOS -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {ERC7575VaultUpgradeable} from "../src/ERC7575VaultUpgradeable.sol";
import {ShareTokenUpgradeable} from "../src/ShareTokenUpgradeable.sol";
import {MockERC20} from "../test/mocks/MockERC20.sol";

contract Exploit_VaultUnregistrationDOS is Test {
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable[] vaults;
    MockERC20[] assets;
    
    address owner = address(this);
    address investmentManager = address(0x1234);
    address user = address(0x5678);
    
    function setUp() public {
        // Deploy share token
        shareToken = new ShareTokenUpgradeable();
        shareToken.initialize("Share Token", "SHARE", owner);
        shareToken.setInvestmentManager(investmentManager);
        
        // Deploy and register 10 vaults (MAX_VAULTS_PER_SHARE_TOKEN)
        for (uint i = 0; i < 10; i++) {
            MockERC20 asset = new MockERC20("Asset", "AST", 18);
            assets.push(asset);
            
            ERC7575VaultUpgradeable vault = new ERC7575VaultUpgradeable();
            vault.initialize(asset, address(shareToken), owner);
            vaults.push(vault);
            
            shareToken.registerVault(address(asset), address(vault));
        }
    }
    
    function test_VaultUnregistrationDOS() public {
        // SETUP: User deposits and requests redemption in Vault 0
        MockERC20 asset0 = assets[0];
        ERC7575VaultUpgradeable vault0 = vaults[0];
        
        // Give user some assets
        asset0.mint(user, 1000e18);
        
        // User deposits
        vm.startPrank(user);
        asset0.approve(address(vault0), 1000e18);
        vault0.requestDeposit(1000e18, user, user);
        vm.stopPrank();
        
        // Investment manager fulfills deposit
        vm.prank(investmentManager);
        vault0.fulfillDeposit(user, 1000e18);
        
        // User claims shares
        vm.prank(user);
        vault0.deposit(1000e18, user, user);
        
        // User requests redemption
        uint256 userShares = shareToken.balanceOf(user);
        vm.startPrank(user);
        vault0.requestRedeem(userShares, user, user);
        vm.stopPrank();
        
        // EXPLOIT: Investment manager fulfills redemption
        vm.prank(investmentManager);
        vault0.fulfillRedeem(user, userShares);
        
        // At this point, user has claimable redemption but never claims it
        // Simulate user losing access to wallet / forgetting / being malicious
        
        // VERIFY: Protocol wants to add 11th vault but cannot
        MockERC20 newAsset = new MockERC20("New Asset", "NEW", 18);
        ERC7575VaultUpgradeable newVault = new ERC7575VaultUpgradeable();
        newVault.initialize(newAsset, address(shareToken), owner);
        
        // Attempt to register 11th vault - fails due to MAX_VAULTS limit
        vm.expectRevert();
        shareToken.registerVault(address(newAsset), address(newVault));
        
        // Owner tries to unregister Vault 0 first
        // But vault 0 has claimable redemptions that user never claimed
        
        // First, owner must set vault inactive
        vault0.setVaultActive(false);
        
        // Attempt unregistration - FAILS because totalClaimableRedeemAssets > 0
        vm.expectRevert(); // Reverts with CannotUnregisterVaultClaimableRedemptions
        shareToken.unregisterVault(address(asset0));
        
        // RESULT: Protocol is permanently DOS'd from adding new vaults
        // Even though owner controls vault activation, investment management,
        // and all admin functions, they CANNOT force user to claim or bypass
        // the unregistration check.
        
        console.log("Protocol DOS confirmed:");
        console.log("- 10 vaults registered (MAX limit reached)");
        console.log("- Vault 0 has unclaimed redemptions");
        console.log("- Cannot unregister Vault 0");
        console.log("- Cannot register new vaults");
        console.log("- Protocol upgrade permanently blocked");
    }
}
```

**Notes:**
- This vulnerability affects **both** `ShareTokenUpgradeable` (Investment Layer) and `WERC7575ShareToken` (Settlement Layer) as they both implement the same registration/unregistration logic
- The issue is not about centralization or trusted roles - it's about uncontrollable user behavior blocking critical protocol operations
- Even upgrading the contract to increase MAX_VAULTS won't help if vaults are already stuck with unclaimed redemptions
- The protocol explicitly states "No DOS requiring non-trivial cost" as an invariant violation - this issue allows DOS at zero cost

### Citations

**File:** src/ShareTokenUpgradeable.sol (L79-79)
```text
    uint256 private constant MAX_VAULTS_PER_SHARE_TOKEN = 10; // DoS mitigation: prevents unbounded loop in aggregation
```

**File:** src/ShareTokenUpgradeable.sol (L282-327)
```text
    function unregisterVault(address asset) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();

        (bool exists, address vaultAddress) = $.assetToVault.tryGet(asset);
        if (!exists) revert AssetNotRegistered();

        // COMPREHENSIVE SAFETY CHECK: Ensure vault has no user funds at risk
        // This covers pending deposits, claimable redemptions, ERC7887 cancelations, and any remaining assets

        // 1. Check vault metrics for pending requests, active users, and ERC7887 cancelation assets
        try IVaultMetrics(vaultAddress).getVaultMetrics() returns (IVaultMetrics.VaultMetrics memory metrics) {
            if (metrics.isActive) revert CannotUnregisterActiveVault();
            if (metrics.totalPendingDepositAssets != 0) {
                revert CannotUnregisterVaultPendingDeposits();
            }
            if (metrics.totalClaimableRedeemAssets != 0) {
                revert CannotUnregisterVaultClaimableRedemptions();
            }
            if (metrics.totalCancelDepositAssets != 0) {
                revert CannotUnregisterVaultAssetBalance();
            }
            if (metrics.activeDepositRequestersCount != 0) {
                revert CannotUnregisterVaultActiveDepositRequesters();
            }
            if (metrics.activeRedeemRequestersCount != 0) {
                revert CannotUnregisterVaultActiveRedeemRequesters();
            }
        } catch {
            // If we can't get vault metrics, we can't safely verify no pending requests
            revert CannotUnregisterActiveVault();
        }
        // 2. Final safety: Check raw asset balance in vault contract
        // This catches any remaining assets including investments and edge cases
        // If this happens, there is either a bug in the vault
        // or assets were sent to the vault without directly
        if (IERC20(asset).balanceOf(vaultAddress) != 0) {
            revert CannotUnregisterVaultAssetBalance();
        }

        // Remove vault registration (automatically removes from enumerable collection)
        $.assetToVault.remove(asset);
        delete $.vaultToAsset[vaultAddress];

        emit VaultUpdate(asset, address(0));
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L857-904)
```text
     * - Converts shares to assets using the stored share-asset ratio
     * - Allows partial claims of claimable amounts
     * - Reentrancy-protected via nonReentrant
     *
     * AUTHORIZATION:
     * Controller (msg.sender == controller) can call directly, or
     * Operator must be approved via setOperator() on the share token
     *
     * SECURITY CONSIDERATIONS:
     * - Uses nonReentrant guard to prevent reentrancy attacks
     * - Asset calculation uses Floor rounding (conservative for protocol)
     * - Only callable by controller or approved operator
     * - Burns shares held by vault after asset calculation
     * - Removes controller from active set if all shares are claimed
     *
     * @param shares The amount of shares to redeem (must be <= claimableRedeemShares[controller])
     * @param receiver Address that will receive the assets
     * @param controller Address that made the original redeem request
     *
     * @return assets The amount of assets received from the redemption
     *
     * @custom:throws InvalidCaller If caller is neither controller nor approved operator
     * @custom:throws ZeroShares If shares parameter is 0
     * @custom:throws InsufficientClaimableShares If shares > claimableRedeemShares[controller]
     * @custom:throws AssetTransferFailed If asset transfer to receiver fails
     *
     * @custom:event Withdraw(receiver, controller, owner, assets, shares)
     */
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
```
