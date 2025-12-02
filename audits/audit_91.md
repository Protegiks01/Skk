## Title
Unregistered Vaults Cannot Burn Shares, Creating Permanently Locked User Funds

## Summary
The `unregisterVault()` function deletes the vault-to-asset mapping without verifying that all shares minted by the vault have been redeemed. This causes users holding shares from an unregistered vault to lose access to their funds because the vault can no longer call `burn()` during redemption, as the `onlyVaults` modifier rejects unregistered vaults.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` - `unregisterVault()` function (lines 282-327), `onlyVaults` modifier (lines 127-131), `burn()` function (lines 412-414)

**Intended Logic:** The `unregisterVault()` function should only allow vault removal when it's safe to do so, meaning no user funds are at risk. The `onlyVaults` modifier protects critical share operations by restricting them to registered vaults.

**Actual Logic:** The unregistration checks verify that the vault has no pending deposits, claimable redemptions, or asset balance, but they don't verify that users have redeemed all shares minted by this vault. After unregistration, the vault loses its ability to call `burn()` because the `onlyVaults` modifier checks `$.vaultToAsset[msg.sender] != address(0)`, which becomes false when the mapping is deleted. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. **Initial Setup**: VaultA (USDC) is registered and mints 1,000,000 shares to Alice after she deposits 1,000,000 USDC
2. **Investment Phase**: Investment manager calls `investAssets(1,000,000)` on VaultA, which deposits the USDC into an investment vault. The investment shares are credited to the ShareToken contract, not VaultA itself
3. **Vault Deactivation**: VaultA is paused (`isActive = false`), all pending/claimable requests are fulfilled and claimed
4. **Unregistration Succeeds**: Owner calls `unregisterVault(USDC)`. The check at line 318-320 passes because `IERC20(USDC).balanceOf(VaultA) == 0` (assets are in the investment vault, not VaultA) [3](#0-2) 

5. **Redemption Fails**: Alice calls `requestRedeem()` on VaultA, the investment manager calls `fulfillRedeem()`, then Alice calls `redeem()`. VaultA attempts to burn shares by calling `ShareTokenUpgradeable($.shareToken).burn(address(this), shares)` at line 912 [4](#0-3) 

6. **Transaction Reverts**: The `burn()` function has the `onlyVaults` modifier which checks if `$.vaultToAsset[msg.sender] == address(0)`. Since VaultA was unregistered, this evaluates to true, causing the transaction to revert with `Unauthorized()` [5](#0-4) 

**Security Property Broken:** Violates invariant #7 ("Vault Registry: Only registered vaults can mint/burn shares") by creating a state where shares exist but cannot be burned, and invariant #12 ("No Fund Theft: No double-claims, no reentrancy, no authorization bypass") by preventing legitimate redemptions.

## Impact Explanation
- **Affected Assets**: All shares minted by the unregistered vault become unredeemable. In a single-vault scenario, users lose 100% of their deposited funds. In multi-vault scenarios, users must redeem through different vaults, receiving assets in the wrong denomination (e.g., USDC depositors forced to take DAI).
- **Damage Severity**: Complete loss of access to deposited funds for users holding shares from unregistered vaults. If VaultA manages $10M in user deposits and gets unregistered, all $10M becomes inaccessible.
- **User Impact**: Any user holding shares minted by the unregistered vault cannot redeem them through that vault. The async ERC-7540 flow (requestRedeem → fulfillRedeem → redeem) will fail at the final claim step when `burn()` reverts.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is an operational/administrative error that protocol owners could trigger inadvertently when managing vault lifecycles.
- **Preconditions**: 
  1. Users hold shares minted by a vault
  2. The vault's assets are invested in an investment vault (so vault balance is zero)
  3. All pending/claimable requests are fulfilled/claimed (no active requesters)
  4. Owner calls `unregisterVault()` without realizing users still hold unredeemed shares
- **Execution Complexity**: Single transaction by protocol owner. The vulnerability manifests when users subsequently attempt redemptions.
- **Frequency**: Can occur whenever a vault is unregistered prematurely. The protocol architecture encourages investment of idle assets, making the vault's asset balance zero while users still hold shares representing those invested assets.

## Recommendation

Add a comprehensive check to verify that no shares backed by this vault exist before allowing unregistration. Since the ShareToken is multi-asset and shares are fungible across vaults, track the total invested assets for each vault and require that both the vault's direct asset balance AND its invested assets are zero:

```solidity
// In src/ShareTokenUpgradeable.sol, function unregisterVault, after line 320:

// CURRENT (vulnerable):
// Only checks direct vault asset balance
if (IERC20(asset).balanceOf(vaultAddress) != 0) {
    revert CannotUnregisterVaultAssetBalance();
}

// FIXED:
// Check both direct vault balance AND invested assets
if (IERC20(asset).balanceOf(vaultAddress) != 0) {
    revert CannotUnregisterVaultAssetBalance();
}

// Additionally check if this vault has invested assets
// Get vault's share balance from investment ShareToken (if configured)
address investmentShareToken_ = $.investmentShareToken;
if (investmentShareToken_ != address(0)) {
    address investmentVault = IERC7575ShareExtended(investmentShareToken_).vault(asset);
    if (investmentVault != address(0)) {
        uint256 investedShares = IERC20(investmentShareToken_).balanceOf(address(this));
        // Get this vault's portion using rBalanceOf if available
        try IWERC7575ShareToken(investmentShareToken_).rBalanceOf(address(this)) returns (uint256 rShares) {
            investedShares += rShares;
        } catch {}
        
        if (investedShares > 0) {
            // Convert investment shares to assets to verify economic value
            uint256 investedAssets = IERC7575(investmentVault).convertToAssets(investedShares);
            if (investedAssets > 0) {
                revert CannotUnregisterVaultInvestedAssets();
            }
        }
    }
}

// Critical: Verify total circulating supply would not decrease
// In multi-asset system, can't track shares per vault, so require
// that total supply equals claimable shares (meaning no user-held shares exist)
uint256 currentSupply = totalSupply();
uint256 totalClaimableAcrossAllVaults = 0;
uint256 length = $.assetToVault.length();
for (uint256 i = 0; i < length; i++) {
    (, address otherVault) = $.assetToVault.at(i);
    (uint256 claimable,) = IERC7575Vault(otherVault).getClaimableSharesAndNormalizedAssets();
    totalClaimableAcrossAllVaults += claimable;
}
// If supply > claimable shares, users hold unredeemed shares
if (currentSupply > totalClaimableAcrossAllVaults) {
    revert CannotUnregisterVaultOutstandingShares();
}
```

**Alternative simpler fix**: Require that `totalSupply() == 0` before allowing any vault unregistration, ensuring the ShareToken has no outstanding shares before decommissioning the last vault.

## Proof of Concept

```solidity
// File: test/Exploit_OrphanedShares.t.sol
// Run with: forge test --match-test test_OrphanedSharesAfterUnregistration -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("USD Coin", "USDC") {
        _mint(msg.sender, 10_000_000 * 10**6);
    }
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

contract Exploit_OrphanedShares is Test {
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable vaultA;
    MockUSDC usdc;
    
    address owner = address(0x1);
    address alice = address(0x2);
    address investmentManager = address(0x3);
    
    function setUp() public {
        // Deploy USDC
        usdc = new MockUSDC();
        
        // Deploy ShareToken
        ShareTokenUpgradeable impl = new ShareTokenUpgradeable();
        bytes memory initData = abi.encodeCall(
            ShareTokenUpgradeable.initialize,
            ("Sukuk Shares", "SUKUK", owner)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        shareToken = ShareTokenUpgradeable(address(proxy));
        
        // Deploy VaultA
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeCall(
            ERC7575VaultUpgradeable.initialize,
            (address(usdc), address(shareToken), owner, 1000)
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vaultA = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // Register vault and setup
        vm.startPrank(owner);
        shareToken.registerVault(address(usdc), address(vaultA));
        shareToken.setInvestmentManager(investmentManager);
        vaultA.activateVault();
        vm.stopPrank();
        
        // Give Alice USDC
        usdc.transfer(alice, 1_000_000 * 10**6);
    }
    
    function test_OrphanedSharesAfterUnregistration() public {
        // SETUP: Alice deposits USDC and receives shares
        uint256 depositAmount = 1_000_000 * 10**6;
        vm.startPrank(alice);
        usdc.approve(address(vaultA), depositAmount);
        vaultA.requestDeposit(depositAmount, alice, alice);
        vm.stopPrank();
        
        // Investment manager fulfills deposit
        vm.prank(investmentManager);
        vaultA.fulfillDeposit(alice, depositAmount);
        
        // Alice claims shares
        vm.prank(alice);
        vaultA.deposit(depositAmount, alice, alice);
        
        uint256 aliceShares = shareToken.balanceOf(alice);
        assertGt(aliceShares, 0, "Alice should have shares");
        
        // Owner deactivates and unregisters vault
        // (assuming all assets were invested, vault balance is 0)
        vm.startPrank(owner);
        vaultA.deactivateVault();
        shareToken.unregisterVault(address(usdc));
        vm.stopPrank();
        
        // EXPLOIT: Alice tries to redeem her shares
        vm.startPrank(alice);
        shareToken.approve(address(vaultA), aliceShares);
        vaultA.requestRedeem(aliceShares, alice, alice);
        vm.stopPrank();
        
        // Investment manager fulfills redeem
        vm.prank(investmentManager);
        vaultA.fulfillRedeem(alice, aliceShares);
        
        // VERIFY: Alice cannot claim (burn will revert)
        vm.prank(alice);
        vm.expectRevert(); // Expecting Unauthorized() revert
        vaultA.redeem(aliceShares, alice, alice);
        
        // Verify Alice still has shares but cannot access funds
        assertEq(shareToken.balanceOf(address(vaultA)), aliceShares, 
            "Vault holds Alice's shares but cannot burn them");
    }
}
```

## Notes

- The vulnerability exists because `unregisterVault()` checks focus on the vault's immediate state (pending requests, asset balance) rather than the global system state (total shares in circulation backed by this vault's assets).

- The issue is exacerbated by the investment mechanism: when `investAssets()` is called, assets move from the vault to an investment vault, and investment shares are credited to the ShareToken contract (not the vault). This makes the vault's asset balance zero while user shares still represent claims on those invested assets. [6](#0-5) 

- In the multi-asset architecture, shares are fungible across vaults, so there's no way to track which specific vault minted which shares. This makes it impossible to verify that a vault has no outstanding shares before unregistration without checking global supply.

- While users could theoretically redeem through other registered vaults to recover value, this forces asset denomination changes (USDC depositors getting DAI) and fails completely if the unregistered vault is the only vault in the system.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L127-131)
```text
    modifier onlyVaults() {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        if ($.vaultToAsset[msg.sender] == address(0)) revert Unauthorized();
        _;
    }
```

**File:** src/ShareTokenUpgradeable.sol (L318-320)
```text
        if (IERC20(asset).balanceOf(vaultAddress) != 0) {
            revert CannotUnregisterVaultAssetBalance();
        }
```

**File:** src/ShareTokenUpgradeable.sol (L324-324)
```text
        delete $.vaultToAsset[vaultAddress];
```

**File:** src/ShareTokenUpgradeable.sol (L412-414)
```text
    function burn(address account, uint256 amount) external onlyVaults {
        _burn(account, amount);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L912-912)
```text
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);
```

**File:** src/ERC7575VaultUpgradeable.sol (L1461-1461)
```text
        shares = IERC7575($.investmentVault).deposit(amount, $.shareToken);
```
