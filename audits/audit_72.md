## Title
Permanent Fund Lockup When Underlying Asset Introduces Transfer Fees After Investment

## Summary
The `withdrawFromInvestment()` function will permanently revert if the underlying asset introduces a transfer fee after assets have been invested into the investment vault. This occurs because the investment vault's `redeem()` function uses `SafeTokenTransfers.safeTransfer()`, which enforces exact balance validation and reverts on any transfer fee. Users with pending redemptions will be unable to claim their assets, resulting in permanent fund lockup.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` (function `withdrawFromInvestment`, lines 1477-1509) and `src/WERC7575Vault.sol` (function `_withdraw`, lines 397-411)

**Intended Logic:** The system is designed to support standard ERC20 tokens like USDC, DAI, and USDT. The `SafeTokenTransfers` library protects against fee-on-transfer tokens by validating exact balance changes. The `withdrawFromInvestment()` function should retrieve assets from the investment vault to fulfill pending redemptions.

**Actual Logic:** When `withdrawFromInvestment()` is called, it invokes the investment vault's `redeem()` function, which internally uses `SafeTokenTransfers.safeTransfer()`. If the underlying asset introduces a transfer fee AFTER initial investments were made (e.g., USDT enables its built-in fee mechanism), the `SafeTokenTransfers` check at line 53 will fail because `balanceAfter != balanceBefore + amount`, causing the entire transaction to revert. [1](#0-0) [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. **Initial State**: Asset (e.g., USDT) has NO transfer fee enabled
2. **Investment Phase**: Investment Manager calls `investAssets(1000e6)` - assets successfully transferred to investment vault via `IERC7575(investmentVault).deposit()`, no issues
3. **Redemption Request**: User calls `requestRedeem(1000 shares)`
4. **Fulfillment**: Investment Manager calls `fulfillRedeem(user, 1000 shares)` - sets `claimableRedeemAssets[user] = 1000e6` based on share price
5. **Fee Introduction**: USDT contract owner enables transfer fee (e.g., 0.1% = 1 USDT per 1000)
6. **Withdrawal Attempt**: Investment Manager calls `withdrawFromInvestment(1000e6)` to retrieve assets:
   - Calls `IERC7575(investmentVault).redeem(shares, address(this), shareToken)`
   - Investment vault's `redeem()` → `_withdraw()` → `SafeTokenTransfers.safeTransfer(asset, receiver, 1000e6)`
   - Due to 0.1% fee: only 999e6 assets arrive at receiver
   - `SafeTokenTransfers` check: `999e6 != balanceBefore + 1000e6` → **REVERTS with TransferAmountMismatch()**
7. **Permanent Lockup**: All future `withdrawFromInvestment()` calls will revert. User cannot claim their 1000e6 assets via `redeem()` because the vault lacks sufficient balance. No cancellation is possible (request is in Claimable state, not Pending).

**Security Property Broken:** Invariant #12 "No Fund Theft" - users cannot access their legitimately claimed assets due to protocol inability to handle post-investment fee introduction.

## Impact Explanation
- **Affected Assets**: All assets invested in the investment vault at the time a transfer fee is introduced (complete loss of access)
- **Damage Severity**: 100% of invested capital becomes permanently inaccessible. For USDT with typical vault holdings of $1M-$100M+, this represents catastrophic loss.
- **User Impact**: ALL users with pending redemptions (in Claimable state) cannot claim their assets. New redemption requests also cannot be fulfilled since `withdrawFromInvestment()` is permanently broken.

## Likelihood Explanation
- **Attacker Profile**: Not an attacker-triggered issue - this is a protocol design flaw that manifests when the underlying asset's fee mechanism changes (controlled by asset contract owner, e.g., USDT owner)
- **Preconditions**: 
  1. Assets must be invested in the investment vault via `investAssets()`
  2. Underlying asset must have latent fee capability (USDT has this built-in but currently disabled)
  3. Asset contract owner enables transfer fees
- **Execution Complexity**: Extremely simple - automatic failure once fees are enabled, no complex attack needed
- **Frequency**: One-time catastrophic event per asset. USDT's fee capability is well-documented and can be enabled at any time by the USDT owner.

## Recommendation

**Option 1: Handle Actual Received Amount (Recommended)**

Modify both `WERC7575Vault._withdraw()` and the calling context to handle actual received amounts instead of enforcing exact amounts:

```solidity
// In src/WERC7575Vault.sol, function _withdraw (lines 397-411):

// CURRENT (vulnerable):
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
    SafeTokenTransfers.safeTransfer(_asset, receiver, assets);  // <-- REVERTS on fee
    emit Withdraw(msg.sender, receiver, owner, assets, shares);
}

// FIXED (Option 1 - Accept actual received amount):
function _withdraw(uint256 assets, uint256 shares, address receiver, address owner) internal returns (uint256 actualAssets) {
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
    
    // Measure actual received amount to handle potential transfer fees
    uint256 balanceBefore = IERC20Metadata(_asset).balanceOf(receiver);
    IERC20Metadata(_asset).safeTransfer(receiver, assets);
    uint256 balanceAfter = IERC20Metadata(_asset).balanceOf(receiver);
    actualAssets = balanceAfter - balanceBefore;  // May be less than assets due to fee
    
    // Emit actual transferred amount
    emit Withdraw(msg.sender, receiver, owner, actualAssets, shares);
    return actualAssets;
}

// Update public functions to return actual amounts:
function withdraw(uint256 assets, address receiver, address owner) public nonReentrant whenNotPaused returns (uint256 shares, uint256 actualAssets) {
    shares = previewWithdraw(assets);
    actualAssets = _withdraw(assets, shares, receiver, owner);
}

function redeem(uint256 shares, address receiver, address owner) public nonReentrant whenNotPaused returns (uint256 assets, uint256 actualAssets) {
    assets = previewRedeem(shares);
    actualAssets = _withdraw(assets, shares, receiver, owner);
}
```

**Option 2: Explicitly Reject Fee-On-Transfer Assets (More Restrictive)**

Add initialization-time validation to permanently reject assets with fee capability:

```solidity
// In src/WERC7575Vault.sol constructor (after line 99):

// Test for transfer fees by performing a round-trip transfer
uint256 testAmount = 1; // 1 wei
try IERC20Metadata(asset_).transfer(address(this), testAmount) {
    uint256 balanceBefore = IERC20Metadata(asset_).balanceOf(address(this));
    IERC20Metadata(asset_).transfer(msg.sender, testAmount);
    uint256 balanceAfter = IERC20Metadata(asset_).balanceOf(address(this));
    if (balanceAfter != balanceBefore - testAmount) {
        revert FeeOnTransferNotSupported();
    }
} catch {
    // If transfer fails, asset is incompatible
    revert AssetTransferFailed();
}
```

**Note**: Option 1 is recommended as it provides graceful degradation and matches the actual behavior expected by `withdrawFromInvestment()` which already tracks `actualAmount`. Option 2 only protects against assets with fees at deployment time but doesn't prevent fees from being introduced later (the core issue).

## Proof of Concept

```solidity
// File: test/Exploit_TransferFeeLockup.t.sol
// Run with: forge test --match-test test_TransferFeeIntroducedAfterInvestment -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock asset with fee capability (like USDT)
contract MockUSDTWithFee is ERC20 {
    uint256 public transferFeeBps = 0; // 0 = no fee initially
    address public feeOwner;

    constructor() ERC20("Mock USDT", "USDT") {
        feeOwner = msg.sender;
        _mint(msg.sender, 1000000e6);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    // Owner can enable fees (like real USDT)
    function setTransferFee(uint256 feeBps) external {
        require(msg.sender == feeOwner, "Only owner");
        transferFeeBps = feeBps; // 10 = 0.1%, 100 = 1%
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        uint256 fee = (amount * transferFeeBps) / 10000;
        uint256 netAmount = amount - fee;
        
        _transfer(msg.sender, to, netAmount);
        if (fee > 0) {
            _transfer(msg.sender, feeOwner, fee);
        }
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        _spendAllowance(from, msg.sender, amount);
        
        uint256 fee = (amount * transferFeeBps) / 10000;
        uint256 netAmount = amount - fee;
        
        _transfer(from, to, netAmount);
        if (fee > 0) {
            _transfer(from, feeOwner, fee);
        }
        return true;
    }
}

contract Exploit_TransferFeeLockup is Test {
    ERC7575VaultUpgradeable public mainVault;
    ShareTokenUpgradeable public mainShareToken;
    WERC7575Vault public investmentVault;
    WERC7575ShareToken public investmentShareToken;
    MockUSDTWithFee public usdt;

    address public owner = address(this);
    address public user = address(0x1);
    address public investmentManager = address(0x2);
    address public validator = address(0x3);

    function setUp() public {
        // Deploy USDT-like asset (NO FEE initially)
        usdt = new MockUSDTWithFee();
        
        // Deploy Investment Layer (Settlement)
        investmentShareToken = new WERC7575ShareToken("Wrapped USD", "WUSD");
        investmentVault = new WERC7575Vault(address(usdt), investmentShareToken);
        
        // Setup investment vault
        investmentShareToken.setValidator(validator);
        investmentShareToken.setKycAdmin(validator);
        investmentShareToken.registerVault(address(usdt), address(investmentVault));
        
        // Deploy Main Layer (Investment)
        ShareTokenUpgradeable mainShareTokenImpl = new ShareTokenUpgradeable();
        ERC1967Proxy mainShareTokenProxy = new ERC1967Proxy(
            address(mainShareTokenImpl), 
            abi.encodeWithSelector(ShareTokenUpgradeable.initialize.selector, "Main Share", "MSH", owner)
        );
        mainShareToken = ShareTokenUpgradeable(address(mainShareTokenProxy));

        ERC7575VaultUpgradeable mainVaultImpl = new ERC7575VaultUpgradeable();
        ERC1967Proxy mainVaultProxy = new ERC1967Proxy(
            address(mainVaultImpl),
            abi.encodeWithSelector(ERC7575VaultUpgradeable.initialize.selector, usdt, address(mainShareToken), owner)
        );
        mainVault = ERC7575VaultUpgradeable(address(mainVaultProxy));

        // Setup main vault
        mainShareToken.registerVault(address(usdt), address(mainVault));
        mainShareToken.setKycAdmin(validator);
        mainVault.setInvestmentManager(investmentManager);
        mainVault.setInvestmentVault(address(investmentVault));
        
        // Setup KYC
        vm.startPrank(validator);
        mainShareToken.setKycVerified(user, true);
        mainShareToken.setKycVerified(address(mainVault), true);
        mainShareToken.setKycVerified(address(mainShareToken), true);
        investmentShareToken.setKycVerified(address(mainShareToken), true);
        vm.stopPrank();
        
        // Fund user
        usdt.transfer(user, 1000e6);
    }

    function test_TransferFeeIntroducedAfterInvestment() public {
        // STEP 1: User deposits (NO FEE YET)
        vm.startPrank(user);
        usdt.approve(address(mainVault), 1000e6);
        mainVault.requestDeposit(1000e6, user, user);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        mainVault.fulfillDeposit(user, 1000e6);
        
        vm.startPrank(user);
        mainVault.deposit(1000e6, user, user);
        vm.stopPrank();
        
        // STEP 2: Invest assets into investment vault (STILL NO FEE)
        vm.prank(investmentManager);
        mainVault.investAssets(1000e6);
        
        // Verify investment succeeded
        assertEq(usdt.balanceOf(address(investmentVault)), 1000e6, "Investment vault should have 1000 USDT");
        
        // STEP 3: Setup permits for investment vault withdrawal
        vm.startPrank(validator);
        uint256 deadline = block.timestamp + 1 hours;
        
        // Create permit signature for self-allowance
        bytes32 PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
        bytes32 domainSeparator = investmentShareToken.DOMAIN_SEPARATOR();
        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            address(mainShareToken),
            address(mainShareToken),
            type(uint256).max,
            investmentShareToken.nonces(address(mainShareToken)),
            deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(keccak256("validator")), digest);
        vm.stopPrank();
        
        investmentShareToken.permit(address(mainShareToken), address(mainShareToken), type(uint256).max, deadline, v, r, s);
        
        vm.prank(address(mainShareToken));
        investmentShareToken.approve(address(investmentVault), type(uint256).max);
        
        // STEP 4: User requests redemption
        vm.startPrank(user);
        mainVault.requestRedeem(1000e18, user, user);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        mainVault.fulfillRedeem(user, 1000e18);
        
        // STEP 5: USDT OWNER ENABLES TRANSFER FEE (0.1%)
        usdt.setTransferFee(10); // 10 bps = 0.1%
        
        // STEP 6: Try to withdraw from investment - THIS WILL REVERT
        vm.prank(investmentManager);
        vm.expectRevert(); // Expect TransferAmountMismatch from SafeTokenTransfers
        mainVault.withdrawFromInvestment(1000e6);
        
        // STEP 7: User cannot claim redemption (vault has 0 balance)
        vm.startPrank(user);
        vm.expectRevert(); // Will revert due to insufficient balance
        mainVault.redeem(1000e18, user, user);
        vm.stopPrank();
        
        // VERIFY: Funds are permanently locked
        assertEq(usdt.balanceOf(address(mainVault)), 0, "Main vault has no USDT");
        assertEq(usdt.balanceOf(address(investmentVault)), 1000e6, "USDT stuck in investment vault");
        assertEq(mainVault.claimableRedeemAssets(user), 1000e6, "User has claimable assets but cannot access them");
    }
}
```

## Notes

1. **USDT Fee Capability**: The vulnerability is particularly critical for USDT, which has a built-in but currently disabled transfer fee mechanism. The USDT contract owner can enable fees at any time through the `setParams()` function (parameters: `basisPointsRate` and `maximumFee`). This is not a theoretical concern - it's a documented feature of the USDT contract.

2. **Difference from Question Premise**: The security question asks if `actualAmount < requested amount` can cause issues. The actual vulnerability is more severe - the transaction REVERTS entirely rather than returning a reduced amount. This is because `SafeTokenTransfers.safeTransfer()` enforces exact balance validation at line 53. [4](#0-3) 

3. **No Recovery Mechanism**: Once a transfer fee is introduced:
   - `withdrawFromInvestment()` permanently reverts
   - Users in Claimable state cannot cancel (only Pending requests are cancellable per ERC-7887)
   - No emergency withdrawal function exists
   - Upgrade mechanism cannot fix this without breaking ERC-7201 storage layout

4. **Affected Flow**: The issue occurs in the cross-contract call chain:
   - `ERC7575VaultUpgradeable.withdrawFromInvestment()` → `WERC7575Vault.redeem()` → `WERC7575Vault._withdraw()` → `SafeTokenTransfers.safeTransfer()`

5. **Related Code**: The `withdrawFromInvestment()` function already tracks `actualAmount` (line 1504), suggesting the developers anticipated that the received amount might differ from the requested amount. However, the underlying `SafeTokenTransfers` check prevents this from working as intended. [5](#0-4)

### Citations

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

**File:** src/SafeTokenTransfers.sol (L7-36)
```text
/**
 * @title SafeTokenTransfers
 * @notice Library for safe token transfers with strict balance validation
 *
 * This library enforces exact balance changes to prevent fee-on-transfer exploits,
 * accounting mismatches, and silent value leakage in vault systems.
 *
 * COMPATIBLE TOKENS (Standard ERC20):
 * - USDC, DAI, USDT (without fees enabled)
 * - Standard wrapped tokens (WETH, WBTC)
 * - Most ERC20 tokens that transfer exact amounts
 *
 * INCOMPATIBLE TOKENS (will revert with TransferAmountMismatch):
 * - Fee-on-transfer tokens (SAFEMOON, USDT with fees, etc.)
 * - Rebase tokens (stETH, aTokens, AMPL)
 * - Elastic supply tokens
 * - Tokens with transfer hooks that modify balances
 * - Any token that doesn't deliver exact transfer amounts
 *
 * USAGE WARNING:
 * Before deploying a vault with a new token, verify that the token:
 * 1. Transfers exactly the specified amount (no fees)
 * 2. Does not rebase or change balances automatically
 * 3. Does not have transfer hooks that modify amounts
 *
 * Test with small amounts first to ensure compatibility.
 *
 * @dev The balance validation check will reject any token where
 * recipientBalanceAfter != recipientBalanceBefore + amount
 */
```

**File:** src/SafeTokenTransfers.sol (L49-54)
```text
    function safeTransfer(address token, address recipient, uint256 amount) internal {
        uint256 balanceBefore = IERC20Metadata(token).balanceOf(recipient);
        IERC20Metadata(token).safeTransfer(recipient, amount);
        uint256 balanceAfter = IERC20Metadata(token).balanceOf(recipient);
        if (balanceAfter != balanceBefore + amount) revert TransferAmountMismatch();
    }
```
