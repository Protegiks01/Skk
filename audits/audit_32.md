## Title
Permanent Protocol Upgrade DoS Due to MAX_VAULTS_PER_SHARE_TOKEN Limit and Unregistration Safety Checks

## Summary
The `WERC7575ShareToken` contract enforces a hard limit of 10 vaults via `MAX_VAULTS_PER_SHARE_TOKEN` constant, while `unregisterVault()` safety checks require vaults to have zero assets before removal. This creates a deadlock where the protocol cannot register new vaults for critical assets once all 10 slots are filled, as even a single user with minimal funds in any vault permanently blocks unregistration. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` - `registerVault()` (lines 218-241), `unregisterVault()` (lines 256-285), and constant `MAX_VAULTS_PER_SHARE_TOKEN` (line 123)

**Intended Logic:** The MAX_VAULTS_PER_SHARE_TOKEN limit of 10 is designed to prevent unbounded loops in vault aggregation functions, with the expectation that unused vaults can be unregistered and replaced with new ones as the protocol evolves. [2](#0-1) 

**Actual Logic:** The combination of immutable vault limit and strict safety checks creates a permanent deadlock:

1. **Registration Block**: When 10 vaults are registered, `registerVault()` unconditionally reverts with `MaxVaultsExceeded()` [3](#0-2) 

2. **Unregistration Requirements**: `unregisterVault()` requires BOTH `totalAssets() == 0` and `balanceOf(asset) == 0` [4](#0-3) 

3. **No Forced Exit**: The vault has NO mechanism to force users to withdraw. The `setVaultActive()` function only prevents NEW deposits, not existing positions [5](#0-4) 

4. **User Redemptions Don't Check isActive**: Users can redeem from inactive vaults, but there's no requirement they MUST redeem [6](#0-5) 

5. **Constant Cannot Be Changed**: `MAX_VAULTS_PER_SHARE_TOKEN` is a `constant`, and `WERC7575ShareToken` is NOT upgradeable (inherits `Ownable2Step`, not any upgradeable pattern) [7](#0-6) 

**Exploitation Path:**
1. Protocol launches and successfully registers 10 vaults for various assets (USDC, USDT, DAI, EURC, BUSD, sUSD, FRAX, TUSD, GUSD, USDP)
2. Business needs dictate adding a new critical asset (e.g., USDD for new market opportunity or regulatory requirement)
3. Owner calls `registerVault(USDD_ADDRESS, NEW_VAULT_ADDRESS)` → reverts with `MaxVaultsExceeded()`
4. Owner attempts to unregister the least-used vault (e.g., GUSD) by calling `unregisterVault(GUSD_ADDRESS)`
5. If ANY user has ANY amount of funds in GUSD vault → reverts with `CannotUnregisterVaultAssetBalance()`
6. Owner sets GUSD vault inactive via `setVaultActive(false)` to prevent new deposits
7. However, existing users are NOT forced to withdraw - they can keep funds indefinitely (lost keys, dormant accounts, malicious holding)
8. Protocol is permanently blocked from registering new vaults - cannot adapt to market conditions or regulatory requirements

**Security Property Broken:** Protocol governance and evolution capability is blocked. While not a direct invariant violation, this breaks the fundamental ability of the protocol to adapt to changing business requirements.

## Impact Explanation
- **Affected Assets**: All future assets that the protocol needs to support
- **Damage Severity**: Protocol cannot onboard new assets, potentially missing critical market opportunities or failing to meet regulatory requirements (e.g., cannot add EURC when required for European compliance)
- **User Impact**: All users affected indirectly - protocol cannot grow, cannot offer new investment opportunities, becomes obsolete as market evolves

## Likelihood Explanation
- **Attacker Profile**: Not malicious - any passive user behavior creates this condition
- **Preconditions**: Protocol reaches 10 registered vaults (realistic as multi-asset protocol grows)
- **Execution Complexity**: Zero - happens naturally through protocol operation
- **Frequency**: Permanent once condition is reached (10 vaults registered with at least one user having funds in each)

## Recommendation

The root cause is that `MAX_VAULTS_PER_SHARE_TOKEN` is a compile-time constant in a non-upgradeable contract. Multiple solutions exist:

**Solution 1: Make the limit configurable (Recommended)**
```solidity
// In src/WERC7575ShareToken.sol:

// CURRENT (vulnerable):
uint256 private constant MAX_VAULTS_PER_SHARE_TOKEN = 10;

// FIXED:
uint256 private _maxVaultsPerShareToken = 10;

function setMaxVaultsPerShareToken(uint256 newMax) external onlyOwner {
    require(newMax >= _assetToVault.length(), "Cannot set below current vault count");
    require(newMax <= 100, "Unreasonable vault limit"); // Prevent unbounded gas
    _maxVaultsPerShareToken = newMax;
}

// Update registerVault() check:
if (_assetToVault.length() >= _maxVaultsPerShareToken) {
    revert MaxVaultsExceeded();
}
```

**Solution 2: Add vault migration mechanism**
```solidity
// Allow replacing a vault without requiring it to be empty first
function replaceVault(address oldAsset, address newAsset, address newVaultAddress) external onlyOwner {
    // Deactivate old vault
    IERC7575VaultUpgradeable(oldVault).setVaultActive(false);
    
    // Register new vault in same slot
    _assetToVault.set(newAsset, newVaultAddress);
    _vaultToAsset[newVaultAddress] = newAsset;
    
    emit VaultReplaced(oldAsset, newAsset, newVaultAddress);
}
```

**Solution 3: Add forced withdrawal with delay**
```solidity
// In ERC7575VaultUpgradeable.sol:
uint256 public sunsetTimestamp;

function initiateVaultSunset() external onlyOwner {
    require(!isActive, "Must deactivate first");
    sunsetTimestamp = block.timestamp + 90 days;
    emit VaultSunsetInitiated(sunsetTimestamp);
}

function forcedWithdraw(address user) external onlyOwner {
    require(block.timestamp >= sunsetTimestamp, "Sunset period not complete");
    // Force redeem user's shares and return assets
}
```

## Proof of Concept
```solidity
// File: test/Exploit_VaultLimitDoS.t.sol
// Run with: forge test --match-test test_VaultLimitDoS -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    uint8 private _decimals;
    constructor(string memory name, string memory symbol, uint8 decimals_) ERC20(name, symbol) {
        _decimals = decimals_;
    }
    function decimals() public view override returns (uint8) {
        return _decimals;
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract Exploit_VaultLimitDoS is Test {
    WERC7575ShareToken shareToken;
    WERC7575Vault[] vaults;
    MockERC20[] assets;
    
    address owner = address(this);
    address alice = address(0xA11CE);
    
    function setUp() public {
        // Deploy share token
        shareToken = new WERC7575ShareToken("Multi Asset Shares", "MAS");
        
        // Register 10 vaults (the maximum allowed)
        for (uint i = 0; i < 10; i++) {
            MockERC20 asset = new MockERC20(
                string(abi.encodePacked("Asset", vm.toString(i))),
                string(abi.encodePacked("A", vm.toString(i))),
                6
            );
            assets.push(asset);
            
            WERC7575Vault vault = new WERC7575Vault(
                address(asset),
                address(shareToken),
                owner
            );
            vaults.push(vault);
            
            shareToken.registerVault(address(asset), address(vault));
        }
        
        // Alice deposits into vault 9 (the least important one)
        assets[9].mint(alice, 1000e6);
        vm.startPrank(alice);
        shareToken.setKycVerified(alice, true);
        assets[9].approve(address(vaults[9]), 1000e6);
        vaults[9].requestDeposit(1000e6, alice, alice);
        vm.stopPrank();
    }
    
    function test_VaultLimitDoS() public {
        // SETUP: Protocol wants to add new critical asset (e.g., USDD)
        MockERC20 newAsset = new MockERC20("USDD", "USDD", 18);
        WERC7575Vault newVault = new WERC7575Vault(
            address(newAsset),
            address(shareToken),
            owner
        );
        
        // EXPLOIT: Cannot register new vault - limit reached
        vm.expectRevert(abi.encodeWithSignature("MaxVaultsExceeded()"));
        shareToken.registerVault(address(newAsset), address(newVault));
        
        // VERIFY: Attempt to unregister vault 9 fails due to Alice's funds
        vm.expectRevert(abi.encodeWithSignature("CannotUnregisterVaultAssetBalance()"));
        shareToken.unregisterVault(address(assets[9]));
        
        // VERIFY: Even deactivating vault 9 doesn't help - still can't unregister
        vaults[9].setVaultActive(false);
        vm.expectRevert(abi.encodeWithSignature("CannotUnregisterVaultAssetBalance()"));
        shareToken.unregisterVault(address(assets[9]));
        
        console.log("=== DoS Confirmed ===");
        console.log("Protocol has 10 vaults registered");
        console.log("Cannot add new vault for USDD");
        console.log("Cannot remove vault 9 due to Alice's 1000 USDC");
        console.log("Protocol is permanently stuck");
    }
}
```

## Notes
This vulnerability is **NOT listed in KNOWN_ISSUES.md**. While the document mentions "Batch size limits (MAX_BATCH_SIZE = 100)" as a known limitation, it does not mention `MAX_VAULTS_PER_SHARE_TOKEN = 10` or the unregistration deadlock scenario.

The issue arises from the interaction between three design choices:
1. Immutable vault limit (constant, non-upgradeable contract)
2. Strong safety checks preventing vault unregistration with user funds
3. No forced withdrawal or migration mechanism

This is a **protocol design flaw**, not a centralization risk. Even the trusted Owner role cannot overcome this limitation without deploying an entirely new ShareToken contract and migrating all users - a massive undertaking that may be infeasible for a live production system.

### Citations

**File:** src/WERC7575ShareToken.sol (L82-82)
```text
contract WERC7575ShareToken is ERC20, IERC20Permit, EIP712, Nonces, ReentrancyGuard, Ownable2Step, ERC165, Pausable, IERC7575Errors {
```

**File:** src/WERC7575ShareToken.sol (L123-123)
```text
    uint256 private constant MAX_VAULTS_PER_SHARE_TOKEN = 10;
```

**File:** src/WERC7575ShareToken.sol (L231-234)
```text
        // DoS mitigation: Enforce maximum vaults per share token to prevent unbounded loops
        if (_assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
            revert MaxVaultsExceeded();
        }
```

**File:** src/WERC7575ShareToken.sol (L265-279)
```text
        try IERC7575Vault(vaultAddress).totalAssets() returns (uint256 totalAssets) {
            if (totalAssets != 0) revert CannotUnregisterVaultAssetBalance();
        } catch {
            // If we can't verify the vault has no assets, we can't safely unregister
            // This prevents unregistration if the vault is malicious or has interface issues
            revert("ShareToken: cannot verify vault has no outstanding assets");
        }
        // Additional safety: Check if vault still has any assets to prevent user fund loss
        // This is a double-check using ERC20 interface in case totalAssets() is manipulated
        try ERC20(asset).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
            if (vaultBalance != 0) revert CannotUnregisterVaultAssetBalance();
        } catch {
            // If we can't check the asset balance in vault, err on the side of caution
            revert("ShareToken: cannot verify vault asset balance");
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L715-730)
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
```

**File:** src/ERC7575VaultUpgradeable.sol (L1414-1418)
```text
    function setVaultActive(bool _isActive) external onlyOwner {
        VaultStorage storage $ = _getVaultStorage();
        $.isActive = _isActive;
        emit VaultActiveStateChanged(_isActive);
    }
```
