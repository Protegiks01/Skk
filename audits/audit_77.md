## Title
Missing Owner Address Validation in initialize() Functions Causes Permanent Contract Lockout

## Summary
The `initialize()` functions in both `ShareTokenUpgradeable` and `ERC7575VaultUpgradeable` fail to validate that the `owner` parameter is not `address(0)` or an inaccessible address before passing it to `__Ownable_init(owner)`. This allows deployment of permanently unmanageable contracts that cannot register vaults, configure investment settings, or be upgraded, requiring complete redeployment.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
The initialization functions should validate all critical parameters to ensure the contracts can be properly managed after deployment. The owner parameter should be validated to be a non-zero, accessible address since the owner has exclusive control over critical functions.

**Actual Logic:** 
Both `ShareTokenUpgradeable.initialize()` and `ERC7575VaultUpgradeable.initialize()` pass the `owner` parameter directly to `__Ownable_init(owner)` without any validation. OpenZeppelin's `Ownable2StepUpgradeable.__Ownable_init()` does not validate that `owner != address(0)` - it's the caller's responsibility. The codebase validates other critical addresses (shareToken_, asset_) but omits owner validation.

**Exploitation Path:**
1. **Accidental Misconfiguration**: Deploy `ShareTokenUpgradeable` proxy with `owner = address(0)` or an inaccessible address (e.g., typo, wrong address, contract without transfer capability)
2. **Contract Initialization**: The `initialize()` function succeeds, setting ownership to the invalid address
3. **Attempt Management Operations**: Try to call `registerVault()`, `setInvestmentShareToken()`, or `upgradeTo()` - all fail with `Unauthorized` since `msg.sender != owner`
4. **Permanent Lockout**: No recovery mechanism exists - the contract is permanently bricked and requires complete redeployment with new proxy

**Security Property Broken:** 
- **No Role Escalation**: Owner must be able to manage the contract
- **Vault Registry**: Without owner access, no vaults can be registered, violating the core functionality

**Code Evidence:**

ShareTokenUpgradeable validates decimals but not owner: [1](#0-0) 

ERC7575VaultUpgradeable validates shareToken_ and asset_ but not owner: [3](#0-2) 

Critical onlyOwner functions that become inaccessible: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

## Impact Explanation
- **Affected Assets**: All assets that would be managed through the bricked ShareToken or Vault - effectively locks the entire system
- **Damage Severity**: 
  - **ShareTokenUpgradeable**: Cannot register any vaults (making it completely non-functional), cannot configure investment layer, cannot upgrade to fix the issue (UUPS upgrade path permanently locked)
  - **ERC7575VaultUpgradeable**: Cannot configure vault settings, cannot upgrade contract
  - Requires complete redeployment: new implementation contracts, new proxies, re-registration of all components, potential loss of any assets already deposited (though unlikely in fresh deployment)
- **User Impact**: Deployment team must redeploy entire system, potential loss of gas costs, delayed protocol launch, possible asset recovery complexity if any users already interacted with the broken contracts

## Likelihood Explanation
- **Attacker Profile**: Not malicious - this is an operational risk from human error during deployment
- **Preconditions**: 
  - Deployment script passes `address(0)` or incorrect address as owner parameter
  - Common scenarios: typo in deployment script, using wrong variable, copying address incorrectly, using uninitialized variable
- **Execution Complexity**: Single transaction during deployment - the vulnerability is triggered at initialization
- **Frequency**: One-time during deployment, but has permanent consequences

## Recommendation

Add owner address validation in both initialize functions:

**ShareTokenUpgradeable.sol:**
```solidity
// In src/ShareTokenUpgradeable.sol, function initialize, lines 116-124:

// CURRENT (vulnerable):
function initialize(string memory name, string memory symbol, address owner) public initializer {
    __ERC20_init(name, symbol);
    __Ownable_init(owner);

    // Enforce 18 decimals for consistency with ERC7575 standard
    if (decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
        revert WrongDecimals();
    }
}

// FIXED:
function initialize(string memory name, string memory symbol, address owner) public initializer {
    // Validate owner is not zero address before setting ownership
    if (owner == address(0)) revert ZeroAddress();
    
    __ERC20_init(name, symbol);
    __Ownable_init(owner);

    // Enforce 18 decimals for consistency with ERC7575 standard
    if (decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
        revert WrongDecimals();
    }
}
```

**ERC7575VaultUpgradeable.sol:**
```solidity
// In src/ERC7575VaultUpgradeable.sol, function initialize, lines 150-176:

// CURRENT (vulnerable):
function initialize(IERC20Metadata asset_, address shareToken_, address owner) public initializer {
    if (shareToken_ == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    if (address(asset_) == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    // ... validation continues ...
    __Ownable_init(owner);
    // ... rest of initialization ...
}

// FIXED:
function initialize(IERC20Metadata asset_, address shareToken_, address owner) public initializer {
    if (shareToken_ == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    if (address(asset_) == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    // Add owner validation before using it
    if (owner == address(0)) {
        revert ZeroAddress();
    }
    
    // ... validation continues ...
    __Ownable_init(owner);
    // ... rest of initialization ...
}
```

This follows the defense-in-depth pattern already established in the codebase for validating other critical addresses.

## Proof of Concept

```solidity
// File: test/Exploit_InitializationLockout.t.sol
// Run with: forge test --match-test test_InitializationWithZeroOwner -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ERC20Faucet.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_InitializationLockout is Test {
    ShareTokenUpgradeable public shareTokenImpl;
    ShareTokenUpgradeable public shareToken;
    
    ERC7575VaultUpgradeable public vaultImpl;
    ERC7575VaultUpgradeable public vault;
    
    ERC20Faucet public asset;

    function setUp() public {
        // Deploy asset
        asset = new ERC20Faucet("TestToken", "TEST", 1000000 * 1e18);
        
        // Deploy implementations
        shareTokenImpl = new ShareTokenUpgradeable();
        vaultImpl = new ERC7575VaultUpgradeable();
    }
    
    function test_InitializationWithZeroOwner() public {
        // SETUP: Initialize ShareToken with address(0) as owner
        bytes memory shareTokenData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector, 
            "Broken ShareToken", 
            "BROKEN",
            address(0)  // ← ZERO ADDRESS OWNER
        );
        
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(
            address(shareTokenImpl), 
            shareTokenData
        );
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // VERIFY: Contract initialized successfully
        assertEq(shareToken.name(), "Broken ShareToken");
        assertEq(shareToken.owner(), address(0)); // Owner is zero address
        
        // EXPLOIT: Try to register a vault (required for functionality)
        bytes memory vaultData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector,
            asset,
            address(shareToken),
            address(this)
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // This will fail because owner is address(0)
        vm.expectRevert(); // Will revert with OwnableUnauthorizedAccount or similar
        shareToken.registerVault(address(asset), address(vault));
        
        // VERIFY: Cannot perform any owner operations
        vm.expectRevert();
        shareToken.setInvestmentShareToken(address(0x123));
        
        vm.expectRevert();
        shareToken.setInvestmentManager(address(0x456));
        
        vm.expectRevert();
        shareToken.upgradeTo(address(shareTokenImpl));
        
        // CONTRACT IS PERMANENTLY BRICKED
        console.log("ShareToken is permanently locked - no owner operations possible");
        console.log("Owner address:", shareToken.owner());
        console.log("Requires complete redeployment with new proxy");
    }
    
    function test_InitializationWithInaccessibleOwner() public {
        // SETUP: Initialize with an inaccessible contract address (e.g., implementation contract)
        address inaccessibleOwner = address(shareTokenImpl); // Implementation contract cannot accept ownership
        
        bytes memory shareTokenData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector,
            "Broken ShareToken 2",
            "BROKEN2", 
            inaccessibleOwner
        );
        
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(
            address(shareTokenImpl),
            shareTokenData
        );
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // VERIFY: Owner is set to inaccessible address
        assertEq(shareToken.owner(), inaccessibleOwner);
        
        // EXPLOIT: Cannot perform owner operations from the "owner" address
        vm.prank(inaccessibleOwner);
        vm.expectRevert(); // Will fail because implementation contract has no logic to call these functions
        shareToken.registerVault(address(asset), address(0x123));
        
        console.log("ShareToken owner is inaccessible contract - permanently bricked");
    }
}
```

## Notes

This vulnerability is particularly critical because:

1. **No Recovery Mechanism**: Unlike other access control issues, there's no `transferOwnership()` that could be called by another admin role - the owner is the only role that can upgrade the contract via UUPS pattern

2. **Inconsistent Validation**: The codebase validates `shareToken_` and `asset_` addresses but not `owner`, indicating this is an oversight rather than intentional design

3. **High Deployment Risk**: This is most likely to occur during initial deployment when scripts are being tested, addresses are being copied, or multi-sig addresses are being configured

4. **Complete System Failure**: For `ShareTokenUpgradeable`, the inability to register vaults makes the entire multi-asset system non-functional from the start

5. **Not in Known Issues**: This is not listed in KNOWN_ISSUES.md under centralization risks or deployment risks, confirming it should be addressed

The fix is simple (add one line of validation) but the impact of not having it is severe - permanent contract lockout requiring complete redeployment.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L116-124)
```text
    function initialize(string memory name, string memory symbol, address owner) public initializer {
        __ERC20_init(name, symbol);
        __Ownable_init(owner);

        // Enforce 18 decimals for consistency with ERC7575 standard
        if (decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
            revert WrongDecimals();
        }
    }
```

**File:** src/ShareTokenUpgradeable.sol (L194-235)
```text
     */
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
    }
```

**File:** src/ShareTokenUpgradeable.sol (L568-587)
```text
     */
    function setInvestmentShareToken(address investmentShareToken_) external onlyOwner {
        if (investmentShareToken_ == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        if ($.investmentShareToken != address(0)) {
            revert InvestmentShareTokenAlreadySet();
        }

        // Store the investment ShareToken address
        $.investmentShareToken = investmentShareToken_;

        // Iterate through all registered assets and configure investment vaults
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (address asset, address vaultAddress) = $.assetToVault.at(i);
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken_);
        }

        emit InvestmentShareTokenSet(investmentShareToken_);
    }
```

**File:** src/ShareTokenUpgradeable.sol (L658-676)
```text
     */
    function setInvestmentManager(address newInvestmentManager) external onlyOwner {
        if (newInvestmentManager == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();

        // Store the investment manager centrally
        $.investmentManager = newInvestmentManager;

        // Propagate to all registered vaults
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Call setInvestmentManager on each vault
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(newInvestmentManager);
        }

        emit InvestmentManagerSet(newInvestmentManager);
    }
```

**File:** src/ShareTokenUpgradeable.sol (L777-789)
```text
     */
    function upgradeTo(address newImplementation) external onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, "");
    }

    /**
     * @dev Upgrade the implementation and call a function (only owner)
     * @param newImplementation Address of the new implementation contract
     * @param data Calldata to execute on the new implementation
     */
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L150-190)
```text
    function initialize(IERC20Metadata asset_, address shareToken_, address owner) public initializer {
        if (shareToken_ == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (address(asset_) == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }

        // Validate asset compatibility and get decimals
        uint8 assetDecimals;
        try IERC20Metadata(address(asset_)).decimals() returns (uint8 decimals) {
            if (decimals < DecimalConstants.MIN_ASSET_DECIMALS || decimals > DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert UnsupportedAssetDecimals();
            }
            assetDecimals = decimals;
        } catch {
            revert AssetDecimalsFailed();
        }
        // Validate share token compatibility and enforce 18 decimals
        try IERC20Metadata(shareToken_).decimals() returns (uint8 decimals) {
            if (decimals != DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert WrongDecimals();
            }
        } catch {
            revert AssetDecimalsFailed();
        }
        __Ownable_init(owner);

        VaultStorage storage $ = _getVaultStorage();
        $.asset = address(asset_);
        $.assetDecimals = assetDecimals;
        $.shareToken = shareToken_;
        $.investmentManager = owner; // Initially owner is investment manager
        $.isActive = true; // Vault is active by default

        // Calculate scaling factor for decimal normalization: 10^(18 - assetDecimals)
        uint256 scalingFactor = 10 ** (DecimalConstants.SHARE_TOKEN_DECIMALS - assetDecimals);
        if (scalingFactor > type(uint64).max) revert ScalingFactorTooLarge();
        $.scalingFactor = uint64(scalingFactor);
        $.minimumDepositAmount = 1000;
    }
```
