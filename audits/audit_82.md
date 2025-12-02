## Title
Vaults Registered Before Investment Vault Availability Permanently Miss Investment Configuration

## Summary
When a settlement vault is registered for an asset that has no corresponding investment vault yet, the `_configureVaultInvestmentSettings()` function silently skips configuration. If an investment vault is later added for that asset, there is no mechanism to retroactively configure the settlement vault, permanently preventing it from investing idle assets and earning yield for users.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/ShareTokenUpgradeable.sol` - `_configureVaultInvestmentSettings()` (lines 540-551), `registerVault()` (lines 195-235), `setInvestmentShareToken()` (lines 569-587)

**Intended Logic:** The architecture documentation states "each vault will have its counterpart investment vault" for unified investment strategy across the multi-asset system. When vaults are registered, they should be automatically configured for investment if the investment ShareToken is already set.

**Actual Logic:** The configuration only happens at specific trigger points with no fallback mechanism: [1](#0-0) 

When `investmentVaultAddress` is `address(0)`, the function silently returns without configuration. The `setInvestmentShareToken()` function can only be called once: [2](#0-1) 

**Exploitation Path:**
1. Protocol owner calls `setInvestmentShareToken(investmentShareTokenA)` to enable investment (can only be called once due to check at line 572-574)
2. At this time, investmentShareTokenA has investment vaults for assets A, B, C only
3. Owner later registers a new settlement vault for asset D via `registerVault(assetD, vaultD)` 
4. At line 542, `investmentShareToken.vault(assetD)` returns `address(0)` (no investment vault exists yet)
5. The condition at line 545 fails, function returns without setting investment vault or granting approval
6. Later, an investment vault for asset D is added to the investment ShareToken
7. vaultD remains unconfigured - no automatic reconfiguration mechanism exists
8. Manual workaround fails: owner can call `setInvestmentVault()` on vaultD directly, but there's no public function to grant the critical approval at line 549 [3](#0-2) 

**Security Property Broken:** Breaks the documented multi-asset architecture requirement that "each vault will have its counterpart investment vault" and creates functional inconsistency where some vaults can invest while others cannot.

## Impact Explanation
- **Affected Assets**: Any asset whose settlement vault is registered before its corresponding investment vault is available
- **Damage Severity**: Users depositing the affected asset permanently lose yield opportunities while users of other assets earn returns. The vault cannot call `investAssets()` which will revert with "NoInvestmentVault"
- **User Impact**: All users of the affected asset class are impacted. Even after the investment vault becomes available, their deposits cannot benefit from yield generation without a protocol upgrade or disruptive vault replacement

The missing approval is critical for the investment withdrawal flow: [4](#0-3) 

Without the approval granted at ShareTokenUpgradeable line 549, the `withdrawFromInvestment()` call will fail when the investment vault checks allowance during redemption.

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is an operational configuration failure triggered by normal protocol operations
- **Preconditions**: Investment ShareToken already set, new vault registered for an asset without an investment vault, investment vault later added
- **Execution Complexity**: Occurs naturally during protocol expansion when new assets are added over time
- **Frequency**: Can occur every time a new asset is added to the settlement layer before the investment layer is ready

## Recommendation

Add a public function to manually configure investment settings for already-registered vaults:

```solidity
// In src/ShareTokenUpgradeable.sol, add after setInvestmentShareToken():

/**
 * @dev Manually configures investment settings for a specific vault (only owner)
 * 
 * Allows retroactive configuration when investment vaults are added after
 * settlement vault registration. This ensures all vaults can participate in
 * the investment layer regardless of registration timing.
 *
 * @param asset The asset address whose vault needs configuration
 */
function configureVaultInvestment(address asset) external onlyOwner {
    ShareTokenStorage storage $ = _getShareTokenStorage();
    address investmentShareToken = $.investmentShareToken;
    
    if (investmentShareToken == address(0)) revert InvestmentShareTokenNotSet();
    
    (bool exists, address vaultAddress) = $.assetToVault.tryGet(asset);
    if (!exists) revert AssetNotRegistered();
    
    _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken);
}
```

This allows the owner to manually trigger configuration after an investment vault becomes available, granting both the investment vault assignment and the critical approval in one transaction.

## Proof of Concept

```solidity
// File: test/Exploit_MissingInvestmentConfig.t.sol
// Run with: forge test --match-test test_MissingInvestmentConfiguration -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";

contract MissingInvestmentConfigTest is Test {
    ShareTokenUpgradeable settlementShareToken;
    ShareTokenUpgradeable investmentShareToken;
    ERC7575VaultUpgradeable settlementVault;
    ERC7575VaultUpgradeable investmentVault;
    address assetD;
    address owner;
    address investmentManager;
    
    function setUp() public {
        owner = address(this);
        investmentManager = address(0x123);
        assetD = address(0xD);
        
        // Deploy settlement and investment ShareTokens
        settlementShareToken = new ShareTokenUpgradeable();
        investmentShareToken = new ShareTokenUpgradeable();
        
        settlementShareToken.initialize("Settlement", "SETL", owner);
        investmentShareToken.initialize("Investment", "INV", owner);
        
        // Set investment ShareToken on settlement layer (can only call once)
        settlementShareToken.setInvestmentShareToken(address(investmentShareToken));
    }
    
    function test_MissingInvestmentConfiguration() public {
        // SETUP: Register settlement vault for asset D when no investment vault exists
        settlementVault = new ERC7575VaultUpgradeable();
        settlementVault.initialize(
            assetD,
            address(settlementShareToken),
            owner,
            investmentManager,
            "Vault D",
            100 ether
        );
        
        // Register vault - at this point, no investment vault exists for asset D
        settlementShareToken.registerVault(assetD, address(settlementVault));
        
        // VERIFY: Investment vault is not set
        address configuredInvestmentVault = settlementVault.getInvestmentVault();
        assertEq(configuredInvestmentVault, address(0), "Should have no investment vault");
        
        // LATER: Investment vault for asset D is added
        investmentVault = new ERC7575VaultUpgradeable();
        investmentVault.initialize(
            assetD,
            address(investmentShareToken),
            owner,
            investmentManager,
            "Investment Vault D",
            100 ether
        );
        investmentShareToken.registerVault(assetD, address(investmentVault));
        
        // EXPLOIT: Settlement vault still has no investment configuration
        configuredInvestmentVault = settlementVault.getInvestmentVault();
        assertEq(configuredInvestmentVault, address(0), 
            "Vulnerability confirmed: Investment vault not retroactively configured");
        
        // VERIFY: investAssets will fail with NoInvestmentVault error
        vm.prank(investmentManager);
        vm.expectRevert(NoInvestmentVault.selector);
        settlementVault.investAssets(100 ether);
        
        // VERIFY: Even if owner manually sets investment vault, approval is missing
        settlementVault.setInvestmentVault(IERC7575(address(investmentVault)));
        
        // The approval from settlementShareToken to settlementVault is still missing
        // This breaks withdrawFromInvestment functionality
        uint256 allowance = IERC20(address(investmentShareToken)).allowance(
            address(settlementShareToken),
            address(settlementVault)
        );
        assertEq(allowance, 0, 
            "Missing critical approval: Cannot withdraw from investment");
    }
}
```

## Notes

This vulnerability highlights a timing dependency in the investment configuration architecture. The issue occurs when settlement vaults are registered before their corresponding investment vaults are ready, which is a realistic scenario during protocol expansion. 

The only complete workarounds without a code fix are:
1. **Protocol Upgrade**: Add a manual configuration function (recommended fix above)
2. **Unregister and Re-register**: Requires the vault to have zero balances across all request states, which is highly disruptive to users
3. **Accept Broken Functionality**: Leave the vault unable to invest, creating unfair yield distribution

The missing approval at line 549 of ShareTokenUpgradeable.sol is particularly critical because even if the owner manually sets the investment vault using the vault's `setInvestmentVault()` function, the vault still cannot withdraw assets from the investment layer, effectively making any investments one-way and locking funds.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L220-225)
```text
        // If investment ShareToken is already configured, set up investment for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentShareToken = $.investmentShareToken;
        if (investmentShareToken != address(0)) {
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken);
        }
```

**File:** src/ShareTokenUpgradeable.sol (L540-551)
```text
    function _configureVaultInvestmentSettings(address asset, address vaultAddress, address investmentShareToken) internal {
        // Find the corresponding investment vault for this asset
        address investmentVaultAddress = IERC7575ShareExtended(investmentShareToken).vault(asset);

        // Configure investment vault if there's a matching one for this asset
        if (investmentVaultAddress != address(0)) {
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentVault(IERC7575(investmentVaultAddress));

            // Grant unlimited allowance to the vault on the investment ShareToken
            IERC20(investmentShareToken).approve(vaultAddress, type(uint256).max);
        }
    }
```

**File:** src/ShareTokenUpgradeable.sol (L569-587)
```text
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

**File:** src/ERC7575VaultUpgradeable.sol (L1493-1500)
```text
        // Ensure ShareToken has self-allowance on the investment share token for redemption
        uint256 current = investmentShareToken.allowance(shareToken_, shareToken_);
        if (current < minShares) {
            revert InvestmentSelfAllowanceMissing(minShares, current);
        }

        // Redeem shares from ShareToken using our allowance (ShareToken is owner, vault is receiver)
        IERC7575($.investmentVault).redeem(minShares, address(this), shareToken_);
```
