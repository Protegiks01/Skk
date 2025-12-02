## Title
Missing Investment Vault Share Token Compatibility Validation Causes Permanent Fund Lock

## Summary
The `setInvestmentVault()` function in `ERC7575VaultUpgradeable` does not verify that the investment vault's share token is compatible with the ShareToken's authorization model. [1](#0-0)  If an investment vault is set whose share token requires self-allowance (like WERC7575ShareToken's permit-based authorization), assets can be invested but never withdrawn, resulting in permanent fund lock.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol` - `setInvestmentVault()` function (lines 1397-1408) and `withdrawFromInvestment()` function (lines 1477-1509)

**Intended Logic:** The `setInvestmentVault()` function should validate that the investment vault is fully compatible with the protocol's investment/withdrawal flows before allowing it to be set. The ShareToken should be able to withdraw invested assets when needed.

**Actual Logic:** The function only validates asset matching and non-zero address. [2](#0-1)  It does not verify that the ShareToken can obtain the required self-allowance on the investment vault's share token, which is checked later during withdrawal. [3](#0-2) 

**Exploitation Path:**

1. **Owner sets incompatible investment vault:** Owner calls `setInvestmentVault()` with a WERC7575Vault (or similar architecture) whose share token requires permit-based self-allowance. The function only validates asset match, allowing the incompatible vault to be set.

2. **Investment succeeds:** Investment manager calls `investAssets(amount)`, which deposits assets into the investment vault and receives investment shares to the ShareToken. [4](#0-3)  The investment vault's shares are now held by ShareToken.

3. **Withdrawal requires self-allowance:** When attempting to withdraw via `withdrawFromInvestment()`, the function checks that ShareToken has self-allowance on the investment share token. [5](#0-4) 

4. **Self-allowance cannot be obtained:** The ShareToken has no mechanism to grant itself self-allowance on external tokens. The approval granted during configuration only gives the vault permission to spend ShareToken's balance, not self-allowance. [6](#0-5)  For WERC7575ShareToken-style tokens that block self-approval via `approve()` [7](#0-6)  and require validator-signed `permit()` for self-allowance, there's no way for ShareToken to obtain this authorization.

5. **Funds permanently locked:** The withdrawal reverts with `InvestmentSelfAllowanceMissing`. Assets remain locked in the investment vault with no recovery mechanism. Even if the owner sets a different investment vault, the locked assets cannot be retrieved from the incompatible vault.

**Security Property Broken:** Violates invariant #12 "No Fund Theft" - while not theft, it results in permanent fund loss due to logic error in validation.

## Impact Explanation

- **Affected Assets**: All assets invested through the incompatible investment vault become permanently locked
- **Damage Severity**: 100% loss of invested capital - assets cannot be withdrawn due to missing self-allowance
- **User Impact**: All users with shares backed by the locked invested assets lose access to their proportional share of those assets. The investment layer vault becomes effectively bricked for investment operations.

## Likelihood Explanation

- **Attacker Profile**: Does not require an attacker - this is triggered by owner configuration error due to missing validation
- **Preconditions**: Owner sets an investment vault whose share token requires self-allowance but ShareToken cannot obtain it (e.g., another WERC7575 deployment, or any vault with similar authorization architecture)
- **Execution Complexity**: Single transaction by owner to set vault, then normal investment operations by investment manager
- **Frequency**: Can occur whenever integrating with external protocols that have incompatible share token architectures

## Recommendation

Add validation in `setInvestmentVault()` to verify the investment vault's share token is compatible:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function setInvestmentVault, after line 1405:

// CURRENT (vulnerable):
// Missing validation of share token compatibility

// FIXED:
function setInvestmentVault(IERC7575 investmentVault_) external {
    VaultStorage storage $ = _getVaultStorage();
    if (msg.sender != owner() && msg.sender != $.shareToken) {
        revert Unauthorized();
    }
    if (address(investmentVault_) == address(0)) revert InvalidVault();
    if (address(investmentVault_.asset()) != $.asset) {
        revert AssetMismatch();
    }
    
    // NEW: Validate share token compatibility
    // Check that ShareToken has or can obtain self-allowance on investment shares
    address investmentShareToken = investmentVault_.share();
    address shareToken_ = $.shareToken;
    
    // Try to verify ShareToken can approve itself on the investment share token
    // For WERC7575-style tokens, this would require permit support
    // For standard ERC20s, ShareToken would need a function to call approve
    uint256 currentAllowance = IERC20Metadata(investmentShareToken).allowance(shareToken_, shareToken_);
    if (currentAllowance == 0) {
        // Attempt to verify the share token supports the required authorization model
        // This could check for EIP-2612 permit support or other compatibility markers
        try IERC20Permit(investmentShareToken).DOMAIN_SEPARATOR() returns (bytes32) {
            // Token supports permit, but we need to ensure ShareToken can obtain self-allowance
            // Either require pre-existing allowance or provide mechanism to obtain it
            revert InvestmentVaultIncompatible();
        } catch {
            // Standard ERC20 without permit - ShareToken needs way to approve itself
            revert InvestmentVaultIncompatible();
        }
    }
    
    $.investmentVault = address(investmentVault_);
    emit InvestmentVaultSet(address(investmentVault_));
}

// Alternative simpler fix: Add function to grant self-allowance
function grantInvestmentSelfAllowance(uint256 amount) external onlyOwner {
    VaultStorage storage $ = _getVaultStorage();
    if ($.investmentVault == address(0)) revert NoInvestmentVault();
    address investmentShareToken = IERC7575($.investmentVault).share();
    
    // This requires ShareToken to have a function that calls approve on external tokens
    // Add to ShareTokenUpgradeable:
    // function approveExternalToken(address token, address spender, uint256 amount) external onlyOwner {
    //     IERC20(token).approve(spender, amount);
    // }
}
```

**Better architectural fix:** Add a function in `ShareTokenUpgradeable` that allows the owner to grant self-allowance on external tokens, and require this to be called before investment operations can proceed.

## Proof of Concept

```solidity
// File: test/Exploit_InvestmentVaultBrick.t.sol
// Run with: forge test --match-test test_IncompatibleInvestmentVaultBricksWithdrawal -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";
import "./MockAsset.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_InvestmentVaultBrick is Test {
    ERC7575VaultUpgradeable public vault;
    ShareTokenUpgradeable public shareToken;
    MockAsset public asset;
    
    // Incompatible investment layer (separate WERC7575 deployment with different validator)
    WERC7575Vault public investmentVault;
    WERC7575ShareToken public investmentShareToken;
    
    address public owner = makeAddr("owner");
    address public investmentManager = makeAddr("investmentManager");
    address public validator1 = makeAddr("validator1"); // Settlement layer validator
    address public validator2 = makeAddr("validator2"); // Investment layer validator (different!)
    
    function setUp() public {
        asset = new MockAsset();
        
        vm.startPrank(owner);
        
        // Deploy SEPARATE investment system with DIFFERENT validator
        investmentShareToken = new WERC7575ShareToken("External USD", "eUSD");
        investmentVault = new WERC7575Vault(address(asset), investmentShareToken);
        investmentShareToken.registerVault(address(asset), address(investmentVault));
        investmentShareToken.setValidator(validator2); // Different validator!
        investmentShareToken.setKycAdmin(validator2);
        
        // Seed investment vault
        asset.mint(address(investmentVault), 1000000e18);
        
        vm.stopPrank();
        
        vm.startPrank(owner);
        
        // Deploy settlement layer
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        bytes memory shareTokenInitData = abi.encodeWithSelector(
            ShareTokenUpgradeable.initialize.selector, "Settlement Shares", "SS", owner
        );
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(address(shareTokenImpl), shareTokenInitData);
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        bytes memory vaultInitData = abi.encodeWithSelector(
            ERC7575VaultUpgradeable.initialize.selector, asset, address(shareToken), owner
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        shareToken.registerVault(address(asset), address(vault));
        shareToken.setInvestmentManager(investmentManager);
        
        // Set up investment vault - THIS SHOULD FAIL BUT DOESN'T
        vault.setInvestmentVault(investmentVault);
        
        vm.stopPrank();
        
        // KYC ShareToken in investment layer
        vm.prank(validator2);
        investmentShareToken.setKycVerified(address(shareToken), true);
        
        // Give vault some assets to invest
        asset.mint(address(vault), 100000e18);
    }
    
    function test_IncompatibleInvestmentVaultBricksWithdrawal() public {
        // SETUP: Investment succeeds
        vm.prank(investmentManager);
        uint256 investedShares = vault.investAssets(50000e18);
        
        assertGt(investedShares, 0, "Investment succeeded");
        assertEq(investmentShareToken.balanceOf(address(shareToken)), investedShares, 
                 "ShareToken holds investment shares");
        
        // EXPLOIT: Withdrawal fails due to missing self-allowance
        // ShareToken has 0 self-allowance on investmentShareToken
        uint256 selfAllowance = investmentShareToken.allowance(address(shareToken), address(shareToken));
        assertEq(selfAllowance, 0, "ShareToken has no self-allowance on investment shares");
        
        // Try to withdraw - THIS WILL REVERT
        vm.prank(investmentManager);
        vm.expectRevert(
            abi.encodeWithSignature("InvestmentSelfAllowanceMissing(uint256,uint256)", investedShares, 0)
        );
        vault.withdrawFromInvestment(25000e18);
        
        // VERIFY: Funds are permanently locked
        // Even if we try to grant allowance via permit, we would need validator2's signature
        // But validator2 is external and not controlled by the settlement layer
        // There's no way to recover the locked assets
        assertEq(asset.balanceOf(address(vault)), 50000e18, 
                 "Half of assets still in vault");
        assertEq(investmentShareToken.balanceOf(address(shareToken)), investedShares,
                 "Investment shares locked in ShareToken with no way to redeem");
    }
}
```

## Notes

This vulnerability demonstrates a critical validation gap in the investment vault integration. The `withdrawFromInvestment()` function explicitly checks for self-allowance [5](#0-4) , indicating the protocol developers were aware of this requirement. However, the `setInvestmentVault()` function fails to validate this prerequisite upfront.

The test suite confirms that manual `permit()` calls are required to grant self-allowance before investment operations, [8](#0-7)  but there's no mechanism for the ShareToken to obtain this allowance on external tokens.

This is not merely an "admin misconfiguration" - it's a missing validation that should prevent easy-to-make integration errors. The protocol should either validate compatibility upfront or provide mechanisms for the ShareToken to obtain required authorizations on external tokens.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L1397-1408)
```text
    function setInvestmentVault(IERC7575 investmentVault_) external {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != owner() && msg.sender != $.shareToken) {
            revert Unauthorized();
        }
        if (address(investmentVault_) == address(0)) revert InvalidVault();
        if (address(investmentVault_.asset()) != $.asset) {
            revert AssetMismatch();
        }
        $.investmentVault = address(investmentVault_);
        emit InvestmentVaultSet(address(investmentVault_));
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1459-1461)
```text
        // Approve and deposit into investment vault with ShareToken as receiver
        IERC20Metadata($.asset).safeIncreaseAllowance($.investmentVault, amount);
        shares = IERC7575($.investmentVault).deposit(amount, $.shareToken);
```

**File:** src/ERC7575VaultUpgradeable.sol (L1493-1497)
```text
        // Ensure ShareToken has self-allowance on the investment share token for redemption
        uint256 current = investmentShareToken.allowance(shareToken_, shareToken_);
        if (current < minShares) {
            revert InvestmentSelfAllowanceMissing(minShares, current);
        }
```

**File:** src/ShareTokenUpgradeable.sol (L548-549)
```text
            // Grant unlimited allowance to the vault on the investment ShareToken
            IERC20(investmentShareToken).approve(vaultAddress, type(uint256).max);
```

**File:** src/WERC7575ShareToken.sol (L439-444)
```text
    function approve(address spender, uint256 value) public virtual override returns (bool) {
        if (msg.sender != spender) {
            return super.approve(spender, value);
        }
        revert ERC20InvalidSpender(msg.sender);
    }
```

**File:** test/ERC7540ComplianceComplete.t.sol (L130-131)
```text
        // Apply the permit (validator signature allows ShareToken to spend its own tokens)
        investmentShareToken.permit(shareTokenAddress, shareTokenAddress, value, deadline, v, r, s);
```
