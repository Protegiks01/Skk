## Title
Share Token Balance Confusion in totalAssets() Calculation When shareToken Equals Asset Token

## Summary
When a vault is configured with `shareToken == asset` (same token address), the `totalAssets()` function incorrectly includes shares held by the vault from pending/claimable redemption requests as available assets. This inflates the vault's reported asset balance, breaking conversion rates and enabling share price manipulation.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/ERC7575VaultUpgradeable.sol` - `totalAssets()` function (lines 1174-1180), `initialize()` function (lines 150-190), `requestRedeem()` function (line 740), `fulfillRedeem()` function (lines 822-841) [1](#0-0) 

**Intended Logic:** The vault should maintain separate accounting for asset tokens (deposits awaiting investment) and share tokens (redemption requests awaiting conversion to assets). The `totalAssets()` function should only count actual asset tokens available for operations, excluding reserved amounts.

**Actual Logic:** The initialization function lacks validation preventing `shareToken` from being set equal to `asset`. When they are the same address, share tokens held by the vault (from redemption requests) become indistinguishable from asset tokens in the balance calculation. [2](#0-1) 

During the redemption lifecycle:
1. `requestRedeem()` transfers shares from user to vault and stores them in `pendingRedeemShares`
2. `fulfillRedeem()` moves shares to `claimableRedeemShares` and increments `totalClaimableRedeemShares`
3. `redeem()`/`withdraw()` finally burns the shares [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. Owner deploys a vault where `shareToken == asset` (both are 18-decimal ERC20 tokens, no validation prevents this)
2. Users deposit 1000 asset tokens and receive 1000 shares (same token)
3. User calls `requestRedeem(500 shares)`, transferring 500 tokens to vault
4. Investment manager calls `fulfillRedeem()`, setting `totalClaimableRedeemShares = 500`
5. At this point, vault holds 500 tokens that are both "shares to be burned" AND counted as "assets" by `totalAssets()`
6. `totalAssets()` returns: `balance (1500) - reservedAssets (calculated without subtracting shares) = inflated value`
7. This inflated `totalAssets()` breaks `convertToShares()` and `convertToAssets()`, allowing subsequent depositors to receive fewer shares than deserved, or redeemers to claim more assets

**Security Property Broken:** 
- **Invariant #9 Violated**: "Reserved Asset Protection: investedAssets + reservedAssets ≤ totalAssets" - The calculation is broken because shares are incorrectly counted as available assets
- **Invariant #10 Violated**: "Conversion Accuracy: convertToShares(convertToAssets(x)) ≈ x" - Conversion rates become inaccurate due to inflated totalAssets [5](#0-4) 

## Impact Explanation
- **Affected Assets**: All assets in vaults where shareToken == asset
- **Damage Severity**: Complete accounting breakdown - the vault's reported asset balance includes tokens that should be burned as shares. For example, with 500 shares pending burn, totalAssets() is inflated by 500 tokens worth of value. This creates systematic mispricing.
- **User Impact**: 
  - Later depositors receive fewer shares than they should (paying more per share)
  - Earlier redeemers can extract more assets than they should (receiving inflated value)
  - Investment manager may invest "phantom" assets that don't exist
  - All conversion calculations (`convertToShares`, `convertToAssets`) become incorrect

## Likelihood Explanation
- **Attacker Profile**: Vault deployer (owner) or first depositor who can influence vault parameters
- **Preconditions**: 
  - Vault deployed with `shareToken == asset` (no validation prevents this)
  - Share token has 18 decimals (required by initialization check)
  - At least one redemption request exists in pending or claimable state
- **Execution Complexity**: Single transaction to deploy misconfigured vault, then normal redemption flows trigger the issue
- **Frequency**: Continuous - the issue persists as long as any shares are held by the vault awaiting burn

## Recommendation

Add validation in the `initialize()` function to prevent `shareToken` from being set equal to `asset`: [6](#0-5) 

```solidity
// In src/ERC7575VaultUpgradeable.sol, initialize() function, after line 156:

// CURRENT (vulnerable):
// [No check preventing shareToken == asset]

// FIXED:
function initialize(IERC20Metadata asset_, address shareToken_, address owner) public initializer {
    if (shareToken_ == address(0)) {
        revert IERC20Errors.ERC20InvalidReceiver(address(0));
    }
    if (address(asset_) == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    
    // ADD THIS CHECK:
    if (shareToken_ == address(asset_)) {
        revert InvalidConfiguration(); // Share token cannot be same as asset token
    }
    
    // ... rest of initialization
}
```

Additionally, add the same check in `ShareTokenUpgradeable.registerVault()` as defense-in-depth: [7](#0-6) 

```solidity
// In src/ShareTokenUpgradeable.sol, registerVault() function, after line 197:

function registerVault(address asset, address vaultAddress) external onlyOwner {
    if (asset == address(0)) revert ZeroAddress();
    if (vaultAddress == address(0)) revert ZeroAddress();
    
    // ADD THIS CHECK:
    if (asset == address(this)) {
        revert InvalidConfiguration(); // Asset cannot be same as share token
    }
    
    // ... rest of registration logic
}
```

## Proof of Concept

```solidity
// File: test/Exploit_ShareTokenAssetConfusion.t.sol
// Run with: forge test --match-test test_ShareTokenAssetConfusion -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/ShareTokenUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Mock18DecimalToken is ERC20 {
    constructor() ERC20("Mock18", "M18") {
        _mint(msg.sender, 1000000 * 10**18);
    }
    function decimals() public pure override returns (uint8) {
        return 18;
    }
}

contract Exploit_ShareTokenAssetConfusion is Test {
    ERC7575VaultUpgradeable public vault;
    Mock18DecimalToken public token;
    
    address public owner = address(this);
    address public user1 = address(0x1);
    address public user2 = address(0x2);
    address public investmentManager = address(0x3);
    
    function setUp() public {
        // Deploy an 18-decimal token that will be BOTH share and asset
        token = new Mock18DecimalToken();
        
        // Deploy vault with token as BOTH shareToken AND asset
        ERC7575VaultUpgradeable vaultImpl = new ERC7575VaultUpgradeable();
        ERC1967Proxy vaultProxy = new ERC1967Proxy(
            address(vaultImpl),
            abi.encodeWithSelector(
                ERC7575VaultUpgradeable.initialize.selector,
                token, // asset
                address(token), // shareToken == asset (THE BUG)
                owner
            )
        );
        vault = ERC7575VaultUpgradeable(address(vaultProxy));
        
        // Setup
        vault.setInvestmentManager(investmentManager);
        vault.setMinimumDepositAmount(0);
        
        // Fund users
        token.transfer(user1, 1000 * 10**18);
        token.transfer(user2, 1000 * 10**18);
    }
    
    function test_ShareTokenAssetConfusion() public {
        // SETUP: User1 deposits 1000 tokens
        vm.startPrank(user1);
        token.approve(address(vault), 1000 * 10**18);
        vault.requestDeposit(1000 * 10**18, user1, user1);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        vault.fulfillDeposit(user1, 1000 * 10**18);
        
        vm.prank(user1);
        vault.deposit(1000 * 10**18, user1, user1);
        
        // Record initial totalAssets - should be 0 (no assets in vault after deposit fulfilled)
        uint256 assetsBeforeRedeem = vault.totalAssets();
        console.log("Assets before redeem request:", assetsBeforeRedeem);
        
        // EXPLOIT: User1 requests redemption of 500 shares
        // This transfers 500 tokens to vault (they're both shares AND assets)
        vm.startPrank(user1);
        token.approve(address(vault), 500 * 10**18);
        vault.requestRedeem(500 * 10**18, user1, user1);
        vm.stopPrank();
        
        // Investment manager fulfills the redemption
        vm.prank(investmentManager);
        vault.fulfillRedeem(user1, 500 * 10**18);
        
        // VERIFY: totalAssets() is now INFLATED by the shares in vault
        uint256 assetsAfterRedeem = vault.totalAssets();
        console.log("Assets after redeem fulfilled:", assetsAfterRedeem);
        console.log("Vault token balance:", token.balanceOf(address(vault)));
        console.log("Total claimable redeem shares:", vault.totalClaimableRedeemShares());
        
        // The vault now holds 500 tokens (shares waiting to be burned)
        // But totalAssets() incorrectly counts them as available assets!
        assertGt(assetsAfterRedeem, assetsBeforeRedeem, 
            "Vulnerability confirmed: totalAssets inflated by shares held for burning");
        
        // This breaks conversions - subsequent depositor gets wrong share amount
        vm.startPrank(user2);
        token.approve(address(vault), 100 * 10**18);
        vault.requestDeposit(100 * 10**18, user2, user2);
        vm.stopPrank();
        
        vm.prank(investmentManager);
        uint256 sharesForUser2 = vault.fulfillDeposit(user2, 100 * 10**18);
        
        // User2 receives fewer shares due to inflated totalAssets
        console.log("Shares issued to user2 for 100 tokens:", sharesForUser2);
        assertLt(sharesForUser2, 100 * 10**18, "User2 receives fewer shares than deserved");
    }
}
```

## Notes

The vulnerability stems from insufficient validation during vault initialization. While the code correctly enforces that share tokens must have 18 decimals and assets must have 6-18 decimals, it never validates that these two addresses must be different. This oversight creates a fundamental accounting confusion where tokens serving as "shares to be burned" are simultaneously counted as "available assets."

The issue is particularly insidious because:
1. It requires no malicious intent - it can occur from honest misconfiguration
2. SafeTokenTransfers library operates correctly - the problem is conceptual accounting confusion, not transfer validation
3. The bug surfaces gradually as redemption requests accumulate, making it harder to detect
4. It violates the core separation of concerns between the share token (ownership representation) and asset token (underlying value)

The fix is straightforward: add explicit validation preventing `shareToken == asset` during initialization and registration.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L86-123)
```text
    struct VaultStorage {
        // Storage slot optimization: pack address + uint64 + bool in single 32-byte slot
        address asset; // 20 bytes
        uint64 scalingFactor; // 8 bytes
        bool isActive; // 1 byte (fits with asset + scalingFactor: total 29 bytes + 3 bytes padding)
        uint8 assetDecimals; // 1 byte
        uint16 minimumDepositAmount; // 2 bytes
        // Remaining addresses (each takes full 32-byte slot)
        address shareToken;
        address investmentManager;
        address investmentVault;
        // Large numbers (each takes full 32-byte slot)
        uint256 totalPendingDepositAssets;
        uint256 totalClaimableRedeemAssets; // Assets reserved for users who can claim them
        uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
        // ERC7540 mappings with descriptive names
        mapping(address controller => uint256 assets) pendingDepositAssets;
        mapping(address controller => uint256 shares) claimableDepositShares;
        mapping(address controller => uint256 assets) claimableDepositAssets; // Store corresponding asset amounts
        mapping(address controller => uint256 shares) pendingRedeemShares;
        mapping(address controller => uint256 assets) claimableRedeemAssets;
        mapping(address controller => uint256 shares) claimableRedeemShares;
        // Off-chain helper sets for tracking active requests (using EnumerableSet for O(1) operations)
        EnumerableSet.AddressSet activeDepositRequesters;
        EnumerableSet.AddressSet activeRedeemRequesters;
        // ERC7887 Cancelation Request Storage (simplified - requestId is always 0)
        // Deposit cancelations: controller => assets (requestId always 0)
        mapping(address controller => uint256 assets) pendingCancelDepositAssets;
        mapping(address controller => uint256 assets) claimableCancelDepositAssets;
        // Redeem cancelations: controller => shares (requestId always 0)
        mapping(address controller => uint256 shares) pendingCancelRedeemShares;
        mapping(address controller => uint256 shares) claimableCancelRedeemShares;
        // Total pending and claimable cancelation deposit assets (for totalAssets() calculation)
        uint256 totalCancelDepositAssets;
        // Track controllers with pending cancelations to block new requests
        EnumerableSet.AddressSet controllersWithPendingDepositCancelations;
        EnumerableSet.AddressSet controllersWithPendingRedeemCancelations;
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

**File:** src/ERC7575VaultUpgradeable.sol (L738-742)
```text
        // Pull-Then-Credit pattern: Transfer shares first before updating state
        // This ensures we only credit shares that have been successfully received
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }
```

**File:** src/ERC7575VaultUpgradeable.sol (L833-837)
```text
        $.pendingRedeemShares[controller] -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned
```

**File:** src/ERC7575VaultUpgradeable.sol (L1174-1180)
```text
    function totalAssets() public view virtual returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        uint256 balance = IERC20Metadata($.asset).balanceOf(address(this));
        // Exclude pending deposits, pending/claimable cancelation deposits, and claimable withdrawals from total assets
        uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;
        return balance > reservedAssets ? balance - reservedAssets : 0;
    }
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
