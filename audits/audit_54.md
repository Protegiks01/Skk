## Title
Missing `totalClaimableDepositAssets` Tracking Enables Vault Over-Investment and Violates Reserved Asset Protection

## Summary
The `ERC7575VaultUpgradeable` contract fails to track claimable deposit assets globally, causing `totalAssets()` to miscalculate available funds after the investment manager fulfills deposit requests. This accounting asymmetry allows the vault to over-invest reserved capital, violating the "Reserved Asset Protection" invariant and potentially creating liquidity shortfalls when servicing redemptions.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol`
- `fulfillDeposit()` function (lines 425-445)
- `totalAssets()` function (lines 1174-1180)
- `VaultStorage` struct (lines 86-123)

**Intended Logic:** 
The vault should maintain complete accounting of all reserved assets (pending deposits, claimable deposits, claimable redeems, and cancelations) and exclude them from `totalAssets()` to prevent over-investment. This is evident from how the protocol tracks `totalClaimableRedeemAssets` globally for redemptions. [1](#0-0) 

**Actual Logic:** 
The vault tracks `totalPendingDepositAssets` before fulfillment but has NO corresponding `totalClaimableDepositAssets` variable after fulfillment. When `fulfillDeposit()` moves assets from pending to claimable state, it only updates per-controller mappings without maintaining a global total. [2](#0-1) 

The storage structure confirms this asymmetry - `totalClaimableRedeemAssets` exists for redemptions, but no equivalent for deposits: [3](#0-2) 

Consequently, `totalAssets()` only excludes `totalPendingDepositAssets` (line 1178), not claimable deposit assets: [4](#0-3) 

**Exploitation Path:**

1. **Large Deposit Request**: Whale calls `requestDeposit(10,000,000 USDC)`
   - Assets transfer to vault
   - `totalPendingDepositAssets = 10M`
   - `totalAssets() = balance - 10M = 0` (correctly reserved) [5](#0-4) 

2. **Investment Manager Fulfills**: IM calls `fulfillDeposit(whale, 10M)`
   - Line 437: `totalPendingDepositAssets -= 10M` (now 0)
   - Line 439: `claimableDepositAssets[whale] = 10M` (no global total!)
   - Vault still has 10M USDC physically, but accounting shows it as "available"
   - `totalAssets() = 10M - 0 = 10M` ❌ **WRONG - should be 0**

3. **Over-Investment**: IM calls `investAssets(10M)`
   - Line 1454: `availableBalance = totalAssets()` returns 10M
   - Check passes (10M ≤ 10M)
   - All 10M invested despite being reserved for deposit claims [6](#0-5) 

4. **Liquidity Crunch**: Existing shareholder requests redemption
   - Vault must service redemption but all funds are invested
   - Forced to call `withdrawFromInvestment()`, creating liquidity pressure
   - May cause delays, losses, or inability to fulfill redemptions

**Security Property Broken:** 
Violates Invariant #9: "**Reserved Asset Protection**: investedAssets + reservedAssets ≤ totalAssets"

The claimable deposit assets are not included in "reservedAssets" calculation, allowing the vault to invest more than it should.

## Impact Explanation

- **Affected Assets**: All assets in vaults with fulfilled but unclaimed deposits (USDC, DAI, or any supported asset)
- **Damage Severity**: Potential liquidity shortfalls proportional to unclaimed deposits. In extreme cases with multiple large deposits:
  - Vault balance: 0 (all invested)
  - Claimable deposits: 10M+ (users expect to claim shares)
  - Claimable redeems: 2M+ (users expect assets)
  - Vault cannot service redemptions without forced divestment
- **User Impact**: 
  - All users with pending redemptions face delays or losses
  - Investment vault may incur slippage/fees on forced withdrawals
  - Protocol reputation damage from liquidity management failures

## Likelihood Explanation

- **Attacker Profile**: Any whale user with sufficient capital (not malicious intent required - normal protocol usage triggers this)
- **Preconditions**: 
  - Vault has investment vault configured
  - Investment manager actively fulfills deposits
  - Users request large deposits that get fulfilled
- **Execution Complexity**: Single-transaction deposits by normal users trigger the accounting error; no sophisticated attack needed
- **Frequency**: Occurs continuously whenever deposits are fulfilled but not yet claimed (common in async ERC-7540 flows where users may delay claiming)

## Recommendation

Add `totalClaimableDepositAssets` tracking to mirror the redemption accounting pattern:

```solidity
// In src/ERC7575VaultUpgradeable.sol:

// STORAGE (line 100, add after totalClaimableRedeemShares):
uint256 totalClaimableDepositAssets; // Assets reserved for fulfilled deposits awaiting claim

// FULFILL DEPOSIT (line 439, add after claimableDepositAssets update):
function fulfillDeposit(address controller, uint256 assets) public nonReentrant returns (uint256 shares) {
    // ... existing validation ...
    
    $.pendingDepositAssets[controller] -= assets;
    $.totalPendingDepositAssets -= assets;
    $.claimableDepositShares[controller] += shares;
    $.claimableDepositAssets[controller] += assets;
    $.totalClaimableDepositAssets += assets; // ADD THIS LINE
    
    // ... rest of function ...
}

// DEPOSIT CLAIM (line 580, add after claimableDepositAssets update):
function deposit(uint256 assets, address receiver, address controller) public nonReentrant returns (uint256 shares) {
    // ... existing logic ...
    
    if (availableAssets == assets) {
        $.activeDepositRequesters.remove(controller);
        delete $.claimableDepositShares[controller];
        delete $.claimableDepositAssets[controller];
        $.totalClaimableDepositAssets -= assets; // ADD THIS LINE
    } else {
        $.claimableDepositShares[controller] -= shares;
        $.claimableDepositAssets[controller] -= assets;
        $.totalClaimableDepositAssets -= assets; // ADD THIS LINE
    }
    
    // ... rest of function ...
}

// TOTAL ASSETS (line 1178, update reserved calculation):
function totalAssets() public view virtual returns (uint256) {
    VaultStorage storage $ = _getVaultStorage();
    uint256 balance = IERC20Metadata($.asset).balanceOf(address(this));
    // ADD totalClaimableDepositAssets to reserved calculation
    uint256 reservedAssets = $.totalPendingDepositAssets 
        + $.totalClaimableDepositAssets  // ADD THIS
        + $.totalClaimableRedeemAssets 
        + $.totalCancelDepositAssets;
    return balance > reservedAssets ? balance - reservedAssets : 0;
}
```

Apply the same pattern to `mint()` function (lines 641-657) which also claims deposits.

## Proof of Concept

```solidity
// File: test/Exploit_MissingClaimableDepositTracking.t.sol
// Run with: forge test --match-test test_MissingClaimableDepositTracking -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575ShareToken.sol";
import "../src/WERC7575Vault.sol";

contract Exploit_MissingClaimableDepositTracking is Test {
    ERC7575VaultUpgradeable iusdVault;
    WERC7575ShareToken shareToken;
    WERC7575Vault wusdVault;
    address usdc;
    
    address whale = address(0x1);
    address investmentManager = address(0x2);
    address existingShareholder = address(0x3);
    
    function setUp() public {
        // Deploy mock USDC
        usdc = address(new MockERC20("USDC", "USDC", 6));
        
        // Deploy contracts
        shareToken = new WERC7575ShareToken();
        shareToken.initialize(address(this));
        
        iusdVault = new ERC7575VaultUpgradeable();
        iusdVault.initialize(IERC20Metadata(usdc), address(shareToken), address(this));
        
        wusdVault = new WERC7575Vault();
        wusdVault.initialize(IERC20Metadata(usdc), address(shareToken), address(this));
        
        // Setup
        iusdVault.setInvestmentManager(investmentManager);
        iusdVault.setInvestmentVault(address(wusdVault));
        iusdVault.setActive(true);
        
        // Fund whale with 10M USDC
        MockERC20(usdc).mint(whale, 10_000_000e6);
    }
    
    function test_MissingClaimableDepositTracking() public {
        // SETUP: Whale deposits 10M USDC
        vm.startPrank(whale);
        MockERC20(usdc).approve(address(iusdVault), 10_000_000e6);
        iusdVault.requestDeposit(10_000_000e6, whale, whale);
        vm.stopPrank();
        
        // Verify: totalAssets correctly excludes pending deposits
        uint256 totalAssetsAfterRequest = iusdVault.totalAssets();
        assertEq(totalAssetsAfterRequest, 0, "totalAssets should be 0 (pending deposits reserved)");
        
        // EXPLOIT: Investment manager fulfills deposit
        vm.prank(investmentManager);
        iusdVault.fulfillDeposit(whale, 10_000_000e6);
        
        // VERIFY VULNERABILITY: totalAssets incorrectly shows 10M available
        uint256 totalAssetsAfterFulfill = iusdVault.totalAssets();
        assertEq(totalAssetsAfterFulfill, 10_000_000e6, "BUG: totalAssets shows 10M available!");
        
        // EXPLOIT IMPACT: Investment manager can over-invest
        vm.prank(investmentManager);
        iusdVault.investAssets(10_000_000e6);
        
        // RESULT: All funds invested, but whale still has valid claim
        uint256 vaultBalance = MockERC20(usdc).balanceOf(address(iusdVault));
        assertEq(vaultBalance, 0, "All funds invested - liquidity crunch!");
        
        // Whale's claim is still valid
        (uint256 claimableShares, uint256 claimableAssets) = iusdVault.claimableDepositRequest(whale);
        assertGt(claimableShares, 0, "Whale has valid claim for shares");
        assertEq(claimableAssets, 10_000_000e6, "Whale's 10M USDC claim still exists");
    }
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
```

## Notes

- The original security question about overflow is not the vulnerability (Solidity 0.8.30 prevents silent overflow)
- The actual vulnerability is the **missing accounting variable** that causes `totalAssets()` to miscalculate available funds
- This is a **logic error**, not an overflow issue
- The vulnerability manifests in normal protocol operation (doesn't require malicious actors)
- Similar to how `totalClaimableRedeemAssets` is properly tracked for redemptions, deposits need the same treatment
- The fix mirrors the existing redemption accounting pattern, maintaining consistency across the codebase

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

**File:** src/ERC7575VaultUpgradeable.sol (L425-445)
```text
    function fulfillDeposit(address controller, uint256 assets) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        uint256 pendingAssets = $.pendingDepositAssets[controller];
        if (assets > pendingAssets) {
            revert ERC20InsufficientBalance(address(this), pendingAssets, assets);
        }

        shares = _convertToShares(assets, Math.Rounding.Floor);
        if (shares == 0) revert ZeroShares();

        $.pendingDepositAssets[controller] -= assets;
        $.totalPendingDepositAssets -= assets;
        $.claimableDepositShares[controller] += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming

        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);

        return shares;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L822-841)
```text
    function fulfillRedeem(address controller, uint256 shares) public nonReentrant returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if (shares == 0) revert ZeroShares();
        uint256 pendingShares = $.pendingRedeemShares[controller];
        if (shares > pendingShares) {
            revert ERC20InsufficientBalance(address(this), pendingShares, shares);
        }

        assets = _convertToAssets(shares, Math.Rounding.Floor);

        $.pendingRedeemShares[controller] -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned

        // Note: Shares are NOT burned here - they will be burned during redeem/withdraw claim
        return assets;
    }
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

**File:** src/ERC7575VaultUpgradeable.sol (L1448-1465)
```text
    function investAssets(uint256 amount) external nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if ($.investmentVault == address(0)) revert NoInvestmentVault();
        if (amount == 0) revert ZeroAmount();

        uint256 availableBalance = totalAssets();
        if (amount > availableBalance) {
            revert ERC20InsufficientBalance(address(this), availableBalance, amount);
        }

        // Approve and deposit into investment vault with ShareToken as receiver
        IERC20Metadata($.asset).safeIncreaseAllowance($.investmentVault, amount);
        shares = IERC7575($.investmentVault).deposit(amount, $.shareToken);

        emit AssetsInvested(amount, shares, $.investmentVault);
        return shares;
    }
```
