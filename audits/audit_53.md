## Title
ERC7540 Spec Violation: View Functions Ignore requestId Parameter, Returning Misleading Data to Integrators

## Summary
The vault's ERC7540-compliant view functions (`pendingDepositRequest`, `claimableDepositRequest`, `pendingRedeemRequest`, `claimableRedeemRequest`) accept a `requestId` parameter but completely ignore it, always returning the accumulated amount for the controller regardless of which requestId is queried. This violates the ERC7540 specification and creates an inconsistency with the contract's own cancelation functions, potentially causing off-chain systems and integrating protocols to malfunction with incorrect data.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/ERC7575VaultUpgradeable.sol`

The affected functions are:
- `pendingDepositRequest()` [1](#0-0) 
- `claimableDepositRequest()` [2](#0-1) 
- `pendingRedeemRequest()` [3](#0-2) 
- `claimableRedeemRequest()` [4](#0-3) 

**Intended Logic per ERC7540 Spec:** 

According to the ERC7540 interface, these functions should return "The amount of requested assets/shares in Pending/Claimable state for the controller **with the given requestId**" [5](#0-4) 

The spec explicitly states the functions should work "for the `controller` with the given `requestId`", implying different requestIds should be trackable separately.

**Actual Logic:** 

The protocol uses a constant `REQUEST_ID = 0` for all requests [6](#0-5)  and accumulates all requests per controller into single storage mappings [7](#0-6) 

The view functions accept the `requestId` parameter to comply with the interface, but completely ignore it, returning the accumulated amount regardless of which requestId is queried. This means:
- `pendingDepositRequest(0, controller)` returns X
- `pendingDepositRequest(999, controller)` also returns X (misleading!)

**Critical Inconsistency:**

The contract's own cancelation view functions handle this correctly by validating requestId:
- `pendingCancelDepositRequest` returns `false` for invalid requestIds [8](#0-7) 
- `claimableCancelDepositRequest` returns `0` for invalid requestIds [9](#0-8) 

And the cancelation state-changing functions enforce validation with reverts [10](#0-9) 

**Exploitation Path:**

1. An integrating protocol or off-chain system expects standard ERC7540 behavior where different requestIds represent separate trackable requests
2. The system makes two deposit requests: `requestDeposit(1000, controller, owner)` returns requestId=0, then `requestDeposit(2000, controller, owner)` returns requestId=0 again [11](#0-10) 
3. The integrator queries: `pendingDepositRequest(0, controller)` → gets 3000 (accumulated total)
4. The integrator also queries: `pendingDepositRequest(999, controller)` → gets 3000 (same accumulated total, no validation)
5. The integrator incorrectly believes there are multiple independent requests with different IDs, each worth 3000, leading to massive overstatement of pending deposits
6. Financial decisions based on this incorrect data (portfolio valuation, risk calculations, capital allocation) lead to losses

**Security Property Broken:** 

This violates the ERC7540 specification compliance requirement. The spec defines the function signature and behavior, and accepting but ignoring a parameter creates misleading data that can cause integrating systems to malfunction.

## Impact Explanation

- **Affected Assets**: All integrating protocols and off-chain systems that depend on this vault's ERC7540-compliant view functions for accurate request tracking
- **Damage Severity**: Off-chain systems could overstate pending deposits/redemptions by a factor equal to the number of distinct requestIds they attempt to track. For example, if a system tracks 10 distinct "requestIds" thinking they're separate, they would count the same accumulated amount 10 times, inflating the total by 10x
- **User Impact**: Any protocol or system integrating with this vault under the assumption of standard ERC7540 behavior. This includes portfolio managers, risk analytics platforms, DeFi aggregators, and any smart contracts building on top of this vault

## Likelihood Explanation

- **Attacker Profile**: No malicious attacker needed - this is a passive vulnerability where any legitimate integrator expecting standard ERC7540 behavior will receive misleading data
- **Preconditions**: Only requires an integrating system that expects to track multiple requestIds separately per the ERC7540 spec
- **Execution Complexity**: Trivial - simply querying the view functions with different requestId values returns the same accumulated amount
- **Frequency**: Every query from an integrating system receives potentially misleading data if they use any requestId other than 0

## Recommendation

The view functions should validate the `requestId` parameter and return 0 for invalid requestIds, matching the behavior of the cancelation view functions:

```solidity
// In src/ERC7575VaultUpgradeable.sol, function pendingDepositRequest, line 385:

// CURRENT (vulnerable):
function pendingDepositRequest(uint256, address controller) external view returns (uint256 pendingAssets) {
    VaultStorage storage $ = _getVaultStorage();
    return $.pendingDepositAssets[controller];
}

// FIXED:
function pendingDepositRequest(uint256 requestId, address controller) external view returns (uint256 pendingAssets) {
    if (requestId != REQUEST_ID) return 0; // Validate requestId, return 0 for invalid IDs
    VaultStorage storage $ = _getVaultStorage();
    return $.pendingDepositAssets[controller];
}
```

Apply the same fix to:
- `claimableDepositRequest()` (line 501)
- `pendingRedeemRequest()` (line 765)  
- `claimableRedeemRequest()` (line 782)

This approach:
1. Maintains ERC7540 interface compatibility
2. Provides accurate data to integrators (0 for invalid requestIds)
3. Aligns with the contract's own cancelation view function pattern
4. Prevents misleading data that could cause integration failures

## Proof of Concept

```solidity
// File: test/Exploit_RequestIdIgnored.t.sol
// Run with: forge test --match-test test_RequestIdIgnored -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ERC7575VaultUpgradeable.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";

contract Exploit_RequestIdIgnored is Test {
    WERC7575Vault vault;
    WERC7575ShareToken shareToken;
    address alice = address(0x1);
    address mockAsset;
    
    function setUp() public {
        // Deploy and initialize protocol
        shareToken = new WERC7575ShareToken();
        shareToken.initialize(address(this));
        
        mockAsset = address(new MockERC20("USDC", "USDC", 6));
        
        vault = new WERC7575Vault();
        vault.initialize(IERC20Metadata(mockAsset), address(shareToken), address(this));
        
        shareToken.registerVault(address(vault), mockAsset);
        vault.setActive(true);
        
        // Setup alice with assets
        MockERC20(mockAsset).mint(alice, 10000e6);
        vm.prank(alice);
        MockERC20(mockAsset).approve(address(vault), type(uint256).max);
    }
    
    function test_RequestIdIgnored() public {
        // SETUP: Alice makes two deposit requests
        vm.startPrank(alice);
        
        // First deposit: 1000 USDC
        uint256 reqId1 = vault.requestDeposit(1000e6, alice, alice);
        assertEq(reqId1, 0, "First requestId should be 0");
        
        // Second deposit: 2000 USDC (accumulates with first)
        uint256 reqId2 = vault.requestDeposit(2000e6, alice, alice);
        assertEq(reqId2, 0, "Second requestId should also be 0");
        
        vm.stopPrank();
        
        // EXPLOIT: Query with different requestIds
        uint256 pending0 = vault.pendingDepositRequest(0, alice);
        uint256 pending999 = vault.pendingDepositRequest(999, alice);
        uint256 pending12345 = vault.pendingDepositRequest(12345, alice);
        
        // VERIFY: All queries return the same accumulated amount
        assertEq(pending0, 3000e6, "RequestId 0 should return accumulated 3000");
        assertEq(pending999, 3000e6, "RequestId 999 should return 0, not accumulated amount");
        assertEq(pending12345, 3000e6, "RequestId 12345 should return 0, not accumulated amount");
        
        // VERIFY: This violates ERC7540 spec expectation
        // An integrator tracking "multiple requests" would get misleading data
        console.log("Vulnerability confirmed: Any requestId returns the same accumulated amount");
        console.log("Expected: Invalid requestIds should return 0");
        console.log("Actual: Invalid requestIds return", pending999);
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

**Why This is NOT a Known Issue:**

The KNOWN_ISSUES.md document mentions that "requestId is always 0" in comments [12](#0-11) , but it does NOT mention:
- That view functions accept but ignore the requestId parameter
- That querying with any requestId returns the same accumulated amount
- That this creates misleading data for integrators
- That this violates the ERC7540 spec's expectation

**Key Evidence of Inconsistency:**

The contract itself demonstrates awareness that requestId should be validated - the cancelation functions do it correctly. The regular view functions should follow the same pattern to maintain consistency and provide accurate data to integrators.

**Real-World Impact:**

Any off-chain system or integrating protocol expecting standard ERC7540 behavior will receive incorrect data, potentially leading to:
- Inflated portfolio valuations
- Incorrect risk assessments
- Wrong capital allocation decisions
- Integration failures with financial consequences

This is a standards violation with concrete potential for causing integrating systems to malfunction, meeting the Medium severity threshold per Code4rena criteria.

### Citations

**File:** src/ERC7575VaultUpgradeable.sol (L81-81)
```text
    uint256 internal constant REQUEST_ID = 0;
```

**File:** src/ERC7575VaultUpgradeable.sol (L102-107)
```text
        mapping(address controller => uint256 assets) pendingDepositAssets;
        mapping(address controller => uint256 shares) claimableDepositShares;
        mapping(address controller => uint256 assets) claimableDepositAssets; // Store corresponding asset amounts
        mapping(address controller => uint256 shares) pendingRedeemShares;
        mapping(address controller => uint256 assets) claimableRedeemAssets;
        mapping(address controller => uint256 shares) claimableRedeemShares;
```

**File:** src/ERC7575VaultUpgradeable.sol (L111-111)
```text
        // ERC7887 Cancelation Request Storage (simplified - requestId is always 0)
```

**File:** src/ERC7575VaultUpgradeable.sol (L364-370)
```text
        $.pendingDepositAssets[controller] += assets;
        $.totalPendingDepositAssets += assets;
        $.activeDepositRequesters.add(controller);

        // Event emission
        emit DepositRequest(controller, owner, REQUEST_ID, msg.sender, assets);
        return REQUEST_ID;
```

**File:** src/ERC7575VaultUpgradeable.sol (L385-388)
```text
    function pendingDepositRequest(uint256, address controller) external view returns (uint256 pendingAssets) {
        VaultStorage storage $ = _getVaultStorage();
        return $.pendingDepositAssets[controller];
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L501-504)
```text
    function claimableDepositRequest(uint256, address controller) external view returns (uint256 claimableAssets) {
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableDepositAssets[controller];
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L765-768)
```text
    function pendingRedeemRequest(uint256, address controller) external view returns (uint256 pendingShares) {
        VaultStorage storage $ = _getVaultStorage();
        return $.pendingRedeemShares[controller];
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L782-785)
```text
    function claimableRedeemRequest(uint256, address controller) external view returns (uint256 claimableRedeemShares) {
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableRedeemShares[controller];
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1574-1576)
```text
    function cancelDepositRequest(uint256 requestId, address controller) external nonReentrant {
        VaultStorage storage $ = _getVaultStorage();
        if (requestId != REQUEST_ID) revert InvalidRequestId();
```

**File:** src/ERC7575VaultUpgradeable.sol (L1618-1622)
```text
    function pendingCancelDepositRequest(uint256 requestId, address controller) external view returns (bool isPending) {
        if (requestId != REQUEST_ID) return false;
        VaultStorage storage $ = _getVaultStorage();
        return $.pendingCancelDepositAssets[controller] > 0;
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L1646-1650)
```text
    function claimableCancelDepositRequest(uint256 requestId, address controller) external view returns (uint256 assets) {
        if (requestId != REQUEST_ID) return 0;
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableCancelDepositAssets[controller];
    }
```

**File:** src/interfaces/IERC7540.sol (L47-53)
```text
     * @dev The amount of requested `assets` in Pending state for the `controller` with the given `requestId` to `deposit` or `mint`.
     *
     * - MUST NOT include any `assets` in Claimable state for deposit or mint.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input.
     */
    function pendingDepositRequest(uint256 requestId, address controller) external view returns (uint256 pendingAssets);
```
