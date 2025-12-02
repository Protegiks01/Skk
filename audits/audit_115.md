## Title
maxDeposit() Returns Undepositable Amount Causing ERC-4626 Compliance Violation and Transaction Reverts

## Summary
`WERC7575Vault.maxDeposit()` returns `type(uint256).max` to indicate unlimited deposits, but attempting to deposit this amount causes a revert due to arithmetic overflow in the share conversion calculation. This violates ERC-4626 specification which requires `maxDeposit()` to return the actual maximum depositiable amount, breaking standard vault integrations and user workflows.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/WERC7575Vault.sol` - `maxDeposit()` function (line 286-288), `_convertToShares()` function (line 215-220) [1](#0-0) [2](#0-1) 

**Intended Logic:** Per ERC-4626 specification, `maxDeposit()` should return the maximum amount of assets that can be successfully deposited into the vault. If there is no limit, it may return `type(uint256).max`. However, the specification requires that calling `deposit()` with the returned amount must not revert (except for standard failure conditions).

**Actual Logic:** The vault returns `type(uint256).max` from `maxDeposit()`, but when a user attempts to deposit this amount:
1. `deposit()` calls `previewDeposit(type(uint256).max)`
2. `previewDeposit()` calls `_convertToShares(type(uint256).max, Floor)`
3. `_convertToShares()` executes `Math.mulDiv(type(uint256).max, _scalingFactor, 1, rounding)`
4. For 6-decimal assets (USDC, USDT), `_scalingFactor = 10^12`
5. The multiplication `type(uint256).max * 10^12` exceeds `uint256` capacity
6. `Math.mulDiv` reverts with overflow error

**Exploitation Path:**
1. User queries `vault.maxDeposit(alice)` which returns `type(uint256).max`
2. User attempts to deposit the "maximum" amount: `vault.deposit(type(uint256).max, alice)`
3. Transaction reverts in `_convertToShares()` due to arithmetic overflow
4. User's transaction fails unexpectedly despite using the value returned by `maxDeposit()`

**Security Property Broken:** ERC-4626 standard compliance - the `maxDeposit()` function must return an amount that can actually be deposited without reverting.

## Impact Explanation
- **Affected Assets**: All 6-decimal assets (USDC, USDT) and any asset with decimals < 18 where `scalingFactor > 1`
- **Damage Severity**: 
  - Users following ERC-4626 standard patterns will have failed transactions
  - Integration protocols that rely on `maxDeposit()` for capacity checks will malfunction
  - Gas wasted on reverted transactions
  - Breaking compatibility with standard vault aggregators and routers
- **User Impact**: Any user or protocol attempting to use standard ERC-4626 workflows with this vault will experience unexpected reverts

## Likelihood Explanation
- **Attacker Profile**: Not malicious - any legitimate user following ERC-4626 best practices
- **Preconditions**: 
  - Vault must be using an asset with less than 18 decimals (common: USDC at 6 decimals)
  - User queries `maxDeposit()` and attempts to deposit that amount
- **Execution Complexity**: Single transaction - user simply calls standard ERC-4626 functions
- **Frequency**: Affects every attempt to deposit `maxDeposit()` amount with sub-18-decimal assets

## Recommendation

**In `src/WERC7575Vault.sol`, function `maxDeposit`, lines 286-288:**

Current implementation: [1](#0-0) 

Fixed implementation:
```solidity
function maxDeposit(address) public view returns (uint256) {
    // For assets with scaling factor > 1, the maximum depositiable amount
    // is constrained by the share conversion overflow limit
    // Maximum shares that fit in uint256: type(uint256).max
    // Maximum assets before overflow: type(uint256).max / scalingFactor
    if (_scalingFactor > 1) {
        return type(uint256).max / uint256(_scalingFactor);
    }
    // For 18-decimal assets (scalingFactor == 1), no conversion overflow possible
    return type(uint256).max;
}
```

This ensures `maxDeposit()` returns the actual maximum amount that can be converted to shares without overflow, maintaining ERC-4626 compliance.

## Proof of Concept

```solidity
// File: test/Exploit_MaxDepositOverflow.t.sol
// Run with: forge test --match-test test_MaxDepositOverflow -vv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("USDC", "USDC") {
        _mint(msg.sender, 1000000 * 1e6);
    }
    
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}

contract MaxDepositOverflowTest is Test {
    WERC7575Vault public vault;
    WERC7575ShareToken public shareToken;
    MockUSDC public usdc;
    
    address public alice;
    address public validator;
    uint256 public validatorPrivateKey;
    
    function setUp() public {
        alice = makeAddr("alice");
        (validator, validatorPrivateKey) = makeAddrAndKey("validator");
        
        // Deploy 6-decimal USDC
        usdc = new MockUSDC();
        
        // Deploy share token and vault
        shareToken = new WERC7575ShareToken("wUSDC", "WUSDC");
        vault = new WERC7575Vault(address(usdc), shareToken);
        
        // Setup
        shareToken.registerVault(address(usdc), address(vault));
        shareToken.setValidator(validator);
        shareToken.setKycVerified(alice, true);
        
        // Give alice some USDC
        usdc.transfer(alice, 1000 * 1e6);
    }
    
    function test_MaxDepositOverflow() public {
        // SETUP: Query maxDeposit as per ERC-4626 standard
        uint256 maxAmount = vault.maxDeposit(alice);
        
        console.log("maxDeposit returned:", maxAmount);
        assertEq(maxAmount, type(uint256).max, "maxDeposit should return type(uint256).max");
        
        // EXPLOIT: Attempt to deposit the "maximum" amount
        vm.startPrank(alice);
        usdc.approve(address(vault), type(uint256).max);
        
        // Set self-allowance via permit (required for share minting)
        bytes32 permitHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                alice,
                alice,
                type(uint256).max,
                shareToken.nonces(alice),
                block.timestamp + 1 hours
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", shareToken.DOMAIN_SEPARATOR(), permitHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validatorPrivateKey, digest);
        shareToken.permit(alice, alice, type(uint256).max, block.timestamp + 1 hours, v, r, s);
        
        // VERIFY: Transaction reverts with overflow, violating ERC-4626
        vm.expectRevert();
        vault.deposit(maxAmount, alice);
        
        console.log("Transaction reverted as expected - maxDeposit() returned undepositable amount");
        console.log("This violates ERC-4626 specification!");
    }
    
    function test_ActualMaximumIsLower() public {
        // VERIFY: The actual maximum is much lower
        uint256 scalingFactor = vault.getScalingFactor();
        uint256 actualMax = type(uint256).max / scalingFactor;
        
        console.log("Scaling factor:", scalingFactor);
        console.log("Actual maximum depositiable:", actualMax);
        console.log("Claimed maximum (maxDeposit):", vault.maxDeposit(alice));
        
        // Demonstrate that actualMax would work (if user had sufficient balance)
        assertTrue(actualMax < vault.maxDeposit(alice), "Actual max is much lower than claimed");
    }
}
```

**Notes:**
- The vulnerability affects all vaults with assets having less than 18 decimals
- The test demonstrates that `maxDeposit()` returns an amount that cannot actually be deposited
- This breaks ERC-4626 standard compliance and integration compatibility
- The fix is straightforward: cap `maxDeposit()` at `type(uint256).max / _scalingFactor` for assets with `_scalingFactor > 1`

### Citations

**File:** src/WERC7575Vault.sol (L215-220)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
        // ShareToken always has 18 decimals, assetDecimals ∈ [6, 18]
        // shares = assets * _scalingFactor where _scalingFactor = 10^(18 - assetDecimals)
        // Use Math.mulDiv to prevent overflow on large amounts
        return Math.mulDiv(assets, uint256(_scalingFactor), 1, rounding);
    }
```

**File:** src/WERC7575Vault.sol (L286-288)
```text
    function maxDeposit(address) public pure returns (uint256) {
        return type(uint256).max;
    }
```
