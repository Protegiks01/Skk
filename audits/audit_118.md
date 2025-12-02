# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the `WERC7575Vault.previewWithdraw()` rounding mechanism, I found **no exploitable vulnerability**. The ceiling rounding cannot cause required shares to exceed the owner's balance, preventing legitimate withdrawals.

## Key Findings

### 1. Ceiling Rounding is Effectively a No-Op

The `previewWithdraw()` function uses Ceil rounding when converting assets to shares: [1](#0-0) 

However, the internal conversion delegates to: [2](#0-1) 

**Critical observation**: The formula computes `(assets × scalingFactor) ÷ 1`. When the denominator is 1, there is **no fractional remainder** to round. The result is always exact (`assets × scalingFactor`), making Ceil vs Floor rounding functionally equivalent.

### 2. Mathematical Proof of Safety

The withdrawal flow ensures no overage:

1. User has `S` shares
2. `maxWithdraw(owner)` calculates: `floor(S / scalingFactor) = M` [3](#0-2) 

3. User calls `withdraw(M)`, which computes required shares: `M × scalingFactor` [4](#0-3) 

4. **Proof that required shares ≤ user's balance**:
   - Since `M = floor(S / scalingFactor)`, then `M ≤ S / scalingFactor`
   - Therefore: `M × scalingFactor ≤ S`
   - The required shares will always be ≤ the user's actual balance

### 3. Decimal Normalization Design

The scaling factor is deterministically computed based on asset decimals: [5](#0-4) 

With `MIN_ASSET_DECIMALS = 6` and `SHARE_TOKEN_DECIMALS = 18`: [6](#0-5) 

The scaling factor ranges from 1 (for 18-decimal assets like DAI) to 10^12 (for 6-decimal assets like USDC). In all cases, the conversion maintains a deterministic 1:1 value ratio with decimal normalization, independent of vault state or total supply.

## Notes

The question's premise about "insufficient shares in circulation" causing ceiling rounding issues does not apply to `WERC7575Vault` because:

1. **No state-dependent conversions**: Unlike ERC4626 vaults that use `totalAssets/totalSupply` ratios, this vault uses fixed decimal scaling
2. **No fractional rounding**: Division by 1 produces exact results, nullifying the Ceil parameter
3. **Mathematical invariant**: The relationship between `maxWithdraw` and required shares guarantees sufficient balance

The ceiling rounding in `previewWithdraw()` follows ERC4626 best practices (favoring the vault) but is mathematically incapable of preventing legitimate withdrawals in this implementation.

### Citations

**File:** src/WERC7575Vault.sol (L105-108)
```text
        // Precompute scaling factor: 10^(18 - assetDecimals)
        // Max scaling factor is 10^12 (for 6 decimals) which fits in uint64
        uint256 scalingFactor = 10 ** (DecimalConstants.SHARE_TOKEN_DECIMALS - assetDecimals);
        if (scalingFactor > type(uint64).max) revert ScalingFactorTooLarge();
```

**File:** src/WERC7575Vault.sol (L215-220)
```text
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
        // ShareToken always has 18 decimals, assetDecimals ∈ [6, 18]
        // shares = assets * _scalingFactor where _scalingFactor = 10^(18 - assetDecimals)
        // Use Math.mulDiv to prevent overflow on large amounts
        return Math.mulDiv(assets, uint256(_scalingFactor), 1, rounding);
    }
```

**File:** src/WERC7575Vault.sol (L268-270)
```text
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Ceil);
    }
```

**File:** src/WERC7575Vault.sol (L305-307)
```text
    function maxWithdraw(address owner) public view returns (uint256) {
        return _convertToAssets(_shareToken.balanceOf(owner), Math.Rounding.Floor);
    }
```

**File:** src/WERC7575Vault.sol (L434-437)
```text
    function withdraw(uint256 assets, address receiver, address owner) public nonReentrant whenNotPaused returns (uint256 shares) {
        shares = previewWithdraw(assets);
        _withdraw(assets, shares, receiver, owner);
    }
```

**File:** src/DecimalConstants.sol (L8-13)
```text
library DecimalConstants {
    /// @dev Share tokens always use 18 decimals
    uint8 constant SHARE_TOKEN_DECIMALS = 18;

    /// @dev Minimum allowed asset decimals
    uint8 constant MIN_ASSET_DECIMALS = 6;
```
