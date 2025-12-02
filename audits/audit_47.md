# NoVulnerability found for this question.

After thorough investigation of the decimal check in WERC7575Vault constructor and potential upgrade scenarios, I found no exploitable vulnerability. Here's my analysis:

## Investigation Summary

The WERC7575Vault constructor contains a decimal validation check: [1](#0-0) 

This check validates that the shareToken has exactly 18 decimals, enforced by the constant: [2](#0-1) 

## Why This Is Not a Vulnerability

**1. Architectural Design Choice**

The protocol has two distinct architectures:
- **Non-upgradeable**: WERC7575Vault + WERC7575ShareToken (both immutable)
- **Upgradeable**: ERC7575VaultUpgradeable + ShareTokenUpgradeable (both upgradeable via UUPS) [3](#0-2) 

**2. Requires Trusted Role Action**

The scenario requires the owner to upgrade ShareTokenUpgradeable. The trust model explicitly states:
- "DO NOT assume trusted roles act maliciously. Focus on unprivileged attackers."
- "Out-of-scope: Admin key compromise, misconfiguration by owners, reckless admin mistakes"

**3. Known Design Decision**

The KNOWN_ISSUES section explicitly acknowledges: "All shares 18 decimals (intentional multi-asset design) - QA/Low"

**4. Working as Intended**

The decimal check is a **safety feature**, not a bug. It correctly enforces compatibility requirements. If ShareTokenUpgradeable is upgraded to return different decimals, the vault should reject it to prevent:
- Incorrect share/asset conversions [4](#0-3) 
- Breaking the decimal normalization architecture
- Asset loss from scaling factor mismatches [5](#0-4) 

**5. Not Exploitable by Unprivileged Attackers**

No unprivileged user can:
- Upgrade ShareTokenUpgradeable (requires owner)
- Deploy WERC7575Vault with incompatible ShareToken (constructor reverts correctly)
- Bypass the decimal check (it's in the constructor, executed once at deployment)

## Notes

The decimal check enforces a critical invariant that all shares use 18 decimals for cross-asset compatibility. If the protocol evolves to support different decimal configurations, new vault contracts would need to be deployed with updated validation logic. The current implementation correctly prevents incompatible configurations, which is the intended behavior, not a vulnerability.

### Citations

**File:** src/WERC7575Vault.sol (L101-103)
```text
        if (shareToken_.decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
            revert WrongDecimals();
        }
```

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

**File:** src/DecimalConstants.sol (L10-10)
```text
    uint8 constant SHARE_TOKEN_DECIMALS = 18;
```

**File:** src/ShareTokenUpgradeable.sol (L778-780)
```text
    function upgradeTo(address newImplementation) external onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, "");
    }
```
