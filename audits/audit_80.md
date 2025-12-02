# NoVulnerability found for this question.

After conducting a thorough analysis of the `setInvestmentShareToken()` function and its interaction with the broader protocol, I have determined that there is no valid High or Medium severity vulnerability related to the security question posed.

## Analysis Summary

**The Question's Premise:**
The security question suggests that if the owner accidentally sets a regular ERC20 or EOA address as the `investmentShareToken`, it would cause permanent undercounting of investment assets because `balanceOf()` would succeed but `rBalanceOf()` would fail.

**Why This Is Not A Valid Vulnerability:**

### 1. Try-Catch Error Handling Is Intentional

The `_calculateInvestmentAssets()` function includes a try-catch block specifically to handle tokens that don't implement `rBalanceOf()`: [1](#0-0) 

This is **intentional design** to support compatibility with share tokens that may not have rBalance tracking. The comment explicitly states: "If rBalanceOf is not supported, continue with regular balance only." This is a feature, not a bug.

### 2. Wrong Address Causes Immediate Revert, Not Silent Failure

If the owner sets an address that doesn't implement `IERC7575ShareExtended`, the system fails **loudly** rather than silently: [2](#0-1) 

When `_configureVaultInvestmentSettings` is called (either during `setInvestmentShareToken` if vaults exist, or during `registerVault` afterwards), it calls `.vault(asset)` on the investmentShareToken. If the address is:
- **Regular ERC20**: The call to `.vault(asset)` will revert (function doesn't exist)
- **EOA**: The call will revert (no code at address)
- **Wrong WERC7575ShareToken**: Returns address(0) or wrong vault, preventing proper investment setup

The transaction reverts immediately, making the error obvious rather than causing silent undercounting.

### 3. This Falls Under "Admin Misconfiguration" (Out of Scope)

Per the trust model and KNOWN_ISSUES.md: [3](#0-2) 

The scenario described is an admin making an accidental configuration error, which is explicitly classified as invalid per Code4rena judging criteria.

### 4. Recoverable Via UUPS Upgrade

Even if the wrong address is set, the protocol uses UUPS upgradeability. The owner can deploy a new implementation that either:
- Adds a function to reset the `investmentShareToken`
- Directly fixes the storage slot

This provides a recovery path, reducing the severity to at most a QA/Low issue about lack of input validation.

### 5. No Scenario Causes Silent Undercounting

The question's scenario assumes that:
1. Wrong token is set → The system continues operating → rBalance is silently uncounted

However, the actual behavior is:
1. Wrong token is set with no vaults → Later vault registration reverts
2. Wrong token is set with existing vaults → Transaction immediately reverts
3. Compatible token without rBalance → Try-catch handles it gracefully (intentional)

There is no execution path where the system silently undercounts actual invested assets.

## Conclusion

While it is true that `setInvestmentShareToken()` lacks explicit interface validation, this does not constitute a valid High or Medium severity vulnerability because:

- The error handling is intentional (try-catch for compatibility)
- Wrong inputs cause immediate transaction reverts (not silent failures)  
- It represents admin misconfiguration (out of scope per trust model)
- There is a recovery path via contract upgrades
- No unprivileged attacker can exploit this
- No financial loss occurs without admin error

This would at best be classified as a **QA/Low** issue regarding input validation, but does not meet the criteria for a valid Code4rena High or Medium severity finding.

### Citations

**File:** src/ShareTokenUpgradeable.sol (L540-542)
```text
    function _configureVaultInvestmentSettings(address asset, address vaultAddress, address investmentShareToken) internal {
        // Find the corresponding investment vault for this asset
        address investmentVaultAddress = IERC7575ShareExtended(investmentShareToken).vault(asset);
```

**File:** src/ShareTokenUpgradeable.sol (L615-619)
```text
        try IWERC7575ShareToken(investmentShareToken).rBalanceOf(address(this)) returns (uint256 rShares) {
            totalInvestmentAssets += rShares;
        } catch {
            // If rBalanceOf is not supported, continue with regular balance only
        }
```

**File:** KNOWN_ISSUES.md (L24-27)
```markdown
### 2. Admin Mistakes Are Invalid
**C4 Guidance**: "Reckless admin mistakes are invalid. Assume calls are previewed."

Reports claiming "admin could accidentally do X" or "owner might mistakenly do Y" are invalid. Admin actions are assumed to be intentional and previewed.
```
