## Title
Global Operator Approval Enables Cross-Vault Share Theft in Multi-Asset System

## Summary
The operator approval system in the ShareToken contract is global and applies across all vaults. If a user approves an operator for any purpose, that operator is granted full privileges over all the user’s positions in every vault tied to the ShareToken. This allows a malicious operator to drain shares from any vault—regardless of the asset—for which they were never intended to have access.

## Impact
**Severity**: High

## Finding Description

**Location:**  
`src/ShareTokenUpgradeable.sol`, centralized operator mapping and setOperator/isOperator functions  
`src/ERC7575VaultUpgradeable.sol`, `requestRedeem` authorization and cross-vault flows

**Intended Logic:**  
Operator approval by a user should be limited in scope to only the vaults/assets for which the user intends to delegate control, protecting assets in unrelated vaults from unauthorized operator actions.

**Actual Logic:**  
Operator approval in ShareToken is global: any operator approved by a user can act as operator on their behalf in all vaults sharing the ShareToken. The vaults’ request flows check only whether the operator is approved globally, not per-vault. There is no way for a user to approve an operator for USDC but not for USDT, or vice versa.

**Exploitation Path:**
1. Alice approves Bob as her operator in ShareToken, intending Bob to help with Vault A (USDC) actions.
2. Bob can now call `requestRedeem` in Vault B (USDT) or any other vault, as operator for Alice, sending the redeemed assets to any controller he chooses (including himself).
3. Bob can drain Alice's shares and claim assets from vaults/Alice accounts never intended to be touched by him.

**Security Property Broken:**  
- No Fund Theft (Invariant #12)
- No Role Escalation / Access Control Boundaries (Invariant #11)

## Impact Explanation
- **Affected Assets**: All vaults tied to the ShareToken; any user's shares in any asset/vault can be drained by a globally-approved operator.
- **Damage Severity**: Any globally-approved operator can take all shares from all vaults belonging to a user and claim the underlying assets, up to the user's entire balance in every vault.
- **User Impact**: All users who ever approve any operator are at risk; all their vault positions may be stolen.

## Likelihood Explanation
- **Attacker Profile**: Any malicious or compromised third party whom a user approves as global operator (even for limited, intended scope).
- **Preconditions**: User must approve operator in ShareToken.
- **Execution Complexity**: Single transaction per vault; no admin or validator collusion required.
- **Frequency**: Can be exploited as often as operator is approved.

## Recommendation
Add per-vault (per-asset) operator approvals to ShareToken, or move operator approval logic from ShareToken to each vault so users can grant/revoke operators with vault-level granularity. Consistently enforce this in `isOperator` and in all deposit/redeem/cancel flows that check operator authorization.

## Proof of Concept

Omitted per instructions. (Can be supplied as described above, using a simple Forge-style test.)

--- [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/ShareTokenUpgradeable.sol (L89-89)
```text
        mapping(address controller => mapping(address operator => bool approved)) operators;
```

**File:** src/ShareTokenUpgradeable.sol (L480-505)
```text
    function setOperator(address operator, bool approved) external virtual returns (bool) {
        if (msg.sender == operator) revert CannotSetSelfAsOperator();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        $.operators[msg.sender][operator] = approved;
        emit OperatorSet(msg.sender, operator, approved);
        return true;
    }

    /**
     * @dev Checks if an operator is approved for a controller (centralized for all vaults)
     *
     * ERC7540 SPECIFICATION:
     * "Returns `true` if the `operator` is approved as an operator for a `controller`."
     *
     * CENTRALIZED ARCHITECTURE:
     * This single function serves ALL ERC7575 vaults, providing consistent
     * operator permissions across the entire multi-asset system.
     *
     * @param controller Address of the controller
     * @param operator Address of the operator
     * @return True if operator is approved
     */
    function isOperator(address controller, address operator) external view virtual returns (bool) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.operators[controller][operator];
    }
```

**File:** src/ERC7575VaultUpgradeable.sol (L715-750)
```text
    function requestRedeem(uint256 shares, address controller, address owner) external nonReentrant returns (uint256 requestId) {
        if (shares == 0) revert ZeroShares();
        VaultStorage storage $ = _getVaultStorage();

        // ERC7540 REQUIREMENT: Authorization check for redemption
        // Per spec: "Redeem Request approval of shares for a msg.sender NOT equal to owner may come
        // either from ERC-20 approval over the shares of owner or if the owner has approved the
        // msg.sender as an operator."
        bool isOwnerOrOperator = owner == msg.sender || IERC7540($.shareToken).isOperator(owner, msg.sender);
        if (!isOwnerOrOperator) {
            ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
        }

        uint256 ownerShares = IERC20Metadata($.shareToken).balanceOf(owner);
        if (ownerShares < shares) {
            revert ERC20InsufficientBalance(owner, ownerShares, shares);
        }

        // ERC7887: Block new redeem requests while cancelation is pending for this controller
        if ($.controllersWithPendingRedeemCancelations.contains(controller)) {
            revert RedeemCancelationPending();
        }

        // Pull-Then-Credit pattern: Transfer shares first before updating state
        // This ensures we only credit shares that have been successfully received
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }

        // State changes after successful transfer
        $.pendingRedeemShares[controller] += shares;
        $.activeRedeemRequesters.add(controller);

        // Event emission
        emit RedeemRequest(controller, owner, REQUEST_ID, msg.sender, shares);
        return REQUEST_ID;
```
