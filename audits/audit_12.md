# NoVulnerability found for this question.

After conducting a thorough investigation of both security questions, I found that the described attack vectors are **not exploitable** in the current codebase due to existing protections:

## Question 1 Analysis: DecimalConstants Fragmentation

The scenario of mixing vaults with different decimal constants is **prevented by design**: [1](#0-0) [2](#0-1) [3](#0-2) 

**Why the attack fails:**
1. When a vault is initialized, it validates that `shareToken.decimals() == DecimalConstants.SHARE_TOKEN_DECIMALS`
2. The ShareToken enforces 18 decimals at deployment time
3. If new vaults are compiled with different DecimalConstants (e.g., 24 instead of 18), they would check for 24 decimals
4. The old ShareToken returns 18 decimals
5. Vault initialization reverts with `WrongDecimals()`
6. Incompatible vault cannot be registered

The only way to use different decimal constants would be to deploy an entirely new ShareToken system, which would be completely separate from the old one with no cross-interaction possible.

## Question 2 Analysis: ERC777/ERC1363 Reentrancy

The reentrancy attack via token hooks is **blocked by nonReentrant guards**: [4](#0-3) [5](#0-4) 

**Why the attack fails:**
1. All functions using SafeTokenTransfers have the `nonReentrant` modifier
2. OpenZeppelin's ReentrancyGuard sets a status flag that prevents any reentry
3. When ERC777/ERC1363 hooks trigger during `safeTransferFrom`, attempts to reenter any `nonReentrant` function revert
4. State variables like `$.pendingDepositAssets` cannot be manipulated before the balance check completes

The comprehensive use of `nonReentrant` across all state-changing functions that perform external calls provides robust protection against this attack vector.

## Notes

Both security questions describe theoretically concerning scenarios, but the protocol's existing validation checks and reentrancy protections effectively prevent exploitation. The decimal validation ensures vault-ShareToken compatibility, while the nonReentrant guards prevent state manipulation during token transfers.

### Citations

**File:** src/DecimalConstants.sol (L8-13)
```text
library DecimalConstants {
    /// @dev Share tokens always use 18 decimals
    uint8 constant SHARE_TOKEN_DECIMALS = 18;

    /// @dev Minimum allowed asset decimals
    uint8 constant MIN_ASSET_DECIMALS = 6;
```

**File:** src/ERC7575VaultUpgradeable.sol (L168-174)
```text
        // Validate share token compatibility and enforce 18 decimals
        try IERC20Metadata(shareToken_).decimals() returns (uint8 decimals) {
            if (decimals != DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert WrongDecimals();
            }
        } catch {
            revert AssetDecimalsFailed();
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

**File:** src/WERC7575ShareToken.sol (L164-167)
```text
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) EIP712(name_, "1") Ownable(msg.sender) {
        if (decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
            revert WrongDecimals();
        }
```

**File:** src/SafeTokenTransfers.sol (L63-68)
```text
    function safeTransferFrom(address token, address sender, address recipient, uint256 amount) internal {
        uint256 balanceBefore = IERC20Metadata(token).balanceOf(recipient);
        IERC20Metadata(token).safeTransferFrom(sender, recipient, amount);
        uint256 balanceAfter = IERC20Metadata(token).balanceOf(recipient);
        if (balanceAfter != balanceBefore + amount) revert TransferAmountMismatch();
    }
```
