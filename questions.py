questions = [

    "In WERC7575ShareToken. batchTransfers(), after computing net amounts, the function updates _balances[account. owner] and _rBalances[account.owner] based on net debit/credit. If a malicious validator (or signature replay) causes the same batch to execute twice, does the lack of idempotency protection allow double-application of the same balance changes, violating token supply conservation?",
    "WERC7575ShareToken. batchTransfers() skips transfers where debtor == creditor (self-transfers).  If an attacker includes a self-transfer with a non-zero amount in a batch that also includes other transfers affecting the same account, can the skipped self-transfer cause the zero-sum validation to pass while actual net effect is non-zero due to the missing debit/credit pair?",
    "In WERC7575ShareToken.batchTransfers(), the function checks require(_balances[account.owner] >= netAmount) for net debit accounts (line ~760). If an account participates in the batch with both large debits and large credits that net to a small debit, but _rBalances[account.owner] is substantial, can the function incorrectly allow the transfer by only checking _balances without considering that rBalances should also be updated, leading to inconsistent dual-balance tracking?",
    # WERC7575ShareToken.sol - Dual Allowance Model (Lines ~88-125)
    "WERC7575ShareToken.transfer() calls _spendAllowance(msg.sender, msg.sender, value) to enforce self-allowance before executing the transfer (line ~90). If a user has self-allowance but is not KYC-verified, and the recipient is KYC-verified, does the KYC check in _update() occur AFTER allowance is spent, allowing a non-KYC'd user to permanently lock their allowance without completing the transfer?",
    "In WERC7575ShareToken. transferFrom(), the function calls _spendAllowance(from, from, value) for self-allowance and then super. transferFrom() which checks allowance[from][msg.sender]. If the self-allowance check passes but the caller allowance is exactly 'value', and super.transferFrom() decrements caller allowance before the transfer completes, can a reentrancy via a malicious token hook in _update() allow the caller to reuse the same allowance for multiple transfers?",
    "WERC7575ShareToken. approve() explicitly reverts if msg.sender == spender with ERC20InvalidSpender(msg.sender) (line ~121). However, permit() function (if present) processes EIP-712 signatures to set allowances. If permit() does not have the same self-approval block, can an attacker use permit signatures to grant themselves self-allowance, bypassing the validator's permit-based authorization flow?",

    # WERC7575ShareToken. sol - Permit Signature Validation (Lines ~440-520)
    "WERC7575ShareToken.permit() validates EIP-712 signatures with ECDSA. recover() and checks the recovered address matches the owner. If the function does not verify that block.chainid matches the DOMAIN_SEPARATOR's cached chain ID before signature validation, can an attacker replay valid permit signatures from a testnet or forked chain to grant unauthorized allowances on mainnet?",

    "In WERC7575ShareToken.permit(), the function increments nonces[owner] after signature validation (line ~495). If the nonce increment happens AFTER the _approve() call and a reentrancy occurs during _approve() (e.g., via a malicious spender contract's onApprove hook if implemented), can the attacker reuse the same signature to set allowances multiple times before the nonce increments? ",

    "WERC7575ShareToken uses EIP712 domain separator with name, version, chainId, and verifyingContract.  If the contract is deployed behind a proxy (UUPS for upgradeable version) but the DOMAIN_SEPARATOR is calculated in the implementation's constructor/initializer using address(this), does the domain separator mismatch between proxy and implementation addresses invalidate all permit signatures, or can an attacker exploit the mismatch to forge signatures? ",

    # WERC7575ShareToken.sol - rBalance Adjustment (Lines ~741-780)
    "WERC7575ShareToken. adjustrBalance() allows the Revenue Admin to adjust _rBalances and _balances for multiple accounts with amounti (invested) and amountr (returned).  If amountr > amounti (profit scenario), the function increases _balances by (amountr - amounti).  If a malicious Revenue Admin (or compromised key, but admin is TRUSTED) calls this with amountr = type(uint256).max and amounti = 1, does the unchecked profit calculation cause integer overflow, minting unlimited tokens to the account and violating total supply invariant?",

    "In WERC7575ShareToken.adjustrBalance(), the function stores adjustments in _rBalanceAdjustments[account][ts] for potential cancellation. If the same (account, ts) pair is adjusted twice (replay or mistake), the require statement should prevent double-application. However, if ts is attacker-controlled and not validated against block.timestamp, can an attacker use future timestamps to bypass the 'already applied' check and apply the same adjustment multiple times?",

    "WERC7575ShareToken. adjustrBalance() decrements _rBalances[account] by amounti and increments _balances[account] by amountr. If amounti > _rBalances[account] (user has insufficient rBalance), does the function use unchecked arithmetic that allows underflow, resulting in _rBalances[account] wrapping to type(uint256).max and corrupting the dual-balance tracking system?",

    "In WERC7575ShareToken.cancelrBalanceAdjustment(), the function reverses a previous adjustment by subtracting amountr from _balances and adding amounti back to _rBalances. If the cancellation is called AFTER the user has already transferred away the amountr tokens, can the cancellation cause _balances[account] to underflow (if _balances[account] < amountr), permanently corrupting the account's balance? ",

    # WERC7575ShareToken.sol - Asset-Vault Registry (Lines ~880-950)
    "WERC7575ShareToken.registerVault() adds a bidirectional mapping between asset and vault addresses using EnumerableMap and a reverse mapping.  If an attacker (or buggy Owner call, but Owner is TRUSTED) calls registerVault() with an asset that is already registered to a different vault, does the function correctly revert, or can it overwrite the existing mapping and orphan the old vault's mint/burn permissions, preventing legitimate share operations?",

    "In WERC7575ShareToken. unregisterVault(), the function removes the asset↔vault mappings.  If a vault still has outstanding shares minted (totalSupply > 0 for that asset's shares) when unregisterVault() is called, does the function allow the unregistration, permanently locking users' ability to burn those shares since mint()/burn() will revert when assetToVault[asset] returns address(0)?",

    "WERC7575ShareToken.mint() checks that msg.sender == assetToVault[asset] to authorize minting (line ~305). If an attacker deploys a malicious contract and convinces the Owner to register it as a vault for a fake asset, can the attacker's contract mint unlimited shares by calling mint() with arbitrary amounts, then transfer those shares to other users who might unknowingly treat them as legitimate?",

    # WERC7575ShareToken. sol - KYC Enforcement (Lines ~245-270)
    "WERC7575ShareToken._update() checks require(isKycVerified[to]) to prevent non-KYC'd addresses from receiving shares (line ~259). However, if 'to' is a contract that implements a fallback function and delegatecalls to another address during the balance update, can the final recipient bypass KYC checks since the require only validates the immediate 'to' address, not the ultimate beneficiary?",

    "In WERC7575ShareToken, batchTransfers() updates _balances directly without calling _update() (which contains KYC checks for ERC20. transfer).  If the validator includes a non-KYC'd creditor in a batch transfer, does batchTransfers() enforce KYC via its own logic, or does it bypass the KYC gating entirely, allowing unauthorized addresses to receive shares through batch operations?",

    "WERC7575ShareToken.setKycStatus() (if present) is restricted to KYC Admin.  If the KYC Admin revokes KYC for a user who currently holds shares (isKycVerified[user] = false), are the user's existing shares frozen (they can't transfer), or can they still transfer to KYC-verified recipients?  If frozen, can the user's position become permanently locked if KYC is never reinstated?",

    # ShareTokenUpgradeable.sol - ERC-7201 Storage (Lines ~84-111)
    "ShareTokenUpgradeable uses ERC-7201 namespaced storage with keccak256('erc7575. sharetoken.storage') as the slot.  If a future upgrade adds a new parent contract (e.g., ERC721Enumerable) that uses traditional storage slots (slot 0, 1, 2.. .), can the new parent's storage variables collide with the namespaced storage struct's internal layout, corrupting assetToVault mappings or investmentManager address? ",

    "In ShareTokenUpgradeable._getShareTokenStorage(), the function uses inline assembly to load the storage pointer: assembly { $. slot := SHARE_TOKEN_STORAGE_SLOT }. If a compiler bug or future Solidity version changes how storage pointers are accessed in assembly, can this cause the returned storage struct to point to an incorrect slot, leading to reads/writes of arbitrary storage locations?",

    "ShareTokenUpgradeable's ShareTokenStorage struct includes EnumerableMap. AddressToAddressMap assetToVault (line ~95). If the EnumerableMap library is upgraded in a future version and changes its internal storage layout (e.g., adding a new field), does the new layout corrupt the existing assetToVault data, preventing vaults from being looked up correctly and breaking mint/burn operations?",

    # ShareTokenUpgradeable.sol - UUPS Upgrade (Lines ~160-185)
    "ShareTokenUpgradeable inherits UUPSUpgradeable and overrides _authorizeUpgrade(address newImplementation) with onlyOwner (line ~175). If the Owner's private key is compromised (but Owner is TRUSTED per spec), they could upgrade to a malicious implementation. However, if _authorizeUpgrade does not validate that newImplementation is a contract (e.g., address(newImplementation). code.length > 0), can an attacker trick the Owner into upgrading to an EOA, bricking the proxy?",

    "In ShareTokenUpgradeable, if a new implementation is deployed with a different storage layout (e.g., removing the __gap array or reordering ShareTokenStorage fields), does the UUPS upgrade mechanism have any runtime checks to prevent storage corruption, or does it allow the upgrade to proceed, immediately corrupting all assetToVault mappings and investment manager settings upon the first storage write?",

    "ShareTokenUpgradeable's initializer function __ShareTokenUpgradeable_init() uses the initializer modifier from OwnableUpgradeable.  If an attacker front-runs the deployment transaction and calls initialize() on the implementation contract (not the proxy) before the legitimate deployer, can the attacker become the owner of the implementation contract, preventing the proxy from initializing correctly (since implementation's initialized flag is set)?",

    # ShareTokenUpgradeable.sol - Operator System (Lines ~200-230)
    "ShareTokenUpgradeable implements an operator approval system where controllers can approve operators to act on their behalf (setOperator). If the operator approval is not scoped per vault (i.e., approving operator for vault A also grants operator permissions for vault B), can a malicious operator drain a controller's positions across all vaults once approved for a single vault?",

    "In ShareTokenUpgradeable, if setOperator(operator, approved) does not emit an event, and the operator status is later used in access control checks for sensitive operations (e.g., fulfillDeposit, investAssets), can an attacker who previously gained operator approval (then had it revoked off-chain) exploit a front-running scenario where they execute a privileged operation before the revocation transaction confirms?",

    # ERC7575VaultUpgradeable.sol - Reserved Asset Calculation (Lines ~1083-1096)
    "ERC7575VaultUpgradeable._calculateReservedAssets() sums totalPendingDeposit, totalClaimableDeposit, and totalPendingRedeem (line ~1085). However, totalPendingDeposit is denominated in asset units (e.g., 1,000,000 USDC = 1e6), while totalClaimableDeposit and totalPendingRedeem are denominated in share units (e.g., 1e18). If the function adds these values directly without converting shares to assets using convertToAssets(), does the unit mixing cause reserved assets to be massively overestimated for low-decimal assets (USDC 6 decimals) or underestimated for 18-decimal assets (DAI), leading to over-investment and potential insolvency?",

    "In ERC7575VaultUpgradeable._calculateReservedAssets(), if totalClaimableDeposit is large (e.g., 1000e18 shares representing 1000 USDC), and the function incorrectly adds it as '1000e18' assets instead of converting to '1000e6' assets, the reserved calculation becomes 1 trillion times larger than actual.  If investAssets() relies on this calculation to determine available assets (totalAssets - reserved), does this permanently prevent any investment since reserved > totalAssets, locking idle capital?",

    "ERC7575VaultUpgradeable. investAssets() calculates available assets as totalAssets() - _calculateReservedAssets() - investedAssets() (line ~1120). If _calculateReservedAssets() underestimates due to unit mixing (e.g., treating 1e18 shares as 1e18 assets when it should be 1e6 assets for USDC), can the Investment Manager inadvertently invest pending/claimable assets that should be reserved, causing deposit claims to revert when users try to claim their shares since the vault has insufficient assets?",

    # ERC7575VaultUpgradeable.sol - Async State Machine (Lines ~300-450)
    "ERC7575VaultUpgradeable. fulfillDeposit() transitions pending deposit requests to claimable by decrementing totalPendingDeposit and incrementing totalClaimableDeposit (lines ~352-358). If the Investment Manager calls fulfillDeposit() for the same controller twice (due to off-chain bug or replay), does the function's lack of idempotency protection allow totalClaimableDeposit to be incremented twice while totalPendingDeposit is only decremented once (if it underflows to zero on second call), violating the async state invariant?",

    "In ERC7575VaultUpgradeable.deposit(), the function checks claimableDepositRequest[controller] >= shares and decrements it (line ~405). If the controller has exactly 'shares' claimable but the function uses '>' instead of '>=' in the require check, can the controller never claim their final wei of shares, permanently locking a small amount of value?  Conversely, if the check is '>=' but the decrement uses unchecked arithmetic, can claimableDepositRequest underflow if shares > claimableDepositRequest due to a prior partial claim?",

    "ERC7575VaultUpgradeable.cancelDepositRequest() allows a controller to cancel their pending deposit and reclaim assets (line ~480). If the controller calls cancelDepositRequest() and simultaneously (via another transaction) the Investment Manager calls fulfillDeposit() for the same controller, does the lack of atomicity allow a race condition where the pending request is both fulfilled (assets converted to claimable shares) and canceled (assets returned to controller), causing the controller to receive assets twice and the vault to lose funds?",

    "In ERC7575VaultUpgradeable.fulfillRedeem(), the function mints shares to the vault as an intermediate step before burning them (line ~560). If the ShareToken's mint() function has a reentrancy hook (e.g., calling back into the vault), can an attacker exploit this to re-enter fulfillRedeem() and double-decrement totalPendingRedeem, causing the vault to release more assets than corresponding shares were burned, violating solvency? ",

    # ERC7575VaultUpgradeable.sol - Decimal Conversion (Lines ~1200-1250)
    "ERC7575VaultUpgradeable.convertToShares() multiplies assets by offset (10^(18 - decimals)) to normalize to 18-decimal shares (line ~1230). For USDC (6 decimals), offset = 1e12.  If an attacker deposits type(uint256).max / 1e12 USDC (approximately 1e65 USDC), does the multiplication assets * offset overflow in unchecked arithmetic, wrapping to a small number and minting far fewer shares than deserved, allowing the attacker to later redeem those shares for the full deposit amount and drain the vault?",

    "In ERC7575VaultUpgradeable.convertToAssets(), the function divides shares by offset (line ~1245). If offset is calculated incorrectly (e.g., using decimals from a different asset due to misconfiguration), can the conversion return assets with wrong magnitude?  For example, if USDC vault incorrectly uses DAI's decimals (18), offset = 1, and 1e18 shares converts to 1e18 assets instead of 1e6 USDC, causing massive over-redemption? ",

    "ERC7575VaultUpgradeable calculates offset in the initializer as 10 ** (18 - assetDecimals) (line ~1150). If assetDecimals > 18 (e.g., a token with 24 decimals, though rare), does the exponent become negative, causing 10 ** (18 - 24) = 10 ** (-6) to revert or compute incorrectly in Solidity, preventing vault initialization for high-decimal assets?",

    "In ERC7575VaultUpgradeable, if the asset token's decimals() function is malicious and returns a value > 77 (since 10^(18-decimals) would overflow uint256 if decimals < -59, but more realistically if decimals is manipulated), can the offset calculation in the initializer cause an integer overflow, setting offset to 0 or a wrapped value, breaking all share conversions and preventing deposits/withdrawals?",

    # ERC7575VaultUpgradeable.sol - Investment Integration (Lines ~650-800)
    "ERC7575VaultUpgradeable.investAssets() calls investmentVault.deposit(assets, investmentShareToken) to invest idle assets (line ~705). If the investmentVault is a malicious contract deployed by an attacker (but Owner is TRUSTED and would not register a malicious vault), it could transfer assets to itself but not mint investment shares, causing the vault to lose tracking of invested capital. However, since Owner is trusted, the real risk is: if the external investment vault has a reentrancy vulnerability, can it call back into the vault during deposit and trigger a state corruption (e.g., double-incrementing investedAssets)?",

    "In ERC7575VaultUpgradeable.withdrawFromInvestment(), the function redeems investment shares to retrieve assets (line ~780). If the investment vault's redeem() function returns fewer assets than expected (e.g., due to loss or slippage), but withdrawFromInvestment() does not validate that returnedAssets >= expectedAssets (based on shares redeemed), can the vault's accounting become inconsistent where investedAssets decrements by the intended amount but the actual asset balance increases by less, causing future insolvency?",

    "ERC7575VaultUpgradeable.investAssets() checks available = totalAssets - reserved - investedAssets and requires assets <= available (line ~700). If investedAssets() returns a cached value (e.g., stored in storage) rather than querying the investment vault's actual share balance, and the investment vault has suffered a loss (investment shares now worth less than originally deposited), does the vault's accounting overestimate investedAssets, allowing investAssets() to invest more than truly available and reserve insufficient assets for pending claims?",

    # ERC7575VaultUpgradeable.sol - UUPS Upgrade (Lines ~950-1000)
    "ERC7575VaultUpgradeable inherits UUPSUpgradeable and restricts _authorizeUpgrade to onlyOwner.  If a malicious implementation is deployed with a storage layout that moves the 'asset' address field (currently at VaultStorage.asset, line ~98) to a different slot, does the upgrade immediately corrupt the asset address, causing subsequent deposit() calls to transfer tokens to/from the wrong asset, leading to fund loss?",

    "In ERC7575VaultUpgradeable, the VaultStorage struct includes a __gap array for future expansion (if present). If a future upgrade adds 10 new storage variables but removes the __gap or reduces its size by less than 10 slots, does the new storage layout shift existing variables (e.g., controllerToRequest mapping) to different slots, corrupting all pending/claimable request data and preventing users from claiming their deposits/redeems?",

    "ERC7575VaultUpgradeable uses ERC-7201 namespaced storage with slot = keccak256('erc7575.vault.storage'). If the upgrade mechanism does not prevent the new implementation from using a different namespace (e.g., keccak256('erc7575.vault.storage.v2')), can the new implementation operate on a completely fresh storage struct, losing all existing vault state (asset, totalPendingDeposit, controllerToRequest), effectively resetting the vault and locking all user funds?",

    # WERC7575Vault.sol - Decimal Normalization (Lines ~82-100)
    "WERC7575Vault constructor calculates _offset = 10 ** (18 - _decimals) where _decimals is read from the asset token's decimals() function (line ~88). If the asset contract is malicious and returns decimals() = 0, does _offset = 10^18, causing convertToShares() to multiply by 1e18 and potentially overflow for any reasonable deposit amount, DoS'ing the vault? ",

    "In WERC7575Vault.convertToShares(), the function returns assets * _offset (line ~252). If _decimals = 18 (DAI), _offset = 1, and assets = type(uint256).max, does the multiplication overflow silently in unchecked arithmetic, wrapping to a small value and minting far fewer shares than deserved, allowing the attacker to deposit massive amounts and withdraw later by redeeming at correct conversion, draining the vault? ",

    "WERC7575Vault.convertToAssets() divides shares / _offset (line ~261). If _offset = 1 (for 18-decimal assets), the division is identity.  But if _offset was incorrectly calculated due to a non-standard asset token that changes decimals() return value after deployment (e.g., upgradeable token), can the conversion return incorrect asset amounts, causing withdrawals to over/under-pay users?",

    # WERC7575Vault.sol - Deposit/Redeem Flows (Lines ~110-200)
    "WERC7575Vault.deposit() calls _shareToken.mint(msg.sender, shares) to issue shares (line ~145). If the ShareToken contract has a reentrancy vulnerability in its mint() function (e.g., it calls an external hook before updating balances), can an attacker re-enter deposit() and mint shares multiple times for a single asset deposit, violating the token supply conservation invariant?",

    "In WERC7575Vault.redeem(), the function burns shares via _shareToken.burn(msg. sender, shares) and then transfers assets to the receiver (line ~180). If the asset token is a malicious ERC20 that re-enters redeem() during the transfer (e.g., via a transfer hook), can the attacker burn shares once but withdraw assets multiple times before the share burn completes, draining the vault?",

    "WERC7575Vault.deposit() converts assets to shares using convertToShares(assets).  If the conversion rounds down (due to integer division) and an attacker makes many small deposits (e.g., 1 wei each), can the rounding loss accumulate such that the attacker deposits X assets but receives < X equivalent shares, and the vault retains the dust as profit?  Conversely, if rounding up, can the attacker receive more shares than deserved, inflating supply? ",

    # SafeTokenTransfers.sol - Safe Transfer Implementation (Lines ~8-26)
    "SafeTokenTransfers.safeTransferToken() uses a low-level call to token.transfer(to, amount) and checks the return data (line ~15). If the token contract returns true in returndata but actually reverts inside a try-catch block (e.g., a malicious token that catches its own revert and returns success), does safeTransferToken() incorrectly assume the transfer succeeded, allowing the vault to update balances without actually receiving tokens?",

    "In SafeTokenTransfers.safeTransferToken(), if the token contract does not return any data (returndata.length == 0) and the call succeeds, the function treats it as success (line ~18). If the token is a malicious contract that implements transfer() as a no-op (simply returns without reverting or transferring), does the vault accept the 'transfer' as successful and credit the user with shares, despite no actual tokens being received?",

    "SafeTokenTransfers.safeTransferFrom() calls token.transferFrom(from, to, amount) via low-level call.  If the 'from' address is a malicious contract that implements ERC20 approval but does not actually hold the asset tokens, can the transferFrom call succeed (return true) but transfer 0 tokens (or revert silently), causing the vault to mint shares for deposits that never materialize?",

    # Cross-Layer Interactions: Settlement ↔ Investment
    "When ERC7575VaultUpgradeable.fulfillDeposit() mints shares to the vault (as an intermediate holder) before transferring to the controller, the ShareToken's mint() function is called. If WERC7575ShareToken.mint() checks msg.sender == assetToVault[asset] but ERC7575VaultUpgradeable is a UUPS proxy, does the check compare against the proxy address or implementation address?  If implementation, can an attacker deploy a malicious proxy with the same implementation and mint unauthorized shares? ",

    "ERC7575VaultUpgradeable.investAssets() deposits assets into an external investment vault and expects investment shares to be minted to the ShareToken contract (investmentShareToken address). If the investment vault mints shares to the vault proxy instead of the ShareToken, does this break the accounting where the vault's investedAssets() calculation relies on ShareToken holding the investment shares, causing investedAssets() to return 0 and allowing over-investment?",

    "WERC7575ShareToken.batchTransfers() is called by the Validator to settle carrier obligations.  If a batch includes a transfer from a vault address (e.g., as part of revenue distribution), does the batch transfer reduce the vault's share balance, and can this cause ERC7575VaultUpgradeable.totalAssets() to decrease unexpectedly, breaking the reserved asset calculation and allowing the Investment Manager to over-invest reserved funds?",

    # Edge Cases and Boundary Conditions
    "In WERC7575ShareToken.batchTransfers(), if all transfers in the batch are self-transfers (debtor == creditor), the function skips all entries and never updates any balances (line ~690). Does the function still emit Transfer events for these skipped transfers, and if so, can off-chain systems misinterpret the events as actual transfers, causing accounting discrepancies in external integrations?",

    "ERC7575VaultUpgradeable.requestDeposit() accepts assets from the user and increments totalPendingDeposit (line ~320). If the user immediately calls cancelDepositRequest() in the same block, the pending request is decremented and assets returned (line ~485). If the vault has multiple users with pending requests and the cancelation causes totalPendingDeposit to underflow (if storage was corrupted), can this permanently DoS all other users' fulfillDeposit() calls since the decrement would revert?",

    "WERC7575ShareToken.permit() allows granting allowances via signature. If a user signs a permit for type(uint256).max allowance with deadline = type(uint256).max (infinite), and later the user's address is de-KYC'd (isKycVerified = false), can a holder of the permit signature still use it to transfer the user's shares to a KYC-verified recipient, bypassing the user's inability to directly transfer due to KYC revocation?",

    "In ERC7575VaultUpgradeable, if totalPendingDeposit and totalClaimableDeposit both approach type(uint256).max (e.g., vault has been operating for years with massive volume), can the addition totalPendingDeposit + totalClaimableDeposit in _calculateReservedAssets() overflow, wrapping to a small number and causing the vault to massively under-reserve, allowing investAssets() to invest nearly all assets and leaving insufficient funds for pending claims?",

    "WERC7575Vault.convertToShares(0) returns 0 * _offset = 0.  If a user calls deposit(0, receiver), does the function attempt to mint 0 shares, and does the ShareToken's mint(receiver, 0) emit a Transfer event with amount=0? If so, can this be abused to spam Transfer events or bypass KYC checks (since _update() might not validate 'to' for zero-value transfers)?",

    "ERC7575VaultUpgradeable.fulfillDeposit() calculates shares = convertToShares(assets) and increments totalClaimableDeposit by shares (line ~355). If assets = 1 wei and offset = 1e12 (USDC), shares = 1e12.  If the user's pendingDepositRequest was 1 wei but they are credited with 1e12 shares (due to decimal normalization), can the user claim 1e12 shares and redeem them for 1 USDC (1e6 wei), profiting 1e6x from the conversion rounding? ",

    "WERC7575ShareToken.batchTransfers() checks that arrays have the same length (debtors.length == creditors. length == amounts.length).  If an attacker submits a batch where debtors.length = 100 but creditors.length = 99 (due to off-chain bug), the function reverts with ArrayLengthMismatch.  However, if the validator's off-chain system has a bug that silently pads creditors with address(0), does the batch execute with address(0) as creditor, causing tokens to be burned (transferred to zero address) and violating the zero-sum invariant?",

    # Reentrancy Scenarios
    "ERC7575VaultUpgradeable.fulfillDeposit() has the nonReentrant modifier, but the function calls _shareToken.mint() (external call) before updating controllerToRequest[controller]. claimableDepositRequest (line ~355). If ShareToken's mint() is malicious and calls back into the vault (e.g., via a mint hook), can it re-enter fulfillDeposit() and double-increment claimableDepositRequest before the first call completes, allowing the controller to claim shares twice?",
    "WERC7575Vault.deposit() calls asset.transferFrom(msg.sender, address(this), assets) and then _shareToken.mint(msg.sender, shares). If the asset token has a malicious transferFrom that re-enters deposit() before returning, does the reentrancy guard (if present) prevent the re-entry, or can the attacker deposit once but mint shares multiple times? ",
    "In ERC7575VaultUpgradeable.investAssets(), the function calls investmentVault.deposit(assets, investmentShareToken) (external call) and then updates investedAssets storage. If the investment vault re-enters and calls withdrawFromInvestment() during the same transaction, can the nested call decrement investedAssets before the outer call increments it, causing accounting corruption?",
    # Access Control and Authorization
    "WERC7575ShareToken.batchTransfers() has onlyValidator modifier, restricting calls to the validator address (line ~630). If the validator address is set to address(0) during initialization (or Owner accidentally calls setValidator(address(0))), does the modifier allow ANY caller (since msg.sender == address(0) is false, but no valid validator exists), effectively DoS'ing all batch transfers?",
    "ERC7575VaultUpgradeable.fulfillDeposit() has onlyInvestmentManager modifier.  If the Investment Manager role is transferred to a malicious actor (but Investment Manager is TRUSTED per spec), they could fulfill requests with incorrect share amounts.  However, the realistic attack is: if setInvestmentManager() does not validate the new address is a contract or EOA with specific capabilities, can the Owner accidentally set investmentManager to a contract that cannot call fulfill functions, permanently locking all async requests?",
    "In WERC7575ShareToken.registerVault(), the function has onlyOwner modifier. If the Owner is a multisig and one signer is compromised, can the compromised signer call registerVault() with a malicious vault address before other signers notice, allowing the malicious vault to mint unlimited shares via mint() calls until the registration is revoked?",
    # Decimal and Unit Precision Edge Cases
    "ERC7575VaultUpgradeable.convertToShares() for a 6-decimal asset (USDC) converts 1 USDC (1e6) to 1e18 shares. If totalSupply is 1e18 shares and totalAssets is 1 USDC (1e6), the share price is 1:1.  But if totalAssets increases by 1 wei to 1e6 + 1, the new share price is (1e6 + 1) / 1e18 assets per share.  For the next deposit of 1 USDC (1e6), shares = 1e6 * 1e18 / (1e6 + 1) ≈ 1e18 - epsilon. Can an attacker exploit this rounding to gradually extract value by depositing and withdrawing repeatedly?",
    "In WERC7575Vault. convertToAssets(1), if offset = 1e12 (USDC), the function returns 1 / 1e12 = 0 due to integer division. If a user holds 1e11 shares (less than 1 USDC equivalent), convertToAssets(1e11) = 1e11 / 1e12 = 0, meaning they cannot redeem any assets. Can the user's shares become permanently unredeemable dust, violating the withdrawal availability invariant?",
    "ERC7575VaultUpgradeable uses _convertToAssets() in reserved asset calculation.  If the vault holds both DAI (18 decimals, offset=1) and USDC (6 decimals, offset=1e12), and _calculateReservedAssets() is called on a USDC vault but accidentally uses DAI's offset, the conversion returns assets with wrong magnitude (1e12x error). If the vault operates multi-asset (though spec says one vault per asset), can this cross-contamination occur?",
    # Storage Corruption and Upgrade Risks
    "ShareTokenUpgradeable's ShareTokenStorage struct uses EnumerableMap.AddressToAddressMap for assetToVault (line ~95). If the OpenZeppelin EnumerableMap library is upgraded in a dependency and changes the internal layout (e.g., adding a new field), and the ShareToken contract is redeployed without updating the storage struct, does the layout mismatch corrupt all asset-vault mappings, preventing vaults from being looked up and breaking all mint/burn operations?",
    "ERC7575VaultUpgradeable's VaultStorage struct includes bool isActive (line ~120). In Solidity, bool is stored as uint8 in storage.  If a future upgrade mistakenly changes isActive to uint8 or adds a new uint8 field adjacent to it, does the storage slot packing/unpacking logic shift, causing isActive reads to return incorrect values and potentially DoS'ing deposits when isActive is read as false despite being set to true?",
    "In WERC7575ShareToken, if the contract is deployed with a specific storage layout and later a library function (e.g., in SafeERC20 or SafeTokenTransfers) is updated to use delegatecall, can the delegatecall context operate on the caller's storage, accidentally overwriting _balances or _rBalances mappings and corrupting user balances?",
    # Batch Transfer Zero-Sum Invariant
    "WERC7575ShareToken.batchTransfers() enforces zero-sum by netting debits and credits. If the validator submits a batch where sum(amounts) for debtors != sum(amounts) for creditors due to an off-chain calculation error, does the on-chain netting algorithm still pass the zero-sum check (since it only validates final balances are sufficient), or does it have an explicit sum(amounts_in) == sum(amounts_out) validation that would catch the discrepancy?",
    "In batchTransfers(), the netting process aggregates net amounts per account. If two entries in the batch involve the same debtor→creditor pair with amounts X and Y, does the netting correctly sum them as a single net transfer of X+Y, or does it process them as separate transfers? If separate, can an attacker exploit this to cause the zero-sum validation to pass while individual transfers violate balance constraints?",
    "WERC7575ShareToken.batchTransfers() updates _rBalances based on net debits/credits. If an account has net debit (pays out), _rBalances increases (line ~760). If net credit (receives), _rBalances decreases (line ~770). However, if the account receives more credit than their _rBalances (rBalances < netCredit), the function sets _rBalances = 0 (line ~773). Does this silent truncation break the dual-balance invariant where _balances + _rBalances should represent total wealth, potentially hiding lost funds?",
    # Signature and Permit Edge Cases
    "WERC7575ShareToken. permit() validates deadline > block.timestamp (or >=). If a user signs a permit with deadline = block.timestamp + 1 (expires next block), and the transaction is delayed in the mempool for multiple blocks, the permit becomes invalid. However, if the signature is then replayed on a different chain (with same address but different chain ID), can the permit be used on the new chain if the DOMAIN_SEPARATOR is not chain-specific?",
    "In permit(), after signature validation, the function calls _approve(owner, spender, value).  If _approve emits an Approval event but the actual allowance storage update is conditional (e.g., only updates if value != current allowance), can an attacker spam permit transactions with the same signature (if nonce is not incremented atomically) to generate Approval events without actually changing allowances, causing off-chain systems to misinterpret allowance states?",
    # Investment Layer Integration Risks
    "ERC7575VaultUpgradeable.investAssets() requires the investment vault to mint shares to investmentShareToken address (the ShareToken contract). If the investment vault's deposit() function is malicious and mints shares to msg.sender (the vault proxy) instead, does the ShareToken contract not receive the shares, causing investedAssets() (which queries ShareToken's balance) to return 0, allowing the Investment Manager to re-invest the same assets multiple times and over-leverage?",
    "In withdrawFromInvestment(), the function calls investmentVault.redeem(shares, vault, investmentShareToken) expecting assets to be returned to the vault (line ~785). If the investment vault's redeem() has a withdrawal fee (e.g., returns 99% of expected assets), does the vault's accounting assume 100% return, causing a slow balance leak where investedAssets decrements by full amount but actual assets received is less, leading to gradual insolvency?",
    "ERC7575VaultUpgradeable.investedAssets() returns the balance of investment shares held by the ShareToken (line ~1100). If the ShareToken contract holds investment shares for multiple vaults (e.g., USDC vault and DAI vault both invest in the same WUSD investment vault), does investedAssets() incorrectly return the total balance across all vaults, causing one vault to count another vault's investments as its own and allowing over-investment?",
    # Request Cancellation Boundary Conditions
    "ERC7575VaultUpgradeable.cancelDepositRequest() allows canceling pending deposits (line ~480). If a controller has pendingDepositRequest = X and the Investment Manager simultaneously calls fulfillDeposit(controller, X), can the race condition result in: (1) fulfillDeposit moves X from pending to claimable, (2) cancelDepositRequest tries to decrement pending (now 0), causing underflow and reverting?  Or worse, if unchecked, wrapping pending to type(uint256).max and corrupting the vault state?",
    "In cancelRedeemRequest(), the function returns shares to the controller by transferring from the vault back to the controller (line ~520). If the controller has delegated their shares to an operator, and the operator cancels the redeem request, do the shares get transferred to the controller or the operator? If operator, can the operator steal shares by repeatedly requesting and canceling redeems?",
    "ERC7575VaultUpgradeable.cancelDepositRequest() checks controllerToRequest[controller].pendingDepositRequest >= assets before decrementing (line ~482). If the check is '>' instead of '>=', can a controller with exactly 'assets' pending never cancel (edge case DoS)? If '>=', and assets > pending due to concurrent fulfillDeposit, does the unchecked decrement wrap pending to type(uint256).max, corrupting state? ",
]


def question_format(question: str) -> str:
    prompt = f"""
You are an Elite Web3 Security Auditor specializing in ERC-7575/ERC-7540 vault protocols and institutional DeFi systems.  Your task is to analyze the SukukFi WERC7575 codebase with laser focus on this single question:

**Security Question (scope for this run):** {question}

**SUKUKFI PROTOCOL CONTEXT:**
- **Architecture**: Dual-layer system with Settlement Layer (WERC7575ShareToken) and Investment Layer (ERC7575VaultUpgradeable) with UUPS upgradeability
- **Key Components**: 
  - ShareToken: Multi-asset settlement token with dual balance tracking (_balances + _rBalances)
  - VaultUpgradeable: Async ERC-7540 deposit/redeem with investment vault integration
  - Batch Settlement: Netting algorithm for telecom carrier settlements with zero-sum invariant
- **Technology**: Solidity with ERC-7201 namespaced storage, ERC-7540 async flows, permit-based transfers, KYC enforcement
- **Files in Scope**: 6 contracts totaling 1,670 nSLOC (see scope.txt):
  - DecimalConstants.sol (5 nSLOC)
  - ERC7575VaultUpgradeable.sol (737 nSLOC)
  - SafeTokenTransfers.sol (19 nSLOC)
  - ShareTokenUpgradeable.sol (243 nSLOC)
  - WERC7575ShareToken.sol (514 nSLOC)
  - WERC7575Vault.sol (152 nSLOC)
- **Test Files**: ALL files in ./test/** are OUT OF SCOPE

**CRITICAL INVARIANTS (from README):**
1. **Token Supply Conservation**: sum(balances) == totalSupply
2. **Zero-Sum Settlement**: batchTransfers: sum(balance changes) == 0
3. **Dual Authorization**: transfer requires self-allowance[user] (permit enforcement)
4. **TransferFrom Dual Check**: requires both self-allowance AND caller allowance
5. **KYC Gating**: Only KYC-verified addresses can receive/hold shares
6. **Asset-Vault Mapping**: assetToVault[asset] ↔ vaultToAsset[vault] (bijection)
7. **Vault Registry**: Only registered vaults can mint/burn shares
8. **Async State Flow**: Deposit/Redeem: Pending → Claimable → Claimed (no skipping)
9. **Reserved Asset Protection**: investedAssets + reservedAssets ≤ totalAssets
10. **Conversion Accuracy**: convertToShares(convertToAssets(x)) ≈ x (within rounding tolerance)
11. **No Role Escalation**: Access control boundaries enforced
12. **No Fund Theft**: No double-claims, no reentrancy, no authorization bypass

**YOUR INVESTIGATION MISSION:**
- Use the security question as your starting point.  Accept its premise and investigate ALL code paths, system components, and protocol logic related to that question.
- Look for ONE concrete, exploitable vulnerability tied to the question.  Do not surface-level scan—go deep into business logic, state transitions, and cross-module interactions. 

**ATTACK SURFACE EXPLORATION:**
1. **Input Scenarios**: Test extreme boundary values, zero values, type(uint256).max, empty arrays, duplicate entries, mismatched array lengths
2. **State Manipulation**: Vault registration, deposit/redeem requests, batch settlements, investment operations, rBalance adjustments, request cancellations, reentrancy via external calls
3. **Cross-Module Flows**: Track how user actions propagate through User → Vault → ShareToken → InvestmentVault.  Verify state consistency at each hop.
4. **Decimal Handling**: Protocol normalizes all shares to 18 decimals regardless of asset decimals (USDC=6, DAI=18).  Look for:
   - Offset calculation errors (offset = 10^(18 - assetDecimals))
   - Unit mixing in reserved asset calculations (shares vs assets)
   - Conversion rounding exploits (convertToShares/convertToAssets)
   - Overflow in offset multiplication
5. **Async Request Flows**: ERC-7540 async operations with state transitions:
   - Request → Fulfill → Claim flow integrity
   - Cancellation edge cases (can cancel pending, not claimable)
   - Double-claiming via reentrancy
   - State skipping (bypassing pending/claimable states)

**SUKUKFI-SPECIFIC ATTACK VECTORS:**
- **Batch Netting Abuse**: Can netting algorithm be exploited to bypass balance checks or create tokens from nothing? 
- **Unit Mixing**: Reserved asset calculation adds totalClaimableDeposit (shares) to totalPendingDeposit (assets) - type confusion exploit? 
- **rBalance Manipulation**: Can rBalance adjustments be used to inflate balances without actual capital? 
- **Permit Bypass**: Can dual-allowance requirement be circumvented to transfer without validator approval?
- **Investment Layer Exploits**: Can investAssets/withdrawFromInvestment be abused to drain vaults?
- **Cancellation Exploits**: Can request cancellation be exploited for double-spending or theft? 
- **Upgrade Attacks**: Can UUPS upgrade pattern be exploited for storage corruption? 
- **KYC Bypass**: Can non-KYC'd addresses receive tokens via batch transfers or other flows? 
- **Decimal Offset Exploits**: Can offset calculation be manipulated for USDC (6 decimals) vs DAI (18 decimals)?

**TRUST MODEL (from KNOWN_ISSUES.md):**
- **Trusted Roles**: Owner (upgrades, vault management), Investment Manager (fulfillment timing), Validator (permits, KYC, batch transfers), KYC Admin, Revenue Admin
- **DO NOT assume trusted roles act maliciously**.  Focus on unprivileged attackers.
- **In-scope**: Logic errors, subtle bugs, unintended behaviors triggerable by normal users
- **Out-of-scope**: Admin key compromise, misconfiguration by owners, reckless admin mistakes

**KNOWN ISSUES (DO NOT REPORT):**
- Centralized access control (Owner/Validator/Investment Manager powers) - QA/Low
- Non-standard ERC-20 behavior (permit requirements, dual allowances, KYC) - QA/Low
- External protocol incompatibility (DEXs, lending, standard wallets) - Invalid
- No fulfillment deadlines (Investment Manager can delay) - QA/Low
- Reserved assets not invested (intentional safety buffer) - QA/Low
- Request cancellation allowed (intentional user protection) - QA/Low
- Unilateral upgrades without timelock - QA/Low
- All shares 18 decimals (intentional multi-asset design) - QA/Low
- Rounding ≤1 wei (acceptable ERC-4626 tolerance) - QA/Low
- Batch size limits (MAX_BATCH_SIZE = 100) - QA/Low
- Batch netting allows "overdraft" within batch (intentional, final state validated) - QA/Low
- Self-transfers skipped in batch operations - QA/Low
- rBalance silent truncation (informational tracking) - QA/Low
- Two batch transfer functions (batchTransfers vs rBatchTransfers) - QA/Low

**VALID IMPACTS (Code4rena Severity Framework):**
- **High**: Direct theft of user funds, unauthorized minting/burning, asset theft vectors, access control bypass (unintended), storage corruption in upgrades
- **Medium**: Reentrancy affecting state, signature replay attacks, accounting errors breaking functionality, DOS requiring non-trivial cost, standards violations breaking functionality, exploitable precision loss

**OUTPUT REQUIREMENTS:**
- If you find a valid vulnerability: Produce a full report in the format below
- If **NO** valid vulnerability emerges: State exactly: **"#NoVulnerability found for this question."**
- **DO NOT** invent findings, repeat previous findings for this question, or report out-of-scope issues
- **DO NOT** report theoretical issues—only exploitable vulnerabilities with concrete attack paths
- Focus on finding **ONE** high-quality vulnerability, not multiple weak claims

**VALIDATION CHECKLIST (Before Reporting):**
- [ ] Vulnerability is in a file listed in scope. txt (NOT in test/**)
- [ ] Issue is exploitable by an unprivileged attacker (not requiring admin keys)
- [ ] Attack path is realistic and executable on-chain
- [ ] Impact matches Code4rena severity criteria (High/Medium minimum for HM pool)
- [ ] PoC can be implemented in the provided test suite without mocking contracts
- [ ] Issue violates a documented invariant or causes financial harm
- [ ] Not a known issue from KNOWN_ISSUES.md
- [ ] Not about centralization (all admin roles are trusted)
- [ ] Not about non-standard ERC-20 behavior (intentional design)
- [ ] Not about external compatibility (DEXs, wallets, lending not supported)

---

**Audit Report Format** (if vulnerability found):

## Title
[Clear, specific vulnerability name tied to the question]

## Summary
A concise 2-3 sentence description of the issue and its location in the codebase. 

## Impact
**Severity**: [High / Medium]

## Finding Description
**Location:** `src/[path]/[file].sol` (specific contract and function name, line numbers if possible)

**Intended Logic:** [What the code is supposed to do per documentation/comments]

**Actual Logic:** [What the code actually does in the vulnerable scenario]

**Exploitation Path:**
1. [Step 1: Specific function call with realistic parameters]
2. [Step 2: State change with code evidence]
3. [Step 3: Follow-up action exploiting the state]
4. [Step 4: Unauthorized outcome - theft, DOS, invariant violation]

**Security Property Broken:** [Which invariant from README or protocol logic is violated]

## Impact Explanation
- **Affected Assets**: [Which tokens, positions, vaults are at risk]
- **Damage Severity**: [Quantify the potential loss]
- **User Impact**: [How many users affected, what actions trigger the loss]

## Likelihood Explanation
- **Attacker Profile**: [Who can exploit this]
- **Preconditions**: [What state must exist]
- **Execution Complexity**: [Single transaction, multiple blocks, specific timing]
- **Frequency**: [How often can this be exploited]

## Recommendation
Provide a specific code fix with precise changes:
```solidity
// In src/[file]. sol, function [name], line [X]:

// CURRENT (vulnerable):
[paste vulnerable code]

// FIXED:
[paste corrected code with inline comments explaining the fix]

## Proof of Concept
```solidity
// File: test/Exploit_[VulnerabilityName].t.sol
// Run with: forge test --match-test test_[VulnerabilityName] -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/[relevant contracts]. sol";

contract Exploit_[Name] is Test {{
    // Setup contracts
    [Contract] vault;
    [Contract] shareToken;
    
    function setUp() public {{
        // Initialize protocol state
        [deployment and initialization code]
    }}
    
    function test_[VulnerabilityName]() public {{
        // SETUP: Initial state
        [arrange initial conditions]
        
        // EXPLOIT: Trigger vulnerability
        [execute attack transactions]
        
        // VERIFY: Confirm exploit success
        [assertions proving the vulnerability]
        assertEq([actual], [expected_bad_value], "Vulnerability confirmed: [description]");
    }}
}}

**If NO vulnerability found, output ONLY:**
#NoVulnerability found for this question.

---

**FINAL REMINDERS:**
- **Deep dive into async state transitions** (Pending → Claimable → Claimed flows)
- **Trace complete execution flows** through Settlement Layer ↔ Investment Layer
- **Verify reserved asset calculation** (watch for unit mixing: shares vs assets)
- **Test decimal conversion edge cases** (offset calculations for 6-decimal vs 18-decimal assets)
- **Check batch netting zero-sum invariant** (sum of all deltas must equal zero)
- **Validate dual allowance enforcement** (self-allowance + caller allowance)
- **Examine rBalance adjustment logic** (can it be exploited for balance inflation?)
- **Review upgrade safety** (ERC-7201 storage, gap arrays, no collisions)
- **Be 100% certain** before reporting—false positives damage credibility

Now investigate the security question thoroughly and produce your finding.
"""
    return prompt



def validation_format(report: str) -> str:
    prompt = f"""
You are an **Elite Web3 Security Judge** with deep expertise in Solidity, ERC-7575/ERC-7540 vaults, async deposit/redeem patterns, and institutional DeFi systems.  Your ONLY task is **ruthless technical validation** of security claims against the SukukFi WERC7575 codebase.

**SECURITY CLAIM TO VALIDATE:**
{report}

================================================================================
## **SUKUKFI PROTOCOL VALIDATION FRAMEWORK**

### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**
Reject immediately (#NoVulnerability) if ANY apply:

#### **A.  Scope Violations**
- ❌ Affects files NOT in scope. txt (only 6 files: DecimalConstants.sol, ERC7575VaultUpgradeable.sol, SafeTokenTransfers.sol, ShareTokenUpgradeable.sol, WERC7575ShareToken.sol, WERC7575Vault.sol)
- ❌ Targets test files (./test/** is explicitly OUT OF SCOPE)
- ❌ Claims about documentation, comments, NatSpec, or event emissions
- ❌ Focuses on out-of-scope components (interfaces, faucets, scripts)
- ❌ Any issues that have been seen allready in the readme is out of scope so consider it invalid

**Verify**: Check if reported file path matches EXACTLY a line in scope.txt

#### **B. Threat Model Violations**
- ❌ Requires Owner, Validator, Investment Manager, KYC Admin, or Revenue Admin to act maliciously
- ❌ Assumes compromised admin keys, private keys, or leaked secrets
- ❌ Needs external protocol misbehavior (DEX, lending protocol, investment vault)
- ❌ Requires admin mistakes ("Owner could accidentally...")
- ❌ Depends on external factors: network attacks, relay manipulation, censorship

**SukukFi Trusted Roles**: Owner (upgrades, vault management), Validator (permits, batch transfers, KYC), Investment Manager (fulfillment timing, investment operations), KYC Admin, Revenue Admin—DO NOT assume they steal user funds or act maliciously. 

#### **C. Known Issues from KNOWN_ISSUES.md**
- ❌ Centralized access control (Owner/Validator/Investment Manager powers) - Section 1
- ❌ Non-standard ERC-20 (permit requirements, dual allowances, KYC) - Section 2
- ❌ External protocol incompatibility (DEXs, lending, wallets) - Section 3
- ❌ No fulfillment deadlines (async design) - Section 4
- ❌ Reserved assets not invested (safety buffer) - Section 4
- ❌ Request cancellation allowed (user protection) - Section 4
- ❌ Unilateral upgrades without timelock - Section 5
- ❌ All shares 18 decimals (multi-asset design) - Section 6
- ❌ Rounding ≤1 wei (acceptable tolerance) - Section 6
- ❌ Batch size limits (gas protection) - Section 7
- ❌ Batch netting "overdraft" (intentional settlement logic) - Section 7
- ❌ Self-transfers skipped (gas optimization) - Section 7
- ❌ rBalance silent truncation (informational tracking) - Section 7a
- ❌ Two batch functions (batchTransfers vs rBatchTransfers) - Section 7a

**Cross-reference**: Does claim match known issues in KNOWN_ISSUES.md lines 1-748?

#### **D. Non-Security Issues**
- ❌ Gas optimizations, storage packing, code refactoring
- ❌ Missing events, incorrect log outputs, poor error messages
- ❌ Code style, naming conventions, comment improvements
- ❌ "Best practices" without exploitable security impact
- ❌ Precision loss with negligible financial impact (<0.01% of value)
- ❌ Input validation preventing honest user mistakes (not attacker exploits)

#### **E. Invalid Exploit Scenarios**
- ❌ Requires impossible inputs (beyond type bounds, negative unsigned ints)
- ❌ Cannot be triggered via ANY realistic transaction or contract call
- ❌ Depends on race conditions (blockchain state is deterministic per block)
- ❌ Relies on timing attacks, network delays, or block timestamp manipulation beyond miner control
- ❌ Needs multiple transactions in exact order without economic incentive
- ❌ Requires attacker to already possess what they're trying to steal

### **PHASE 2: SUKUKFI-SPECIFIC DEEP CODE VALIDATION**

#### **Step 1: TRACE COMPLETE EXECUTION PATH THROUGH DUAL-LAYER ARCHITECTURE**

**SukukFi Flow Pattern:**
User → Vault (async request) → Investment Manager (fulfillment) → ShareToken (mint/burn) → Investment Vault (yield generation)

**Trace Requirements:**
1. **Entry Point Identification**:
   - Which function is called?  (requestDeposit, fulfillDeposit, deposit, batchTransfers, etc.)
   - Who can call it? (User, Validator, Investment Manager, Owner)
   - What preconditions exist? (KYC verified, vault active, sufficient balance)

2. **State Transition Validation**:
   - What is the state BEFORE exploit? (pending amounts, balances, rBalances)
   - What state transitions occur? (pending → claimable → claimed)
   - Are there version counters, locks, or reentrancy guards? (Check nonReentrant modifier)

3.  **Cross-Layer Interactions**:
   - Does Vault correctly call ShareToken for minting/burning?
   - Does Investment Manager correctly update pending/claimable amounts?
   - Are reserved assets calculated correctly before investment? 

4. **Decimal Conversion Scrutiny**:
   - Is offset calculated correctly?  (offset = 10^(18 - assetDecimals))
   - Are conversions consistent?  (convertToShares ↔ convertToAssets)
   - Is there unit mixing? (shares added to assets without conversion)

5. **Async State Machine**:
   - Can user skip states? (pending → claimed without claimable)
   - Can user double-claim? (claim twice from same claimable amount)
   - Is cancellation properly gated? (only pending, not claimable)

#### **Step 2: VALIDATE EVERY CLAIM WITH CODE EVIDENCE**

For EACH assertion in the report, demand:

**✅ Required Evidence:**
- Exact file path matching scope.txt
- Precise line numbers (e.g., `ERC7575VaultUpgradeable.sol:352-358`)
- Direct code quotes (paste actual Solidity code)
- Function call traces with ACTUAL parameter values

**🚩 RED FLAGS (indicate INVALID):**

1. **"Missing Validation" Claims**:
   - ❌ "Function doesn't check X" → Verify NO validation in called functions, modifiers, or type system
   - ✅ Valid ONLY if: Input bypasses ALL layers AND causes unauthorized harm

2. **"Unit Mixing" Claims**:
   - ❌ "Mixes shares and assets" → Check if conversion happens in caller or elsewhere
   - ✅ Valid ONLY if: Actual arithmetic adds/subtracts different units causing incorrect state

3. **"Reentrancy" Claims**:
   - ❌ "External call without nonReentrant" → Check if modifier exists
   - ✅ Valid ONLY if: No nonReentrant guard AND attacker can reenter to corrupt state

4. **"Rounding Error" Claims**:
   - ❌ "Division rounds down" → Normal integer behavior
   - ✅ Valid ONLY if: Exploitable for >0.1% profit across realistic # of transactions

5. **"Access Control" Claims**:
   - ❌ "Only Validator can call" → This IS the design (centralization known issue)
   - ✅ Valid ONLY if: Unauthorized user CAN call despite intended restrictions

6. **"Batch Transfer Exploit" Claims**:
   - ❌ "User can transfer more than balance in batch" → Intentional netting (KNOWN_ISSUES.md Section 7)
   - ✅ Valid ONLY if: Final balance incorrect after batch OR zero-sum violated

7. **"Reserved Asset Calculation" Claims**:
   - ❌ "Reserved assets include claimable deposits" → Check if unit conversion missing
   - ✅ Valid ONLY if: Calculation mixes units (shares + assets) causing over/under-investment

8. **"Request Cancellation" Claims**:
   - ❌ "Users can cancel and reclaim funds" → Intentional (KNOWN_ISSUES.md Section 4)
   - ✅ Valid ONLY if: Can cancel CLAIMABLE (not just pending) OR double-spend via cancellation

#### **Step 3: CROSS-REFERENCE WITH TEST SUITE**

**Questions to Ask:**
1. Do current tests pass scenarios that would expose this bug?
2. Is there a fuzz test that should have caught this?
3. Would invariant tests catch this?  (Check test/invariant/*. t.sol if they exist)
4. Do test assertions contradict the claim? 

**Test Case Realism Check:**
- Does PoC use realistic addresses?  (not address(0), not uninitialized)
- Does PoC set up state properly? (vault registered, KYC verified, balances funded)
- Does PoC avoid mocking in-scope contracts? (no mock vaults replacing real ones)

### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION**

#### **Impact Must Be CONCRETE and IN-SCOPE**

**✅ Valid High Severity Impacts:**
- Direct theft of user funds from vaults or share tokens
- Unauthorized minting/burning of shares
- Asset theft vectors (drain vault, steal from other users)
- Access control bypass allowing unprivileged user to gain admin powers
- Storage corruption in upgrades causing fund loss

**✅ Valid Medium Severity Impacts:**
- Reentrancy affecting state (temporary inconsistency, recoverable)
- Signature replay attacks allowing unauthorized transfers
- Accounting errors (reserved asset calculation breaking investment logic)
- DOS requiring non-trivial cost (blocking all deposits/withdrawals)
- Standards violations breaking functionality (ERC-7540 async flow broken)
- Exploitable precision loss (>0.1% profit per exploit)

**❌ Invalid "Impacts":**
- User withdraws own funds (that's the design!)
- Owner upgrades contract (that's their privilege per KNOWN_ISSUES.md Section 5)
- Validator controls permits (that's centralization, QA/Low per Section 1)
- Investment Manager delays fulfillments (that's async design per Section 4)
- Attacker loses their own funds in failed exploit
- Theoretical cryptographic weakness without practical exploit
- "Could be problematic if..." without demonstrating HOW
- DOS without theft (unless preventing 25%+ of users)
- Compatibility issues (DEXs, wallets not supported per Section 3)

**Severity Cross-Check (Code4rena Framework):**
- **High**: Direct theft, permanent loss, unauthorized minting/burning
- **Medium**: Temporary loss, recoverable lock, significant griefing, accounting errors
- **Low/QA**: Minor fund leakage, temporary DOS, edge case reverts, centralization

#### **Likelihood Reality Check**

**Assess Realistic Probability:**

1. **Attacker Profile**:
   - Any user?  KYC-verified user? Malicious vault deployer?
   - Requires special position?  (e.g., must be first depositor)

2. **Preconditions**:
   - Vault registered and active? 
   - How much capital required? (for deposits/investments)
   - Specific timing?  (pending state, claimable state)
   - Other users' actions required?

3. **Execution Complexity**:
   - Single transaction or multiple?
   - Must be atomic (within one call) or across blocks?
   - Requires front-running or specific transaction ordering? 
   - Economic cost to execute?  (gas, capital lockup)

4. **Combined Probability**:
   If requires:
   - Rare market condition: 1%
   - Specific vault state: 5%
   - Timing window: 10%
   Combined: 0.01 * 0.05 * 0.10 = 0.00005 (0.005%)
   If <0.1% probability with no amplification → INVALID

### **PHASE 4: PROOF OF CONCEPT VALIDATION**

**A Valid PoC MUST:**

1. **Be Implementable in Foundry**:
   - Uses Forge's `Test` contract
   - Imports actual in-scope contracts (not mocks)
   - Compiles with `forge build`
   - Runs with `forge test --match-test test_VulnName -vvv`

2. **Use Realistic, Achievable Inputs**:
   - Addresses are real (not address(0) unless testing null check)
   - Amounts are realistic (not type(uint256).max unless testing overflow)
   - State is properly initialized (vaults registered, KYC verified)

3. **Show BEFORE → ACTION → AFTER with Clear Violation**:
   - Log balances before exploit
   - Execute exploit transaction(s)
   - Assert violation (e.g., attacker gained funds, zero-sum broken)

4. **NOT Require Modifying Security Checks**:
   - Cannot comment out nonReentrant modifier
   - Cannot remove onlyValidator restriction
   - Cannot mock in-scope contracts to bypass checks

5. **Actually Compile and Run**:
   - Code is valid Solidity
   - No syntax errors
   - Assertions fail as expected (proving vulnerability)

**PoC Red Flags (INVALID):**
- "Attacker constructs malicious vault state" (HOW via what function?)
- "Manually set totalPendingDeposit" (no external function allows this!)
- "Bypass Validator check" (without showing concrete method)
- "Call internal function _calculateReservedAssets" (not externally accessible!)
- Code that wouldn't compile
- Requires deploying modified versions of in-scope contracts

### **PHASE 5: DIFFERENTIAL ANALYSIS**

**Compare with Similar Systems:**

1. **Is this standard ERC-7540 behavior? **
   - Async deposit/redeem is core ERC-7540 design
   - Is reported "issue" actually how async vaults function?
   - Check: https://eips.ethereum.org/EIPS/eip-7540

2. **Is the behavior intentional for SukukFi?**
   - Does KNOWN_ISSUES.md explain this?  (Sections 1-12)
   - Is it mentioned in TECHNICAL_ARCHITECTURE.md?
   - Is it documented in README.md Areas of Concern?

3. **Design vs.  Bug Distinction:**
   Design Feature (NOT a bug):
   - Async operations with fulfillment delay (Section 4)
   - Batch netting allowing interim "overdraft" (Section 7)
   - Reserved assets not invested (Section 4)
   - Request cancellation by controller (Section 4)
   - Dual allowance requirement (Section 2)
   - KYC gating (Section 2)
   
   Actual Bug:
   - Reserved asset calculation mixes units (shares + assets) causing over-investment
   - Reentrancy in fulfillDeposit allows double-minting
   - Batch transfer violates zero-sum invariant
   - Cancellation of CLAIMABLE requests allows double-claim

4. **System-Level Protections:**
   - Does nonReentrant modifier prevent reported reentrancy?
   - Does reserved asset check prevent reported over-investment?
   - Does onlyValidator modifier prevent reported unauthorized call?
   - Are there checks in MULTIPLE layers? 

### **FINAL DECISION MATRIX**

**A claim is VALID only if ALL are true:**

- [ ] Vulnerability is in file from scope.txt (6 specific files)
- [ ] NOT in test/** folder (all test files out of scope)
- [ ] No trusted role misbehavior required (all admin roles act honestly)
- [ ] No external protocol misbehavior (DEXs, lending, investment vaults trusted)
- [ ] NOT a known issue from KNOWN_ISSUES.md Sections 1-12
- [ ] Unprivileged attacker can execute via normal contract calls
- [ ] Complete execution path confirmed with EXACT line numbers
- [ ] No hidden validation in called functions, modifiers, or type system
- [ ] State change is UNAUTHORIZED (not user managing own funds)
- [ ] Impact is High or Medium per Code4rena severity (concrete financial harm)
- [ ] PoC is realistic, compilable, and runnable without modifying src/
- [ ] Violates documented invariant (12 invariants from README lines 90-112)
- [ ] NOT standard ERC-7540 behavior (cross-referenced with EIP-7540)
- [ ] NOT intentional design per KNOWN_ISSUES.md or TECHNICAL_ARCHITECTURE.md

**If ANY checkbox unchecked → Output:** `#NoVulnerability found for this question. `

### **SPECIAL SUKUKFI VALIDATION RULES**

#### **1. "Missing Validation" Claims**
- ✅ Valid ONLY if: Input bypasses ALL layers (Vault, ShareToken, modifiers, type system) AND causes unauthorized harm
- ❌ Invalid if: Validation exists in caller, type system prevents it, or natural revert occurs, or only user harms themselves

#### **2. "Reserved Asset Calculation" Claims**
- ✅ Valid ONLY if: Calculation demonstrably mixes units (totalClaimableDeposit in shares added to totalPendingDeposit in assets) AND causes over/under-investment
- ❌ Invalid if: Unit conversion happens elsewhere OR calculation is informational only
- **VERIFY**: Trace _calculateReservedAssets() usage in investAssets() to see if bug is exploitable

#### **3. "Batch Transfer Exploit" Claims**
- ✅ Valid ONLY if: Final balances incorrect after batch OR zero-sum invariant violated (sum of deltas ≠ 0)
- ❌ Invalid if: Interim "overdraft" allowed but final state correct (KNOWN_ISSUES.md Section 7)
- **CHECK**: Verify sum of all debits == sum of all credits in batch

#### **4. "Request Cancellation" Claims**
- ✅ Valid ONLY if: Can cancel CLAIMABLE requests (not just pending) OR can double-spend via cancel+claim
- ❌ Invalid if: Cancellation only works on pending requests and returns funds correctly (KNOWN_ISSUES.md Section 4)

#### **5. "Decimal Conversion" Claims**
- ✅ Valid ONLY if: Offset calculation wrong (offset ≠ 10^(18 - assetDecimals)) OR conversion exploitable for >0.1% profit
- ❌ Invalid if: Normal ≤1 wei rounding (KNOWN_ISSUES.md Section 6)

#### **6. "rBalance Manipulation" Claims**
- ✅ Valid ONLY if: Attacker can inflate _balances via rBalance adjustment without corresponding asset deposit
- ❌ Invalid if: rBalance adjustment only redistributes existing capital (zero-sum) or is controlled by Revenue Admin (trusted)

#### **7. "Async State Skipping" Claims**
- ✅ Valid ONLY if: User can claim without fulfillment (skip pending → claimable) OR double-claim
- ❌ Invalid if: State transitions enforced correctly (pending decremented, claimable incremented)

#### **8. "Access Control Bypass" Claims**
- ✅ Valid ONLY if: Unprivileged user can call onlyValidator/onlyOwner/onlyInvestmentManager functions
- ❌ Invalid if: "Validator has too much power" (centralization, KNOWN_ISSUES.md Section 1)

#### **9. "Upgrade Storage Corruption" Claims**
- ✅ Valid ONLY if: Demonstration of actual storage slot collision between versions
- ❌ Invalid if: ERC-7201 namespaced storage used correctly with gap arrays

#### **10. "KYC Bypass" Claims**
- ✅ Valid ONLY if: Non-KYC'd address can receive shares via exploit
- ❌ Invalid if: KYC requirement is centralized control (KNOWN_ISSUES.md Section 2)

### **OUTPUT REQUIREMENTS**

**If VALID (extremely rare—be ruthlessly certain):**

## Audit Report

### Title
[Precise vulnerability name, e.g., "Unit Mixing in Reserved Asset Calculation Allows Over-Investment"]

### Summary
[2-3 sentences max: what, where, why critical]

### Impact
**Severity**: [High / Medium] - Justify using Code4rena framework

[1 paragraph: concrete financial impact with quantification]

### Finding Description

**Location:** `src/[path]/[file]. sol:[line_start]-[line_end]`, function `[functionName]()`

**Intended Logic:** 
[What SHOULD happen per SukukFi documentation, code comments, or README invariants]

**Actual Logic:**
[What DOES happen per code analysis - quote EXACT code]

**Exploitation Path:**
1. **Setup**: [Attacker deploys contracts, registers vault, deposits assets - specific values]
2. **Trigger**: [Call specific function with params = ...]
3. **State Change**: [Vault/ShareToken state transitions from X to Y - quote storage updates]
4. **Extraction**: [Attacker calls function to extract funds]
5. **Result**: [Vault balance incorrect OR attacker gains unauthorized tokens]

**Security Guarantee Broken:**
[Quote from README invariants: "investedAssets + reservedAssets ≤ totalAssets"]

**Code Evidence:**
```solidity
// src/ERC7575VaultUpgradeable.sol:1083-1096
function _calculateReservedAssets() internal view returns (uint256 total) {{
    // [paste actual vulnerable code section]
    // VULNERABLE: Mixes units - totalClaimableDeposit is SHARES, not assets
    total = $. totalPendingDeposit       // Assets ✓
          + $.totalClaimableDeposit     // SHARES ❌ (should be converted to assets)
          + $.totalPendingRedeem;       // Shares (but represents assets to reserve) ✓
}}

### Impact Explanation

**Affected Assets**: [USDC/USDT/DAI in vaults, user deposits]

**Damage Severity**:
- Attacker can cause vault to over-invest (~$X if condition Y)
- Users unable to withdraw deposited funds
- Protocol becomes insolvent (violates reserved asset invariant)

**User Impact**: All depositors in affected vault

**Trigger Conditions**: [Specific conditions for exploit]

### Likelihood Explanation

**Attacker Profile**: Any KYC-verified user or deposit requester

**Preconditions**:
1.  Vault must have pending/claimable deposits
2. Investment Manager must call investAssets()
3. No other special preconditions

**Execution Complexity**: Single transaction or natural protocol operation

**Economic Cost**: Minimal (only gas fees)

**Frequency**: Can occur on every investment operation

**Overall Likelihood**: HIGH - Naturally triggered by normal operations

### Recommendation

**Primary Fix:**
solidity
// In src/ERC7575VaultUpgradeable.sol, function _calculateReservedAssets(), line 1084-1096:

// CURRENT (vulnerable):
function _calculateReservedAssets() internal view returns (uint256 total) {{
    total = $.totalPendingDeposit       // Assets
          + $.totalClaimableDeposit     // SHARES (wrong unit!)
          + $.totalPendingRedeem;       // Shares
}}

// FIXED:
function _calculateReservedAssets() internal view returns (uint256 total) {{
    total = $.totalPendingDeposit                       // Assets
          + _convertToAssets($.totalClaimableDeposit)   // Convert shares → assets
          + _convertToAssets($.totalPendingRedeem);     // Convert shares → assets
}}

**Additional Mitigations**:
- Add unit tests specifically testing reserved asset calculation with different decimal assets
- Add invariant: `investedAssets() + _calculateReservedAssets() <= totalAssets()` checked in investAssets()

### Proof of Concept

solidity
// File: test/Exploit_ReservedAssetUnitMixing.t.sol
// Run with: forge test --match-test test_ReservedAssetUnitMixing -vvv

pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/WERC7575Vault.sol";
import "../src/WERC7575ShareToken.sol";

contract Exploit_ReservedAssetUnitMixing is Test {{
    WERC7575Vault vault;
    WERC7575ShareToken shareToken;
    MockUSDC usdc;
    
    function setUp() public {{
        // Deploy USDC (6 decimals)
        usdc = new MockUSDC();
        
        // Deploy ShareToken and Vault
        shareToken = new WERC7575ShareToken();
        vault = new WERC7575Vault(address(usdc), address(shareToken));
        
        // Register vault
        shareToken.registerVault(address(usdc), address(vault));
    }}
    
    function test_ReservedAssetUnitMixing() public {{
        // SETUP: User requests deposit
        uint256 depositAmount = 1000e6; // 1000 USDC
        usdc.mint(address(this), depositAmount);
        usdc.approve(address(vault), depositAmount);
        vault.requestDeposit(depositAmount, address(this));
        
        // Investment Manager fulfills deposit
        vm.prank(investmentManager);
        vault.fulfillDeposit(address(this), depositAmount);
        
        // BUG: totalClaimableDeposit is now 1000e18 (shares), not 1000e6 (assets)
        // Reserved asset calculation will add 1000e18 instead of 1000e6
        
        uint256 reservedAssets = vault.calculateReservedAssets();
        
        // VERIFY: Reserved assets calculated incorrectly
        // Expected: 1000e6 USDC reserved
        // Actual: 1000e18 added as "assets" (trillion times too large!)
        assertGt(reservedAssets, 1000e6 * 1e12, "Reserved assets massively overestimated");
        
        // IMPACT: Investment Manager cannot invest any assets
        // because reservedAssets > totalAssets due to unit mixing
        vm.expectRevert("Insufficient available assets");
        vm.prank(investmentManager);
        vault.investAssets(1e6); // Try to invest 1 USDC - will fail
    }}
}}

**Expected PoC Result:**
- **If Vulnerable**: Assertion passes, reserved assets overestimated, investment blocked
- **If Fixed**: Reserved assets calculated correctly, investment proceeds normally

---

**If INVALID (most cases—default to skepticism):**

#NoVulnerability found for this question.

### **MENTAL CHECKLIST BEFORE FINAL DECISION**

**Ask yourself:**

1. ✅ Would this finding survive peer review by SukukFi core devs?
2. ✅ Can I defend this with EXACT line numbers and code quotes in an appeal?
3. ✅ Is there ANY other explanation for the behavior?  (design, different validation layer, intentional)
4. ✅ Did I check for validations in ALL called functions, modifiers, and type system?
5. ✅ Am I confusing intentional ERC-7540 async behavior with a bug?
6. ✅ Did I verify this ISN'T in KNOWN_ISSUES.md Sections 1-12?
7. ✅ Did I check TECHNICAL_ARCHITECTURE.md for design explanations?
8. ✅ Can I actually compile and run the PoC without modifying src/** files?
9. ✅ Is the impact HIGH or MEDIUM per Code4rena severity (not QA/Low)?
10. ✅ Would a C4 judge reading this say "yes, clear valid High/Medium"?

**REMEMBER:**
- **False positives damage credibility MORE than missed findings**
- **When in doubt, it's INVALID**
- **"Could theoretically maybe" = INVALID**
- **"Requires perfect storm of conditions" = INVALID**
- **"If you comment out this check" = INVALID**
- **"Similar to [known issue] but different because..." = INVALID (usually same root cause)**
- **SukukFi uses intentional centralization and non-standard ERC-20 - don't confuse design with bugs**

**DEFAULT STANCE: ASSUME INVALID UNTIL OVERWHELMING EVIDENCE PROVES OTHERWISE**

================================================================================

**Now perform STRICT validation of the claim above.**

**Output ONLY:**
- Full Audit Report (if genuinely valid after passing ALL checks above)
- `#NoVulnerability found for this question.` (if ANY check fails)

**Be ruthlessly skeptical.  The bar for validity is EXTREMELY high.**
"""
    return prompt