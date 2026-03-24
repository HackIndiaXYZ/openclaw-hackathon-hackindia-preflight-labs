/**
 * @dev All flags default to false (safe). True = risk signal.
 *
 *  Confidence levels are documented inline:
 *    [DEFINITE]   — checked via direct on-chain state read, no ambiguity
 *    [HEURISTIC]  — inferred from function existence / known patterns, not 100%
 */
struct TokenGuardResult {
    // ── Contract validity ─────────────────────────────────────────────────
    bool NOT_A_CONTRACT; // [DEFINITE]  address has no code
    bool EMPTY_BYTECODE; // [DEFINITE]  extcodesize == 0 (self-destructed / pre-deploy)
    // ── ERC20 interface ───────────────────────────────────────────────────
    bool DECIMALS_REVERT; // [DEFINITE]  decimals() reverts (non-standard token)
    bool WEIRD_DECIMALS; // [DEFINITE]  decimals == 0 or > 18
    bool HIGH_DECIMALS; // [DEFINITE]  decimals > 18  (overflow risk in math)
    bool TOTAL_SUPPLY_REVERT; // [DEFINITE]  totalSupply() reverts
    bool ZERO_TOTAL_SUPPLY; // [DEFINITE]  totalSupply == 0
    bool VERY_LOW_TOTAL_SUPPLY; // [DEFINITE]  totalSupply < LOW_SUPPLY_THRESHOLD
    bool SYMBOL_REVERT; // [DEFINITE]  symbol() reverts
    bool NAME_REVERT; // [DEFINITE]  name() reverts
    // ── Proxy / upgradeability ────────────────────────────────────────────
    bool IS_EIP1967_PROXY; // [DEFINITE]  EIP-1967 implementation slot is non-zero
    bool IS_EIP1822_PROXY; // [DEFINITE]  EIP-1822 PROXIABLE slot is non-zero
    bool IS_MINIMAL_PROXY; // [DEFINITE]  EIP-1167 clone bytecode prefix detected
    // ── Ownership / admin risk ────────────────────────────────────────────
    bool HAS_OWNER; // [DEFINITE]  owner() returns a non-zero address
    bool OWNERSHIP_RENOUNCED; // [DEFINITE]  owner() returns address(0) explicitly
    bool OWNER_IS_EOA; // [DEFINITE]  owner address has no code (single key risk)
    // ── Pause / freeze ────────────────────────────────────────────────────
    bool IS_PAUSABLE; // [DEFINITE]  paused() function exists
    bool IS_CURRENTLY_PAUSED; // [DEFINITE]  paused() returns true right now
    // ── Blacklist / blocklist ─────────────────────────────────────────────
    bool HAS_BLACKLIST; // [HEURISTIC] blacklisted(address) or isBlacklisted(address)
    bool HAS_BLOCKLIST; // [HEURISTIC] isBlocklisted(address) variant
    // ── Fee-on-transfer ───────────────────────────────────────────────────
    // NOTE: True fee-on-transfer detection requires an actual transfer.
    // These are multi-signal heuristics. High confidence but NOT definitive.
    bool POSSIBLE_FEE_ON_TRANSFER; // [HEURISTIC] fee-related getter functions found
    bool HAS_TRANSFER_FEE_GETTER; // [HEURISTIC] transferFee() / buyFee() / sellFee() found
    bool HAS_TAX_FUNCTION; // [HEURISTIC] _taxFee() / taxRate() / getTax() found
    // ── Rebasing ──────────────────────────────────────────────────────────
    bool POSSIBLE_REBASING; // [HEURISTIC] rebase() / scaledBalanceOf() / gons found
    // ── Supply manipulation risk ──────────────────────────────────────────
    bool HAS_MINT_CAPABILITY; // [HEURISTIC] mint(address,uint256) selector exists in code
    bool HAS_BURN_CAPABILITY; // [HEURISTIC] burn(uint256) or burnFrom() selector found
    // ── Permit / flash-mint ───────────────────────────────────────────────
    bool HAS_PERMIT; // [DEFINITE]  DOMAIN_SEPARATOR() and permit() both callable
    bool HAS_FLASH_MINT; // [HEURISTIC] flashLoan() / flashMint() selector found
}

interface IERC20 {
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function symbol() external view returns (string memory);
    function name() external view returns (string memory);
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
}

interface IOwnable {
    function owner() external view returns (address);
}

interface IPausable {
    function paused() external view returns (bool);
}

interface ITokenGuard {
    function checkToken(address token) external view returns (TokenGuardResult memory r);
}
