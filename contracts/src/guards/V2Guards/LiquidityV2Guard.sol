// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {ITokenGuard, TokenGuardResult} from "../interfaces/ITokenGuard.sol";
import {IUniswapV2Factory, IUniswapV2Pair, IUniswapV2Router} from "../interfaces/IUniswapV2Interfaces.sol";

/**
 * @title  LiquidityGuard
 * @notice Pre-transaction safety guard for Uniswap V2 liquidity operations.
 *         Works for both token/token pairs and ETH pairs (via WETH substitution).
 *
 * @dev Three-phase flow:
 *
 *  Phase 1 – [eth_call, zero gas]
 *      checkLiquidity(router, tokenA, tokenB, amountADesired, amountBDesired, operationType)
 *      Returns a fully-populated LiquidityGuardResult. Inspect flags in the UI.
 *
 *  Phase 2 – [on-chain tx via PreFlightRouter]
 *      storeCheck(router, tokenA, tokenB, amountADesired, amountBDesired, user, operationType)
 *      Records a keccak256 fingerprint of the current pool state for `user`.
 *      Returns the stored result for NFT minting.
 *
 *  Phase 3 – [on-chain tx, SAME BLOCK as Phase 2, via LiquidityV2Executor]
 *      validateCheck(router, tokenA, tokenB, amountADesired, amountBDesired, user, operationType)
 *      Re-runs the check, compares fingerprint. Reverts if state changed.
 *      Hard-block flags are always re-evaluated regardless of stored state.
 */

contract LiquidityGuard is UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    //  Result struct
    /**
     * @dev All flags default to false (safe). true = risk signal.
     */

    struct LiquidityGuardResult {
        bool ROUTER_NOT_TRUSTED;
        bool PAIR_NOT_EXISTS;
        bool ZERO_LIQUIDITY;
        bool LOW_LIQUIDITY; //either raw reserve < MINIMUM_RAW_RESERVE
        bool LOW_LP_SUPPLY; //totalSupply < THRESHOLD_LP_SUPPLY
        bool FIRST_DEPOSITOR_RISK; // totalSupply == 0 — ratio set adversarially
        bool SEVERE_IMBALANCE; // one reserve < 1 % of the other
        bool K_INVARIANT_BROKEN; // current k < kLast (reserve drain)
        bool POOL_TOO_NEW; //pool younger than MIN_POOL_AGE_BLOCKS
        bool AMOUNT_RATIO_DEVIATION; // provided amounts deviate > MAX_RATIO_BPS from pool ratio
        bool HIGH_LP_IMPACT; // deposit exceeds MAX_LP_IMPACT_BPS of pool
        bool FLASHLOAN_RISK;
        bool ZERO_LP_OUT; // ADD: estimated LP mint rounds to 0
        bool ZERO_AMOUNTS_OUT; // REMOVE: estimated token out rounds to 0
        bool DUST_LP; // LP amount below MIN_LP
        TokenGuardResult tokenAResult;
        TokenGuardResult tokenBResult;
    }

    /**
     * @dev Identifies which of the four Uniswap V2 liquidity operations is being checked.
     */

    enum LiquidityOperationType {
        ADD,
        ADD_ETH,
        REMOVE,
        REMOVE_ETH
    }

    uint256 public constant MAX_BPS = 10_000;
    uint256 public constant MINIMUM_RAW_RESERVE = 1_000;
    uint256 public constant THRESHOLD_LP_SUPPLY = 1_000e18;
    uint256 public constant SEVERE_IMBALANCE_BPS = 100;
    uint256 public constant MIN_POOL_AGE_BLOCKS = 300;
    uint256 public constant MAX_RATIO_DEVIATION = 500; // 5% tolerance on amount ratio
    uint256 public constant MAX_LP_IMPACT_BPS = 1_000; // 10% of pool
    uint256 public constant MIN_LP = 1_000;

    ITokenGuard public tokenGuard;
    /// @notice Routers whose factory/pair combination is trusted by this guard.
    mapping(address => bool) public trustedRouters;

    /// @dev user => router => abi.encode(LiquidityGuardResult) stored at check time.
    mapping(address => mapping(address => bytes)) internal storedUserChecksPerRouter;

    /// @notice Addresses allowed to call storeCheck and validateCheck.
    mapping(address => bool) public trustedCallers;

    /// @notice Block number at which each pair address was first observed.
    mapping(address => uint256) public poolFirstSeenBlock;

    /// @dev user => router => block number of last stored check.
    mapping(address => mapping(address => uint256)) public lastCheckBlock;

    event LiquidityCheckPerformed(
        address indexed user, address tokenA, address tokenB, LiquidityOperationType operationType
    );
    event CheckStored(address indexed user, address indexed router, uint256 blockNumber);
    event TrustedRoutersSet(address indexed router, bool status);
    event TrustedCallersAuthorized(address indexed caller, bool authorized);

    modifier onlyTrustedCaller() {
        require(trustedCallers[msg.sender], "NOT_AUTHORIZED_CALLER");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    /**
     * @notice UUPS initializer.
     * @param _tokenGuard Address of the deployed TokenGuard contract.
     */
    function initialize(address _tokenGuard) public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        tokenGuard = ITokenGuard(_tokenGuard);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /**
     * @notice Run all  Core safety checks for a liquidity operation.
     * @param user           the user who is performing the operation.
     * @param router         Uniswap V2-compatible router address.
     * @param tokenA         First token address. Use address(0) for ETH.
     * @param tokenB         Second token address. Use address(0) for ETH.
     * @param amountADesired For ADD/ADD_ETH: desired tokenA amount. For REMOVE: LP amount to burn.
     * @param amountBDesired For ADD: desired tokenB amount. Zero for remove ops.
     * @param operationType  Which of the four liquidity operations to validate.
     * @return result        Fully-populated LiquidityGuardResult. All false = safe.
     */
    function checkLiquidity(
        address user,
        address router,
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        LiquidityOperationType operationType
    ) external returns (LiquidityGuardResult memory result) {
        emit LiquidityCheckPerformed(user, tokenA, tokenB, operationType);
        return _checkLiquidity(router, tokenA, tokenB, amountADesired, amountBDesired, operationType);
    }

    /**
     * @dev Internal check logic shared by checkLiquidity, storeCheck, and validateCheck.
     * @param router         Uniswap V2-compatible router.
     * @param tokenA         First token. address(0) resolves to WETH.
     * @param tokenB         Second token. address(0) resolves to WETH.
     * @param amountADesired ADD: tokenA desired in. REMOVE: LP tokens to burn.
     * @param amountBDesired ADD: tokenB desired in. REMOVE: 0 (unused).
     * @param operationType  Liquidity operation type.
     * @return result        Populated LiquidityGuardResult struct.
     */
    function _checkLiquidity(
        address router,
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        LiquidityOperationType operationType
    ) internal view returns (LiquidityGuardResult memory result) {
        if (!trustedRouters[router]) {
            result.ROUTER_NOT_TRUSTED = true;
        }

        require(tokenA != tokenB, "INVALID_TOKEN_ADDRESS");

        address weth = IUniswapV2Router(router).WETH();
        if (tokenA == address(0)) tokenA = weth;
        if (tokenB == address(0)) tokenB = weth;

        result.tokenAResult = tokenGuard.checkToken(tokenA);
        result.tokenBResult = tokenGuard.checkToken(tokenB);

        address factory = IUniswapV2Router(router).factory();
        address pair = IUniswapV2Factory(factory).getPair(tokenA, tokenB);

        if (pair == address(0)) {
            result.PAIR_NOT_EXISTS = true;
            return result;
        }

        (uint112 token0Reserve, uint112 token1Reserve, uint32 lastBlockTimestamp) = IUniswapV2Pair(pair).getReserves();

        if (token0Reserve == 0 || token1Reserve == 0) {
            result.ZERO_LIQUIDITY = true;
            result.FIRST_DEPOSITOR_RISK = true;
            return result;
        }

        address token0 = IUniswapV2Pair(pair).token0();
        uint256 tokenAdecimal = _safeDecimals(tokenA);
        uint256 tokenBdecimal = _safeDecimals(tokenB);

        // Align reserves to tokenA / tokenB
        (uint256 reserveA, uint256 reserveB) = (tokenA == token0)
            ? (uint256(token0Reserve), uint256(token1Reserve))
            : (uint256(token1Reserve), uint256(token0Reserve));

        // Normalise by decimals
        uint256 rawReserveA = reserveA / (10 ** tokenAdecimal);
        uint256 rawReserveB = reserveB / (10 ** tokenBdecimal);

        uint256 lpTotalSupply = IUniswapV2Pair(pair).totalSupply();

        if (rawReserveA < MINIMUM_RAW_RESERVE || rawReserveB < MINIMUM_RAW_RESERVE) result.LOW_LIQUIDITY = true;
        if (lpTotalSupply < THRESHOLD_LP_SUPPLY) result.LOW_LP_SUPPLY = true;
        if (lpTotalSupply == 0) result.FIRST_DEPOSITOR_RISK = true;

        if (_isSeverelyImbalanced(rawReserveA, rawReserveB)) result.SEVERE_IMBALANCE = true;

        uint256 kLast = IUniswapV2Pair(pair).kLast();
        if (kLast > 0 && uint256(token0Reserve) * uint256(token1Reserve) < kLast) result.K_INVARIANT_BROKEN = true;

        uint256 firstSeen = poolFirstSeenBlock[pair];
        if (firstSeen != 0 && block.number - firstSeen < MIN_POOL_AGE_BLOCKS) result.POOL_TOO_NEW = true;

        if (uint32(block.timestamp) == lastBlockTimestamp) result.FLASHLOAN_RISK = true;

        // Amount ratio deviation vs pool ratio
        if (amountADesired > 0 && amountBDesired > 0 && reserveA > 0 && reserveB > 0) {
            // Pool ratio: B per A (scaled 1e18)
            uint256 poolRatio = (reserveB * 1e18) / reserveA;
            uint256 inputRatio = (amountBDesired * 1e18) / amountADesired;
            uint256 delta = poolRatio > inputRatio ? poolRatio - inputRatio : inputRatio - poolRatio;
            if ((delta * MAX_BPS) / poolRatio > MAX_RATIO_DEVIATION) result.AMOUNT_RATIO_DEVIATION = true;

            // LP impact: does this deposit materially move the pool?
            if ((amountADesired * MAX_BPS) / reserveA > MAX_LP_IMPACT_BPS) result.HIGH_LP_IMPACT = true;
        }

        // Operation-specific checks
        if (operationType == LiquidityOperationType.ADD || operationType == LiquidityOperationType.ADD_ETH) {
            _checkAdd(amountADesired, reserveA, lpTotalSupply, result);
        } else {
            _checkRemove(amountADesired, reserveA, reserveB, lpTotalSupply, result);
        }
    }

    /**
     * @dev Validates add-liquidity specific conditions.
     * @param amountA   Desired tokenA input amount.
     * @param reserveA        Current pool reserveA aligned to tokenA.
     * @param lpSupply  Current LP token total supply.
     * @param result    Result struct mutated in place.
     */
    function _checkAdd(uint256 amountA, uint256 reserveA, uint256 lpSupply, LiquidityGuardResult memory result)
        private
        pure
    {
        if (lpSupply > 0 && reserveA > 0) {
            uint256 lpEst = (amountA * lpSupply) / reserveA;
            if (lpEst == 0) result.ZERO_LP_OUT = true;
            if (lpEst > 0 && lpEst < MIN_LP) result.DUST_LP = true;
        }
    }

    /**
     * @dev Validates remove-liquidity specific conditions.
     * @param lpAmount  LP token amount to burn.
     * @param reserveA        Current pool reserveA aligned to tokenA.
     * @param reserveB        Current pool reserveB aligned to tokenB.
     * @param lpSupply  Current LP token total supply.
     * @param result    Result struct mutated in place.
     */
    function _checkRemove(
        uint256 lpAmount,
        uint256 reserveA,
        uint256 reserveB,
        uint256 lpSupply,
        LiquidityGuardResult memory result
    ) private pure {
        if (lpAmount == 0 || lpAmount < MIN_LP) {
            result.DUST_LP = true;
            return;
        }
        if (lpSupply > 0) {
            uint256 AmountOutA = (lpAmount * reserveA) / lpSupply;
            uint256 AmountOutB = (lpAmount * reserveB) / lpSupply;
            if (AmountOutA == 0 || AmountOutB == 0) result.ZERO_AMOUNTS_OUT = true;
        }
    }

    /**
     * @notice Record the current pool state fingerprint for `user`.
     *         MUST be called in the same block as the Phase 3 execution.
     * @param router         Uniswap V2-compatible router.
     * @param tokenA         First token. address(0) resolves to WETH.
     * @param tokenB         Second token. address(0) resolves to WETH.
     * @param amountADesired ADD: tokenA desired. REMOVE: LP amount.
     * @param amountBDesired ADD: tokenB desired. REMOVE: 0.
     * @param user           Address whose check is being stored.
     * @param operationType             Liquidity operation type.
     * @return result        The LiquidityGuardResult at storage time.
     */
    function storeCheck(
        address router,
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        address user,
        LiquidityOperationType operationType
    ) external nonReentrant onlyTrustedCaller returns (LiquidityGuardResult memory result) {
        result = _checkLiquidity(router, tokenA, tokenB, amountADesired, amountBDesired, operationType);
        storedUserChecksPerRouter[user][router] = abi.encode(result);
        lastCheckBlock[user][router] = block.number;

        emit CheckStored(user, router, block.number);

        return result;
    }

    /**
     * @notice Validate stored fingerprint. Reverts if pool state changed since storeCheck.
     * @param router         Must match value used in storeCheck.
     * @param tokenA         Must match value used in storeCheck.
     * @param tokenB         Must match value used in storeCheck.
     * @param amountADesired Must match value used in storeCheck.
     * @param amountBDesired Must match value used in storeCheck.
     * @param user           Address whose fingerprint is being checked.
     * @param operationType  Must match value used in storeCheck.
     */

    function validateCheck(
        address router,
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        address user,
        LiquidityOperationType operationType
    ) external view {
        require(lastCheckBlock[user][router] == block.number, "STALE_LIQ_CHECK");
        LiquidityGuardResult memory currentResult =
            _checkLiquidity(router, tokenA, tokenB, amountADesired, amountBDesired, operationType);
        bytes32 currentFingerprint = keccak256(abi.encode(currentResult));
        bytes32 storedFingerprint = keccak256(storedUserChecksPerRouter[user][router]);

        require(currentFingerprint == storedFingerprint, "LIQ_STATE_CHANGED");
    }

    /**
     * @notice Returns the stored check result for a given user and router.
     * @param user   The address whose check was stored.
     * @param router The router used at check time.
     * @return currentResult  The decoded LiquidityGuardResult stored for this user/router pair.
     */
    function getStoredCheck(address user, address router)
        external
        view
        returns (LiquidityGuardResult memory currentResult)
    {
        return abi.decode(storedUserChecksPerRouter[user][router], (LiquidityGuardResult));
    }

    /// ADMIN FUNCTION ///
    /**
     * @notice Whitelist or remove a Uniswap V2-compatible router.
     * @param router The router address to configure.
     * @param status true = trusted, false = untrusted.
     */
    function setTrustedRouter(address router, bool status) external onlyOwner {
        trustedRouters[router] = status;
        emit TrustedRoutersSet(router, status);
    }

    /**
     * @notice Grant or revoke call permissions for storeCheck / validateCheck.
     * @param caller     The address to configure.
     * @param authorized true = allowed, false = blocked.
     */
    function setTrustedCaller(address caller, bool authorized) external onlyOwner {
        require(caller != address(0), "ZERO_ADDRESS");
        trustedCallers[caller] = authorized;
        emit TrustedCallersAuthorized(caller, authorized);
    }

    /// INTERNAL HELPER FUNCTIONS ///
    /**
     * @dev Safe decimals read — returns 18 if the token does not implement decimals().
     * @param token The ERC-20 token address to query.
     * @return The token's decimal places, or 18 as a safe default.
     */
    function _safeDecimals(address token) internal view returns (uint256) {
        try IERC20Metadata(token).decimals() returns (uint8 d) {
            return d;
        } catch {
            return 18;
        }
    }

    /**
     * @dev Returns true if one reserve is less than SEVERE_IMBALANCE_BPS percent of the other.
     * @param token0Reserve First normalised reserve value.
     * @param token1Reserve Second normalised reserve value.
     * @return True if the pool is severely imbalanced.
     */
    function _isSeverelyImbalanced(uint256 token0Reserve, uint256 token1Reserve) internal pure returns (bool) {
        // token0Reserve < 1% of token1Reserve  OR  token1Reserve < 1% of token0Reserve
        return token0Reserve * 10_000 < token1Reserve * SEVERE_IMBALANCE_BPS
            || token1Reserve * 10_000 < token0Reserve * SEVERE_IMBALANCE_BPS;
    }
}
