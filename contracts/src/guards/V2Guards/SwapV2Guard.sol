// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {
    AutomationCompatibleInterface
} from "@chainlink/contracts/src/v0.8/automation/interfaces/AutomationCompatibleInterface.sol";
import {IUniswapV2Factory, IUniswapV2Pair, IUniswapV2Router} from "../interfaces/IUniswapV2Interfaces.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ITokenGuard, TokenGuardResult} from "../interfaces/ITokenGuard.sol";

/**
 * @title  SwapV2Guard
 * @notice Pre-transaction guard for Uniswap V2-compatible swaps or forked versions .
 *         Provides swapCheckV2 (view simulation), storeSwapCheckFor (fingerprint
 *         storage), and validateSwapFor (state-change detection before execution).
 *         Chainlink Automation keeps TWAP snapshots fresh for price-manipulation detection.
 */
contract SwapV2Guard is UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable, AutomationCompatibleInterface {
    /// @notice Full guard result. All flags default to false (safe).
    /// A true flag signals a risk condition. Callers should decide whether to proceed based on which flags are set and their risk tolerance.
    struct GuardResultV2 {
        bool ROUTER_NOT_TRUSTED; // router not in our trusted list
        bool FACTORY_NOT_TRUSTED; // factory not in our trusted list
        bool DEEP_MULTIHOP; // path length > MAX_PATH_LEN
        bool DUPLICATE_TOKEN_IN_PATH; // same token appears twice (circular route)
        // --- Per-pool flags (true if ANY hop triggered it) ---
        bool POOL_NOT_EXISTS;
        bool FACTORY_MISMATCH; // pool's stored factory != router's factory
        bool ZERO_LIQUIDITY; // either reserve is 0
        bool LOW_LIQUIDITY; // either reserve below MINIMUM_RESERVE
        bool LOW_LP_SUPPLY; // total LP supply below THRESHOLD_LP_SUPPLY
        bool POOL_TOO_NEW; // pool created < MIN_POOL_AGE_BLOCKS ago
        bool SEVERE_IMBALANCE; // one reserve is < SEVERE_IMBALANCE_BPS of the other
        bool K_INVARIANT_BROKEN; // current k < kLast (fee switch off — reserve drained)
        bool HIGH_SWAP_IMPACT; // amountIn would consume > MAX_IMPACT_BPS of reserve
        bool FLASHLOAN_RISK; // reserve was touched in the current block
        bool PRICE_MANIPULATED; // spot deviates from TWAP beyond MAX_DEVIATION_BPS
        // --- Token-level flags (checked for all tokens in the path) ---
        TokenGuardResult[] tokenResult; // result of TokenGuard checks on token
    }

    /// @notice Per-pool TWAP snapshot stored by Chainlink Automation.
    struct PriceSnapshot {
        uint256 cumulative0; // price0CumulativeLast at snapshot time + current-block accrual
        uint256 cumulative1;
        uint32 timestamp; // block.timestamp at snapshot
        uint256 lastBlock; // block.number at snapshot
    }

    /// @CONSTANTS

    /// Minimum reserve (raw units). Below this we flag LOW_LIQUIDITY.
    uint256 public constant MINIMUM_RAW_RESERVE = 1_000;
    /// Minimum LP token total supply.
    uint256 public constant THRESHOLD_LP_SUPPLY = 1_000e18;
    /// Maximum swap price deviation from TWAP (basis points, 500 = 5%).
    uint256 public constant MAX_DEVIATION_BPS = 500;
    /// Minimum TWAP window before we trust it (seconds).
    uint256 public constant MIN_TWAP_WINDOW = 60;
    /// Maximum path length before flagging deep multihop.
    uint256 public constant MAX_PATH_LEN = 4;
    /// Max swap impact as % of the input-side reserve (basis points, 1000 = 10%).
    uint256 public constant MAX_IMPACT_BPS = 1_000;
    /// A pool younger than this many blocks is flagged as risky.
    uint256 public constant MIN_POOL_AGE_BLOCKS = 300; // ~1 hour on mainnet
    /// If one reserve < this fraction of the other (bps), flag SEVERE_IMBALANCE.
    uint256 public constant SEVERE_IMBALANCE_BPS = 100; // 1% — very skewed

    /// @STORAGE

    ITokenGuard public tokenGuard; // Address of the TokenGuard contract for token-level checks.
    address public automationForwarder; // Authorised Chainlink Automation forwarder address.
    mapping(address => PriceSnapshot) public snapshots;
    address[] public trackedPools;

    mapping(address => bool) public trustedRouters;
    mapping(address => bool) public trustedFactories;
    mapping(address => bool) public authorizedPreflightCallers;
    mapping(address => uint256) public poolFirstSeenBlock; // Block number at which a pool was first snapshotted (used as a proxy for pool age when the pair contract itself doesn't store creation block).
    uint256 public snapshotBlockInterval; // How many blocks between Chainlink Automation snapshots.
    /// user => router => bytes
    mapping(address => mapping(address => bytes)) internal storedUserChecksPerRouter;
    mapping(address => mapping(address => uint256)) public lastCheckBlock; // user => router => block number of last stored check (used to prevent replaying old checks)

    /// @EVENTS

    event RouterTrustSet(address indexed router, bool status);
    event FactoryTrustSet(address indexed factory, bool status);
    event PoolTracked(address indexed pool);
    event SnapshotRecorded(address indexed pool, uint256 block_);
    event ForwarderSet(address indexed forwarder);
    event SnapshotBlockIntervalSet(uint256 blocks);
    event PreflightCallerSet(address indexed caller, bool authorized);
    event SwapCheckStored(
        address indexed user, address indexed router, bytes32 pathHash, bytes32 checkHash, uint256 blockNumber
    );
    event SwapCheckPerformed(
        address indexed router, address[] indexed path, uint256 amountIn, GuardResultV2 indexed result
    );

    modifier onlyPreflightCaller() {
        require(authorizedPreflightCallers[msg.sender], "NOT_AUTHORIZED_PREFLIGHT_CALLER");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(uint256 _snapshotBlockInterval, address _tokenGuard) public initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        snapshotBlockInterval = _snapshotBlockInterval == 0 ? 1 : _snapshotBlockInterval;
        tokenGuard = ITokenGuard(_tokenGuard);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    // EXTERNAL VIEW FUNCTION //

    /**
     * @notice Core Pre-transaction swap check function. Called as a static call before submitting a swap.
     *
     * @param router    The Uniswap V2-compatible/forked router to be used.
     * @param path      Token path (e.g. [WETH, USDC] for a single-hop).
     * @param amountIn  The exact input amount for the swap (used for impact check).
     *                  Pass 0 to skip the impact check.
     * @return result   GuardResultV2 flags struct. All false = clean.
     */
    function swapCheckV2(address router, address[] calldata path, uint256 amountIn)
        external
        view
        returns (GuardResultV2 memory result)
    {
        if (!trustedRouters[router]) {
            result.ROUTER_NOT_TRUSTED = true;
        }

        uint256 len = path.length;
        require(len >= 2, "PATH_TOO_SHORT");

        if (len > MAX_PATH_LEN) {
            result.DEEP_MULTIHOP = true;
        }

        if (_hasDuplicateToken(path)) {
            result.DUPLICATE_TOKEN_IN_PATH = true;
        }

        address factory = IUniswapV2Router(router).factory();
        if (!trustedFactories[factory]) {
            result.FACTORY_NOT_TRUSTED = true;
        }

        for (uint256 i = 0; i < len - 1;) {
            address tokenIn = path[i];
            address tokenOut = path[i + 1];

            address pair = IUniswapV2Factory(factory).getPair(tokenIn, tokenOut);

            if (pair == address(0)) {
                result.POOL_NOT_EXISTS = true;
                unchecked {
                    ++i;
                }
                continue;
            }

            // Factory stored inside the pair must match the router's factory.
            if (IUniswapV2Pair(pair).factory() != factory) {
                result.FACTORY_MISMATCH = true;
                unchecked {
                    ++i;
                }
                continue;
            }

            (uint112 r0, uint112 r1, uint32 blockTimestampLast) = IUniswapV2Pair(pair).getReserves();

            if (r0 == 0 || r1 == 0) {
                result.ZERO_LIQUIDITY = true;
                unchecked {
                    ++i;
                }
                continue;
            }

            // this will check the token
            TokenGuardResult memory tokenInResult = tokenGuard.checkToken(tokenIn);
            result.tokenResult.push(tokenInResult);

            if (i == len - 2) {
                // also check the final output token
                TokenGuardResult memory tokenOutResult = tokenGuard.checkToken(tokenOut);
                result.tokenResult.push(tokenOutResult);
            }

            address token0 = IUniswapV2Pair(pair).token0();
            address token1 = IUniswapV2Pair(pair).token1();
            uint256 token0Decimals = IERC20Metadata(token0).decimals();
            uint256 token1Decimals = IERC20Metadata(token1).decimals();
            uint256 RawReserve0 = uint256(r0) / (10 ** token0Decimals);
            uint256 RawReserve1 = uint256(r1) / (10 ** token1Decimals);

            if (RawReserve0 < MINIMUM_RAW_RESERVE || RawReserve1 < MINIMUM_RAW_RESERVE) {
                result.LOW_LIQUIDITY = true;
            }

            if (IUniswapV2Pair(pair).totalSupply() < THRESHOLD_LP_SUPPLY) {
                result.LOW_LP_SUPPLY = true;
            }

            uint256 firstSeen = poolFirstSeenBlock[pair];
            if (firstSeen != 0 && block.number - firstSeen < MIN_POOL_AGE_BLOCKS) {
                result.POOL_TOO_NEW = true;
            }

            if (_isSeverelyImbalanced(RawReserve0, RawReserve1)) {
                result.SEVERE_IMBALANCE = true;
            }

            // If fee switch is off, kLast == 0 so we skip. If it's set and the
            // current k < kLast, the reserves have been drained abnormally.
            uint256 kLast = IUniswapV2Pair(pair).kLast();
            if (kLast > 0) {
                uint256 currentK = uint256(r0) * uint256(r1);
                if (currentK < kLast) {
                    result.K_INVARIANT_BROKEN = true;
                }
            }

            // Using block number: if the pair's last-updated timestamp matches
            // the current block's timestamp exactly, a tx already ran in this block.
            if (uint32(block.timestamp) == blockTimestampLast) {
                result.FLASHLOAN_RISK = true;
            }

            //  Swap impact
            if (amountIn > 0 && i == 0) {
                // Check impact only on the first hop (subsequent hops depend on output).
                address token0 = IUniswapV2Pair(pair).token0();
                uint256 reserveIn = (tokenIn == token0) ? uint256(r0) : uint256(r1);
                if (_isHighImpact(amountIn, reserveIn)) {
                    result.HIGH_SWAP_IMPACT = true;
                }
            }

            if (_isPriceManipulated(pair, tokenIn, r0, r1, blockTimestampLast)) {
                result.PRICE_MANIPULATED = true;
            }

            unchecked {
                ++i;
            }
        }
        emit SwapCheckPerformed(router, path, amountIn, result);
    }

    /**
     * @notice Validate that pool state has not changed since storeSwapCheck.
     *         Called by SwapV2Executor before executing swaps.
     */
    function validateSwapCheck(address router, address[] calldata path, uint256 amountIn, address user) external view {
        require(lastCheckBlock[user][router] == block.number, "STALE_CHECK");
        GuardResultV2 memory currentResult = swapCheckV2(router, path, amountIn);
        bytes32 currentFingerprint = keccak256(abi.encode(currentResult));
        bytes32 storedFingerprint = keccak256(storedUserChecksPerRouter[user][router]);
        require(currentFingerprint == storedFingerprint, "SWAP_STATE_CHANGED");
    }

    function getStoredCheck(address user, address router) external view returns (GuardResultV2) {
        GuardResultV2 memory result = abi.decode(storedUserChecksPerRouter[user][router], (GuardResultV2));
        require(result.tokenResult.length > 0, "NO_STORED_CHECK");
        return result;
    }

    /**
     * @notice Returns the current TWAP for a tracked pool.
     *         Prices are in UQ112x112 format (multiply by 1e18 / 2^112 for decimal).
     * @return twap0UQ TWAP of token0 priced in token1 (UQ112x112)
     * @return twap1UQ TWAP of token1 priced in token0 (UQ112x112)
     * @return windowSeconds Duration of the TWAP window
     */
    function getTWAP(address pair) external view returns (uint256 twap0UQ, uint256 twap1UQ, uint32 windowSeconds) {
        PriceSnapshot memory snap = snapshots[pair];
        if (snap.timestamp == 0) return (0, 0, 0);

        uint32 elapsed = uint32(block.timestamp) - snap.timestamp;
        if (elapsed == 0) return (0, 0, 0);

        (uint112 r0, uint112 r1, uint32 blockTimestampLast) = IUniswapV2Pair(pair).getReserves();

        uint32 timeElapsedSinceTrade = uint32(block.timestamp) - blockTimestampLast;
        uint256 price0UQ = r0 > 0 ? (uint256(r1) << 112) / uint256(r0) : 0;
        uint256 price1UQ = r1 > 0 ? (uint256(r0) << 112) / uint256(r1) : 0;

        IUniswapV2Pair p = IUniswapV2Pair(pair);
        uint256 current0 = p.price0CumulativeLast() + price0UQ * timeElapsedSinceTrade;
        uint256 current1 = p.price1CumulativeLast() + price1UQ * timeElapsedSinceTrade;

        twap0UQ = (current0 - snap.cumulative0) / elapsed;
        twap1UQ = (current1 - snap.cumulative1) / elapsed;
        windowSeconds = elapsed;
    }

    /**
     * @notice Chainlink Automation checkUpkeep — identifies pools needing a snapshot.
     */
    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory performData) {
        uint256 total = trackedPools.length;
        address[] memory temp = new address[](total);
        uint256 count;

        for (uint256 i = 0; i < total;) {
            address pool = trackedPools[i];
            if (block.number - snapshots[pool].lastBlock >= snapshotBlockInterval) {
                temp[count] = pool;
                unchecked {
                    ++count;
                }
            }
            unchecked {
                ++i;
            }
        }

        if (count == 0) return (false, "");

        address[] memory pools = new address[](count);
        for (uint256 i = 0; i < count;) {
            pools[i] = temp[i];
            unchecked {
                ++i;
            }
        }

        return (true, abi.encode(pools));
    }

    //-----------------------------------//@STORAGE WRITE FUNCTIONS//-----------------------------------------------//

    /**
     * @notice Chainlink Automation performUpkeep — records snapshots.
     */
    function performUpkeep(bytes calldata data) external override nonReentrant {
        require(msg.sender == automationForwarder || msg.sender == owner(), "UNAUTHORIZED_UPKEEP");

        address[] memory pools = abi.decode(data, (address[]));
        uint256 len = pools.length;

        for (uint256 i = 0; i < len;) {
            address pool = pools[i];
            if (block.number - snapshots[pool].lastBlock >= snapshotBlockInterval) {
                _recordSnapshot(pool);
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Store swap state fingerprint for `user`. Called by PreFlightRouter.
     *         The fingerprint covers pool reserves and TWAP snapshots for all hops.
     */
    function storeSwapCheck(address router, address[] calldata path, uint256 amountIn, address user)
        external
        nonReentrant
        onlyPreflightCaller
        returns (GuardResultV2)
    {
        require(user != address(0), "INVALID_USER");
        require(amountIn > 0, "AMOUNT_IN_IS_ZERO");

        GuardResultV2 memory result = swapCheckV2(router, path, amountIn);
        storedUserChecksPerRouter[user][router] = abi.encode(result);
        lastCheckBlock[user][router] = block.number;

        emit SwapCheckStored(user, router, result, block.number);
        return result;
    }

    //------------------------------// @INTERNAL PURE HELPER FUNCTIONS//-------------------------------------------//

    /**
     * @dev Records a TWAP snapshot with corrected cumulative price (includes
     *      current-block accrual so getFairPrice is always fresh).
     */
    function _recordSnapshot(address pair) internal {
        IUniswapV2Pair p = IUniswapV2Pair(pair);
        (uint112 r0, uint112 r1, uint32 blockTimestampLast) = p.getReserves();

        // Include accrual since last trade
        uint32 timeElapsedSinceTrade = uint32(block.timestamp) - blockTimestampLast;
        uint256 price0UQ = r0 > 0 ? (uint256(r1) << 112) / uint256(r0) : 0;
        uint256 price1UQ = r1 > 0 ? (uint256(r0) << 112) / uint256(r1) : 0;

        snapshots[pair] = PriceSnapshot({
            cumulative0: p.price0CumulativeLast() + price0UQ * timeElapsedSinceTrade,
            cumulative1: p.price1CumulativeLast() + price1UQ * timeElapsedSinceTrade,
            timestamp: uint32(block.timestamp),
            lastBlock: block.number
        });

        emit SnapshotRecorded(pair, block.number);
    }

    /**
     * @dev Detects any duplicate token address in the path (catches circular routes).
     */
    function _hasDuplicateToken(address[] calldata path) internal pure returns (bool) {
        uint256 len = path.length;
        for (uint256 i = 0; i < len;) {
            for (uint256 j = i + 1; j < len;) {
                if (path[i] == path[j]) return true;
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        return false;
    }

    /**
     * @dev True if one reserve is < SEVERE_IMBALANCE_BPS percent of the other.
     */
    function _isSeverelyImbalanced(uint256 r0, uint256 r1) internal pure returns (bool) {
        // r0 < 1% of r1  OR  r1 < 1% of r0
        return r0 * 10_000 < r1 * SEVERE_IMBALANCE_BPS || r1 * 10_000 < r0 * SEVERE_IMBALANCE_BPS;
    }

    /**
     * @dev True if amountIn would consume more than MAX_IMPACT_BPS of reserveIn.
     *      Uses the constant product formula to estimate actual price impact.
     *      amountInWithFee / (reserveIn + amountInWithFee) > MAX_IMPACT_BPS / 10000
     */
    function _isHighImpact(uint256 amountIn, uint256 reserveIn) internal pure returns (bool) {
        if (reserveIn == 0) return true;
        uint256 amountInWithFee = amountIn * 997; // 0.3% V2 fee
        uint256 numerator = amountInWithFee * 10_000;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        uint256 impactBps = numerator / denominator;
        return impactBps >= MAX_IMPACT_BPS;
    }

    /**
     * @dev TWAP deviation check. It returns true if the current spot price deviates from the TWAP by more than
     *     MAX_DEVIATION_BPS. This can indicate price manipulation attempts like sandwich attacks.
     * @param pair The Uniswap V2 pair address.
     * @param tokenIn The input token of the swap (used to determine price direction).
     * @param r0 Current reserve0 from getReserves().
     * @param r1 Current reserve1 from getReserves().
     * @param blockTimestampLast The last update timestamp from getReserves() (used for current cumulative price).
     */
    function _isPriceManipulated(address pair, address tokenIn, uint112 r0, uint112 r1, uint32 blockTimestampLast)
        internal
        view
        returns (bool)
    {
        PriceSnapshot memory snap = snapshots[pair];
        if (snap.lastBlock == 0) return false; // no snapshot yet

        uint32 windowElapsed = uint32(block.timestamp) - snap.timestamp;
        if (windowElapsed < MIN_TWAP_WINDOW) return false; // window too short to trust

        // Reconstruct the current cumulative price including elapsed time in this block.
        // Uniswap stores cumulative as sum(price * dt) where price is UQ112x112.
        uint32 timeElapsedSinceTrade = uint32(block.timestamp) - blockTimestampLast;

        uint256 current0;
        uint256 current1;
        {
            IUniswapV2Pair p = IUniswapV2Pair(pair);
            // price0 = r1/r0 in UQ112x112
            uint256 price0UQ = (uint256(r1) << 112) / uint256(r0);
            uint256 price1UQ = (uint256(r0) << 112) / uint256(r1);
            current0 = p.price0CumulativeLast() + price0UQ * timeElapsedSinceTrade;
            current1 = p.price1CumulativeLast() + price1UQ * timeElapsedSinceTrade;
        }

        // TWAP = delta_cumulative / delta_time ,  result is UQ112x112
        uint256 twap0UQ = (current0 - snap.cumulative0) / windowElapsed;
        uint256 twap1UQ = (current1 - snap.cumulative1) / windowElapsed;

        address token0 = IUniswapV2Pair(pair).token0();
        uint256 spotUQ;
        uint256 twapUQ;

        if (tokenIn == token0) {
            // We want: how much token1 per unit of token0
            spotUQ = (uint256(r1) << 112) / uint256(r0);
            twapUQ = twap0UQ;
        } else {
            // We want: how much token0 per unit of token1
            spotUQ = (uint256(r0) << 112) / uint256(r1);
            twapUQ = twap1UQ;
        }

        if (twapUQ == 0) return false;

        return !_withinDeviation(spotUQ, twapUQ);
    }

    /**
     * @dev Returns true when spot is within MAX_DEVIATION_BPS of twap.
     *      Both values must be in the same unit (UQ112x112).
     */
    function _withinDeviation(uint256 spot, uint256 twap) internal pure returns (bool) {
        uint256 diff = spot > twap ? spot - twap : twap - spot;
        return (diff * 10_000) / twap < MAX_DEVIATION_BPS;
    }

    //--------------------------------------------// @ADMIN FUNCTIONS //---------------------------------------------//

    function addTrackedPool(address pool) external onlyOwner {
        require(pool != address(0), "ZERO_ADDRESS");
        trackedPools.push(pool);

        if (poolFirstSeenBlock[pool] == 0) {
            poolFirstSeenBlock[pool] = block.number;
        }

        _recordSnapshot(pool);
        emit PoolTracked(pool);
    }

    function removeTrackedPool(address pool) external onlyOwner {
        uint256 len = trackedPools.length;
        for (uint256 i = 0; i < len;) {
            if (trackedPools[i] == pool) {
                trackedPools[i] = trackedPools[len - 1];
                trackedPools.pop();
                return;
            }
            unchecked {
                ++i;
            }
        }
        revert("POOL_NOT_TRACKED");
    }

    function setSnapshotBlockInterval(uint256 blocks_) external onlyOwner {
        require(blocks_ > 0, "ZERO_INTERVAL");
        snapshotBlockInterval = blocks_;
        emit SnapshotBlockIntervalSet(blocks_);
    }

    function setTrustedRouter(address router, bool status) external onlyOwner {
        trustedRouters[router] = status;
        emit RouterTrustSet(router, status);
    }

    function setTrustedFactory(address factory, bool status) external onlyOwner {
        trustedFactories[factory] = status;
        emit FactoryTrustSet(factory, status);
    }

    /**
     * @notice Set the Chainlink Automation forwarder address.
     */
    function setAutomationForwarder(address forwarder) external onlyOwner {
        require(forwarder != address(0), "ZERO_ADDRESS");
        automationForwarder = forwarder;
        emit ForwarderSet(forwarder);
    }

    function setPreflightCaller(address caller, bool authorized) external onlyOwner {
        require(caller != address(0), "ZERO_ADDRESS");
        authorizedPreflightCallers[caller] = authorized;
        emit PreflightCallerSet(caller, authorized);
    }

    function trackedPoolsLength() external view returns (uint256) {
        return trackedPools.length;
    }
}
