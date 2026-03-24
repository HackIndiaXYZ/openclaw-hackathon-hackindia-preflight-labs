// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

 
 contract LiquidityV2Executor is UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
 receive() external payable {}


 // ── Guarded execution ──────────────────────────────────────────────────────

    /**
     * @notice addLiquidity. LiquidityGuard must hold amountADesired of tokenA
     *         and amountBDesired of tokenB before this call.
     */
    function guardedAddLiquidity(
        address router,
        address user,
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external nonReentrant onlyTrustedCaller
      returns (uint256 amountA, uint256 amountB, uint256 liquidity)
    {
        validateFor(router, tokenA, tokenB, amountADesired, amountBDesired, user);
        require(IERC20(tokenA).balanceOf(address(this)) >= amountADesired, "INSUFFICIENT_TOKEN_A");
        require(IERC20(tokenB).balanceOf(address(this)) >= amountBDesired, "INSUFFICIENT_TOKEN_B");

        IERC20(tokenA).forceApprove(router, amountADesired);
        IERC20(tokenB).forceApprove(router, amountBDesired);

        (amountA, amountB, liquidity) = IUniV2LiqRouter(router).addLiquidity(
            tokenA, tokenB, amountADesired, amountBDesired, amountAMin, amountBMin, to, deadline
        );

        // Refund unused tokens to `to`
        uint256 unusedA = amountADesired - amountA;
        uint256 unusedB = amountBDesired - amountB;
        if (unusedA > 0) IERC20(tokenA).safeTransfer(to, unusedA);
        if (unusedB > 0) IERC20(tokenB).safeTransfer(to, unusedB);
    }

    /**
     * @notice addLiquidityETH. LiquidityGuard must hold amountTokenDesired of token.
     *         ETH is passed via msg.value.
     */
    function guardedAddLiquidityETH(
        address router,
        address user,
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    ) external payable nonReentrant onlyTrustedCaller
      returns (uint256 amountToken, uint256 amountETH, uint256 liquidity)
    {
        address weth = IUniV2LiqRouter(router).WETH();
        validateFor(router, token, weth, amountTokenDesired, msg.value, user);
        require(IERC20(token).balanceOf(address(this)) >= amountTokenDesired, "INSUFFICIENT_TOKEN");
        require(msg.value > 0, "ZERO_ETH");

        IERC20(token).forceApprove(router, amountTokenDesired);

        (amountToken, amountETH, liquidity) = IUniV2LiqRouter(router).addLiquidityETH{value: msg.value}(
            token, amountTokenDesired, amountTokenMin, amountETHMin, to, deadline
        );

        // Refund unused token
        uint256 unusedToken = amountTokenDesired - amountToken;
        if (unusedToken > 0) IERC20(token).safeTransfer(to, unusedToken);
        // Refund unused ETH (router sends back via receive)
        uint256 unusedETH = msg.value - amountETH;
        if (unusedETH > 0) {
            (bool ok,) = payable(to).call{value: unusedETH}("");
            require(ok, "ETH_REFUND_FAILED");
        }
    }

    /**
     * @notice removeLiquidity. LiquidityGuard must hold `liquidity` LP tokens.
     */
    function guardedRemoveLiquidity(
        address router,
        address user,
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external nonReentrant onlyTrustedCaller returns (uint256 amountA, uint256 amountB) {
        validateFor(router, tokenA, tokenB, 0, 0, user);

        address factory = IUniV2LiqRouter(router).factory();
        address pair    = IUniV2Factory(factory).getPair(tokenA, tokenB);
        require(pair != address(0), "PAIR_NOT_EXISTS");
        require(IERC20(pair).balanceOf(address(this)) >= liquidity, "INSUFFICIENT_LP");

        IERC20(pair).forceApprove(router, liquidity);

        (amountA, amountB) = IUniV2LiqRouter(router).removeLiquidity(
            tokenA, tokenB, liquidity, amountAMin, amountBMin, to, deadline
        );
    }

    /**
     * @notice removeLiquidityETH. LiquidityGuard must hold `liquidity` LP tokens.
     */
    function guardedRemoveLiquidityETH(
        address router,
        address user,
        address token,
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    ) external nonReentrant onlyTrustedCaller returns (uint256 amountToken, uint256 amountETH) {
        address weth    = IUniV2LiqRouter(router).WETH();
        validateFor(router, token, weth, 0, 0, user);

        address factory = IUniV2LiqRouter(router).factory();
        address pair    = IUniV2Factory(factory).getPair(token, weth);
        require(pair != address(0), "PAIR_NOT_EXISTS");
        require(IERC20(pair).balanceOf(address(this)) >= liquidity, "INSUFFICIENT_LP");

        IERC20(pair).forceApprove(router, liquidity);

        (amountToken, amountETH) = IUniV2LiqRouter(router).removeLiquidityETH(
            token, liquidity, amountTokenMin, amountETHMin, to, deadline
        );
    }




// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20}    from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IUniswapV2Router,IUniswapV2Factory} from "../interfaces/IUniswapV2Interface.sol";

// Internal imports
import {ILiquidityV2Guard, LiquidityOpType} from "../../interfaces/ILiquidityV2Guard.sol";

/*──────────────────────────────────────────────────────────────────────────────
  LiquidityV2Executor
──────────────────────────────────────────────────────────────────────────────*/

/**
 * @title  LiquidityV2Executor
 * @notice Executes the four Uniswap V2 liquidity operations after the
 *         PreFlightRouter has stored a check fingerprint in LiquidityGuard.
 *
 * ─── Role in the three-phase flow ───────────────────────────────────────────
 *
 *  Phase 1 – LiquidityGuard.checkLiquidity (eth_call, UI display)
 *  Phase 2 – PreFlightRouter.storeLiquidityCheck (stores fingerprint + mints NFT)
 *  Phase 3 – PreFlightRouter calls this contract:
 *               LiquidityV2Executor.guardedAdd*       (ADD / ADD_ETH)
 *               LiquidityV2Executor.guardedRemove*    (REMOVE / REMOVE_ETH)
 *
 * ─── Token custody model ─────────────────────────────────────────────────────
 *
 *  PreFlightRouter transfers all required tokens from the user to THIS contract
 *  BEFORE calling the guarded* functions. Specifically:
 *
 *    ADD          – PreFlightRouter sends amountADesired of tokenA +
 *                   amountBDesired of tokenB to this contract.
 *    ADD_ETH      – PreFlightRouter sends amountTokenDesired of token to this contract
 *                   AND forwards ETH as msg.value.
 *    REMOVE       – PreFlightRouter sends lpAmount of the pair LP token to this contract.
 *    REMOVE_ETH   – PreFlightRouter sends lpAmount of the pair LP token to this contract.
 *
 *  Any unspent tokens (e.g. one side of an ADD) are refunded to `refundRecipient`
 *  (typically the user / PreFlightRouter) at the end of the call.
 *
 * ─── Security properties ─────────────────────────────────────────────────────
 *  • LiquidityGuard.validateCheck reverts if pool state changed since storeCheck
 *    (sandwich / front-run protection).
 *  • forceApprove(0) is called after every router interaction to prevent
 *    lingering allowances.
 *  • ReentrancyGuard prevents re-entrant calls through the router callback.
 */
contract LiquidityV2Executor is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /*──────────────────────────────────────────────────────────────────────────
      Storage
    ──────────────────────────────────────────────────────────────────────────*/

    /**
     * @notice The deployed LiquidityGuard contract.
     *         Called for validateCheck on every execution.
     */
    ILiquidityGuard public liquidityGuard;

    /**
     * @notice Addresses authorised to call guarded* functions.
     *         Should include PreFlightRouter only.
     */
    mapping(address => bool) public authorizedCallers;

    /*──────────────────────────────────────────────────────────────────────────
      Events
    ──────────────────────────────────────────────────────────────────────────*/

    event LiquidityGuardUpdated(address indexed newGuard);
    event AuthorizedCallerSet(address indexed caller, bool authorized);

    event AddLiquidityExecuted(
        address indexed user,
        address indexed tokenA,
        address indexed tokenB,
        uint256 amountADeposited,
        uint256 amountBDeposited,
        uint256 lpTokensMinted
    );
    event AddLiquidityETHExecuted(
        address indexed user,
        address indexed token,
        uint256 tokenDeposited,
        uint256 ethDeposited,
        uint256 lpTokensMinted
    );
    event RemoveLiquidityExecuted(
        address indexed user,
        address indexed tokenA,
        address indexed tokenB,
        uint256 lpTokensBurned,
        uint256 amountAReceived,
        uint256 amountBReceived
    );
    event RemoveLiquidityETHExecuted(
        address indexed user,
        address indexed token,
        uint256 lpTokensBurned,
        uint256 tokenReceived,
        uint256 ethReceived
    );

    /*──────────────────────────────────────────────────────────────────────────
      Access control
    ──────────────────────────────────────────────────────────────────────────*/

    /// @dev Only PreFlightRouter may call guarded execution functions.
    modifier onlyAuthorizedCaller() {
        require(authorizedCallers[msg.sender], "LIQUIDITY_EXECUTOR: NOT_AUTHORIZED_CALLER");
        _;
    }

    /*──────────────────────────────────────────────────────────────────────────
      Initializer
    ──────────────────────────────────────────────────────────────────────────*/

    constructor(address _liquidityGuard) {
        liquidityGuard = ILiquidityGuard(_liquidityGuard);
      }



    /*──────────────────────────────────────────────────────────────────────────
      Guarded execution — ADD LIQUIDITY (token / token)
    ──────────────────────────────────────────────────────────────────────────*/

    /**
     * @notice Execute a guarded addLiquidity call.
     *
     *         Pre-condition: PreFlightRouter has transferred `amountADesired` of
     *         tokenA and `amountBDesired` of tokenB to this contract.
     *
     * @param router           Uniswap V2-compatible router.
     * @param user             Original user whose check is being validated.
     * @param tokenA           First token address.
     * @param tokenB           Second token address.
     * @param amountADesired   Maximum tokenA to deposit (must match storeCheck).
     * @param amountBDesired   Maximum tokenB to deposit (must match storeCheck).
     * @param amountAMin       Slippage floor for tokenA.
     * @param amountBMin       Slippage floor for tokenB.
     * @param lpRecipient      Address that receives the minted LP tokens.
     * @param refundRecipient  Address that receives unspent tokenA / tokenB.
     * @param deadline         Unix timestamp deadline forwarded to the router.
     * @return amountADeposited   Actual tokenA deposited.
     * @return amountBDeposited   Actual tokenB deposited.
     * @return lpTokensMinted     LP tokens sent to lpRecipient.
     */
    function guardedAddLiquidity(
        address router,
        address user,
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address lpRecipient,
        address refundRecipient,
        uint256 deadline
    )
        external
        nonReentrant
        onlyAuthorizedCaller
        returns (uint256 amountADeposited, uint256 amountBDeposited, uint256 lpTokensMinted)
    {
        // Phase 3 validation: reverts if state changed since storeCheck
        liquidityGuard.validateCheck(
            router, tokenA, tokenB, amountADesired, amountBDesired, user, LiquidityOpType.ADD
        );

        require(
            IERC20(tokenA).balanceOf(address(this)) >= amountADesired,
            "LIQUIDITY_EXECUTOR: INSUFFICIENT_TOKEN_A"
        );
        require(
            IERC20(tokenB).balanceOf(address(this)) >= amountBDesired,
            "LIQUIDITY_EXECUTOR: INSUFFICIENT_TOKEN_B"
        );

        IERC20(tokenA).forceApprove(router, amountADesired);
        IERC20(tokenB).forceApprove(router, amountBDesired);

        (amountADeposited, amountBDeposited, lpTokensMinted) =
            IUniV2LiquidityRouter(router).addLiquidity(
                tokenA, tokenB,
                amountADesired, amountBDesired,
                amountAMin, amountBMin,
                lpRecipient,
                deadline
            );

        // Revoke residual router allowances
        IERC20(tokenA).forceApprove(router, 0);
        IERC20(tokenB).forceApprove(router, 0);

        // Refund unspent tokens to refundRecipient (PreFlightRouter forwards to user)
        uint256 unspentA = amountADesired - amountADeposited;
        uint256 unspentB = amountBDesired - amountBDeposited;
        if (unspentA > 0) IERC20(tokenA).safeTransfer(refundRecipient, unspentA);
        if (unspentB > 0) IERC20(tokenB).safeTransfer(refundRecipient, unspentB);

        require(lpTokensMinted > 0, "LIQUIDITY_EXECUTOR: ZERO_LP_MINTED");

        emit AddLiquidityExecuted(user, tokenA, tokenB, amountADeposited, amountBDeposited, lpTokensMinted);
    }

    /*──────────────────────────────────────────────────────────────────────────
      Guarded execution — ADD LIQUIDITY ETH (token / ETH)
    ──────────────────────────────────────────────────────────────────────────*/

    /**
     * @notice Execute a guarded addLiquidityETH call.
     *
     *         Pre-condition: PreFlightRouter has transferred `amountTokenDesired`
     *         of `token` to this contract AND forwarded ETH as msg.value.
     *
     * @param router                Uniswap V2-compatible router.
     * @param user                  Original user whose check is being validated.
     * @param token                 ERC-20 token address (ETH side is implicit via msg.value).
     * @param amountTokenDesired    Maximum ERC-20 tokens to deposit (must match storeCheck).
     * @param amountTokenMin        Slippage floor for the ERC-20 side.
     * @param amountETHMin          Slippage floor for the ETH side.
     * @param lpRecipient           Address that receives the minted LP tokens.
     * @param refundRecipient       Address that receives unspent token / ETH.
     * @param deadline              Unix timestamp deadline forwarded to the router.
     * @return tokenDeposited   Actual ERC-20 tokens deposited.
     * @return ethDeposited     Actual ETH deposited.
     * @return lpTokensMinted   LP tokens sent to lpRecipient.
     */
    function guardedAddLiquidityETH(
        address router,
        address user,
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address lpRecipient,
        address refundRecipient,
        uint256 deadline
    )
        external
        payable
        nonReentrant
        onlyAuthorizedCaller
        returns (uint256 tokenDeposited, uint256 ethDeposited, uint256 lpTokensMinted)
    {
        require(msg.value > 0, "LIQUIDITY_EXECUTOR: ZERO_ETH");

        // Phase 3 validation (tokenB = address(0) resolves to WETH inside LiquidityGuard)
        liquidityGuard.validateCheck(
            router, token, address(0), amountTokenDesired, msg.value, user, LiquidityOpType.ADD_ETH
        );

        require(
            IERC20(token).balanceOf(address(this)) >= amountTokenDesired,
            "LIQUIDITY_EXECUTOR: INSUFFICIENT_TOKEN"
        );

        IERC20(token).forceApprove(router, amountTokenDesired);

        (tokenDeposited, ethDeposited, lpTokensMinted) =
            IUniV2LiquidityRouter(router).addLiquidityETH{value: msg.value}(
                token,
                amountTokenDesired,
                amountTokenMin,
                amountETHMin,
                lpRecipient,
                deadline
            );

        // Revoke residual token allowance
        IERC20(token).forceApprove(router, 0);

        // Refund unspent ERC-20 to refundRecipient
        uint256 unspentToken = amountTokenDesired - tokenDeposited;
        if (unspentToken > 0) IERC20(token).safeTransfer(refundRecipient, unspentToken);

        // Refund unspent ETH to refundRecipient (router sends ETH excess back via receive())
        uint256 unspentETH = msg.value - ethDeposited;
        if (unspentETH > 0) {
            (bool refundOk,) = payable(refundRecipient).call{value: unspentETH}("");
            require(refundOk, "LIQUIDITY_EXECUTOR: ETH_REFUND_FAILED");
        }

        require(lpTokensMinted > 0, "LIQUIDITY_EXECUTOR: ZERO_LP_MINTED");

        emit AddLiquidityETHExecuted(user, token, tokenDeposited, ethDeposited, lpTokensMinted);
    }

    /*──────────────────────────────────────────────────────────────────────────
      Guarded execution — REMOVE LIQUIDITY (token / token)
    ──────────────────────────────────────────────────────────────────────────*/

    /**
     * @notice Execute a guarded removeLiquidity call.
     *
     *         Pre-condition: PreFlightRouter has transferred `lpAmountToBurn`
     *         of the pair's LP token to this contract.
     *
     * @param router          Uniswap V2-compatible router.
     * @param user            Original user whose check is being validated.
     * @param tokenA          First token of the pair.
     * @param tokenB          Second token of the pair.
     * @param lpAmountToBurn  LP token amount to burn (must match storeCheck amountADesired).
     * @param amountAMin      Slippage floor for tokenA output.
     * @param amountBMin      Slippage floor for tokenB output.
     * @param tokenRecipient  Address that receives tokenA and tokenB.
     * @param deadline        Unix timestamp deadline forwarded to the router.
     * @return amountAReceived  tokenA returned to tokenRecipient.
     * @return amountBReceived  tokenB returned to tokenRecipient.
     */
    function guardedRemoveLiquidity(
        address router,
        address user,
        address tokenA,
        address tokenB,
        uint256 lpAmountToBurn,
        uint256 amountAMin,
        uint256 amountBMin,
        address tokenRecipient,
        uint256 deadline
    )
        external
        nonReentrant
        onlyAuthorizedCaller
        returns (uint256 amountAReceived, uint256 amountBReceived)
    {
        // Phase 3 validation — amountADesired carries lpAmountToBurn for remove ops
        liquidityGuard.validateCheck(
            router, tokenA, tokenB, lpAmountToBurn, 0, user, LiquidityOpType.REMOVE
        );

        // Locate the pair LP token
        address factory  = IUniV2LiquidityRouter(router).factory();
        address pairAddr = IUniV2FactoryMin(factory).getPair(tokenA, tokenB);
        require(pairAddr != address(0), "LIQUIDITY_EXECUTOR: PAIR_NOT_EXISTS");
        require(
            IERC20(pairAddr).balanceOf(address(this)) >= lpAmountToBurn,
            "LIQUIDITY_EXECUTOR: INSUFFICIENT_LP_TOKENS"
        );

        IERC20(pairAddr).forceApprove(router, lpAmountToBurn);

        (amountAReceived, amountBReceived) =
            IUniV2LiquidityRouter(router).removeLiquidity(
                tokenA, tokenB,
                lpAmountToBurn,
                amountAMin, amountBMin,
                tokenRecipient,
                deadline
            );

        // Revoke residual LP allowance
        IERC20(pairAddr).forceApprove(router, 0);

        require(
            amountAReceived > 0 && amountBReceived > 0,
            "LIQUIDITY_EXECUTOR: ZERO_AMOUNTS_RETURNED"
        );

        emit RemoveLiquidityExecuted(user, tokenA, tokenB, lpAmountToBurn, amountAReceived, amountBReceived);
    }

    /*──────────────────────────────────────────────────────────────────────────
      Guarded execution — REMOVE LIQUIDITY ETH (token / ETH)
    ──────────────────────────────────────────────────────────────────────────*/

    /**
     * @notice Execute a guarded removeLiquidityETH call.
     *
     *         Pre-condition: PreFlightRouter has transferred `lpAmountToBurn`
     *         of the pair's LP token to this contract.
     *
     * @param router          Uniswap V2-compatible router.
     * @param user            Original user whose check is being validated.
     * @param token           ERC-20 token of the pair (ETH side is implicit).
     * @param lpAmountToBurn  LP token amount to burn (must match storeCheck amountADesired).
     * @param amountTokenMin  Slippage floor for ERC-20 output.
     * @param amountETHMin    Slippage floor for ETH output.
     * @param tokenRecipient  Address that receives the ERC-20 token and ETH.
     * @param deadline        Unix timestamp deadline forwarded to the router.
     * @return tokenReceived  ERC-20 tokens returned to tokenRecipient.
     * @return ethReceived    ETH returned to tokenRecipient.
     */
    function guardedRemoveLiquidityETH(
        address router,
        address user,
        address token,
        uint256 lpAmountToBurn,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address payable tokenRecipient,
        uint256 deadline
    )
        external
        nonReentrant
        onlyAuthorizedCaller
        returns (uint256 tokenReceived, uint256 ethReceived)
    {
        // Phase 3 validation — tokenB = address(0) resolves to WETH inside LiquidityGuard
        liquidityGuard.validateCheck(
            router, token, address(0), lpAmountToBurn, 0, user, LiquidityOpType.REMOVE_ETH
        );

        address weth     = IUniV2LiquidityRouter(router).WETH();
        address factory  = IUniV2LiquidityRouter(router).factory();
        address pairAddr = IUniV2FactoryMin(factory).getPair(token, weth);
        require(pairAddr != address(0), "LIQUIDITY_EXECUTOR: PAIR_NOT_EXISTS");
        require(
            IERC20(pairAddr).balanceOf(address(this)) >= lpAmountToBurn,
            "LIQUIDITY_EXECUTOR: INSUFFICIENT_LP_TOKENS"
        );

        IERC20(pairAddr).forceApprove(router, lpAmountToBurn);

        // Router sends ETH to THIS contract; we forward it to tokenRecipient below
        (tokenReceived, ethReceived) =
            IUniV2LiquidityRouter(router).removeLiquidityETH(
                token,
                lpAmountToBurn,
                amountTokenMin,
                amountETHMin,
                tokenRecipient,   // ERC-20 goes directly to recipient
                deadline
            );

        // Revoke residual LP allowance
        IERC20(pairAddr).forceApprove(router, 0);

        require(
            tokenReceived > 0 && ethReceived > 0,
            "LIQUIDITY_EXECUTOR: ZERO_AMOUNTS_RETURNED"
        );

        emit RemoveLiquidityETHExecuted(user, token, lpAmountToBurn, tokenReceived, ethReceived);
    }

    /*──────────────────────────────────────────────────────────────────────────
      Admin — owner-only
    ──────────────────────────────────────────────────────────────────────────*/

    /**
     * @notice Update the LiquidityGuard reference (e.g. after an upgrade).
     * @param _newGuard  New LiquidityGuard proxy address.
     */
    function setLiquidityGuard(address _newGuard) external onlyOwner {
        require(_newGuard != address(0), "LIQUIDITY_EXECUTOR: ZERO_ADDRESS");
        liquidityGuard = LiquidityGuard(_newGuard);
        emit LiquidityGuardUpdated(_newGuard);
    }

    /**
     * @notice Grant or revoke the right to call guarded* functions.
     *         Should be set to PreFlightRouter address only.
     * @param caller     Address to configure.
     * @param authorized true = allowed, false = blocked.
     */
    function setAuthorizedCaller(address caller, bool authorized) external onlyOwner {
        require(caller != address(0), "LIQUIDITY_EXECUTOR: ZERO_ADDRESS");
        authorizedCallers[caller] = authorized;
        emit AuthorizedCallerSet(caller, authorized);
    }

    /**
     * @notice Emergency ERC-20 recovery for tokens accidentally stuck here.
     * @param token   Token address to recover.
     * @param to      Recipient address.
     * @param amount  Amount to transfer.
     */
    function rescueERC20(address token, address to, uint256 amount) external onlyOwner {
        require(to != address(0), "LIQUIDITY_EXECUTOR: ZERO_ADDRESS");
        IERC20(token).safeTransfer(to, amount);
    }

    /**
     * @notice Emergency ETH recovery for ETH accidentally stuck here.
     * @param to  Recipient address.
     */
    function rescueETH(address payable to) external onlyOwner {
        require(to != address(0), "LIQUIDITY_EXECUTOR: ZERO_ADDRESS");
        (bool ok,) = to.call{value: address(this).balance}("");
        require(ok, "LIQUIDITY_EXECUTOR: ETH_RESCUE_FAILED");
    }


    /// @dev Needed to receive ETH refunds from the router (ETH operations).
    receive() external payable {}

}



function previewAddLiqudity(bytes offChainData) return (CombinedData){
      LiqdityV2Guard result = liqidityguard.checkLiqidity(..);
      Combined result = riskPolicy.combined(offchainData resut);
      return COmbined 
}

function storeOnCHainCheck(){
    liqisityv2guard.store
}

function addLiqidity(){
    
    (IERC20(tokenA).safeTransferfrom(user,address(this)));
    router.addLiqidty();
    _mint()
}