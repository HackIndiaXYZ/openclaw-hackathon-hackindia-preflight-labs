// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/**
 * @title  SwapV2Executor
 * @notice Executes guarded Uniswap V2-compatible swaps.
 *         Calls SwapV2Guard.validateSwapFor() before every execution to ensure
 *         pool state has not changed since the user's storeSwapCheck call.
 *
 *         All token/ETH flow: funds must already reside in this contract (sent
 *         by PreFlightRouter) before any guarded function is called.
 */

interface ISwapV2GuardValidator {
    function validateSwapFor(address router, address[] calldata path, uint256 amountIn, address user) external view;
}

interface IUniV2Router {
    function WETH() external view returns (address);
    function swapExactTokensForTokens(uint256, uint256, address[] calldata, address, uint256)
        external
        returns (uint256[] memory);
    function swapTokensForExactTokens(uint256, uint256, address[] calldata, address, uint256)
        external
        returns (uint256[] memory);
    function swapExactETHForTokens(uint256, address[] calldata, address, uint256)
        external
        payable
        returns (uint256[] memory);
    function swapETHForExactTokens(uint256, address[] calldata, address, uint256)
        external
        payable
        returns (uint256[] memory);
    function swapExactTokensForETH(uint256, uint256, address[] calldata, address, uint256)
        external
        returns (uint256[] memory);
    function swapTokensForExactETH(uint256, uint256, address[] calldata, address, uint256)
        external
        returns (uint256[] memory);
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256,
        uint256,
        address[] calldata,
        address,
        uint256
    ) external;
}

contract SwapV2Executor is UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    ISwapV2GuardValidator public swapGuard;
    mapping(address => bool) public authorizedRouters;

    event RouterAuthorized(address indexed router, bool authorized);
    event GuardSet(address indexed guard);

    modifier onlyAuthRouter() {
        require(authorizedRouters[msg.sender], "NOT_AUTHORIZED_ROUTER");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _swapGuard) public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        require(_swapGuard != address(0), "ZERO_ADDRESS");
        swapGuard = ISwapV2GuardValidator(_swapGuard);
        emit GuardSet(_swapGuard);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    receive() external payable {}

    // ── Internal validate + approve helper ────────────────────────────────────

    function _validate(address router, address user, address[] calldata path, uint256 amountIn) internal view {
        swapGuard.validateSwapFor(router, path, amountIn, user);
    }

    function _approveToken(address token, address spender, uint256 amount) internal {
        IERC20(token).forceApprove(spender, amount);
    }

    // ── (1) swapExactTokensForTokens ──────────────────────────────────────────

    function guardedSwapExactTokensForTokens(
        address router,
        address user,
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external nonReentrant onlyAuthRouter returns (uint256[] memory amounts) {
        _validate(router, user, path, amountIn);
        require(IERC20(path[0]).balanceOf(address(this)) >= amountIn, "INSUFFICIENT_TOKEN_IN");
        _approveToken(path[0], router, amountIn);
        amounts = IUniV2Router(router).swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline);
    }

    // ── (2) swapTokensForExactTokens ──────────────────────────────────────────

    function guardedSwapTokensForExactTokens(
        address router,
        address user,
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external nonReentrant onlyAuthRouter returns (uint256[] memory amounts) {
        _validate(router, user, path, amountInMax);
        require(IERC20(path[0]).balanceOf(address(this)) >= amountInMax, "INSUFFICIENT_TOKEN_IN");
        _approveToken(path[0], router, amountInMax);
        amounts = IUniV2Router(router).swapTokensForExactTokens(amountOut, amountInMax, path, to, deadline);
        // Refund unused tokens to `to`
        uint256 used = amounts[0];
        if (amountInMax > used) {
            IERC20(path[0]).safeTransfer(to, amountInMax - used);
        }
    }

    // ── (3) swapExactETHForTokens ─────────────────────────────────────────────

    function guardedSwapExactETHForTokens(
        address router,
        address user,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable nonReentrant onlyAuthRouter returns (uint256[] memory amounts) {
        uint256 ethIn = msg.value;
        require(ethIn > 0, "ZERO_ETH");
        address weth = IUniV2Router(router).WETH();
        require(path[0] == weth, "PATH_MUST_START_WITH_WETH");
        _validate(router, user, path, ethIn);
        amounts = IUniV2Router(router).swapExactETHForTokens{value: ethIn}(amountOutMin, path, to, deadline);
    }

    // ── (4) swapETHForExactTokens ─────────────────────────────────────────────

    function guardedSwapETHForExactTokens(
        address router,
        address user,
        uint256 amountOut,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable nonReentrant onlyAuthRouter returns (uint256[] memory amounts) {
        uint256 ethMax = msg.value;
        require(ethMax > 0, "ZERO_ETH");
        address weth = IUniV2Router(router).WETH();
        require(path[0] == weth, "PATH_MUST_START_WITH_WETH");
        _validate(router, user, path, ethMax);
        amounts = IUniV2Router(router).swapETHForExactTokens{value: ethMax}(amountOut, path, to, deadline);
        // Refund excess ETH
        uint256 used = amounts[0];
        if (ethMax > used) {
            (bool ok,) = payable(to).call{value: ethMax - used}("");
            require(ok, "ETH_REFUND_FAILED");
        }
    }

    // ── (5) swapExactTokensForETH ─────────────────────────────────────────────

    function guardedSwapExactTokensForETH(
        address router,
        address user,
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external nonReentrant onlyAuthRouter returns (uint256[] memory amounts) {
        address weth = IUniV2Router(router).WETH();
        require(path[path.length - 1] == weth, "PATH_MUST_END_WITH_WETH");
        _validate(router, user, path, amountIn);
        require(IERC20(path[0]).balanceOf(address(this)) >= amountIn, "INSUFFICIENT_TOKEN_IN");
        _approveToken(path[0], router, amountIn);
        amounts = IUniV2Router(router).swapExactTokensForETH(amountIn, amountOutMin, path, to, deadline);
    }

    // ── (6) swapTokensForExactETH ─────────────────────────────────────────────

    function guardedSwapTokensForExactETH(
        address router,
        address user,
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external nonReentrant onlyAuthRouter returns (uint256[] memory amounts) {
        address weth = IUniV2Router(router).WETH();
        require(path[path.length - 1] == weth, "PATH_MUST_END_WITH_WETH");
        _validate(router, user, path, amountInMax);
        require(IERC20(path[0]).balanceOf(address(this)) >= amountInMax, "INSUFFICIENT_TOKEN_IN");
        _approveToken(path[0], router, amountInMax);
        amounts = IUniV2Router(router).swapTokensForExactETH(amountOut, amountInMax, path, to, deadline);
        uint256 used = amounts[0];
        if (amountInMax > used) {
            IERC20(path[0]).safeTransfer(to, amountInMax - used);
        }
    }

    // ── Admin ──────────────────────────────────────────────────────────────────

    function setSwapGuard(address _guard) external onlyOwner {
        require(_guard != address(0), "ZERO_ADDRESS");
        swapGuard = ISwapV2GuardValidator(_guard);
        emit GuardSet(_guard);
    }

    function setAuthorizedRouter(address router, bool authorized) external onlyOwner {
        require(router != address(0), "ZERO_ADDRESS");
        authorizedRouters[router] = authorized;
        emit RouterAuthorized(router, authorized);
    }

    function rescueERC20(address token, address to, uint256 amount) external onlyOwner {
        require(to != address(0), "ZERO_ADDRESS");
        IERC20(token).safeTransfer(to, amount);
    }

    function rescueETH(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0), "ZERO_ADDRESS");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "ETH_RESCUE_FAILED");
    }
}
