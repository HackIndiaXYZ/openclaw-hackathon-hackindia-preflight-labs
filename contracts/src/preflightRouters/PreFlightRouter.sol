// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// foundry: optimizer=true optimizer_runs=200 via_ir=true

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC4626}           from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {
    VaultOpType, SwapOpType, LiquidityOpType, OperationType, RiskCategory, OffChainSimResult
} from "./interfaces/IPreFlightTypes.sol";
import {RiskPolicy}    from "./RiskPolicy.sol";
import {RiskReportNFT} from "./RiskReportNFT.sol";

// ─── Minimal guard result structs (mirrored from guard contracts) ─────────────

struct VaultGuardResult {
    bool VAULT_NOT_WHITELISTED; bool VAULT_ZERO_SUPPLY; bool DONATION_ATTACK;
    bool SHARE_INFLATION_RISK;  bool VAULT_BALANCE_MISMATCH; bool EXCHANGE_RATE_ANOMALY;
    bool PREVIEW_REVERT;        bool ZERO_SHARES_OUT;  bool ZERO_ASSETS_OUT;
    bool DUST_SHARES;           bool DUST_ASSETS;      bool EXCEEDS_MAX_DEPOSIT;
    bool EXCEEDS_MAX_REDEEM;    bool PREVIEW_CONVERT_MISMATCH;
    // TokenGuardResult omitted for cross-contract struct compat (packed in flags)
}

struct GuardResultV2 {
    bool ROUTER_NOT_TRUSTED; bool FACTORY_NOT_TRUSTED; bool DEEP_MULTIHOP;
    bool DUPLICATE_TOKEN_IN_PATH; bool POOL_NOT_EXISTS; bool FACTORY_MISMATCH;
    bool ZERO_LIQUIDITY;     bool LOW_LIQUIDITY;   bool LOW_LP_SUPPLY;
    bool POOL_TOO_NEW;       bool SEVERE_IMBALANCE; bool K_INVARIANT_BROKEN;
    bool HIGH_SWAP_IMPACT;   bool FLASHLOAN_RISK;  bool PRICE_MANIPULATED;
}

struct LiquidityGuardResult {
    bool ROUTER_NOT_TRUSTED; bool PAIR_NOT_EXISTS;  bool ZERO_RESERVES;
    bool LOW_RESERVES;       bool SEVERE_IMBALANCE; bool K_INVARIANT_BROKEN;
    bool POOL_TOO_NEW;       bool LOW_LP_SUPPLY;    bool FIRST_DEPOSIT;
    bool ZERO_LP_OUT;        bool ZERO_AMOUNTS_OUT; bool DUST_LP;
}

// ─── Guard interfaces ─────────────────────────────────────────────────────────

interface IVaultGuard {
    function storeCheck(address vault, address user, uint256 amount, VaultOpType op)
        external returns (VaultGuardResult memory result, uint256 primaryPreview, bytes32 checkHash);
    function guardedDeposit(address vault, address user, uint256 amount, address receiver, uint256 minShares)
        external returns (uint256 shares);
    function guardedMint(address vault, address user, uint256 shares, address receiver, uint256 maxAssets)
        external returns (uint256 assetsConsumed);
    function guardedWithdraw(address vault, address user, uint256 assets, address receiver, uint256 maxShares)
        external returns (uint256 sharesBurned);
    function guardedRedeem(address vault, address user, uint256 shares, address receiver, uint256 minAssets)
        external returns (uint256 assets);
}

interface ISwapV2Guard {
    function storeSwapCheckFor(address router, address[] calldata path, uint256 amountIn,
        uint256 amountOutMin, bool isETHIn, address user)
        external returns (GuardResultV2 memory result, bytes32 checkHash);
    function guardedSwapExactTokensForTokens(address router, uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline, address user, bool fot)
        external returns (uint256[] memory);
    function guardedSwapTokensForExactTokens(address router, uint256 amountOut, uint256 amountInMax,
        address[] calldata path, address to, uint256 deadline, address user)
        external returns (uint256[] memory);
    function guardedSwapExactETHForTokens(address router, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline, address user, bool fot)
        external payable returns (uint256[] memory);
    function guardedSwapETHForExactTokens(address router, uint256 amountOut,
        address[] calldata path, address to, uint256 deadline, address user)
        external payable returns (uint256[] memory);
    function guardedSwapExactTokensForETH(address router, uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline, address user, bool fot)
        external returns (uint256[] memory);
    function guardedSwapTokensForExactETH(address router, uint256 amountOut, uint256 amountInMax,
        address[] calldata path, address to, uint256 deadline, address user)
        external returns (uint256[] memory);
}

interface ILiquidityGuard {
    function storeCheck(address router, address tokenA, address tokenB, uint256 amount,
        LiquidityOpType op, address user)
        external returns (LiquidityGuardResult memory result, bytes32 checkHash);
    function guardedAddLiquidity(address router, address tokenA, address tokenB,
        uint256 amountADesired, uint256 amountBDesired, uint256 amountAMin, uint256 amountBMin,
        address to, uint256 deadline, address user)
        external returns (uint256,uint256,uint256);
    function guardedAddLiquidityETH(address router, address token, uint256 amountTokenDesired,
        uint256 amountTokenMin, uint256 amountETHMin, address to, uint256 deadline, address user)
        external payable returns (uint256,uint256,uint256);
    function guardedRemoveLiquidity(address router, address tokenA, address tokenB,
        uint256 lpAmount, uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline, address user)
        external returns (uint256,uint256);
    function guardedRemoveLiquidityETH(address router, address token, uint256 lpAmount,
        uint256 amountTokenMin, uint256 amountETHMin, address to, uint256 deadline, address user)
        external returns (uint256,uint256);
}

// ─── Main contract ────────────────────────────────────────────────────────────

contract PreFlightRouter is UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    IVaultGuard     public vaultGuard;
    ISwapV2Guard    public swapGuard;
    ILiquidityGuard public liqGuard;
    RiskPolicy      public riskPolicy;
    RiskReportNFT   public riskNFT;

    mapping(address => bool) public trustedRouters;

    // ─── Events ───────────────────────────────────────────────────────────────

    event CheckStored(address indexed user, OperationType op, uint256 tokenId, RiskCategory risk);
    event Executed(address indexed user, OperationType op, uint256 indexed nftTokenId);

    // ─── Init ─────────────────────────────────────────────────────────────────

    constructor() { _disableInitializers(); }

    function initialize(
        address _vaultGuard,
        address _swapGuard,
        address _liqGuard,
        address _riskPolicy,
        address _riskNFT
    ) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        require(_vaultGuard != address(0) && _swapGuard  != address(0) &&
                _liqGuard   != address(0) && _riskPolicy != address(0) &&
                _riskNFT    != address(0), "ZERO_ADDRESS");
        vaultGuard = IVaultGuard(_vaultGuard);
        swapGuard  = ISwapV2Guard(_swapGuard);
        liqGuard   = ILiquidityGuard(_liqGuard);
        riskPolicy = RiskPolicy(_riskPolicy);
        riskNFT    = RiskReportNFT(_riskNFT);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    // ═══════════════════════════════════════════════════════════════════════════
    //  VAULT — STORE CHECK (Phase 2)
    //  Frontend passes: amount + op + OffChainSimResult from CRE endpoint
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Store a vault check and mint the PreFlight Risk Report NFT.
     * @param vault      ERC-4626 vault address.
     * @param amount     Assets (DEPOSIT/WITHDRAW) or shares (MINT/REDEEM).
     * @param op         VaultOpType: DEPOSIT | MINT | WITHDRAW | REDEEM.
     * @param offChain   Encoded CRE simulation result from frontend.
     * @return tokenId   NFT token ID — pass to executeVault*.
     */
    function storeVaultCheck(
        address                    vault,
        uint256                    amount,
        VaultOpType                op,
        OffChainSimResult calldata offChain
    ) external nonReentrant returns (uint256 tokenId) {
        require(amount > 0, "ZERO_AMOUNT");

        (VaultGuardResult memory res, uint256 preview, bytes32 checkHash) =
            vaultGuard.storeCheck(vault, msg.sender, amount, op);

        (uint8 crit, uint8 warn) = _countVaultFlags(res, op);
        bool hardBlock = _vaultHardBlock(res, op);
        uint32 packed  = _packVaultFlags(res);

        RiskPolicy.PolicyResult memory policy = riskPolicy.evaluate(
            crit, warn, hardBlock, packed, offChain
        );

        tokenId = _mintNFT(
            _vaultOpType(op), policy, msg.sender, vault, address(0),
            amount, preview, checkHash, packed, policy.offChainFlagsPacked,
            14, crit, warn, policy.infoFlagCount
        );

        emit CheckStored(msg.sender, _vaultOpType(op), tokenId, policy.finalCategory);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  VAULT — EXECUTE (Phase 3)
    //  Caller must have approved THIS contract for required tokens.
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Execute a guarded ERC-4626 deposit. User approves router for asset.
    function executeVaultDeposit(
        address vault, uint256 amount, address receiver, uint256 minShares, uint256 nftTokenId
    ) external nonReentrant returns (uint256 shares) {
        _requireNFT(nftTokenId, msg.sender);
        address asset = IERC4626(vault).asset();
        IERC20(asset).safeTransferFrom(msg.sender, address(vaultGuard), amount);
        shares = vaultGuard.guardedDeposit(vault, msg.sender, amount, receiver, minShares);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.VAULT_DEPOSIT, nftTokenId);
    }

    /// @notice Execute a guarded ERC-4626 mint (exact shares out). User approves router for asset.
    function executeVaultMint(
        address vault, uint256 shares, address receiver, uint256 maxAssets, uint256 nftTokenId
    ) external nonReentrant returns (uint256 assetsConsumed) {
        _requireNFT(nftTokenId, msg.sender);
        address asset   = IERC4626(vault).asset();
        uint256 needed  = IERC4626(vault).previewMint(shares);
        require(needed > 0, "PREVIEW_MINT_ZERO");
        IERC20(asset).safeTransferFrom(msg.sender, address(vaultGuard), needed);
        assetsConsumed = vaultGuard.guardedMint(vault, msg.sender, shares, receiver, maxAssets);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.VAULT_MINT, nftTokenId);
    }

    /// @notice Execute a guarded ERC-4626 withdraw (exact assets out). User approves router for vault shares.
    function executeVaultWithdraw(
        address vault, uint256 assets, address receiver, uint256 maxShares, uint256 nftTokenId
    ) external nonReentrant returns (uint256 sharesBurned) {
        _requireNFT(nftTokenId, msg.sender);
        uint256 needed = IERC4626(vault).previewWithdraw(assets);
        require(needed > 0, "PREVIEW_WITHDRAW_ZERO");
        IERC20(vault).safeTransferFrom(msg.sender, address(vaultGuard), needed);
        sharesBurned = vaultGuard.guardedWithdraw(vault, msg.sender, assets, receiver, maxShares);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.VAULT_WITHDRAW, nftTokenId);
    }

    /// @notice Execute a guarded ERC-4626 redeem (exact shares in). User approves router for vault shares.
    function executeVaultRedeem(
        address vault, uint256 shares, address receiver, uint256 minAssets, uint256 nftTokenId
    ) external nonReentrant returns (uint256 assets) {
        _requireNFT(nftTokenId, msg.sender);
        IERC20(vault).safeTransferFrom(msg.sender, address(vaultGuard), shares);
        assets = vaultGuard.guardedRedeem(vault, msg.sender, shares, receiver, minAssets);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.VAULT_REDEEM, nftTokenId);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  SWAP — STORE CHECK
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @param amountIn     Input amount (0 if this is exact-output variant — pass amountInMax instead).
     * @param amountOutMin Slippage commitment; becomes part of the check key.
     * @param isETHIn      True for swapExactETHForTokens / swapETHForExactTokens.
     */
    function storeSwapCheck(
        address                    router,
        address[] calldata         path,
        uint256                    amountIn,
        uint256                    amountOutMin,
        bool                       isETHIn,
        SwapOpType                 opType,
        OffChainSimResult calldata offChain
    ) external nonReentrant returns (uint256 tokenId) {
        require(path.length >= 2, "PATH_TOO_SHORT");
        require(amountIn > 0 || amountOutMin > 0, "ZERO_AMOUNTS");
        require(trustedRouters[router], "UNTRUSTED_ROUTER");

        (GuardResultV2 memory res, bytes32 checkHash) =
            swapGuard.storeSwapCheckFor(router, path, amountIn, amountOutMin, isETHIn, msg.sender);

        (uint8 crit, uint8 warn) = _countSwapFlags(res);
        bool hardBlock = _swapHardBlock(res);
        uint32 packed  = _packSwapFlags(res);

        RiskPolicy.PolicyResult memory policy = riskPolicy.evaluate(
            crit, warn, hardBlock, packed, offChain
        );

        tokenId = _mintNFT(
            _swapOpType(opType), policy, msg.sender, path[0], router,
            amountIn, 0, checkHash, packed, policy.offChainFlagsPacked,
            15, crit, warn, policy.infoFlagCount
        );

        emit CheckStored(msg.sender, _swapOpType(opType), tokenId, policy.finalCategory);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  SWAP — EXECUTE
    //  User approves THIS router for path[0] (token-in variants).
    //  ETH-in variants: send ETH as msg.value.
    // ═══════════════════════════════════════════════════════════════════════════

    function executeSwapExactTokensForTokens(
        address router, uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline, bool fot, uint256 nftTokenId
    ) external nonReentrant returns (uint256[] memory amounts) {
        _requireNFT(nftTokenId, msg.sender);
        IERC20(path[0]).safeTransferFrom(msg.sender, address(swapGuard), amountIn);
        amounts = swapGuard.guardedSwapExactTokensForTokens(router, amountIn, amountOutMin, path, to, deadline, msg.sender, fot);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.SWAP_EXACT_TOKENS_IN, nftTokenId);
    }

    function executeSwapTokensForExactTokens(
        address router, uint256 amountOut, uint256 amountInMax,
        address[] calldata path, address to, uint256 deadline, uint256 nftTokenId
    ) external nonReentrant returns (uint256[] memory amounts) {
        _requireNFT(nftTokenId, msg.sender);
        IERC20(path[0]).safeTransferFrom(msg.sender, address(swapGuard), amountInMax);
        amounts = swapGuard.guardedSwapTokensForExactTokens(router, amountOut, amountInMax, path, to, deadline, msg.sender);
        // Refund unspent
        if (amounts.length > 0 && amountInMax > amounts[0])
            IERC20(path[0]).safeTransfer(msg.sender, amountInMax - amounts[0]);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.SWAP_EXACT_TOKENS_OUT, nftTokenId);
    }

    function executeSwapExactETHForTokens(
        address router, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline, bool fot, uint256 nftTokenId
    ) external payable nonReentrant returns (uint256[] memory amounts) {
        _requireNFT(nftTokenId, msg.sender);
        require(msg.value > 0, "ZERO_ETH");
        amounts = swapGuard.guardedSwapExactETHForTokens{value: msg.value}(router, amountOutMin, path, to, deadline, msg.sender, fot);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.SWAP_EXACT_ETH_IN, nftTokenId);
    }

    function executeSwapETHForExactTokens(
        address router, uint256 amountOut,
        address[] calldata path, address to, uint256 deadline, uint256 nftTokenId
    ) external payable nonReentrant returns (uint256[] memory amounts) {
        _requireNFT(nftTokenId, msg.sender);
        require(msg.value > 0, "ZERO_ETH");
        amounts = swapGuard.guardedSwapETHForExactTokens{value: msg.value}(router, amountOut, path, to, deadline, msg.sender);
        // Refund excess ETH from swapGuard to user (swapGuard sends excess back to router)
        uint256 bal = address(this).balance;
        if (bal > 0) { (bool ok,) = msg.sender.call{value: bal}(""); require(ok, "ETH_REFUND"); }
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.SWAP_EXACT_ETH_OUT, nftTokenId);
    }

    function executeSwapExactTokensForETH(
        address router, uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline, bool fot, uint256 nftTokenId
    ) external nonReentrant returns (uint256[] memory amounts) {
        _requireNFT(nftTokenId, msg.sender);
        IERC20(path[0]).safeTransferFrom(msg.sender, address(swapGuard), amountIn);
        amounts = swapGuard.guardedSwapExactTokensForETH(router, amountIn, amountOutMin, path, to, deadline, msg.sender, fot);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.SWAP_EXACT_TOKENS_FOR_ETH, nftTokenId);
    }

    function executeSwapTokensForExactETH(
        address router, uint256 amountOut, uint256 amountInMax,
        address[] calldata path, address to, uint256 deadline, uint256 nftTokenId
    ) external nonReentrant returns (uint256[] memory amounts) {
        _requireNFT(nftTokenId, msg.sender);
        IERC20(path[0]).safeTransferFrom(msg.sender, address(swapGuard), amountInMax);
        amounts = swapGuard.guardedSwapTokensForExactETH(router, amountOut, amountInMax, path, to, deadline, msg.sender);
        if (amounts.length > 0 && amountInMax > amounts[0])
            IERC20(path[0]).safeTransfer(msg.sender, amountInMax - amounts[0]);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.SWAP_TOKENS_FOR_EXACT_ETH, nftTokenId);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  LIQUIDITY — STORE CHECK
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @param tokenA   ERC-20 token A (or the ERC-20 side for ETH variants).
     * @param tokenB   ERC-20 token B (address(0) for ETH variants).
     * @param amount   amountADesired (ADD/ADD_ETH) or lpAmount (REMOVE/REMOVE_ETH).
     */
    function storeLiquidityCheck(
        address                    router,
        address                    tokenA,
        address                    tokenB,
        uint256                    amount,
        LiquidityOpType            op,
        OffChainSimResult calldata offChain
    ) external nonReentrant returns (uint256 tokenId) {
        require(amount > 0, "ZERO_AMOUNT");
        require(trustedRouters[router], "UNTRUSTED_ROUTER");

        (LiquidityGuardResult memory res, bytes32 checkHash) =
            liqGuard.storeCheck(router, tokenA, tokenB, amount, op, msg.sender);

        (uint8 crit, uint8 warn) = _countLiqFlags(res);
        bool hardBlock = _liqHardBlock(res);
        uint32 packed  = _packLiqFlags(res);

        RiskPolicy.PolicyResult memory policy = riskPolicy.evaluate(
            crit, warn, hardBlock, packed, offChain
        );

        OperationType ot = _liqOpType(op);
        tokenId = _mintNFT(
            ot, policy, msg.sender, tokenA, router,
            amount, 0, checkHash, packed, policy.offChainFlagsPacked,
            12, crit, warn, policy.infoFlagCount
        );

        emit CheckStored(msg.sender, ot, tokenId, policy.finalCategory);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  LIQUIDITY — EXECUTE
    // ═══════════════════════════════════════════════════════════════════════════

    function executeAddLiquidity(
        address router, address tokenA, address tokenB,
        uint256 amountADesired, uint256 amountBDesired,
        uint256 amountAMin, uint256 amountBMin,
        address to, uint256 deadline, uint256 nftTokenId
    ) external nonReentrant returns (uint256 amtA, uint256 amtB, uint256 lp) {
        _requireNFT(nftTokenId, msg.sender);
        IERC20(tokenA).safeTransferFrom(msg.sender, address(liqGuard), amountADesired);
        IERC20(tokenB).safeTransferFrom(msg.sender, address(liqGuard), amountBDesired);
        (amtA, amtB, lp) = liqGuard.guardedAddLiquidity(
            router, tokenA, tokenB, amountADesired, amountBDesired, amountAMin, amountBMin, to, deadline, msg.sender
        );
        // Refund unspent from liqGuard back to user
        if (amountADesired > amtA) IERC20(tokenA).safeTransfer(msg.sender, amountADesired - amtA);
        if (amountBDesired > amtB) IERC20(tokenB).safeTransfer(msg.sender, amountBDesired - amtB);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.LP_ADD, nftTokenId);
    }

    function executeAddLiquidityETH(
        address router, address token,
        uint256 amountTokenDesired, uint256 amountTokenMin, uint256 amountETHMin,
        address to, uint256 deadline, uint256 nftTokenId
    ) external payable nonReentrant returns (uint256 amtToken, uint256 amtETH, uint256 lp) {
        _requireNFT(nftTokenId, msg.sender);
        require(msg.value > 0, "ZERO_ETH");
        IERC20(token).safeTransferFrom(msg.sender, address(liqGuard), amountTokenDesired);
        (amtToken, amtETH, lp) = liqGuard.guardedAddLiquidityETH{value: msg.value}(
            router, token, amountTokenDesired, amountTokenMin, amountETHMin, to, deadline, msg.sender
        );
        if (amountTokenDesired > amtToken) IERC20(token).safeTransfer(msg.sender, amountTokenDesired - amtToken);
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.LP_ADD_ETH, nftTokenId);
    }

    function executeRemoveLiquidity(
        address router, address tokenA, address tokenB,
        uint256 lpAmount, uint256 amountAMin, uint256 amountBMin,
        address to, uint256 deadline, uint256 nftTokenId
    ) external nonReentrant returns (uint256 amtA, uint256 amtB) {
        _requireNFT(nftTokenId, msg.sender);
        address factory = _routerFactory(router);
        address pair    = _getPair(factory, tokenA, tokenB);
        IERC20(pair).safeTransferFrom(msg.sender, address(liqGuard), lpAmount);
        (amtA, amtB) = liqGuard.guardedRemoveLiquidity(
            router, tokenA, tokenB, lpAmount, amountAMin, amountBMin, to, deadline, msg.sender
        );
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.LP_REMOVE, nftTokenId);
    }

    function executeRemoveLiquidityETH(
        address router, address token,
        uint256 lpAmount, uint256 amountTokenMin, uint256 amountETHMin,
        address to, uint256 deadline, uint256 nftTokenId
    ) external nonReentrant returns (uint256 amtToken, uint256 amtETH) {
        _requireNFT(nftTokenId, msg.sender);
        address weth    = _routerWETH(router);
        address factory = _routerFactory(router);
        address pair    = _getPair(factory, token, weth);
        IERC20(pair).safeTransferFrom(msg.sender, address(liqGuard), lpAmount);
        (amtToken, amtETH) = liqGuard.guardedRemoveLiquidityETH(
            router, token, lpAmount, amountTokenMin, amountETHMin, to, deadline, msg.sender
        );
        riskNFT.consume(nftTokenId);
        emit Executed(msg.sender, OperationType.LP_REMOVE_ETH, nftTokenId);
    }

    receive() external payable {}

    // ═══════════════════════════════════════════════════════════════════════════
    //  INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function _requireNFT(uint256 tokenId, address user) internal view {
        RiskReportNFT.RiskReport memory r = riskNFT.getReport(tokenId);
        require(r.user == user,                                     "NFT: wrong owner");
        require(r.status == RiskReportNFT.Status.PENDING,           "NFT: not pending");
        require(r.blockNumber == block.number,                       "NFT: stale block");
        require(!_policyBlocked(r.riskCategory, r.criticalCount),   "NFT: blocked by policy");
    }

    function _policyBlocked(RiskCategory cat, uint8 critCount) internal pure returns (bool) {
        return cat == RiskCategory.CRITICAL && critCount > 0;
    }

    function _mintNFT(
        OperationType  opType,
        RiskPolicy.PolicyResult memory policy,
        address        user,
        address        target,
        address        router,
        uint256        amount,
        uint256        previewValue,
        bytes32        checkHash,
        uint32         onChainPacked,
        uint32         offChainPacked,
        uint8          totalFlags,
        uint8          crit,
        uint8          warn,
        uint8          info
    ) internal returns (uint256 tokenId) {
        tokenId = riskNFT.mint(user, RiskReportNFT.RiskReport({
            opType:              opType,
            riskCategory:        policy.finalCategory,
            status:              RiskReportNFT.Status.PENDING,
            user:                user,
            target:              target,
            router:              router,
            amount:              amount,
            previewValue:        previewValue,
            blockNumber:         block.number,
            timestamp:           block.timestamp,
            checkHash:           checkHash,
            onChainFlagsPacked:  onChainPacked,
            offChainFlagsPacked: offChainPacked,
            totalOnChainFlags:   totalFlags,
            criticalCount:       crit,
            warningCount:        warn,
            infoCount:           info,
            compositeScore:      policy.compositeScore,
            onChainScore:        policy.onChainScore,
            offChainScore:       policy.offChainScore
        }));
    }

    // ─── Flag packing ─────────────────────────────────────────────────────────

    function _packVaultFlags(VaultGuardResult memory r) internal pure returns (uint32 p) {
        if (r.VAULT_NOT_WHITELISTED)     p |= 1 << 0;
        if (r.VAULT_ZERO_SUPPLY)         p |= 1 << 1;
        if (r.DONATION_ATTACK)           p |= 1 << 2;
        if (r.SHARE_INFLATION_RISK)      p |= 1 << 3;
        if (r.VAULT_BALANCE_MISMATCH)    p |= 1 << 4;
        if (r.EXCHANGE_RATE_ANOMALY)     p |= 1 << 5;
        if (r.PREVIEW_REVERT)            p |= 1 << 6;
        if (r.ZERO_SHARES_OUT)           p |= 1 << 7;
        if (r.ZERO_ASSETS_OUT)           p |= 1 << 8;
        if (r.DUST_SHARES)               p |= 1 << 9;
        if (r.DUST_ASSETS)               p |= 1 << 10;
        if (r.EXCEEDS_MAX_DEPOSIT)       p |= 1 << 11;
        if (r.EXCEEDS_MAX_REDEEM)        p |= 1 << 12;
        if (r.PREVIEW_CONVERT_MISMATCH)  p |= 1 << 13;
    }

    function _packSwapFlags(GuardResultV2 memory r) internal pure returns (uint32 p) {
        if (r.ROUTER_NOT_TRUSTED)      p |= 1 << 0;
        if (r.FACTORY_NOT_TRUSTED)     p |= 1 << 1;
        if (r.DEEP_MULTIHOP)           p |= 1 << 2;
        if (r.DUPLICATE_TOKEN_IN_PATH) p |= 1 << 3;
        if (r.POOL_NOT_EXISTS)         p |= 1 << 4;
        if (r.FACTORY_MISMATCH)        p |= 1 << 5;
        if (r.ZERO_LIQUIDITY)          p |= 1 << 6;
        if (r.LOW_LIQUIDITY)           p |= 1 << 7;
        if (r.LOW_LP_SUPPLY)           p |= 1 << 8;
        if (r.POOL_TOO_NEW)            p |= 1 << 9;
        if (r.SEVERE_IMBALANCE)        p |= 1 << 10;
        if (r.K_INVARIANT_BROKEN)      p |= 1 << 11;
        if (r.HIGH_SWAP_IMPACT)        p |= 1 << 12;
        if (r.FLASHLOAN_RISK)          p |= 1 << 13;
        if (r.PRICE_MANIPULATED)       p |= 1 << 14;
    }

    function _packLiqFlags(LiquidityGuardResult memory r) internal pure returns (uint32 p) {
        if (r.ROUTER_NOT_TRUSTED) p |= 1 << 0;
        if (r.PAIR_NOT_EXISTS)    p |= 1 << 1;
        if (r.ZERO_RESERVES)      p |= 1 << 2;
        if (r.LOW_RESERVES)       p |= 1 << 3;
        if (r.SEVERE_IMBALANCE)   p |= 1 << 4;
        if (r.K_INVARIANT_BROKEN) p |= 1 << 5;
        if (r.POOL_TOO_NEW)       p |= 1 << 6;
        if (r.LOW_LP_SUPPLY)      p |= 1 << 7;
        if (r.FIRST_DEPOSIT)      p |= 1 << 8;
        if (r.ZERO_LP_OUT)        p |= 1 << 9;
        if (r.ZERO_AMOUNTS_OUT)   p |= 1 << 10;
        if (r.DUST_LP)            p |= 1 << 11;
    }

    // ─── Flag counting ────────────────────────────────────────────────────────

    function _countVaultFlags(VaultGuardResult memory r, VaultOpType op)
        internal pure returns (uint8 crit, uint8 warn)
    {
        if (r.DONATION_ATTACK)       crit++;
        if (r.VAULT_BALANCE_MISMATCH)crit++;
        if (r.PREVIEW_REVERT)        crit++;
        bool isDeposit = (op == VaultOpType.DEPOSIT || op == VaultOpType.MINT);
        if (isDeposit) { if (r.ZERO_SHARES_OUT) crit++; if (r.EXCEEDS_MAX_DEPOSIT) crit++; }
        else           { if (r.ZERO_ASSETS_OUT)  crit++; if (r.EXCEEDS_MAX_REDEEM)  crit++; }
        if (r.VAULT_NOT_WHITELISTED) warn++; if (r.VAULT_ZERO_SUPPLY) warn++;
        if (r.SHARE_INFLATION_RISK)  warn++; if (r.EXCHANGE_RATE_ANOMALY) warn++;
        if (r.DUST_SHARES) warn++;           if (r.DUST_ASSETS) warn++;
        if (r.PREVIEW_CONVERT_MISMATCH) warn++;
    }

    function _countSwapFlags(GuardResultV2 memory r) internal pure returns (uint8 crit, uint8 warn) {
        if (r.POOL_NOT_EXISTS)         crit++; if (r.ZERO_LIQUIDITY) crit++;
        if (r.DUPLICATE_TOKEN_IN_PATH) crit++; if (r.K_INVARIANT_BROKEN) crit++;
        if (r.PRICE_MANIPULATED)       crit++;
        if (r.DEEP_MULTIHOP)           warn++; if (r.FACTORY_MISMATCH) warn++;
        if (r.LOW_LIQUIDITY)           warn++; if (r.LOW_LP_SUPPLY) warn++;
        if (r.POOL_TOO_NEW)            warn++; if (r.SEVERE_IMBALANCE) warn++;
        if (r.HIGH_SWAP_IMPACT)        warn++; if (r.FLASHLOAN_RISK) warn++;
    }

    function _countLiqFlags(LiquidityGuardResult memory r) internal pure returns (uint8 crit, uint8 warn) {
        if (r.PAIR_NOT_EXISTS)    crit++; if (r.ZERO_RESERVES) crit++;
        if (r.K_INVARIANT_BROKEN) crit++; if (r.FIRST_DEPOSIT) crit++;
        if (r.ZERO_LP_OUT)        crit++; if (r.ZERO_AMOUNTS_OUT) crit++;
        if (r.LOW_RESERVES)       warn++; if (r.SEVERE_IMBALANCE) warn++;
        if (r.POOL_TOO_NEW)       warn++; if (r.LOW_LP_SUPPLY) warn++;
        if (r.DUST_LP)            warn++;
    }

    // ─── Hard-block checks ────────────────────────────────────────────────────

    function _vaultHardBlock(VaultGuardResult memory r, VaultOpType op) internal pure returns (bool) {
        if (r.DONATION_ATTACK || r.VAULT_BALANCE_MISMATCH || r.PREVIEW_REVERT) return true;
        bool isDeposit = (op == VaultOpType.DEPOSIT || op == VaultOpType.MINT);
        return isDeposit
            ? (r.ZERO_SHARES_OUT || r.EXCEEDS_MAX_DEPOSIT)
            : (r.ZERO_ASSETS_OUT || r.EXCEEDS_MAX_REDEEM);
    }

    function _swapHardBlock(GuardResultV2 memory r) internal pure returns (bool) {
        return r.POOL_NOT_EXISTS || r.ZERO_LIQUIDITY || r.DUPLICATE_TOKEN_IN_PATH
            || r.K_INVARIANT_BROKEN || r.PRICE_MANIPULATED;
    }

    function _liqHardBlock(LiquidityGuardResult memory r) internal pure returns (bool) {
        return r.PAIR_NOT_EXISTS || r.ZERO_RESERVES || r.K_INVARIANT_BROKEN
            || r.FIRST_DEPOSIT || r.ZERO_LP_OUT || r.ZERO_AMOUNTS_OUT;
    }

    // ─── OperationType mappers ────────────────────────────────────────────────

    function _vaultOpType(VaultOpType op) internal pure returns (OperationType) {
        if (op == VaultOpType.DEPOSIT)  return OperationType.VAULT_DEPOSIT;
        if (op == VaultOpType.MINT)     return OperationType.VAULT_MINT;
        if (op == VaultOpType.WITHDRAW) return OperationType.VAULT_WITHDRAW;
        return OperationType.VAULT_REDEEM;
    }

    function _swapOpType(SwapOpType op) internal pure returns (OperationType) {
        if (op == SwapOpType.EXACT_TOKENS_IN)       return OperationType.SWAP_EXACT_TOKENS_IN;
        if (op == SwapOpType.EXACT_TOKENS_OUT)      return OperationType.SWAP_EXACT_TOKENS_OUT;
        if (op == SwapOpType.EXACT_ETH_IN)          return OperationType.SWAP_EXACT_ETH_IN;
        if (op == SwapOpType.EXACT_ETH_OUT)         return OperationType.SWAP_EXACT_ETH_OUT;
        if (op == SwapOpType.EXACT_TOKENS_FOR_ETH)  return OperationType.SWAP_EXACT_TOKENS_FOR_ETH;
        return OperationType.SWAP_TOKENS_FOR_EXACT_ETH;
    }

    function _liqOpType(LiquidityOpType op) internal pure returns (OperationType) {
        if (op == LiquidityOpType.ADD)        return OperationType.LP_ADD;
        if (op == LiquidityOpType.ADD_ETH)    return OperationType.LP_ADD_ETH;
        if (op == LiquidityOpType.REMOVE)     return OperationType.LP_REMOVE;
        return OperationType.LP_REMOVE_ETH;
    }

    // ─── Router interface shims ───────────────────────────────────────────────

    function _routerFactory(address router) internal view returns (address f) {
        (bool ok, bytes memory d) = router.staticcall(abi.encodeWithSignature("factory()"));
        require(ok && d.length >= 32, "ROUTER_NO_FACTORY");
        f = abi.decode(d, (address));
    }

    function _routerWETH(address router) internal view returns (address w) {
        (bool ok, bytes memory d) = router.staticcall(abi.encodeWithSignature("WETH()"));
        require(ok && d.length >= 32, "ROUTER_NO_WETH");
        w = abi.decode(d, (address));
    }

    function _getPair(address factory, address tA, address tB) internal view returns (address pair) {
        (bool ok, bytes memory d) = factory.staticcall(abi.encodeWithSignature("getPair(address,address)", tA, tB));
        require(ok && d.length >= 32, "FACTORY_NO_PAIR");
        pair = abi.decode(d, (address));
        require(pair != address(0), "PAIR_NOT_EXIST");
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function setVaultGuard(address a)    external onlyOwner { require(a!=address(0),"Z"); vaultGuard = IVaultGuard(a); }
    function setSwapGuard(address a)     external onlyOwner { require(a!=address(0),"Z"); swapGuard  = ISwapV2Guard(a); }
    function setLiqGuard(address a)      external onlyOwner { require(a!=address(0),"Z"); liqGuard   = ILiquidityGuard(a); }
    function setRiskPolicy(address a)    external onlyOwner { require(a!=address(0),"Z"); riskPolicy = RiskPolicy(a); }
    function setRiskNFT(address a)       external onlyOwner { require(a!=address(0),"Z"); riskNFT    = RiskReportNFT(a); }

    function setTrustedRouter(address router, bool trusted) external onlyOwner {
        require(router != address(0), "ZERO_ADDRESS");
        trustedRouters[router] = trusted;
    }

    function setTrustedRouters(address[] calldata routers, bool trusted) external onlyOwner {
        for (uint256 i; i < routers.length;) {
            if (routers[i] != address(0)) trustedRouters[routers[i]] = trusted;
            unchecked { ++i; }
        }
    }

    function rescueERC20(address token, address to, uint256 amount) external onlyOwner {
        require(to != address(0), "ZERO_ADDRESS");
        IERC20(token).safeTransfer(to, amount);
    }

    function rescueETH(address payable to) external onlyOwner {
        require(to != address(0), "ZERO_ADDRESS");
        (bool ok,) = to.call{value: address(this).balance}("");
        require(ok, "ETH_RESCUE_FAILED");
    }
}
