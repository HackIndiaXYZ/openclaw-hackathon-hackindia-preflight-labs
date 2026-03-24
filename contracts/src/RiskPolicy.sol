// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RiskPolicy
 * @notice Pure stateless policy layer that:
 *         1. packs on-chain guard findings into bitmasks,
 *         2. flattens off-chain simulation findings into a compact generic shape,
 *         3. combines both into a storage-friendly packed report,
 *         4. exposes a decoded rendering-friendly view for later NFT/SVG use.
 *
 * @dev Only this file is touched on purpose so it can become the single place
 *      where policy packing / scoring logic lives.
 */

enum VaultOpType {
    DEPOSIT,
    MINT,
    WITHDRAW,
    REDEEM
}

enum SwapOpType {
    EXACT_TOKENS_IN,
    EXACT_TOKENS_OUT,
    EXACT_ETH_IN,
    EXACT_ETH_OUT,
    EXACT_TOKENS_FOR_ETH,
    TOKENS_FOR_EXACT_ETH
}

enum LiquidityOpType {
    ADD,
    ADD_ETH,
    REMOVE,
    REMOVE_ETH
}

enum OperationType {
    VAULT_DEPOSIT,
    VAULT_MINT,
    VAULT_WITHDRAW,
    VAULT_REDEEM,
    SWAP_EXACT_TOKENS_IN,
    SWAP_EXACT_TOKENS_OUT,
    SWAP_EXACT_ETH_IN,
    SWAP_EXACT_ETH_OUT,
    SWAP_EXACT_TOKENS_FOR_ETH,
    SWAP_TOKENS_FOR_EXACT_ETH,
    LP_ADD,
    LP_ADD_ETH,
    LP_REMOVE,
    LP_REMOVE_ETH
}

enum RiskCategory {
    INFO,
    WARNING,
    MEDIUM,
    CRITICAL
}

struct VaultGuardResult {
    bool VAULT_NOT_WHITELISTED;
    bool VAULT_ZERO_SUPPLY;
    bool DONATION_ATTACK;
    bool SHARE_INFLATION_RISK;
    bool VAULT_BALANCE_MISMATCH;
    bool EXCHANGE_RATE_ANOMALY;
    bool PREVIEW_REVERT;
    bool ZERO_SHARES_OUT;
    bool ZERO_ASSETS_OUT;
    bool DUST_SHARES;
    bool DUST_ASSETS;
    bool EXCEEDS_MAX_DEPOSIT;
    bool EXCEEDS_MAX_REDEEM;
    bool PREVIEW_CONVERT_MISMATCH;
}

struct SwapGuardResult {
    bool ROUTER_NOT_TRUSTED;
    bool FACTORY_NOT_TRUSTED;
    bool DEEP_MULTIHOP;
    bool DUPLICATE_TOKEN_IN_PATH;
    bool POOL_NOT_EXISTS;
    bool FACTORY_MISMATCH;
    bool ZERO_LIQUIDITY;
    bool LOW_LIQUIDITY;
    bool LOW_LP_SUPPLY;
    bool POOL_TOO_NEW;
    bool SEVERE_IMBALANCE;
    bool K_INVARIANT_BROKEN;
    bool HIGH_SWAP_IMPACT;
    bool FLASHLOAN_RISK;
    bool PRICE_MANIPULATED;
}

struct LiquidityGuardResult {
    bool ROUTER_NOT_TRUSTED;
    bool PAIR_NOT_EXISTS;
    bool ZERO_LIQUIDITY;
    bool LOW_LIQUIDITY;
    bool LOW_LP_SUPPLY;
    bool FIRST_DEPOSITOR_RISK;
    bool SEVERE_IMBALANCE;
    bool K_INVARIANT_BROKEN;
    bool POOL_TOO_NEW;
    bool AMOUNT_RATIO_DEVIATION;
    bool HIGH_LP_IMPACT;
    bool FLASHLOAN_RISK;
    bool ZERO_LP_OUT;
    bool ZERO_AMOUNTS_OUT;
    bool DUST_LP;
}

/**
 * @dev Generic flattened off-chain result used by policy scoring.
 *      The detailed CRE structs below can be normalized into this shape.
 */
struct OffChainSimResult {
    bool valid;
    uint8 riskScore;
    bool hasDangerousDelegateCall;
    bool hasSelfDestruct;
    bool hasApprovalDrain;
    bool hasOwnerSweep;
    bool hasReentrancy;
    bool hasUnexpectedCreate;
    bool hasUpgradeCall;
    bool isExitFrozen;
    bool isRemovalFrozen;
    bool isFirstDeposit;
    bool isFeeOnTransfer;
    bool anyOracleStale;
    bool anyContractUnverified;
    bool oracleDeviation;
    bool simulationReverted;
    uint16 priceImpactBps;
    uint16 outputDiscrepancyBps;
    uint16 ratioDeviationBps;
}

// Detailed off-chain shapes mirrored into this file so RiskPolicy can accept
// either a flattened generic result or a more structured CRE result.

struct VaultTraceFindings {
    bool hasDangerousDelegateCall;
    bool hasSelfDestruct;
    bool hasUnexpectedCreate;
    bool hasApprovalDrain;
    bool hasReentrancy;
    bool hasOwnerSweep;
    bool hasUpgradeCall;
}

struct VaultEconomicFindings {
    bool simulationReverted;
    uint256 outputDiscrepancyBps;
    uint256 sharePriceDriftBps;
    uint256 excessPullBps;
    bool isExitFrozen;
    bool assetOracleStale;
}

struct VaultOffChainResult {
    uint256 riskScore;
    VaultTraceFindings trace;
    VaultEconomicFindings economic;
    bool vaultVerified;
    bool assetVerified;
    uint256 simulatedAt;
}

struct SwapTraceFindings {
    bool hasDangerousDelegateCall;
    bool hasSelfDestruct;
    bool hasUnexpectedCreate;
    bool hasApprovalDrain;
    bool hasReentrancy;
}

struct SwapEconomicFindings {
    bool simulationReverted;
    uint256 priceImpactBps;
    bool oracleDeviation;
    bool isFeeOnTransfer;
    bool tokenInOracleStale;
    bool tokenOutOracleStale;
}

struct SwapOffChainResult {
    uint256 riskScore;
    SwapTraceFindings trace;
    SwapEconomicFindings economic;
    bool routerVerified;
    bool tokenInVerified;
    bool tokenOutVerified;
    uint256 simulatedAt;
}

struct LiquidityTraceFindings {
    bool hasDangerousDelegateCall;
    bool hasSelfDestruct;
    bool hasUnexpectedCreate;
    bool hasApprovalDrain;
    bool hasReentrancy;
    bool hasOwnerSweep;
}

struct LiquidityEconomicFindings {
    bool simulationReverted;
    uint256 lpMintDiscrepancyBps;
    bool isFirstDeposit;
    uint256 ratioDeviationBps;
    bool isRemovalFrozen;
    bool tokenAOracleStale;
    bool tokenBOracleStale;
}

struct LiquidityOffChainResult {
    uint256 riskScore;
    LiquidityTraceFindings trace;
    LiquidityEconomicFindings economic;
    bool routerVerified;
    bool pairVerified;
    bool tokenAVerified;
    bool tokenBVerified;
    uint256 simulatedAt;
}

/**
 * @dev Storage-friendly packed report.
 *
 * core layout:
 *   bits   0..3   reportType
 *   bits   4..5   finalCategory
 *   bits   6..12  compositeScore
 *   bits  13..19  onChainScore
 *   bits  20..26  offChainScore
 *   bits  27..31  onChainCriticalCount
 *   bits  32..36  onChainSoftCount
 *   bits  37..41  infoFlagCount
 *   bit      42   anyHardBlock
 *   bit      43   offChainValid
 *   bits  44..45  offChainCategory
 *   bits  46..50  onChainTotalFlags
 *   bits  51..82  onChainFlagsPacked
 *   bits 83..114  offChainFlagsPacked
 *
 * metrics layout:
 *   bits   0..15  priceImpactBps
 *   bits  16..31  outputDiscrepancyBps
 *   bits  32..47  ratioDeviationBps
 *   bits  48..55  rawOffChainRiskScore
 */
struct PackedRiskReport {
    uint256 core;
    uint256 metrics;
}

/**
 * @dev Decoded rendering-friendly view.
 *      This shape intentionally matches the fields that the SVG / NFT side will
 *      want to inspect later, while still being derivable from `PackedRiskReport`.
 */
struct CombinedRiskReport {
    OperationType opType;
    uint8 reportType;
    RiskCategory finalCategory;
    RiskCategory offChainCategory;
    uint8 finalRiskLevel;
    uint8 offChainRiskLevel;
    uint8 finalRiskScore;
    uint8 onChainScore;
    uint8 offChainScore;
    uint8 offChainRiskScore;
    uint8 onChainCriticalCount;
    uint8 onChainSoftCount;
    uint8 onChainTotalFlags;
    uint8 infoFlagCount;
    bool anyHardBlock;
    bool offChainValid;
    uint32 onChainFlagsPacked;
    uint32 offChainFlagsPacked;
    uint16 priceImpactBps;
    uint16 outputDiscrepancyBps;
    uint16 ratioDeviationBps;
    bool hasDangerousDelegateCall;
    bool hasSelfDestruct;
    bool hasApprovalDrain;
    bool hasOwnerSweep;
    bool hasReentrancy;
    bool hasUnexpectedCreate;
    bool hasUpgradeCall;
    bool isExitFrozen;
    bool isRemovalFrozen;
    bool isFirstDeposit;
    bool isFeeOnTransfer;
    bool oracleStale;
    bool contractVerified;
    bool oracleDeviation;
    bool offChainSimReverted;
    address target;
    uint256 amount;
    uint256 blockNumber;
}

contract RiskPolicy {
    struct PolicyResult {
        RiskCategory finalCategory;
        RiskCategory offChainCategory;
        uint8 compositeScore;
        uint8 onChainScore;
        uint8 offChainScore;
        uint8 infoFlagCount;
        uint32 offChainFlagsPacked;
        bool anyHardBlock;
        bool offChainValid;
    }

    uint8 internal constant W_HARD_BLOCK = 40;
    uint8 internal constant W_SOFT_FLAG = 10;
    uint8 internal constant W_OFFCHAIN_BASE_MAX = 30;
    uint8 internal constant W_TRACE = 25;
    uint8 internal constant W_HONEYPOT = 35;
    uint8 internal constant W_FIRST_DEP = 20;
    uint8 internal constant W_PRICE_IMPACT = 15;
    uint8 internal constant W_ORACLE_STALE = 5;
    uint8 internal constant W_UNVERIFIED = 5;

    uint8 internal constant THRESHOLD_CRITICAL = 70;
    uint8 internal constant THRESHOLD_MEDIUM = 40;
    uint8 internal constant THRESHOLD_WARNING = 20;

    uint8 internal constant OFFCHAIN_VALID = 0;
    uint8 internal constant OFFCHAIN_DANGEROUS_DELEGATECALL = 1;
    uint8 internal constant OFFCHAIN_SELFDESTRUCT = 2;
    uint8 internal constant OFFCHAIN_APPROVAL_DRAIN = 3;
    uint8 internal constant OFFCHAIN_OWNER_SWEEP = 4;
    uint8 internal constant OFFCHAIN_REENTRANCY = 5;
    uint8 internal constant OFFCHAIN_UNEXPECTED_CREATE = 6;
    uint8 internal constant OFFCHAIN_UPGRADE_CALL = 7;
    uint8 internal constant OFFCHAIN_EXIT_FROZEN = 8;
    uint8 internal constant OFFCHAIN_REMOVAL_FROZEN = 9;
    uint8 internal constant OFFCHAIN_FIRST_DEPOSIT = 10;
    uint8 internal constant OFFCHAIN_PRICE_IMPACT_HIGH = 11;
    uint8 internal constant OFFCHAIN_OUTPUT_DISCREPANCY_HIGH = 12;
    uint8 internal constant OFFCHAIN_RATIO_DEVIATION_HIGH = 13;
    uint8 internal constant OFFCHAIN_SIMULATION_REVERTED = 14;
    uint8 internal constant OFFCHAIN_FEE_ON_TRANSFER = 15;
    uint8 internal constant OFFCHAIN_ORACLE_STALE = 16;
    uint8 internal constant OFFCHAIN_CONTRACT_UNVERIFIED = 17;
    uint8 internal constant OFFCHAIN_ORACLE_DEVIATION = 18;

    uint8 internal constant CORE_REPORT_TYPE_OFFSET = 0;
    uint8 internal constant CORE_FINAL_CATEGORY_OFFSET = 4;
    uint8 internal constant CORE_COMPOSITE_SCORE_OFFSET = 6;
    uint8 internal constant CORE_ONCHAIN_SCORE_OFFSET = 13;
    uint8 internal constant CORE_OFFCHAIN_SCORE_OFFSET = 20;
    uint8 internal constant CORE_CRIT_COUNT_OFFSET = 27;
    uint8 internal constant CORE_SOFT_COUNT_OFFSET = 32;
    uint8 internal constant CORE_INFO_COUNT_OFFSET = 37;
    uint8 internal constant CORE_ANY_HARD_BLOCK_OFFSET = 42;
    uint8 internal constant CORE_OFFCHAIN_VALID_OFFSET = 43;
    uint8 internal constant CORE_OFFCHAIN_CATEGORY_OFFSET = 44;
    uint8 internal constant CORE_ONCHAIN_TOTAL_OFFSET = 46;
    uint8 internal constant CORE_ONCHAIN_FLAGS_OFFSET = 51;
    uint8 internal constant CORE_OFFCHAIN_FLAGS_OFFSET = 83;

    uint8 internal constant METRIC_PRICE_IMPACT_OFFSET = 0;
    uint8 internal constant METRIC_OUTPUT_DISCREPANCY_OFFSET = 16;
    uint8 internal constant METRIC_RATIO_DEVIATION_OFFSET = 32;
    uint8 internal constant METRIC_RAW_RISK_SCORE_OFFSET = 48;

    function evaluate(
        uint8 onChainCriticalCount,
        uint8 onChainWarnCount,
        bool anyHardBlock,
        uint32 onChainFlagsPacked,
        OffChainSimResult calldata offChain
    ) external pure returns (PolicyResult memory policy) {
        return _evaluate(onChainCriticalCount, onChainWarnCount, anyHardBlock, onChainFlagsPacked, offChain);
    }

    function buildPackedReport(
        OperationType reportType,
        uint8 onChainCriticalCount,
        uint8 onChainWarnCount,
        bool anyHardBlock,
        uint32 onChainFlagsPacked,
        OffChainSimResult calldata offChain
    ) external pure returns (PackedRiskReport memory packedReport) {
        return _buildPackedReport(
            reportType,
            onChainCriticalCount,
            onChainWarnCount,
            anyHardBlock,
            onChainFlagsPacked,
            offChain
        );
    }

    function evaluateVault(
        VaultGuardResult calldata guardResult,
        OffChainSimResult calldata offChain,
        VaultOpType op
    ) external pure returns (PackedRiskReport memory packedReport) {
        (uint8 crit, uint8 warn, uint32 packed, bool hardBlock) = _packVaultFlags(guardResult, op);
        return _buildPackedReport(_vaultOp(op), crit, warn, hardBlock, packed, offChain);
    }

    function evaluateVaultDetailed(
        VaultGuardResult calldata guardResult,
        VaultOffChainResult calldata offChain,
        VaultOpType op
    ) external pure returns (PackedRiskReport memory packedReport) {
        (uint8 crit, uint8 warn, uint32 packed, bool hardBlock) = _packVaultFlags(guardResult, op);
        return _buildPackedReport(_vaultOp(op), crit, warn, hardBlock, packed, _fromVaultOffChain(offChain));
    }

    function evaluateSwap(
        SwapGuardResult calldata guardResult,
        OffChainSimResult calldata offChain,
        SwapOpType op
    ) external pure returns (PackedRiskReport memory packedReport) {
        (uint8 crit, uint8 warn, uint32 packed, bool hardBlock) = _packSwapFlags(guardResult);
        return _buildPackedReport(_swapOp(op), crit, warn, hardBlock, packed, offChain);
    }

    function evaluateSwapDetailed(
        SwapGuardResult calldata guardResult,
        SwapOffChainResult calldata offChain,
        SwapOpType op
    ) external pure returns (PackedRiskReport memory packedReport) {
        (uint8 crit, uint8 warn, uint32 packed, bool hardBlock) = _packSwapFlags(guardResult);
        return _buildPackedReport(_swapOp(op), crit, warn, hardBlock, packed, _fromSwapOffChain(offChain));
    }

    function evaluateLiquidity(
        LiquidityGuardResult calldata guardResult,
        OffChainSimResult calldata offChain,
        LiquidityOpType op
    ) external pure returns (PackedRiskReport memory packedReport) {
        (uint8 crit, uint8 warn, uint32 packed, bool hardBlock) = _packLiquidityFlags(guardResult);
        return _buildPackedReport(_liqOp(op), crit, warn, hardBlock, packed, offChain);
    }

    function evaluateLiquidityDetailed(
        LiquidityGuardResult calldata guardResult,
        LiquidityOffChainResult calldata offChain,
        LiquidityOpType op
    ) external pure returns (PackedRiskReport memory packedReport) {
        (uint8 crit, uint8 warn, uint32 packed, bool hardBlock) = _packLiquidityFlags(guardResult);
        return _buildPackedReport(_liqOp(op), crit, warn, hardBlock, packed, _fromLiquidityOffChain(offChain));
    }

    function decode(PackedRiskReport calldata packedReport)
        external
        pure
        returns (CombinedRiskReport memory report)
    {
        return _decode(packedReport);
    }

    function packVaultFlags(VaultGuardResult calldata guardResult, VaultOpType op)
        external
        pure
        returns (uint8 criticalCount, uint8 softCount, uint32 packedFlags, bool anyHardBlock)
    {
        return _packVaultFlags(guardResult, op);
    }

    function packSwapFlags(SwapGuardResult calldata guardResult)
        external
        pure
        returns (uint8 criticalCount, uint8 softCount, uint32 packedFlags, bool anyHardBlock)
    {
        return _packSwapFlags(guardResult);
    }

    function packLiquidityFlags(LiquidityGuardResult calldata guardResult)
        external
        pure
        returns (uint8 criticalCount, uint8 softCount, uint32 packedFlags, bool anyHardBlock)
    {
        return _packLiquidityFlags(guardResult);
    }

    function packOffChainFlags(OffChainSimResult calldata offChain)
        external
        pure
        returns (uint32 packedFlags, uint8 infoFlagCount)
    {
        packedFlags = _packOffChainFlags(offChain);
        infoFlagCount = _countSetBits32(_clearBit(packedFlags, OFFCHAIN_VALID));
    }

    function normalizeVaultOffChain(VaultOffChainResult calldata offChain)
        external
        pure
        returns (OffChainSimResult memory normalized)
    {
        return _fromVaultOffChain(offChain);
    }

    function normalizeSwapOffChain(SwapOffChainResult calldata offChain)
        external
        pure
        returns (OffChainSimResult memory normalized)
    {
        return _fromSwapOffChain(offChain);
    }

    function normalizeLiquidityOffChain(LiquidityOffChainResult calldata offChain)
        external
        pure
        returns (OffChainSimResult memory normalized)
    {
        return _fromLiquidityOffChain(offChain);
    }

    function _buildPackedReport(
        OperationType reportType,
        uint8 onChainCriticalCount,
        uint8 onChainWarnCount,
        bool anyHardBlock,
        uint32 onChainFlagsPacked,
        OffChainSimResult memory offChain
    ) internal pure returns (PackedRiskReport memory packedReport) {
        PolicyResult memory policy =
            _evaluate(onChainCriticalCount, onChainWarnCount, anyHardBlock, onChainFlagsPacked, offChain);

        uint8 onChainTotalFlags = onChainCriticalCount + onChainWarnCount;
        uint256 core = uint256(uint8(reportType));

        core |= uint256(uint8(policy.finalCategory)) << CORE_FINAL_CATEGORY_OFFSET;
        core |= uint256(policy.compositeScore) << CORE_COMPOSITE_SCORE_OFFSET;
        core |= uint256(policy.onChainScore) << CORE_ONCHAIN_SCORE_OFFSET;
        core |= uint256(policy.offChainScore) << CORE_OFFCHAIN_SCORE_OFFSET;
        core |= uint256(onChainCriticalCount) << CORE_CRIT_COUNT_OFFSET;
        core |= uint256(onChainWarnCount) << CORE_SOFT_COUNT_OFFSET;
        core |= uint256(policy.infoFlagCount) << CORE_INFO_COUNT_OFFSET;
        core |= uint256(uint8(policy.offChainCategory)) << CORE_OFFCHAIN_CATEGORY_OFFSET;
        core |= uint256(onChainTotalFlags) << CORE_ONCHAIN_TOTAL_OFFSET;
        core |= uint256(onChainFlagsPacked) << CORE_ONCHAIN_FLAGS_OFFSET;
        core |= uint256(policy.offChainFlagsPacked) << CORE_OFFCHAIN_FLAGS_OFFSET;

        if (policy.anyHardBlock) {
            core |= uint256(1) << CORE_ANY_HARD_BLOCK_OFFSET;
        }
        if (policy.offChainValid) {
            core |= uint256(1) << CORE_OFFCHAIN_VALID_OFFSET;
        }

        uint256 metrics = uint256(offChain.priceImpactBps);
        metrics |= uint256(offChain.outputDiscrepancyBps) << METRIC_OUTPUT_DISCREPANCY_OFFSET;
        metrics |= uint256(offChain.ratioDeviationBps) << METRIC_RATIO_DEVIATION_OFFSET;
        metrics |= uint256(offChain.riskScore) << METRIC_RAW_RISK_SCORE_OFFSET;

        packedReport.core = core;
        packedReport.metrics = metrics;
    }

    function _evaluate(
        uint8 onChainCriticalCount,
        uint8 onChainWarnCount,
        bool anyHardBlock,
        uint32, /* onChainFlagsPacked */
        OffChainSimResult memory offChain
    ) internal pure returns (PolicyResult memory policy) {
        uint32 offChainFlagsPacked = _packOffChainFlags(offChain);
        uint8 offChainFlagsCount = _countSetBits32(_clearBit(offChainFlagsPacked, OFFCHAIN_VALID));

        bool traceAnomaly = offChain.valid
            && (
                offChain.hasDangerousDelegateCall
                    || offChain.hasSelfDestruct
                    || offChain.hasApprovalDrain
                    || offChain.hasOwnerSweep
                    || offChain.hasReentrancy
                    || offChain.hasUnexpectedCreate
                    || offChain.hasUpgradeCall
            );
        bool honeypot = offChain.valid && (offChain.isExitFrozen || offChain.isRemovalFrozen);
        bool priceImpactAnomaly = offChain.valid && (offChain.priceImpactBps > 500 || offChain.oracleDeviation);

        uint256 onChainScore = uint256(onChainCriticalCount) * W_HARD_BLOCK;
        onChainScore += uint256(onChainWarnCount) * W_SOFT_FLAG;
        onChainScore = _cap100(onChainScore);

        uint256 composite = onChainScore;
        if (offChain.valid) {
            composite = _cap100(composite + ((uint256(offChain.riskScore) * W_OFFCHAIN_BASE_MAX) / 100));
        }
        if (traceAnomaly) {
            composite = _add(composite, W_TRACE);
        }
        if (honeypot) {
            composite = _add(composite, W_HONEYPOT);
        }
        if (offChain.valid && offChain.isFirstDeposit) {
            composite = _add(composite, W_FIRST_DEP);
        }
        if (priceImpactAnomaly) {
            composite = _add(composite, W_PRICE_IMPACT);
        }
        if (offChain.valid && offChain.anyOracleStale) {
            composite = _add(composite, W_ORACLE_STALE);
        }
        if (offChain.valid && offChain.anyContractUnverified) {
            composite = _add(composite, W_UNVERIFIED);
        }
        if (anyHardBlock) {
            composite = _add(composite, W_HARD_BLOCK);
        }

        policy.finalCategory = _category(
            _toUint8(composite),
            anyHardBlock || traceAnomaly || honeypot
        );
        policy.offChainCategory = offChain.valid ? _category(offChain.riskScore, false) : RiskCategory.INFO;
        policy.compositeScore = _toUint8(composite);
        policy.onChainScore = _toUint8(onChainScore);
        policy.offChainScore = offChain.valid ? offChain.riskScore : 0;
        policy.infoFlagCount = offChainFlagsCount;
        policy.offChainFlagsPacked = offChainFlagsPacked;
        policy.anyHardBlock = anyHardBlock;
        policy.offChainValid = offChain.valid;
    }

    function _packVaultFlags(VaultGuardResult memory g, VaultOpType op)
        internal
        pure
        returns (uint8 criticalCount, uint8 softCount, uint32 packedFlags, bool anyHardBlock)
    {
        bool depositSide = op == VaultOpType.DEPOSIT || op == VaultOpType.MINT;

        if (g.VAULT_NOT_WHITELISTED) {
            softCount++;
            packedFlags |= uint32(1) << 0;
        }
        if (g.VAULT_ZERO_SUPPLY) {
            softCount++;
            packedFlags |= uint32(1) << 1;
        }
        if (g.DONATION_ATTACK) {
            criticalCount++;
            packedFlags |= uint32(1) << 2;
            anyHardBlock = true;
        }
        if (g.SHARE_INFLATION_RISK) {
            softCount++;
            packedFlags |= uint32(1) << 3;
        }
        if (g.VAULT_BALANCE_MISMATCH) {
            criticalCount++;
            packedFlags |= uint32(1) << 4;
            anyHardBlock = true;
        }
        if (g.EXCHANGE_RATE_ANOMALY) {
            softCount++;
            packedFlags |= uint32(1) << 5;
        }
        if (g.PREVIEW_REVERT) {
            criticalCount++;
            packedFlags |= uint32(1) << 6;
            anyHardBlock = true;
        }
        if (g.ZERO_SHARES_OUT) {
            packedFlags |= uint32(1) << 7;
            if (depositSide) {
                criticalCount++;
                anyHardBlock = true;
            } else {
                softCount++;
            }
        }
        if (g.ZERO_ASSETS_OUT) {
            packedFlags |= uint32(1) << 8;
            if (!depositSide) {
                criticalCount++;
                anyHardBlock = true;
            } else {
                softCount++;
            }
        }
        if (g.DUST_SHARES) {
            softCount++;
            packedFlags |= uint32(1) << 9;
        }
        if (g.DUST_ASSETS) {
            softCount++;
            packedFlags |= uint32(1) << 10;
        }
        if (g.EXCEEDS_MAX_DEPOSIT) {
            packedFlags |= uint32(1) << 11;
            if (depositSide) {
                criticalCount++;
                anyHardBlock = true;
            } else {
                softCount++;
            }
        }
        if (g.EXCEEDS_MAX_REDEEM) {
            packedFlags |= uint32(1) << 12;
            if (!depositSide) {
                criticalCount++;
                anyHardBlock = true;
            } else {
                softCount++;
            }
        }
        if (g.PREVIEW_CONVERT_MISMATCH) {
            softCount++;
            packedFlags |= uint32(1) << 13;
        }
    }

    function _packSwapFlags(SwapGuardResult memory g)
        internal
        pure
        returns (uint8 criticalCount, uint8 softCount, uint32 packedFlags, bool anyHardBlock)
    {
        if (g.ROUTER_NOT_TRUSTED) {
            softCount++;
            packedFlags |= uint32(1) << 0;
        }
        if (g.FACTORY_NOT_TRUSTED) {
            softCount++;
            packedFlags |= uint32(1) << 1;
        }
        if (g.DEEP_MULTIHOP) {
            softCount++;
            packedFlags |= uint32(1) << 2;
        }
        if (g.DUPLICATE_TOKEN_IN_PATH) {
            criticalCount++;
            packedFlags |= uint32(1) << 3;
            anyHardBlock = true;
        }
        if (g.POOL_NOT_EXISTS) {
            criticalCount++;
            packedFlags |= uint32(1) << 4;
            anyHardBlock = true;
        }
        if (g.FACTORY_MISMATCH) {
            softCount++;
            packedFlags |= uint32(1) << 5;
        }
        if (g.ZERO_LIQUIDITY) {
            criticalCount++;
            packedFlags |= uint32(1) << 6;
            anyHardBlock = true;
        }
        if (g.LOW_LIQUIDITY) {
            softCount++;
            packedFlags |= uint32(1) << 7;
        }
        if (g.LOW_LP_SUPPLY) {
            softCount++;
            packedFlags |= uint32(1) << 8;
        }
        if (g.POOL_TOO_NEW) {
            softCount++;
            packedFlags |= uint32(1) << 9;
        }
        if (g.SEVERE_IMBALANCE) {
            softCount++;
            packedFlags |= uint32(1) << 10;
        }
        if (g.K_INVARIANT_BROKEN) {
            criticalCount++;
            packedFlags |= uint32(1) << 11;
            anyHardBlock = true;
        }
        if (g.HIGH_SWAP_IMPACT) {
            softCount++;
            packedFlags |= uint32(1) << 12;
        }
        if (g.FLASHLOAN_RISK) {
            softCount++;
            packedFlags |= uint32(1) << 13;
        }
        if (g.PRICE_MANIPULATED) {
            criticalCount++;
            packedFlags |= uint32(1) << 14;
            anyHardBlock = true;
        }
    }

    function _packLiquidityFlags(LiquidityGuardResult memory g)
        internal
        pure
        returns (uint8 criticalCount, uint8 softCount, uint32 packedFlags, bool anyHardBlock)
    {
        if (g.ROUTER_NOT_TRUSTED) {
            softCount++;
            packedFlags |= uint32(1) << 0;
        }
        if (g.PAIR_NOT_EXISTS) {
            criticalCount++;
            packedFlags |= uint32(1) << 1;
            anyHardBlock = true;
        }
        if (g.ZERO_LIQUIDITY) {
            criticalCount++;
            packedFlags |= uint32(1) << 2;
            anyHardBlock = true;
        }
        if (g.LOW_LIQUIDITY) {
            softCount++;
            packedFlags |= uint32(1) << 3;
        }
        if (g.LOW_LP_SUPPLY) {
            softCount++;
            packedFlags |= uint32(1) << 4;
        }
        if (g.FIRST_DEPOSITOR_RISK) {
            criticalCount++;
            packedFlags |= uint32(1) << 5;
            anyHardBlock = true;
        }
        if (g.SEVERE_IMBALANCE) {
            softCount++;
            packedFlags |= uint32(1) << 6;
        }
        if (g.K_INVARIANT_BROKEN) {
            criticalCount++;
            packedFlags |= uint32(1) << 7;
            anyHardBlock = true;
        }
        if (g.POOL_TOO_NEW) {
            softCount++;
            packedFlags |= uint32(1) << 8;
        }
        if (g.AMOUNT_RATIO_DEVIATION) {
            softCount++;
            packedFlags |= uint32(1) << 9;
        }
        if (g.HIGH_LP_IMPACT) {
            softCount++;
            packedFlags |= uint32(1) << 10;
        }
        if (g.FLASHLOAN_RISK) {
            softCount++;
            packedFlags |= uint32(1) << 11;
        }
        if (g.ZERO_LP_OUT) {
            criticalCount++;
            packedFlags |= uint32(1) << 12;
            anyHardBlock = true;
        }
        if (g.ZERO_AMOUNTS_OUT) {
            criticalCount++;
            packedFlags |= uint32(1) << 13;
            anyHardBlock = true;
        }
        if (g.DUST_LP) {
            softCount++;
            packedFlags |= uint32(1) << 14;
        }
    }

    function _packOffChainFlags(OffChainSimResult memory o) internal pure returns (uint32 packedFlags) {
        if (o.valid) {
            packedFlags |= uint32(1) << OFFCHAIN_VALID;
        }
        if (o.hasDangerousDelegateCall) {
            packedFlags |= uint32(1) << OFFCHAIN_DANGEROUS_DELEGATECALL;
        }
        if (o.hasSelfDestruct) {
            packedFlags |= uint32(1) << OFFCHAIN_SELFDESTRUCT;
        }
        if (o.hasApprovalDrain) {
            packedFlags |= uint32(1) << OFFCHAIN_APPROVAL_DRAIN;
        }
        if (o.hasOwnerSweep) {
            packedFlags |= uint32(1) << OFFCHAIN_OWNER_SWEEP;
        }
        if (o.hasReentrancy) {
            packedFlags |= uint32(1) << OFFCHAIN_REENTRANCY;
        }
        if (o.hasUnexpectedCreate) {
            packedFlags |= uint32(1) << OFFCHAIN_UNEXPECTED_CREATE;
        }
        if (o.hasUpgradeCall) {
            packedFlags |= uint32(1) << OFFCHAIN_UPGRADE_CALL;
        }
        if (o.isExitFrozen) {
            packedFlags |= uint32(1) << OFFCHAIN_EXIT_FROZEN;
        }
        if (o.isRemovalFrozen) {
            packedFlags |= uint32(1) << OFFCHAIN_REMOVAL_FROZEN;
        }
        if (o.isFirstDeposit) {
            packedFlags |= uint32(1) << OFFCHAIN_FIRST_DEPOSIT;
        }
        if (o.priceImpactBps > 500) {
            packedFlags |= uint32(1) << OFFCHAIN_PRICE_IMPACT_HIGH;
        }
        if (o.outputDiscrepancyBps > 200) {
            packedFlags |= uint32(1) << OFFCHAIN_OUTPUT_DISCREPANCY_HIGH;
        }
        if (o.ratioDeviationBps > 500) {
            packedFlags |= uint32(1) << OFFCHAIN_RATIO_DEVIATION_HIGH;
        }
        if (o.simulationReverted) {
            packedFlags |= uint32(1) << OFFCHAIN_SIMULATION_REVERTED;
        }
        if (o.isFeeOnTransfer) {
            packedFlags |= uint32(1) << OFFCHAIN_FEE_ON_TRANSFER;
        }
        if (o.anyOracleStale) {
            packedFlags |= uint32(1) << OFFCHAIN_ORACLE_STALE;
        }
        if (o.anyContractUnverified) {
            packedFlags |= uint32(1) << OFFCHAIN_CONTRACT_UNVERIFIED;
        }
        if (o.oracleDeviation) {
            packedFlags |= uint32(1) << OFFCHAIN_ORACLE_DEVIATION;
        }
    }

    function _fromVaultOffChain(VaultOffChainResult memory detailed)
        internal
        pure
        returns (OffChainSimResult memory o)
    {
        o.valid = detailed.simulatedAt != 0;
        o.riskScore = _capUint8(detailed.riskScore);
        o.hasDangerousDelegateCall = detailed.trace.hasDangerousDelegateCall;
        o.hasSelfDestruct = detailed.trace.hasSelfDestruct;
        o.hasApprovalDrain = detailed.trace.hasApprovalDrain;
        o.hasOwnerSweep = detailed.trace.hasOwnerSweep;
        o.hasReentrancy = detailed.trace.hasReentrancy;
        o.hasUnexpectedCreate = detailed.trace.hasUnexpectedCreate;
        o.hasUpgradeCall = detailed.trace.hasUpgradeCall;
        o.isExitFrozen = detailed.economic.isExitFrozen;
        o.isRemovalFrozen = false;
        o.isFirstDeposit = false;
        o.isFeeOnTransfer = false;
        o.anyOracleStale = detailed.economic.assetOracleStale;
        o.anyContractUnverified = !(detailed.vaultVerified && detailed.assetVerified);
        o.oracleDeviation = detailed.economic.sharePriceDriftBps > 500;
        o.simulationReverted = detailed.economic.simulationReverted;
        o.priceImpactBps = 0;
        o.outputDiscrepancyBps = _capUint16(
            _max3(
                detailed.economic.outputDiscrepancyBps,
                detailed.economic.sharePriceDriftBps,
                detailed.economic.excessPullBps
            )
        );
        o.ratioDeviationBps = 0;
    }

    function _fromSwapOffChain(SwapOffChainResult memory detailed)
        internal
        pure
        returns (OffChainSimResult memory o)
    {
        o.valid = detailed.simulatedAt != 0;
        o.riskScore = _capUint8(detailed.riskScore);
        o.hasDangerousDelegateCall = detailed.trace.hasDangerousDelegateCall;
        o.hasSelfDestruct = detailed.trace.hasSelfDestruct;
        o.hasApprovalDrain = detailed.trace.hasApprovalDrain;
        o.hasOwnerSweep = false;
        o.hasReentrancy = detailed.trace.hasReentrancy;
        o.hasUnexpectedCreate = detailed.trace.hasUnexpectedCreate;
        o.hasUpgradeCall = false;
        o.isExitFrozen = false;
        o.isRemovalFrozen = false;
        o.isFirstDeposit = false;
        o.isFeeOnTransfer = detailed.economic.isFeeOnTransfer;
        o.anyOracleStale = detailed.economic.tokenInOracleStale || detailed.economic.tokenOutOracleStale;
        o.anyContractUnverified =
            !(detailed.routerVerified && detailed.tokenInVerified && detailed.tokenOutVerified);
        o.oracleDeviation = detailed.economic.oracleDeviation;
        o.simulationReverted = detailed.economic.simulationReverted;
        o.priceImpactBps = _capUint16(detailed.economic.priceImpactBps);
        o.outputDiscrepancyBps = 0;
        o.ratioDeviationBps = 0;
    }

    function _fromLiquidityOffChain(LiquidityOffChainResult memory detailed)
        internal
        pure
        returns (OffChainSimResult memory o)
    {
        o.valid = detailed.simulatedAt != 0;
        o.riskScore = _capUint8(detailed.riskScore);
        o.hasDangerousDelegateCall = detailed.trace.hasDangerousDelegateCall;
        o.hasSelfDestruct = detailed.trace.hasSelfDestruct;
        o.hasApprovalDrain = detailed.trace.hasApprovalDrain;
        o.hasOwnerSweep = detailed.trace.hasOwnerSweep;
        o.hasReentrancy = detailed.trace.hasReentrancy;
        o.hasUnexpectedCreate = detailed.trace.hasUnexpectedCreate;
        o.hasUpgradeCall = false;
        o.isExitFrozen = false;
        o.isRemovalFrozen = detailed.economic.isRemovalFrozen;
        o.isFirstDeposit = detailed.economic.isFirstDeposit;
        o.isFeeOnTransfer = false;
        o.anyOracleStale = detailed.economic.tokenAOracleStale || detailed.economic.tokenBOracleStale;
        o.anyContractUnverified =
            !(detailed.routerVerified && detailed.pairVerified && detailed.tokenAVerified && detailed.tokenBVerified);
        o.oracleDeviation = detailed.economic.ratioDeviationBps > 500;
        o.simulationReverted = detailed.economic.simulationReverted;
        o.priceImpactBps = 0;
        o.outputDiscrepancyBps = _capUint16(detailed.economic.lpMintDiscrepancyBps);
        o.ratioDeviationBps = _capUint16(detailed.economic.ratioDeviationBps);
    }

    function _decode(PackedRiskReport memory packedReport)
        internal
        pure
        returns (CombinedRiskReport memory report)
    {
        uint256 core = packedReport.core;
        uint256 metrics = packedReport.metrics;

        report.opType = OperationType(_readBits(core, CORE_REPORT_TYPE_OFFSET, 4));
        report.reportType = uint8(report.opType);
        report.finalCategory = RiskCategory(_readBits(core, CORE_FINAL_CATEGORY_OFFSET, 2));
        report.offChainCategory = RiskCategory(_readBits(core, CORE_OFFCHAIN_CATEGORY_OFFSET, 2));
        report.finalRiskLevel = _compressCategory(report.finalCategory);
        report.offChainRiskLevel = _compressCategory(report.offChainCategory);
        report.finalRiskScore = uint8(_readBits(core, CORE_COMPOSITE_SCORE_OFFSET, 7));
        report.onChainScore = uint8(_readBits(core, CORE_ONCHAIN_SCORE_OFFSET, 7));
        report.offChainScore = uint8(_readBits(core, CORE_OFFCHAIN_SCORE_OFFSET, 7));
        report.offChainRiskScore = uint8(_readBits(metrics, METRIC_RAW_RISK_SCORE_OFFSET, 8));
        report.onChainCriticalCount = uint8(_readBits(core, CORE_CRIT_COUNT_OFFSET, 5));
        report.onChainSoftCount = uint8(_readBits(core, CORE_SOFT_COUNT_OFFSET, 5));
        report.infoFlagCount = uint8(_readBits(core, CORE_INFO_COUNT_OFFSET, 5));
        report.anyHardBlock = _readBits(core, CORE_ANY_HARD_BLOCK_OFFSET, 1) == 1;
        report.offChainValid = _readBits(core, CORE_OFFCHAIN_VALID_OFFSET, 1) == 1;
        report.onChainTotalFlags = uint8(_readBits(core, CORE_ONCHAIN_TOTAL_OFFSET, 5));
        report.onChainFlagsPacked = uint32(_readBits(core, CORE_ONCHAIN_FLAGS_OFFSET, 32));
        report.offChainFlagsPacked = uint32(_readBits(core, CORE_OFFCHAIN_FLAGS_OFFSET, 32));
        report.priceImpactBps = uint16(_readBits(metrics, METRIC_PRICE_IMPACT_OFFSET, 16));
        report.outputDiscrepancyBps = uint16(_readBits(metrics, METRIC_OUTPUT_DISCREPANCY_OFFSET, 16));
        report.ratioDeviationBps = uint16(_readBits(metrics, METRIC_RATIO_DEVIATION_OFFSET, 16));

        report.hasDangerousDelegateCall = _flag(report.offChainFlagsPacked, OFFCHAIN_DANGEROUS_DELEGATECALL);
        report.hasSelfDestruct = _flag(report.offChainFlagsPacked, OFFCHAIN_SELFDESTRUCT);
        report.hasApprovalDrain = _flag(report.offChainFlagsPacked, OFFCHAIN_APPROVAL_DRAIN);
        report.hasOwnerSweep = _flag(report.offChainFlagsPacked, OFFCHAIN_OWNER_SWEEP);
        report.hasReentrancy = _flag(report.offChainFlagsPacked, OFFCHAIN_REENTRANCY);
        report.hasUnexpectedCreate = _flag(report.offChainFlagsPacked, OFFCHAIN_UNEXPECTED_CREATE);
        report.hasUpgradeCall = _flag(report.offChainFlagsPacked, OFFCHAIN_UPGRADE_CALL);
        report.isExitFrozen = _flag(report.offChainFlagsPacked, OFFCHAIN_EXIT_FROZEN);
        report.isRemovalFrozen = _flag(report.offChainFlagsPacked, OFFCHAIN_REMOVAL_FROZEN);
        report.isFirstDeposit = _flag(report.offChainFlagsPacked, OFFCHAIN_FIRST_DEPOSIT);
        report.isFeeOnTransfer = _flag(report.offChainFlagsPacked, OFFCHAIN_FEE_ON_TRANSFER);
        report.oracleStale = _flag(report.offChainFlagsPacked, OFFCHAIN_ORACLE_STALE);
        report.contractVerified = !_flag(report.offChainFlagsPacked, OFFCHAIN_CONTRACT_UNVERIFIED);
        report.oracleDeviation = _flag(report.offChainFlagsPacked, OFFCHAIN_ORACLE_DEVIATION);
        report.offChainSimReverted = _flag(report.offChainFlagsPacked, OFFCHAIN_SIMULATION_REVERTED);
    }

    function _vaultOp(VaultOpType op) internal pure returns (OperationType) {
        if (op == VaultOpType.DEPOSIT) {
            return OperationType.VAULT_DEPOSIT;
        }
        if (op == VaultOpType.MINT) {
            return OperationType.VAULT_MINT;
        }
        if (op == VaultOpType.WITHDRAW) {
            return OperationType.VAULT_WITHDRAW;
        }
        return OperationType.VAULT_REDEEM;
    }

    function _swapOp(SwapOpType op) internal pure returns (OperationType) {
        if (op == SwapOpType.EXACT_TOKENS_IN) {
            return OperationType.SWAP_EXACT_TOKENS_IN;
        }
        if (op == SwapOpType.EXACT_TOKENS_OUT) {
            return OperationType.SWAP_EXACT_TOKENS_OUT;
        }
        if (op == SwapOpType.EXACT_ETH_IN) {
            return OperationType.SWAP_EXACT_ETH_IN;
        }
        if (op == SwapOpType.EXACT_ETH_OUT) {
            return OperationType.SWAP_EXACT_ETH_OUT;
        }
        if (op == SwapOpType.EXACT_TOKENS_FOR_ETH) {
            return OperationType.SWAP_EXACT_TOKENS_FOR_ETH;
        }
        return OperationType.SWAP_TOKENS_FOR_EXACT_ETH;
    }

    function _liqOp(LiquidityOpType op) internal pure returns (OperationType) {
        if (op == LiquidityOpType.ADD) {
            return OperationType.LP_ADD;
        }
        if (op == LiquidityOpType.ADD_ETH) {
            return OperationType.LP_ADD_ETH;
        }
        if (op == LiquidityOpType.REMOVE) {
            return OperationType.LP_REMOVE;
        }
        return OperationType.LP_REMOVE_ETH;
    }

    function _category(uint8 score, bool forceCritical) internal pure returns (RiskCategory) {
        if (forceCritical || score >= THRESHOLD_CRITICAL) {
            return RiskCategory.CRITICAL;
        }
        if (score >= THRESHOLD_MEDIUM) {
            return RiskCategory.MEDIUM;
        }
        if (score >= THRESHOLD_WARNING) {
            return RiskCategory.WARNING;
        }
        return RiskCategory.INFO;
    }

    function _compressCategory(RiskCategory category) internal pure returns (uint8) {
        if (category == RiskCategory.INFO) {
            return 0;
        }
        if (category == RiskCategory.WARNING) {
            return 1;
        }
        return 2;
    }

    function _flag(uint32 packedFlags, uint8 bit) internal pure returns (bool) {
        return ((packedFlags >> bit) & uint32(1)) == 1;
    }

    function _readBits(uint256 word, uint8 offset, uint8 width) internal pure returns (uint256) {
        return (word >> offset) & ((uint256(1) << width) - 1);
    }

    function _countSetBits32(uint32 value) internal pure returns (uint8 count) {
        while (value != 0) {
            count += uint8(value & 1);
            value >>= 1;
        }
    }

    function _clearBit(uint32 value, uint8 bit) internal pure returns (uint32) {
        return value & ~(uint32(1) << bit);
    }

    function _cap100(uint256 value) internal pure returns (uint256) {
        return value > 100 ? 100 : value;
    }

    function _add(uint256 a, uint8 b) internal pure returns (uint256) {
        return _cap100(a + b);
    }

    function _toUint8(uint256 value) internal pure returns (uint8) {
        return uint8(value > type(uint8).max ? type(uint8).max : value);
    }

    function _capUint8(uint256 value) internal pure returns (uint8) {
        return uint8(value > 100 ? 100 : value);
    }

    function _capUint16(uint256 value) internal pure returns (uint16) {
        return uint16(value > type(uint16).max ? type(uint16).max : value);
    }

    function _max3(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        uint256 m = a > b ? a : b;
        return m > c ? m : c;
    }
}
