pragma solidity ^0.8.20;

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

enum RiskLevel {
    SAFE,
    WARNING,
    CRITICAL
}

enum TraceType {
    CALL,
    DELEGATECALL,
    STATICCALL,
    CREATE,
    CREATE2,
    SELFDESTRUCT
}

struct TraceEntry {
    TraceType traceType;
    address from;
    address to;
    uint256 value;
    bytes input;
    bytes output;
    uint256 gas;
    uint256 gasUsed;
    string error;
    TraceEntry[] calls;
}

struct SharedTraceFindings {
    bool hasDangerousDelegateCall;
    address delegateCallTarget;
    bool hasSelfDestruct;
    bool hasUnexpectedCreate;
    address[] createAddresses;
    bool hasApprovalDrain;
    address approvalDrainSpender;
    bool hasReentrancy;
    address reentrancyAddress;
}

struct VaultTraceFindings {
    bool hasDangerousDelegateCall;
    address delegateCallTarget;
    bool hasSelfDestruct;
    bool hasUnexpectedCreate;
    address[] createAddresses;
    bool hasApprovalDrain;
    address approvalDrainSpender;
    bool hasReentrancy;
    address reentrancyAddress;
    bool hasOwnerSweep;
    uint256 sweepAmount;
    address sweepToken;
    bool hasUpgradeCall;
    address upgradeTarget;
}

struct VaultEconomicFindings {
    bool simulationReverted;
    string revertReason;
    uint256 primaryOutput;
    uint256 primaryExpected;
    uint256 outputDiscrepancyBps;
    uint256 sharePriceBefore;
    uint256 sharePriceAfter;
    uint256 sharePriceDriftBps;
    bool isExitFrozen;
    string exitRevertReason;
    uint256 exitSimulatedOut;
    uint256 actualAssetPull;
    uint256 excessPullBps;
    uint256 assetPriceUSD;
    bool assetOracleStale;
    uint256 assetOracleAge;
}

struct VaultOffChainResult {
    bool isSafe;
    RiskLevel riskLevel;
    uint256 riskScore;
    VaultOpType operation;
    VaultTraceFindings trace;
    VaultEconomicFindings economic;
    bool vaultVerified;
    bool assetVerified;
    uint256 simulatedAt;
    string network;
}

struct SwapTraceFindings {
    bool hasDangerousDelegateCall;
    address delegateCallTarget;
    bool hasSelfDestruct;
    bool hasUnexpectedCreate;
    address[] createAddresses;
    bool hasApprovalDrain;
    address approvalDrainSpender;
    bool hasReentrancy;
    address reentrancyAddress;
}

struct SwapEconomicFindings {
    bool simulationReverted;
    string revertReason;
    uint256 actualAmountIn;
    uint256 actualAmountOut;
    uint256 inputHeadroomBps;
    uint256 ethRefunded;
    uint256 oracleFairAmountOut;
    uint256 priceImpactBps;
    bool oracleDeviation;
    bool isFeeOnTransfer;
    uint256 measuredFeePercent;
    uint256 tokenInPriceUSD;
    uint256 tokenOutPriceUSD;
    bool tokenInOracleStale;
    bool tokenOutOracleStale;
    uint256 tokenInOracleAge;
    uint256 tokenOutOracleAge;
}

struct SwapOffChainResult {
    bool isSafe;
    RiskLevel riskLevel;
    uint256 riskScore;
    SwapOpType operation;
    SwapTraceFindings trace;
    SwapEconomicFindings economic;
    bool routerVerified;
    bool tokenInVerified;
    bool tokenOutVerified;
    uint256 simulatedAt;
    string network;
}

struct LiquidityTraceFindings {
    bool hasDangerousDelegateCall;
    address delegateCallTarget;
    bool hasSelfDestruct;
    bool hasUnexpectedCreate;
    address[] createAddresses;
    bool hasApprovalDrain;
    address approvalDrainSpender;
    bool hasReentrancy;
    address reentrancyAddress;
    bool hasOwnerSweep;
    uint256 sweepAmount;
    address sweepToken;
}

struct LiquidityEconomicFindings {
    bool simulationReverted;
    string revertReason;
    uint256 actualAmountA;
    uint256 actualAmountB;
    uint256 actualLPMinted;
    uint256 expectedLPMinted;
    uint256 lpMintDiscrepancyBps;
    uint256 excessTokenALost;
    uint256 excessTokenBLost;
    uint256 excessValueLostUSD;
    uint256 actualReceivedA;
    uint256 actualReceivedB;
    address pairAddress;
    uint256 lpTotalSupply;
    uint256 reserveA;
    uint256 reserveB;
    bool isFirstDeposit;
    uint256 poolRatio;
    uint256 oracleRatio;
    uint256 ratioDeviationBps;
    bool isRemovalFrozen;
    string removalRevertReason;
    uint256 removalSimAmountA;
    uint256 removalSimAmountB;
    uint256 tokenAPriceUSD;
    uint256 tokenBPriceUSD;
    bool tokenAOracleStale;
    bool tokenBOracleStale;
    uint256 tokenAOracleAge;
    uint256 tokenBOracleAge;
}

struct LiquidityOffChainResult {
    bool isSafe;
    RiskLevel riskLevel;
    uint256 riskScore;
    LiquidityOpType operation;
    LiquidityTraceFindings trace;
    LiquidityEconomicFindings economic;
    bool routerVerified;
    bool pairVerified;
    bool tokenAVerified;
    bool tokenBVerified;
    uint256 simulatedAt;
    string network;
}
