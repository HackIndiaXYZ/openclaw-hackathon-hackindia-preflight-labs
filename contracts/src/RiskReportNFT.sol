// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {OperationType, RiskCategory} from "./interfaces/IPreFlightTypes.sol";

/**
 * @title  RiskReportNFT
 * @notice On-chain audit trail NFT for every PreFlight-guarded transaction.
 *
 *  Each token stores:
 *    • Operation type (14 variants across vault / swap / liquidity)
 *    • 4-level risk category: INFO / WARNING / MEDIUM / CRITICAL
 *    • Composite score (0-100) from RiskPolicy
 *    • On-chain flag bitmask (from guard) + off-chain flag bitmask (from CRE)
 *    • Status: PENDING → CONSUMED | EXPIRED
 *
 *  The tokenURI returns a fully on-chain SVG showing:
 *    • Horizontal sliding risk meter (INFO→WARNING→MEDIUM→CRITICAL)
 *    • Individual flag chips for all triggered risks
 *    • Off-chain vs on-chain findings split
 *    • Transaction details (amount, preview, target, block)
 */
contract RiskReportNFT is ERC721, ERC721Enumerable, ERC721Burnable, Ownable {
    using Strings for uint256;
    using Strings for address;

    // ─── Enums ────────────────────────────────────────────────────────────────

    enum Status { PENDING, CONSUMED, EXPIRED }

    // ─── Core data struct ─────────────────────────────────────────────────────

    struct RiskReport {
        OperationType opType;
        RiskCategory  riskCategory;
        Status        status;
        address       user;
        address       target;           // vault / tokenIn / tokenA
        address       router;           // zero for vault ops
        uint256       amount;
        uint256       previewValue;     // shares / assets / lp estimate
        uint256       blockNumber;
        uint256       timestamp;
        bytes32       checkHash;        // keccak256 of on-chain guard encoded state
        uint32        onChainFlagsPacked;
        uint32        offChainFlagsPacked;
        uint8         totalOnChainFlags;
        uint8         criticalCount;
        uint8         warningCount;
        uint8         infoCount;
        uint8         compositeScore;   // 0-100 from RiskPolicy
        uint8         onChainScore;
        uint8         offChainScore;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    uint256 private _nextTokenId;
    mapping(uint256 => RiskReport) public reports;
    mapping(address => bool)       public authorizedMinters;
    mapping(bytes32 => uint256)    public latestTokenFor;  // key(user,target) → tokenId

    // ─── Events ───────────────────────────────────────────────────────────────

    event ReportMinted(uint256 indexed tokenId, address indexed user, OperationType opType, RiskCategory riskCategory);
    event ReportConsumed(uint256 indexed tokenId, address indexed user);
    event ReportExpired(uint256 indexed tokenId, address indexed user);
    event MinterSet(address indexed minter, bool authorized);

    // ─── Access ───────────────────────────────────────────────────────────────

    modifier onlyAuthorized() {
        require(authorizedMinters[msg.sender], "NOT_AUTHORIZED_MINTER");
        _;
    }

    constructor() ERC721("PreFlight Risk Report", "PFR") Ownable(msg.sender) {}

    // ─── Mint / consume ───────────────────────────────────────────────────────

    function mint(address to, RiskReport calldata report)
        external onlyAuthorized returns (uint256 tokenId)
    {
        tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        reports[tokenId] = report;

        bytes32 key = _key(report.user, report.target);
        uint256 prev = latestTokenFor[key];
        if (prev != 0 && reports[prev].status == Status.PENDING) {
            reports[prev].status = Status.EXPIRED;
            emit ReportExpired(prev, report.user);
        }
        latestTokenFor[key] = tokenId;

        emit ReportMinted(tokenId, to, report.opType, report.riskCategory);
    }

    function consume(uint256 tokenId) external onlyAuthorized {
        require(_ownerOf(tokenId) != address(0), "TOKEN_NOT_EXISTS");
        require(reports[tokenId].status == Status.PENDING, "NOT_PENDING");
        reports[tokenId].status = Status.CONSUMED;
        emit ReportConsumed(tokenId, reports[tokenId].user);
    }

    // ─── tokenURI ─────────────────────────────────────────────────────────────

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_ownerOf(tokenId) != address(0), "TOKEN_NOT_EXISTS");
        RiskReport memory r = reports[tokenId];

        string memory svg  = _buildSVG(r);
        string memory name = string.concat("PreFlight #", tokenId.toString());
        string memory desc = _buildDesc(r);
        string memory attr = _buildAttributes(r);

        string memory json = Base64.encode(bytes(string.concat(
            '{"name":"', name, '",'
            '"description":"', desc, '",'
            '"image":"data:image/svg+xml;base64,', Base64.encode(bytes(svg)), '",'
            '"attributes":[', attr, ']}'
        )));

        return string.concat("data:application/json;base64,", json);
    }

    // ─── SVG builder ─────────────────────────────────────────────────────────

    function _buildSVG(RiskReport memory r) internal pure returns (string memory) {
        (string memory catColor, string memory catLabel) = _catStyle(r.riskCategory);
        (string memory stColor,  string memory stLabel)  = _statusStyle(r.status);
        string memory opLabel = _opLabel(r.opType);
        string memory scoreX  = Strings.toString(16 + (uint256(r.compositeScore) * 432) / 100);

        return string.concat(
            _svgHeader(catColor),
            _svgTopRow(catColor, catLabel, opLabel, stColor, stLabel),
            _svgMeter(catColor, r.compositeScore, scoreX),
            _svgScores(r.onChainScore, r.offChainScore, r.compositeScore, catColor),
            _svgFlagSection(r),
            _svgDetails(r),
            _svgFooter(r, catColor),
            '</svg>'
        );
    }

    function _svgHeader(string memory catColor) internal pure returns (string memory) {
        return string.concat(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 480 360" width="480" height="360">',
            '<defs>',
            '<linearGradient id="bg" x1="0" y1="0" x2="0.3" y2="1">',
            '<stop offset="0%" stop-color="#0d1117"/><stop offset="100%" stop-color="#0a0e14"/>',
            '</linearGradient>',
            '<linearGradient id="rg" x1="0" y1="0" x2="1" y2="0">',
            '<stop offset="0%"   stop-color="#3fb950"/>',   // INFO green
            '<stop offset="33%"  stop-color="#d29922"/>',   // WARNING yellow
            '<stop offset="66%"  stop-color="#f97316"/>',   // MEDIUM orange
            '<stop offset="100%" stop-color="#f85149"/>',   // CRITICAL red
            '</linearGradient>',
            '<filter id="glow"><feGaussianBlur stdDeviation="3" result="blur"/>',
            '<feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>',
            '</defs>',
            '<rect width="480" height="360" rx="20" fill="url(#bg)"/>',
            '<rect width="480" height="360" rx="20" fill="none" stroke="', catColor, '" stroke-width="1.5" stroke-opacity="0.35"/>',
            // top accent line
            '<rect x="0" y="0" width="480" height="3" rx="1.5" fill="', catColor, '"/>'
        );
    }

    function _svgTopRow(
        string memory catColor, string memory catLabel,
        string memory opLabel,
        string memory stColor,  string memory stLabel
    ) internal pure returns (string memory) {
        return string.concat(
            // Shield icon
            '<path d="M20 14 L30 10 L40 14 L40 25 C40 32 30 37 30 37 C30 37 20 32 20 25 Z"',
            ' fill="', catColor, '" fill-opacity="0.18" stroke="', catColor, '" stroke-width="1.3" filter="url(#glow)"/>',
            // PREFLIGHT label
            '<text x="48" y="26" font-family="monospace" font-size="14" font-weight="bold" fill="#e6edf3">PREFLIGHT</text>',
            '<text x="48" y="40" font-family="monospace" font-size="9" fill="#6e7681" letter-spacing="2">RISK AUDIT REPORT</text>',
            // Operation type badge (right side)
            '<rect x="320" y="12" width="148" height="22" rx="11" fill="', catColor, '" fill-opacity="0.12" stroke="', catColor, '" stroke-width="1"/>',
            '<text x="394" y="27" font-family="monospace" font-size="9" fill="', catColor, '" text-anchor="middle" letter-spacing="0.5">', opLabel, '</text>',
            // Status badge (below op badge)
            '<rect x="352" y="38" width="116" height="20" rx="10" fill="', stColor, '" fill-opacity="0.1" stroke="', stColor, '" stroke-width="1"/>',
            '<circle cx="366" cy="48" r="4" fill="', stColor, '" filter="url(#glow)"/>',
            '<text x="410" y="52" font-family="monospace" font-size="9" fill="', stColor, '" text-anchor="middle">', stLabel, '</text>',
            // Divider
            '<line x1="16" y1="62" x2="464" y2="62" stroke="#21262d" stroke-width="1"/>'
        );
    }

    function _svgMeter(string memory catColor, uint8 score, string memory scoreX)
        internal pure returns (string memory)
    {
        string memory scoreTxt = Strings.toString(score);
        return string.concat(
            // Section label
            '<text x="16" y="82" font-family="monospace" font-size="9" fill="#6e7681" letter-spacing="1.5">RISK METER</text>',
            // Category labels
            '<text x="16"  y="97" font-family="monospace" font-size="8" fill="#3fb950">INFO</text>',
            '<text x="130" y="97" font-family="monospace" font-size="8" fill="#d29922">WARNING</text>',
            '<text x="264" y="97" font-family="monospace" font-size="8" fill="#f97316">MEDIUM</text>',
            '<text x="390" y="97" font-family="monospace" font-size="8" fill="#f85149">CRITICAL</text>',
            // Meter track background
            '<rect x="16" y="102" width="448" height="14" rx="7" fill="#21262d"/>',
            // Gradient fill up to score position
            '<clipPath id="meterclip"><rect x="16" y="102" width="', scoreX, '" height="14" rx="7"/></clipPath>',
            '<rect x="16" y="102" width="448" height="14" rx="7" fill="url(#rg)" clip-path="url(#meterclip)"/>',
            // Tick marks at 25%, 50%, 75%
            '<line x1="128" y1="100" x2="128" y2="118" stroke="#0d1117" stroke-width="2"/>',
            '<line x1="240" y1="100" x2="240" y2="118" stroke="#0d1117" stroke-width="2"/>',
            '<line x1="352" y1="100" x2="352" y2="118" stroke="#0d1117" stroke-width="2"/>',
            // Score indicator (diamond)
            '<polygon points="', scoreX, ',99 ', scoreX, '-6,107 ', scoreX, ',117 ', scoreX, '+6,107"',
            ' fill="white" stroke="#0d1117" stroke-width="1.5" filter="url(#glow)"/>',
            // Score label
            '<text x="', scoreX, '" y="135" font-family="monospace" font-size="10" font-weight="bold"',
            ' fill="', catColor, '" text-anchor="middle">', scoreTxt, '/100</text>'
        );
    }

    function _svgScores(uint8 oc, uint8 off, uint8 comp, string memory catColor)
        internal pure returns (string memory)
    {
        return string.concat(
            '<line x1="16" y1="148" x2="464" y2="148" stroke="#21262d" stroke-width="1"/>',
            // Three score boxes
            _scoreBox(16,  150, "ON-CHAIN",  Strings.toString(oc),   "#58a6ff"),
            _scoreBox(176, 150, "OFF-CHAIN", Strings.toString(off),  "#bc8cff"),
            _scoreBox(336, 150, "COMPOSITE", Strings.toString(comp), catColor)
        );
    }

    function _scoreBox(uint256 x, uint256 y, string memory label, string memory val, string memory color)
        internal pure returns (string memory)
    {
        string memory xs = Strings.toString(x);
        string memory ys = Strings.toString(y);
        string memory cx = Strings.toString(x + 72); // center x
        return string.concat(
            '<rect x="', xs, '" y="', ys, '" width="144" height="52" rx="8" fill="', color, '" fill-opacity="0.06" stroke="', color, '" stroke-width="1" stroke-opacity="0.3"/>',
            '<text x="', cx, '" y="', Strings.toString(y + 17), '" font-family="monospace" font-size="8" fill="', color, '" text-anchor="middle" letter-spacing="1">', label, '</text>',
            '<text x="', cx, '" y="', Strings.toString(y + 40), '" font-family="monospace" font-size="22" font-weight="bold" fill="', color, '" text-anchor="middle">', val, '</text>'
        );
    }

    function _svgFlagSection(RiskReport memory r) internal pure returns (string memory) {
        return string.concat(
            '<line x1="16" y1="212" x2="464" y2="212" stroke="#21262d" stroke-width="1"/>',
            // On-chain flags column header
            '<text x="16"  y="228" font-family="monospace" font-size="9" fill="#58a6ff" letter-spacing="1">ON-CHAIN FLAGS</text>',
            '<text x="248" y="228" font-family="monospace" font-size="9" fill="#bc8cff" letter-spacing="1">OFF-CHAIN FINDINGS</text>',
            // Vertical divider
            '<line x1="236" y1="212" x2="236" y2="296" stroke="#21262d" stroke-width="1"/>',
            // On-chain flags
            _renderOnChainFlags(r.onChainFlagsPacked, r.opType),
            // Off-chain flags
            _renderOffChainFlags(r.offChainFlagsPacked)
        );
    }

    function _renderOnChainFlags(uint32 packed, OperationType op) internal pure returns (string memory out) {
        string[14] memory vaultNames = [
            "NOT WHITELISTED","ZERO SUPPLY","DONATION ATTACK","SHARE INFLATION",
            "BAL MISMATCH","RATE ANOMALY","PREVIEW REVERT","ZERO SHARES OUT",
            "ZERO ASSETS OUT","DUST SHARES","DUST ASSETS","EXCEEDS MAX DEP",
            "EXCEEDS MAX REDEEM","PREVIEW MISMATCH"
        ];
        string[13] memory swapNames = [
            "DEEP MULTIHOP","DUPLICATE PATH","POOL NOT EXIST","FACTORY MISMATCH",
            "ZERO LIQUIDITY","LOW LIQUIDITY","LOW LP SUPPLY","POOL TOO NEW",
            "SEVERE IMBALANCE","K BROKEN","HIGH IMPACT","FLASHLOAN RISK","PRICE MANIP"
        ];
        string[12] memory liqNames = [
            "UNTRUSTED ROUTER","PAIR NOT EXIST","ZERO RESERVES","LOW RESERVES",
            "SEVERE IMBALANCE","K BROKEN","POOL TOO NEW","LOW LP SUPPLY",
            "FIRST DEPOSIT","ZERO LP OUT","ZERO TOKENS OUT","DUST LP"
        ];

        bool isSwap = (op == OperationType.SWAP_EXACT_TOKENS_IN  || op == OperationType.SWAP_EXACT_TOKENS_OUT ||
                       op == OperationType.SWAP_EXACT_ETH_IN      || op == OperationType.SWAP_EXACT_ETH_OUT   ||
                       op == OperationType.SWAP_EXACT_TOKENS_FOR_ETH || op == OperationType.SWAP_TOKENS_FOR_EXACT_ETH);
        bool isLiq  = (op == OperationType.LP_ADD || op == OperationType.LP_ADD_ETH ||
                       op == OperationType.LP_REMOVE || op == OperationType.LP_REMOVE_ETH);

        uint8 count = isSwap ? 13 : isLiq ? 12 : 14;

        uint256 yBase = 240;
        uint8   shown = 0;
        for (uint8 i = 0; i < count && shown < 5; ) {
            if ((packed >> i) & 1 == 1) {
                bool isCrit = _isOnChainCritBit(i, isSwap, isLiq);
                string memory flagColor = isCrit ? "#f85149" : "#d29922";
                string memory fname = isSwap ? swapNames[i] : isLiq ? liqNames[i] : vaultNames[i];
                out = string.concat(out,
                    '<rect x="16" y="', Strings.toString(yBase), '" width="210" height="14" rx="4"',
                    ' fill="', flagColor, '" fill-opacity="0.12"/>',
                    '<text x="22" y="', Strings.toString(yBase + 10), '" font-family="monospace" font-size="8" fill="', flagColor, '">', fname, '</text>'
                );
                yBase += 17;
                shown++;
            }
            unchecked { ++i; }
        }
        if (shown == 0) {
            out = '<text x="22" y="254" font-family="monospace" font-size="9" fill="#3fb950">✓ All clean</text>';
        }
    }

    function _isOnChainCritBit(uint8 i, bool isSwap, bool isLiq) internal pure returns (bool) {
        // Vault: bits 2,4,6,7,8,11,12 are critical
        if (!isSwap && !isLiq) return (i==2||i==4||i==6||i==7||i==8||i==11||i==12);
        // Swap: bits 2,4,9,12 are critical
        if (isSwap) return (i==2||i==4||i==9||i==12);
        // Liq: bits 1,2,5,8,9,10 are critical
        return (i==1||i==2||i==5||i==8||i==9||i==10);
    }

    function _renderOffChainFlags(uint32 packed) internal pure returns (string memory out) {
        string[17] memory names = [
            "DELEGATECALL","SELFDESTRUCT","APPROVAL DRAIN","OWNER SWEEP",
            "EXIT FROZEN","LP REMOVAL FROZEN","SIM REVERTED","UNEXPECTED CREATE",
            "REENTRANCY","UPGRADE CALL","FIRST DEPOSIT","ORACLE DEVIATION",
            "FEE ON TRANSFER","OUTPUT DISCREPANCY","RATIO DEVIATION",
            "ORACLE STALE","UNVERIFIED CONTRACT"
        ];
        // Bits 0-6 are critical off-chain
        uint256 yBase = 240;
        uint8   shown = 0;
        for (uint8 i = 0; i < 17 && shown < 5; ) {
            if ((packed >> i) & 1 == 1) {
                bool isCrit = (i < 7);
                string memory flagColor = isCrit ? "#f85149" : (i < 13 ? "#d29922" : "#58a6ff");
                out = string.concat(out,
                    '<rect x="248" y="', Strings.toString(yBase), '" width="210" height="14" rx="4"',
                    ' fill="', flagColor, '" fill-opacity="0.12"/>',
                    '<text x="254" y="', Strings.toString(yBase + 10), '" font-family="monospace" font-size="8" fill="', flagColor, '">', names[i], '</text>'
                );
                yBase += 17;
                shown++;
            }
            unchecked { ++i; }
        }
        if (shown == 0) {
            out = '<text x="254" y="254" font-family="monospace" font-size="9" fill="#3fb950">✓ No findings</text>';
        }
    }

    function _svgDetails(RiskReport memory r) internal pure returns (string memory) {
        return string.concat(
            '<line x1="16" y1="298" x2="464" y2="298" stroke="#21262d" stroke-width="1"/>',
            // Row 1: target + block
            '<text x="16"  y="313" font-family="monospace" font-size="8" fill="#6e7681">TARGET</text>',
            '<text x="16"  y="325" font-family="monospace" font-size="9" fill="#c9d1d9">', _shortAddr(r.target), '</text>',
            '<text x="248" y="313" font-family="monospace" font-size="8" fill="#6e7681">BLOCK</text>',
            '<text x="248" y="325" font-family="monospace" font-size="9" fill="#c9d1d9">', r.blockNumber.toString(), '</text>',
            // Row 2: amount + preview
            '<text x="16"  y="340" font-family="monospace" font-size="8" fill="#6e7681">AMOUNT</text>',
            '<text x="80"  y="340" font-family="monospace" font-size="9" fill="#e6edf3">', _shortNum(r.amount), '</text>',
            '<text x="248" y="340" font-family="monospace" font-size="8" fill="#6e7681">PREVIEW</text>',
            '<text x="316" y="340" font-family="monospace" font-size="9" fill="#e6edf3">',
            r.previewValue > 0 ? _shortNum(r.previewValue) : "N/A", '</text>'
        );
    }

    function _svgFooter(RiskReport memory r, string memory catColor) internal pure returns (string memory) {
        return string.concat(
            '<line x1="16" y1="348" x2="464" y2="348" stroke="#21262d" stroke-width="1"/>',
            '<text x="16" y="358" font-family="monospace" font-size="8" fill="#484f58">',
            'USER: ', _shortAddr(r.user),
            '  ·  CRIT:', Strings.toString(r.criticalCount),
            '  WARN:', Strings.toString(r.warningCount),
            '  INFO:', Strings.toString(r.infoCount),
            '</text>'
        );
    }

    // ─── Attribute builder ────────────────────────────────────────────────────

    function _buildAttributes(RiskReport memory r) internal pure returns (string memory) {
        return string.concat(
            _attr("Operation",       _opLabel(r.opType),          true),   ",",
            _attr("Risk Category",   _catLabel(r.riskCategory),   true),   ",",
            _attr("Status",          _statusLabel(r.status),      true),   ",",
            _attr("Composite Score", Strings.toString(r.compositeScore), false), ",",
            _attr("On-Chain Score",  Strings.toString(r.onChainScore),   false), ",",
            _attr("Off-Chain Score", Strings.toString(r.offChainScore),  false), ",",
            _attr("Critical Flags",  Strings.toString(r.criticalCount),  false), ",",
            _attr("Warning Flags",   Strings.toString(r.warningCount),   false), ",",
            _attr("Block Number",    Strings.toString(r.blockNumber),    false), ",",
            _attr("Amount",          Strings.toString(r.amount),         false), ",",
            _attr("Preview Value",   Strings.toString(r.previewValue),   false)
        );
    }

    function _attr(string memory k, string memory v, bool isStr) internal pure returns (string memory) {
        if (isStr) return string.concat('{"trait_type":"', k, '","value":"', v, '"}');
        return string.concat('{"trait_type":"', k, '","value":', v, '}');
    }

    function _buildDesc(RiskReport memory r) internal pure returns (string memory) {
        return string.concat(
            "PreFlight audit for ", _opLabel(r.opType),
            " on ", _shortAddr(r.target),
            ". Risk: ", _catLabel(r.riskCategory),
            " (score ", Strings.toString(r.compositeScore), "/100). Status: ", _statusLabel(r.status)
        );
    }

    // ─── Style helpers ────────────────────────────────────────────────────────

    function _catStyle(RiskCategory cat) internal pure returns (string memory color, string memory label) {
        if (cat == RiskCategory.INFO)    return ("#3fb950", "INFO");
        if (cat == RiskCategory.WARNING) return ("#d29922", "WARNING");
        if (cat == RiskCategory.MEDIUM)  return ("#f97316", "MEDIUM");
        return ("#f85149", "CRITICAL");
    }

    function _catLabel(RiskCategory cat) internal pure returns (string memory) {
        if (cat == RiskCategory.INFO)    return "INFO";
        if (cat == RiskCategory.WARNING) return "WARNING";
        if (cat == RiskCategory.MEDIUM)  return "MEDIUM";
        return "CRITICAL";
    }

    function _statusStyle(Status s) internal pure returns (string memory color, string memory label) {
        if (s == Status.PENDING)  return ("#58a6ff", "PENDING");
        if (s == Status.CONSUMED) return ("#3fb950", "CONSUMED");
        return ("#6e7681", "EXPIRED");
    }

    function _statusLabel(Status s) internal pure returns (string memory) {
        if (s == Status.PENDING)  return "PENDING";
        if (s == Status.CONSUMED) return "CONSUMED";
        return "EXPIRED";
    }

    function _opLabel(OperationType op) internal pure returns (string memory) {
        if (op == OperationType.VAULT_DEPOSIT)           return "VAULT DEPOSIT";
        if (op == OperationType.VAULT_MINT)              return "VAULT MINT";
        if (op == OperationType.VAULT_WITHDRAW)          return "VAULT WITHDRAW";
        if (op == OperationType.VAULT_REDEEM)            return "VAULT REDEEM";
        if (op == OperationType.SWAP_EXACT_TOKENS_IN)    return "SWAP EXACT IN";
        if (op == OperationType.SWAP_EXACT_TOKENS_OUT)   return "SWAP EXACT OUT";
        if (op == OperationType.SWAP_EXACT_ETH_IN)       return "SWAP ETH IN";
        if (op == OperationType.SWAP_EXACT_ETH_OUT)      return "SWAP ETH OUT";
        if (op == OperationType.SWAP_EXACT_TOKENS_FOR_ETH) return "SWAP TOK→ETH";
        if (op == OperationType.SWAP_TOKENS_FOR_EXACT_ETH) return "SWAP TOK→ETH EXACT";
        if (op == OperationType.LP_ADD)                  return "LP ADD";
        if (op == OperationType.LP_ADD_ETH)              return "LP ADD ETH";
        if (op == OperationType.LP_REMOVE)               return "LP REMOVE";
        return "LP REMOVE ETH";
    }

    // ─── Utility helpers ──────────────────────────────────────────────────────

    function _shortAddr(address addr) internal pure returns (string memory) {
        string memory full = addr.toHexString();
        bytes memory b = bytes(full);
        bytes memory out = new bytes(13);
        for (uint i; i < 8;) { out[i] = b[i]; unchecked { ++i; } }
        out[8] = "."; out[9] = "."; out[10] = ".";
        out[11] = b[38]; out[12] = b[39];
        return string(out);
    }

    function _shortNum(uint256 n) internal pure returns (string memory) {
        if (n == 0) return "0";
        if (n >= 1e18) return string.concat((n / 1e15).toString(), "e15");
        if (n >= 1e9)  return string.concat((n / 1e6).toString(),  "e6");
        if (n >= 1e6)  return string.concat((n / 1e3).toString(),  "e3");
        return n.toString();
    }

    function _key(address user, address target) internal pure returns (bytes32) {
        return keccak256(abi.encode(user, target));
    }

    // ─── View helpers ─────────────────────────────────────────────────────────

    function getReport(uint256 tokenId) external view returns (RiskReport memory) {
        require(_ownerOf(tokenId) != address(0), "TOKEN_NOT_EXISTS");
        return reports[tokenId];
    }

    function isPending(uint256 tokenId) external view returns (bool) {
        return reports[tokenId].status == Status.PENDING;
    }

    function latestToken(address user, address target)
        external view returns (uint256 tokenId, bool exists)
    {
        bytes32 k = _key(user, target);
        tokenId = latestTokenFor[k];
        exists  = tokenId != 0 && _ownerOf(tokenId) != address(0);
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function setAuthorizedMinter(address minter, bool authorized) external onlyOwner {
        require(minter != address(0), "ZERO_ADDRESS");
        authorizedMinters[minter] = authorized;
        emit MinterSet(minter, authorized);
    }

    // ─── ERC721 overrides ─────────────────────────────────────────────────────

    function _update(address to, uint256 tokenId, address auth)
        internal override(ERC721, ERC721Enumerable) returns (address)
    { return super._update(to, tokenId, auth); }

    function _increaseBalance(address account, uint128 value)
        internal override(ERC721, ERC721Enumerable)
    { super._increaseBalance(account, value); }

    function supportsInterface(bytes4 id)
        public view override(ERC721, ERC721Enumerable) returns (bool)
    { return super.supportsInterface(id); }
}
