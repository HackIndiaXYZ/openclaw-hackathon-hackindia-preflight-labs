// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import {CombinedRiskReport} from "../RiskPolicy.sol";

/**
 * @title  SVGRenderer
 * @notice Generates a fully on-chain SVG for each PreFlight Risk Report NFT.
 *         The design is a 420×300 dark-mode card showing:
 *   • Risk level header + operation badge
 *   • Horizontal risk meter (green→yellow→red) with score indicator
 *   • On-chain flags section (critical flags highlighted)
 *   • Off-chain trace & economic findings section
 *   • Transaction details footer
 *   • Status badge
 */
library SVGRenderer {
    using Strings for uint256;
    using Strings for address;

    // ── Palette ────────────────────────────────────────────────────────────────
    string internal constant C_BG      = "#0d1117";
    string internal constant C_SAFE    = "#3fb950";
    string internal constant C_WARN    = "#d29922";
    string internal constant C_CRIT    = "#f85149";
    string internal constant C_INFO    = "#58a6ff";
    string internal constant C_TEXT    = "#c9d1d9";
    string internal constant C_MUTED   = "#8b949e";
    string internal constant C_BORDER  = "#30363d";
    string internal constant C_SURFACE = "#161b22";
    string internal constant C_PENDING = "#58a6ff";
    string internal constant C_CONSUMED= "#3fb950";
    string internal constant C_EXPIRED = "#6e7681";

    // Report-type labels (must match RiskReportNFT.ReportType enum order)
    function _typeLabel(uint8 rt) internal pure returns (string memory) {
        if (rt == 0) return "VAULT DEPOSIT";
        if (rt == 1) return "VAULT REDEEM";
        if (rt == 2) return "VAULT MINT";
        if (rt == 3) return "VAULT WITHDRAW";
        if (rt == 4) return "SWAP V2";
        if (rt == 5) return "SWAP V3";
        if (rt == 6) return "SWAP V4";
        if (rt == 7) return "ADD LIQUIDITY";
        if (rt == 8) return "ADD LIQ ETH";
        if (rt == 9) return "REMOVE LIQ";
        return "REMOVE LIQ ETH";
    }

    function _riskColor(uint8 level) internal pure returns (string memory) {
        if (level == 0) return C_SAFE;
        if (level == 1) return C_WARN;
        return C_CRIT;
    }

    function _riskLabel(uint8 level) internal pure returns (string memory) {
        if (level == 0) return "SAFE";
        if (level == 1) return "WARNING";
        return "CRITICAL";
    }

    function _statusColor(uint8 status) internal pure returns (string memory) {
        if (status == 0) return C_PENDING;
        if (status == 1) return C_CONSUMED;
        return C_EXPIRED;
    }

    function _statusLabel(uint8 status) internal pure returns (string memory) {
        if (status == 0) return "PENDING";
        if (status == 1) return "CONSUMED";
        return "EXPIRED";
    }

    // ── Main render function ───────────────────────────────────────────────────

    function render(
        uint256 tokenId,
        CombinedRiskReport memory r,
        uint8 status
    ) internal pure returns (string memory) {
        string memory riskColor  = _riskColor(r.finalRiskLevel);
        string memory riskLabel  = _riskLabel(r.finalRiskLevel);
        string memory statusColor= _statusColor(status);
        string memory statusLabel= _statusLabel(status);
        string memory typeLabel  = _typeLabel(r.reportType);

        return string.concat(
            _header(tokenId, riskColor, riskLabel, typeLabel),
            _riskMeter(r.finalRiskScore, r.finalRiskLevel),
            _onChainSection(r),
            _offChainSection(r),
            _footer(r, tokenId, statusColor, statusLabel),
            "</svg>"
        );
    }

    function _header(
        uint256 tokenId,
        string memory riskColor,
        string memory riskLabel,
        string memory typeLabel
    ) internal pure returns (string memory) {
        return string.concat(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 420 300" width="420" height="300">',
            '<defs>',
            '<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">',
            '<stop offset="0%" stop-color="', C_BG, '"/>',
            '<stop offset="100%" stop-color="', C_SURFACE, '"/>',
            '</linearGradient>',
            '<linearGradient id="meter" x1="0" y1="0" x2="1" y2="0">',
            '<stop offset="0%" stop-color="', C_SAFE, '"/>',
            '<stop offset="45%" stop-color="', C_WARN, '"/>',
            '<stop offset="100%" stop-color="', C_CRIT, '"/>',
            '</linearGradient>',
            '</defs>',
            // Card background
            '<rect width="420" height="300" rx="14" fill="url(#bg)"/>',
            '<rect width="420" height="300" rx="14" fill="none" stroke="', riskColor, '" stroke-width="1.5" stroke-opacity="0.45"/>',
            // Top accent bar (risk colour gradient)
            '<rect x="0" y="0" width="420" height="5" rx="2" fill="', riskColor, '" opacity="0.9"/>',
            // Shield icon
            '<path d="M18 15 L26 12 L34 15 L34 23 C34 28 26 32 26 32 C26 32 18 28 18 23 Z" fill="', riskColor, '" fill-opacity="0.2" stroke="', riskColor, '" stroke-width="1.2"/>',
            // "PREFLIGHT" branding
            '<text x="40" y="30" font-family="monospace" font-size="13" font-weight="bold" fill="', C_TEXT, '">PREFLIGHT</text>',
            '<text x="40" y="44" font-family="monospace" font-size="9" fill="', C_MUTED, '">RISK REPORT NFT</text>',
            // Token ID
            '<text x="408" y="30" font-family="monospace" font-size="10" fill="', C_MUTED, '" text-anchor="end">#', tokenId.toString(), '</text>',
            // Operation type badge
            '<rect x="295" y="13" width="110" height="20" rx="10" fill="', riskColor, '" fill-opacity="0.12" stroke="', riskColor, '" stroke-width="1"/>',
            '<text x="350" y="27" font-family="monospace" font-size="8" fill="', riskColor, '" text-anchor="middle">', typeLabel, '</text>',
            // Divider
            '<line x1="16" y1="56" x2="404" y2="56" stroke="', C_BORDER, '" stroke-width="1"/>',
            // Risk level text
            '<text x="16" y="76" font-family="monospace" font-size="10" fill="', C_MUTED, '">RISK LEVEL</text>',
            '<text x="16" y="94" font-family="monospace" font-size="20" font-weight="bold" fill="', riskColor, '">', riskLabel, '</text>'
        );
    }

    function _riskMeter(uint8 score, uint8 level) internal pure returns (string memory) {
        // Score indicator position: x = 16 + (score/100)*388
        uint256 indicatorX = 16 + (uint256(score) * 388) / 100;
        string memory indXStr = indicatorX.toString();
        string memory scoreStr = uint256(score).toString();

        // Zone labels on the meter
        return string.concat(
            // Meter track
            '<rect x="16" y="102" width="388" height="10" rx="5" fill="url(#meter)" opacity="0.85"/>',
            // Dark overlay for unused portion (none — full gradient shown)
            // Indicator circle
            '<circle cx="', indXStr, '" cy="107" r="8" fill="', C_BG, '" stroke="white" stroke-width="2"/>',
            '<circle cx="', indXStr, '" cy="107" r="4" fill="white"/>',
            // Score label
            '<text x="', indXStr, '" y="128" font-family="monospace" font-size="8" fill="white" text-anchor="middle">', scoreStr, '/100</text>',
            // Zone captions
            '<text x="16"  y="139" font-family="monospace" font-size="7" fill="', C_SAFE, '">SAFE</text>',
            '<text x="175" y="139" font-family="monospace" font-size="7" fill="', C_WARN, '" text-anchor="middle">WARNING</text>',
            '<text x="404" y="139" font-family="monospace" font-size="7" fill="', C_CRIT, '" text-anchor="end">CRITICAL</text>',
            // Divider
            '<line x1="16" y1="145" x2="404" y2="145" stroke="', C_BORDER, '" stroke-width="1"/>'
        );
    }

    function _onChainSection(CombinedRiskReport memory r) internal pure returns (string memory) {
        // Build flag list from packed bits (vault = 14 flags, swap = 13, liq = 12)
        string memory flagLines = _buildOnChainFlags(r);

        return string.concat(
            // Section header
            '<text x="16" y="160" font-family="monospace" font-size="9" font-weight="bold" fill="', C_INFO, '">ON-CHAIN</text>',
            '<text x="16" y="172" font-family="monospace" font-size="7.5" fill="', C_MUTED, '">',
            uint256(r.onChainCriticalCount).toString(), ' critical  ',
            uint256(r.onChainSoftCount).toString(), ' warnings  ',
            _cleanCount(r.onChainTotalFlags, r.onChainCriticalCount, r.onChainSoftCount), ' clean',
            '</text>',
            flagLines,
            // Vertical divider between on-chain and off-chain sections
            '<line x1="214" y1="148" x2="214" y2="240" stroke="', C_BORDER, '" stroke-width="1"/>'
        );
    }

    function _buildOnChainFlags(CombinedRiskReport memory r) internal pure returns (string memory) {
        // We show up to 4 triggered on-chain flags (names depend on report type)
        bool isSwap = (r.reportType >= 4 && r.reportType <= 6);
        bool isLiq  = (r.reportType >= 7);

        string[14] memory vaultNames = [
            "VAULT_NOT_LISTED", "ZERO_SUPPLY",    "DONATION_ATTACK",   "SHARE_INFLATE",
            "BAL_MISMATCH",     "RATE_ANOMALY",   "PREVIEW_REVERT",    "ZERO_SHARES",
            "ZERO_ASSETS",      "DUST_SHARES",    "DUST_ASSETS",       "EXCEEDS_DEPOSIT",
            "EXCEEDS_REDEEM",   "PREVIEW_MISMATCH"
        ];
        string[13] memory swapNames = [
            "NOT_TRUSTED",      "FACTORY_MISMATCH","DEEP_MULTIHOP",    "DUPE_TOKEN",
            "NO_POOL",          "ZERO_LIQUIDITY",  "LOW_LIQUIDITY",    "LOW_LP",
            "POOL_TOO_NEW",     "SEVERE_IMBALANCE","K_BROKEN",         "HIGH_IMPACT",
            "PRICE_MANIP"
        ];
        string[12] memory liqNames  = [
            "NOT_TRUSTED",      "PAIR_NOT_EXISTS","ZERO_LIQUIDITY",   "LOW_LIQUIDITY",
            "LOW_LP",           "FIRST_DEPOSITOR","SEVERE_IMBALANCE", "K_BROKEN",
            "RATIO_DEVIATION",  "HIGH_LP_IMPACT", "FLASHLOAN_RISK",   "TOKEN_RISK"
        ];

        uint8 count = isSwap ? 13 : (isLiq ? 12 : 14);
        string memory out;
        uint8 shown;
        uint8 row;

        for (uint8 i = 0; i < count && shown < 6;) {
            bool flagSet = (r.onChainFlagsPacked >> i) & 1 == 1;
            if (flagSet) {
                string memory name = isSwap
                    ? swapNames[i]
                    : (isLiq ? liqNames[i] : vaultNames[i]);
                string memory dotColor = i < 7 ? C_CRIT : C_WARN; // first half = critical risk flags
                uint256 yPos = 188 + uint256(row) * 14;
                out = string.concat(out,
                    '<circle cx="22" cy="', yPos.toString(), '" r="3" fill="', dotColor, '"/>',
                    '<text x="29" y="', (yPos + 4).toString(), '" font-family="monospace" font-size="7.5" fill="', C_TEXT, '">',
                    name, '</text>'
                );
                shown++;
                row++;
            }
            unchecked { ++i; }
        }

        if (shown == 0) {
            out = string.concat(
                '<circle cx="22" cy="192" r="3" fill="', C_SAFE, '"/>',
                '<text x="29" y="196" font-family="monospace" font-size="7.5" fill="', C_SAFE, '">ALL CLEAR</text>'
            );
        }

        return out;
    }

    function _offChainSection(CombinedRiskReport memory r) internal pure returns (string memory) {
        string memory lines = _buildOffChainLines(r);

        string memory score = uint256(r.offChainRiskScore).toString();
        string memory lvlColor = _riskColor(r.offChainRiskLevel);

        return string.concat(
            '<text x="222" y="160" font-family="monospace" font-size="9" font-weight="bold" fill="', C_INFO, '">OFF-CHAIN</text>',
            '<text x="222" y="172" font-family="monospace" font-size="7.5" fill="', lvlColor, '">',
            _riskLabel(r.offChainRiskLevel), '  score:', score, '</text>',
            lines
        );
    }

    function _buildOffChainLines(CombinedRiskReport memory r) internal pure returns (string memory) {
        string memory out;
        uint8 row;

        // Absolute-block trace findings (always show if triggered)
        if (r.hasDangerousDelegateCall) { out = _offLine(out, row, "DELEGATECALL!", C_CRIT); row++; }
        if (r.hasSelfDestruct)          { out = _offLine(out, row, "SELFDESTRUCT!", C_CRIT); row++; }
        if (r.hasOwnerSweep)            { out = _offLine(out, row, "OWNER SWEEP!",  C_CRIT); row++; }
        if (r.hasApprovalDrain)         { out = _offLine(out, row, "APPROVAL DRAIN",C_CRIT); row++; }
        if (r.isExitFrozen)             { out = _offLine(out, row, "EXIT FROZEN!",  C_CRIT); row++; }
        if (r.isRemovalFrozen)          { out = _offLine(out, row, "LP FROZEN!",    C_CRIT); row++; }
        if (row >= 6) return out;

        // Warning-level findings
        if (r.hasReentrancy)            { out = _offLine(out, row, "REENTRANCY",    C_WARN); row++; }
        if (r.hasUpgradeCall)           { out = _offLine(out, row, "UPGRADE CALL",  C_WARN); row++; }
        if (r.oracleDeviation)          { out = _offLine(out, row, "ORACLE DEVIATION",C_WARN); row++; }
        if (r.isFeeOnTransfer)          { out = _offLine(out, row, "FEE-ON-TRANSFER",C_WARN); row++; }
        if (r.isFirstDeposit)           { out = _offLine(out, row, "FIRST DEPOSITOR",C_WARN); row++; }
        if (r.oracleStale)              { out = _offLine(out, row, "ORACLE STALE",  C_WARN); row++; }
        if (row >= 6) return out;

        if (r.offChainSimReverted) { out = _offLine(out, row, "SIM REVERTED",  C_CRIT); row++; }
        if (!r.contractVerified)   { out = _offLine(out, row, "NOT VERIFIED",  C_WARN); row++; }

        if (row == 0) {
            out = _offLine(out, 0, "ALL CLEAN", C_SAFE);
        }

        return out;
    }

    function _offLine(string memory acc, uint8 row, string memory label, string memory color)
        internal pure returns (string memory)
    {
        uint256 yPos = 188 + uint256(row) * 14;
        return string.concat(acc,
            '<circle cx="220" cy="', yPos.toString(), '" r="3" fill="', color, '"/>',
            '<text x="227" y="', (yPos + 4).toString(), '" font-family="monospace" font-size="7.5" fill="', C_TEXT, '">',
            label, '</text>'
        );
    }

    function _footer(
        CombinedRiskReport memory r,
        uint256 tokenId,
        string memory statusColor,
        string memory statusLabel
    ) internal pure returns (string memory) {
        string memory verifiedBadge = r.contractVerified
            ? string.concat('<text x="404" y="258" font-family="monospace" font-size="7" fill="', C_SAFE, '" text-anchor="end">✓ VERIFIED</text>')
            : string.concat('<text x="404" y="258" font-family="monospace" font-size="7" fill="', C_WARN, '" text-anchor="end">⚠ UNVERIFIED</text>');

        string memory impactStr = r.priceImpactBps > 0
            ? string.concat("Impact:", uint256(r.priceImpactBps).toString(), "bps")
            : (r.outputDiscrepancyBps > 0
                ? string.concat("Slippage:", uint256(r.outputDiscrepancyBps).toString(), "bps")
                : "");

        return string.concat(
            // Divider
            '<line x1="16" y1="242" x2="404" y2="242" stroke="', C_BORDER, '" stroke-width="1"/>',
            // Target
            '<text x="16" y="255" font-family="monospace" font-size="8" fill="', C_MUTED, '">TARGET</text>',
            '<text x="16" y="266" font-family="monospace" font-size="9" fill="', C_TEXT, '">', _shortAddr(r.target), '</text>',
            // Amount
            '<text x="130" y="255" font-family="monospace" font-size="8" fill="', C_MUTED, '">AMOUNT</text>',
            '<text x="130" y="266" font-family="monospace" font-size="9" fill="', C_TEXT, '">', _shortNum(r.amount), '</text>',
            // Block
            '<text x="248" y="255" font-family="monospace" font-size="8" fill="', C_MUTED, '">BLOCK</text>',
            '<text x="248" y="266" font-family="monospace" font-size="9" fill="', C_TEXT, '">', r.blockNumber.toString(), '</text>',
            // Verified badge
            verifiedBadge,
            // Divider
            '<line x1="16" y1="273" x2="404" y2="273" stroke="', C_BORDER, '" stroke-width="1"/>',
            // Impact / discrepancy
            '<text x="16" y="287" font-family="monospace" font-size="7.5" fill="', C_MUTED, '">', impactStr, '</text>',
            // Status badge
            '<rect x="308" y="278" width="96" height="18" rx="9" fill="', statusColor, '" fill-opacity="0.15" stroke="', statusColor, '" stroke-width="1"/>',
            '<circle cx="323" cy="287" r="3.5" fill="', statusColor, '"/>',
            '<text x="353" y="291" font-family="monospace" font-size="8.5" fill="', statusColor, '" text-anchor="middle">', statusLabel, '</text>'
        );
    }

    // ── Pure helpers ───────────────────────────────────────────────────────────

    function _cleanCount(uint8 total, uint8 crit, uint8 soft) internal pure returns (string memory) {
        uint8 c = (total > crit + soft) ? total - crit - soft : 0;
        return uint256(c).toString();
    }

    function _shortAddr(address addr) internal pure returns (string memory) {
        string memory full = addr.toHexString();
        bytes memory b    = bytes(full);
        bytes memory out  = new bytes(13);
        for (uint i = 0; i < 8; i++) out[i] = b[i];
        out[8]  = "."; out[9]  = "."; out[10] = ".";
        out[11] = b[38]; out[12] = b[39];
        return string(out);
    }

    function _shortNum(uint256 n) internal pure returns (string memory) {
        if (n == 0)      return "0";
        if (n >= 1e18)   return string.concat((n / 1e15).toString(), "e15");
        if (n >= 1e9)    return string.concat((n / 1e6).toString(),  "e6");
        if (n >= 1e6)    return string.concat((n / 1e3).toString(),  "e3");
        return n.toString();
    }
}
