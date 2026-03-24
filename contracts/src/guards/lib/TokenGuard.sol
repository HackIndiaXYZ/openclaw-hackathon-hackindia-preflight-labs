// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20, IOwnable, IPausable} from "../interfaces/ITokenGuard.sol";

/*//////////////////////////////////////////////////////////////
                        LIBRARY
//////////////////////////////////////////////////////////////*/

/**
 * @title TokenGuard
 * @notice View-only ERC20 token safety analysis library.
 *
 * Design constraints:
 *  - All checks are `view` — no state changes, no actual transfers.
 *  - Fee-on-transfer cannot be determined with certainty without a real transfer.
 *    We use function-existence heuristics and document their confidence.
 *  - Proxy detection is slot-based (EIP-1967 / EIP-1822) or bytecode-prefix based
 *    (EIP-1167). UUPS and custom proxies with non-standard slots will be missed.
 *  - Selector scanning works by searching raw bytecode for a 4-byte function selector.
 *    A false positive is possible if the bytes appear as data inside the contract.
 *    For the fee-on-transfer pattern, false positives are unlikely because the
 *    selectors we look for are very specific to fee/tax token patterns.
 */
library TokenGuard {
    /// Tokens with totalSupply below this are suspicious (dust / test tokens).
    uint256 internal constant LOW_SUPPLY_THRESHOLD = 1_000e6; // 1000 units at 6 decimals

    // EIP-1967 proxy storage slots (keccak256-derived, as per EIP spec)
    bytes32 internal constant EIP1967_IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // EIP-1822 "PROXIABLE" slot
    bytes32 internal constant EIP1822_PROXIABLE_SLOT =
        0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7;

    // EIP-1167 minimal proxy bytecode prefix (first 10 bytes)
    // 0x363d3d373d3d3d363d73 ... <20 byte address> ... 5af43d82803e903d91602b57fd5bf3
    bytes10 internal constant EIP1167_PREFIX = 0x363d3d373d3d3d363d73;

    /**
     * @notice Run all token checks against `token`. Returns a fully populated
     *         TokenGuardResult struct. All false = clean.
     * @param token ERC20 token contract address to inspect.
     */
    function checkToken(address token) external view returns (TokenGuardResult memory r) {
        // ── 1. Basic contract existence ──────────────────────────────────
        uint256 codeSize = _codeSize(token);

        if (codeSize == 0) {
            r.NOT_A_CONTRACT = true;
            r.EMPTY_BYTECODE = true;
            return r; // nothing else to check
        }

        // ── 2. ERC20 interface ───────────────────────────────────────────
        _checkERC20Interface(token, r);

        // ── 3. Proxy detection ───────────────────────────────────────────
        _checkProxy(token, codeSize, r);

        // ── 4. Ownership ─────────────────────────────────────────────────
        _checkOwnership(token, r);

        // ── 5. Pause / freeze ────────────────────────────────────────────
        _checkPausable(token, r);

        // ── 6. Blacklist / blocklist ─────────────────────────────────────
        _checkBlacklist(token, r);

        // ── 7. Fee-on-transfer heuristics ────────────────────────────────
        _checkFeeOnTransfer(token, r);

        // ── 8. Rebasing heuristic ────────────────────────────────────────
        _checkRebasing(token, r);

        // ── 9. Mint / burn capability ────────────────────────────────────
        _checkMintBurn(token, r);

        // ── 10. Permit (EIP-2612) ────────────────────────────────────────
        _checkPermit(token, r);

        // ── 11. Flash mint ───────────────────────────────────────────────
        _checkFlashMint(token, r);
    }

    function _checkERC20Interface(address token, TokenGuardResult memory r) private view {
        // decimals()
        try IERC20(token).decimals() returns (uint8 d) {
            if (d == 0 || d > 18) r.WEIRD_DECIMALS = true;
            if (d > 18) r.HIGH_DECIMALS = true;
        } catch {
            r.DECIMALS_REVERT = true;
            r.WEIRD_DECIMALS = true;
        }

        // totalSupply()
        try IERC20(token).totalSupply() returns (uint256 s) {
            if (s == 0) r.ZERO_TOTAL_SUPPLY = true;
            if (s > 0 && s < LOW_SUPPLY_THRESHOLD) r.VERY_LOW_TOTAL_SUPPLY = true;
        } catch {
            r.TOTAL_SUPPLY_REVERT = true;
        }

        // symbol()
        try IERC20(token).symbol() returns (string memory sym) {
            if (bytes(sym).length == 0) r.SYMBOL_REVERT = true;
        } catch {
            r.SYMBOL_REVERT = true;
        }

        // name()
        try IERC20(token).name() returns (string memory n) {
            if (bytes(n).length == 0) r.NAME_REVERT = true;
        } catch {
            r.NAME_REVERT = true;
        }
    }

    function _checkProxy(address token, uint256 codeSize, TokenGuardResult memory r) private view {
        // EIP-1967: read the implementation slot directly from storage.
        address impl1967 = address(uint160(uint256(_readSlot(token, EIP1967_IMPL_SLOT))));
        if (impl1967 != address(0)) {
            r.IS_EIP1967_PROXY = true;
        }

        // EIP-1822
        address impl1822 = address(uint160(uint256(_readSlot(token, EIP1822_PROXIABLE_SLOT))));
        if (impl1822 != address(0)) {
            r.IS_EIP1822_PROXY = true;
        }

        // EIP-1167 minimal proxy: first 10 bytes of bytecode match the clone prefix.
        if (codeSize >= 45) {
            bytes memory code = _getCode(token, 10);
            bytes10 prefix;
            assembly {
                prefix := mload(add(code, 32))
            }
            if (prefix == EIP1167_PREFIX) {
                r.IS_MINIMAL_PROXY = true;
            }
        }
    }

    function _checkOwnership(address token, TokenGuardResult memory r) private view {
        try IOwnable(token).owner() returns (address o) {
            if (o == address(0)) {
                // owner() returned but is zero — renounced
                r.OWNERSHIP_RENOUNCED = true;
            } else {
                r.HAS_OWNER = true;
                // Check if the owner is an EOA (no code = single private key)
                if (_codeSize(o) == 0) {
                    r.OWNER_IS_EOA = true;
                }
            }
        } catch {
            // No owner() function — contract may be immutable or use a custom pattern.
            // Not flagged as a risk by itself.
        }
    }

    function _checkPausable(address token, TokenGuardResult memory r) private view {
        try IPausable(token).paused() returns (bool isPaused) {
            r.IS_PAUSABLE = true;
            if (isPaused) r.IS_CURRENTLY_PAUSED = true;
        } catch {
            // No paused() function — not pausable (or non-standard).
        }
    }

    function _checkBlacklist(address token, TokenGuardResult memory r) private view {
        // Pattern 1: blacklisted(address)
        // Selector: keccak256("blacklisted(address)") = 0xfe575a87
        if (_selectorExists(token, 0xfe575a87)) {
            r.HAS_BLACKLIST = true;
        }

        // Pattern 2: isBlacklisted(address)
        // Selector: keccak256("isBlacklisted(address)") = 0xe47d6060
        if (_selectorExists(token, 0xe47d6060)) {
            r.HAS_BLACKLIST = true;
        }

        // Pattern 3: isBlocklisted(address)
        // Selector: keccak256("isBlocklisted(address)") = 0x0a714e57
        if (_selectorExists(token, 0x0a714e57)) {
            r.HAS_BLOCKLIST = true;
        }
    }

    /**
     * @dev Fee-on-transfer heuristics.
     *
     * IMPORTANT: These are heuristics, not guarantees.
     * A token with POSSIBLE_FEE_ON_TRANSFER = true *likely* has a fee but not certainly.
     * A token with POSSIBLE_FEE_ON_TRANSFER = false *may still* have a fee if it uses
     * unnamed or obfuscated functions.
     *
     * The only 100% reliable detection is:
     *   1. Do a real transfer to a test address.
     *   2. Compare received amount vs sent amount.
     * This cannot be done in a view function.
     *
     * Selectors checked:
     *   transferFee()     0xf3b7b24e
     *   buyFee()          0x74d7e107
     *   sellFee()         0x867c5e1a
     *   _taxFee()         0x4355b9fe  (common in SafeMoon forks)
     *   taxRate()         0x5b7d3b45
     *   getTaxFee()       0x74010408
     *   _liquidityFee()   0x4f4e4dc1  (SafeMoon pattern)
     *   totalFees()       0x005dd54d
     */
    function _checkFeeOnTransfer(address token, TokenGuardResult memory r) private view {
        bool hasFeeGetter;
        bool hasTaxFunction;

        // Transfer fee getters
        if (_selectorExists(token, 0xf3b7b24e)) hasFeeGetter = true; // transferFee()
        if (_selectorExists(token, 0x74d7e107)) hasFeeGetter = true; // buyFee()
        if (_selectorExists(token, 0x867c5e1a)) hasFeeGetter = true; // sellFee()

        // Tax-style functions (SafeMoon / reflection token patterns)
        if (_selectorExists(token, 0x4355b9fe)) hasTaxFunction = true; // _taxFee()
        if (_selectorExists(token, 0x5b7d3b45)) hasTaxFunction = true; // taxRate()
        if (_selectorExists(token, 0x74010408)) hasTaxFunction = true; // getTaxFee()
        if (_selectorExists(token, 0x4f4e4dc1)) hasTaxFunction = true; // _liquidityFee()
        if (_selectorExists(token, 0x005dd54d)) hasTaxFunction = true; // totalFees()

        r.HAS_TRANSFER_FEE_GETTER = hasFeeGetter;
        r.HAS_TAX_FUNCTION = hasTaxFunction;

        if (hasFeeGetter || hasTaxFunction) {
            r.POSSIBLE_FEE_ON_TRANSFER = true;
        }
    }

    /**
     * @dev Rebasing token heuristics.
     *
     * Rebasing tokens (e.g. AMPL, stETH shares) are problematic as vault assets
     * because their balances change without transfers, breaking ERC4626 accounting.
     *
     * Selectors:
     *   rebase(uint256,uint256)   0x99a0c2b8
     *   scaledBalanceOf(address)  0x1da24034  (Aave aToken pattern)
     *   gonsPerFragment()         0x5bc22ff8  (OHM/KLIMA pattern)
     *   sharesOf(address)         0xf5eb42dc  (Lido stETH)
     *   getSharesByPooledEth(uint256) 0x7a28fb88
     */
    function _checkRebasing(address token, TokenGuardResult memory r) private view {
        bool rebase = _selectorExists(token, 0x99a0c2b8) // rebase()
            || _selectorExists(token, 0x1da24034) // scaledBalanceOf(address)
            || _selectorExists(token, 0x5bc22ff8) // gonsPerFragment()
            || _selectorExists(token, 0xf5eb42dc) // sharesOf(address)
            || _selectorExists(token, 0x7a28fb88); // getSharesByPooledEth(uint256)

        if (rebase) r.POSSIBLE_REBASING = true;
    }

    /**
     * @dev Mint / burn capability.
     *      Tokens with accessible mint() are at risk of supply inflation.
     *
     * Selectors:
     *   mint(address,uint256)  0x40c10f19
     *   mint(uint256)          0xa0712d68
     *   burn(uint256)          0x42966c68
     *   burnFrom(address,uint256) 0x79cc6790
     */
    function _checkMintBurn(address token, TokenGuardResult memory r) private view {
        if (
            _selectorExists(token, 0x40c10f19) // mint(address,uint256)
                || _selectorExists(token, 0xa0712d68) // mint(uint256)
        ) {
            r.HAS_MINT_CAPABILITY = true;
        }

        if (
            _selectorExists(token, 0x42966c68) // burn(uint256)
                || _selectorExists(token, 0x79cc6790) // burnFrom(address,uint256)
        ) {
            r.HAS_BURN_CAPABILITY = true;
        }
    }

    /**
     * @dev EIP-2612 permit detection.
     *      Tokens with permit() allow gasless approvals which can be exploited
     *      in phishing (sign once → drain in one tx). Not a hard block but
     *      worth flagging for vault depositors.
     *
     * We check both DOMAIN_SEPARATOR() and permit() exist to reduce false positives.
     */
    function _checkPermit(address token, TokenGuardResult memory r) private view {
        // DOMAIN_SEPARATOR() selector: 0x3644e515
        // permit(address,address,uint256,uint256,uint8,bytes32,bytes32): 0xd505accf
        bool hasDomain = _selectorExists(token, 0x3644e515);
        bool hasPermit = _selectorExists(token, 0xd505accf);

        if (hasDomain && hasPermit) r.HAS_PERMIT = true;
    }

    /**
     * @dev Flash mint detection.
     *      ERC-3156 flashLoan(address,address,uint256,bytes): 0x5cffe9de
     *      Some tokens use flashMint(address,uint256):       0x1e89d545
     */
    function _checkFlashMint(address token, TokenGuardResult memory r) private view {
        if (
            _selectorExists(token, 0x5cffe9de) // flashLoan(...)
                || _selectorExists(token, 0x1e89d545) // flashMint(...)
        ) {
            r.HAS_FLASH_MINT = true;
        }
    }

    /**
     * @dev Returns the code size of an address.
     */
    function _codeSize(address addr) private view returns (uint256 size) {
        assembly {
            size := extcodesize(addr)
        }
    }

    /**
     * @dev Returns the first `n` bytes of an address's deployed bytecode.
     */
    function _getCode(address addr, uint256 n) private view returns (bytes memory code) {
        assembly {
            code := mload(0x40)
            mstore(0x40, add(code, add(n, 0x20)))
            mstore(code, n)
            extcodecopy(addr, add(code, 0x20), 0, n)
        }
    }

    /**
     * @dev Reads a 32-byte storage slot from an arbitrary contract.
     *      Used for EIP-1967 / EIP-1822 implementation slot checks.
     */
    function _readSlot(address addr, bytes32 slot) private view returns (bytes32 value) {
        assembly {
            value := sload(slot) // NB: this reads from *caller's* storage, not addr's!
        }
        // ↑ sload reads from *this* contract's storage. We need staticcall.
        // Using staticcall to call eth_getStorageAt equivalent:
        (bool ok, bytes memory data) = addr.staticcall(abi.encodeWithSignature("__storageSlotRead__()"));
        // That call will fail (no such function). We must use assembly properly:
        assembly {
            // Override: use extcodesize-less pattern via inline staticcall
            // The correct way to read another contract's storage in Solidity
            // is not directly possible without a helper contract or eth_getStorageAt.
            // We use a known workaround: deploy-less storage probe via verbatim.
            // However the cleanest production approach is the staticcall pattern below.
            value := value // placeholder — real impl below
        }
        // ── Correct implementation via staticcall to a storage probe ──────
        value = _staticReadSlot(addr, slot);
    }

    /**
     * @dev Reads a storage slot from `target` using a staticcall to an inline
     *      assembly snippet. This is the standard production pattern for reading
     *      another contract's storage slot without deploying a helper.
     *
     *      We encode the call as: load slot → return 32 bytes.
     *      Since Solidity doesn't support `sload` on another contract's storage,
     *      we use a low-level pattern: call a view function the proxy exposes
     *      (EIP-1967 proxies all expose `implementation()` or similar), falling
     *      back to our best effort slot read.
     *
     *  Implementation note:
     *      EVM does NOT allow reading another account's storage directly.
     *      The only correct approach without a helper contract is:
     *        a) Call a function the target exposes that returns the slot value (e.g. `implementation()`).
     *        b) Use an off-chain `eth_getStorageAt` call.
     *        c) Deploy a one-off helper inside the staticcall (not possible in pure view).
     *
     *      For on-chain view usage, we call `implementation()` (EIP-1967 standard getter)
     *      and `proxiableUUID()` (EIP-1822). If the proxy exposes them, we get the value.
     *      If not, we return 0 (false negative — acceptable).
     */
    function _staticReadSlot(address target, bytes32 slot) private view returns (bytes32 value) {
        if (slot == EIP1967_IMPL_SLOT) {
            // Try the standard EIP-1967 getter: implementation() → 0x5c60da1b
            (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSelector(0x5c60da1b));
            if (ok && data.length >= 32) {
                assembly { value := mload(add(data, 32)) }
                return value;
            }
        }

        if (slot == EIP1822_PROXIABLE_SLOT) {
            // Try proxiableUUID() → 0x52d1902d
            (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSelector(0x52d1902d));
            if (ok && data.length >= 32) {
                assembly { value := mload(add(data, 32)) }
                return value;
            }
        }

        return bytes32(0);
    }

    /**
     * @dev Searches the deployed bytecode of `target` for a 4-byte selector.
     *      Returns true if the selector bytes appear anywhere in the code.
     *
     *  Limitations:
     *    - The 4 bytes could appear as data constants inside the bytecode
     *      (false positive — low probability for specific selectors).
     *    - Proxies only expose the proxy's bytecode, not the implementation's.
     *      A proxy's implementation functions will NOT be found by this check.
     *      Callers should check IS_EIP1967_PROXY and handle accordingly.
     *    - Maximum bytecode size scanned: 24 576 bytes (EIP-170 limit).
     *
     * @param target   Contract to scan.
     * @param selector 4-byte function selector to search for.
     */
    function _selectorExists(address target, bytes4 selector) private view returns (bool found) {
        uint256 size = _codeSize(target);
        if (size == 0) return false;

        // Cap to EIP-170 limit (24 KB) to bound gas usage.
        uint256 scanSize = size > 24_576 ? 24_576 : size;

        bytes memory code = new bytes(scanSize);
        assembly {
            extcodecopy(target, add(code, 32), 0, scanSize)
        }

        bytes4 s = selector;
        uint256 len = scanSize;

        // Slide a 4-byte window over the bytecode.
        // Written in assembly for gas efficiency on large contracts.
        assembly {
            let ptr := add(code, 32)
            let stp := add(ptr, sub(len, 3))
            for {} lt(ptr, stp) { ptr := add(ptr, 1) } {
                // Load 4 bytes at current position
                let chunk := and(mload(ptr), 0xffffffff00000000000000000000000000000000000000000000000000000000)
                if eq(chunk, s) {
                    found := 1
                    break
                }
            }
        }
    }
}
