// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {ITokenGuard, TokenGuardResult} from "./interfaces/ITokenGuard.sol";

/**
 * @title  VaultGuard
 * @notice Pre-transaction security guard for ERC-4626 vaults.
 *         Supports all four ERC-4626 operations: deposit, mint, withdraw, redeem.
 *  Checks performed:
 *   - Vault-level: whitelist, zero supply, donation attack, balance mismatch, share inflation
 *   - Operation-level: zero shares/assets out, dust shares/assets, cap checks, exchange rate anomaly, preview vs convert mismatch
 *   - Token-level: all TokenGuard checks on the vault's asset
 *
 */
contract VaultGuard is UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    struct VaultGuardResult {
        // ----- Vault-level risks -----
        bool VAULT_NOT_WHITELISTED; // vault not in operator whitelist
        bool VAULT_ZERO_SUPPLY; // totalSupply == 0  (fresh vault)
        bool DONATION_ATTACK; // zero-supply vault with large pre-loaded assets
        bool SHARE_INFLATION_RISK; // assets/share ratio suspiciously large vs expected
        bool VAULT_BALANCE_MISMATCH; // realBalance < totalAssets (vault is undercollateralised)
        bool EXCHANGE_RATE_ANOMALY; // preview rate deviates > MAX_DEVIATION_BPS from vault rate
        bool PREVIEW_REVERT; // preview function reverted (hostile vault)
        // ----- Operation risks -----
        bool ZERO_SHARES_OUT; // deposit would mint 0 shares
        bool ZERO_ASSETS_OUT; // redeem would return 0 assets
        bool DUST_SHARES; // shares below MIN_SHARES threshold
        bool DUST_ASSETS; // assets below MIN_ASSETS threshold
        bool EXCEEDS_MAX_DEPOSIT; // amount > vault.maxDeposit(user)
        bool EXCEEDS_MAX_REDEEM; // amount > vault.maxRedeem(user)
        bool PREVIEW_CONVERT_MISMATCH; // previewDeposit vs convertToShares disagree > tolerance
        // ----- Token risks -----
        TokenGuardResult tokenResult;
    }

    // CONSTANTS //

    uint256 public constant MAX_BPS = 10_000;
    uint256 public constant MAX_DEVIATION_BPS = 500; // 5% — exchange rate tolerance
    uint256 public constant PREVIEW_TOLERANCE_BPS = 100; // 1% — previewDeposit vs convertToShares
    uint256 public constant MIN_SHARES = 1e3;
    uint256 public constant MIN_ASSETS = 1e3;
    /// Vault with zero supply but totalAssets > this is a donation-attack signal.
    uint256 public constant DONATION_THRESHOLD = 1 ether;
    /// If assets-per-share > this factor of the expected 1:1 base rate, flag inflation.
    uint256 public constant INFLATION_FACTOR = 100; // 100x base rate

    // STORAGE VARIABLES //

    ITokenGuard public tokenGuard;
    mapping(address => mapping(address => bytes)) public lastCheckEncoded;
    mapping(address => mapping(address => uint256)) public lastCheckBlock;
    mapping(address => bool) public isVaultWhitelisted;
    mapping(address => uint256) public vaultIndex;
    mapping(address => bool) public authorizedRouters;
    address[] public whitelistedVaults;

    event VaultCheckPerformed(address indexed vault, address indexed user);
    event VaultWhitelisted(address indexed vault);
    event VaultRemoved(address indexed vault);
    event CheckStored(address indexed vault, address indexed user, uint256 blockNumber);
    event RouterAuthorized(address indexed router, bool authorized);

    modifier onlyAuthorizedRouter() {
        require(authorizedRouters[msg.sender], "NOT_AUTHORIZED_ROUTER");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _tokenGuard) public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        tokenGuard = ITokenGuard(_tokenGuard);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    //  EXTERNAL VIEW FUNCTIONS  //

    /**
     * @notice Returns the decoded last stored check for a vault + user.
     */
    function getLastCheck(address vault, address user)
        external
        view
        returns (VaultGuardResult memory result, uint256 previewShares, uint256 previewAssets, uint256 blockNumber)
    {
        bytes memory encoded = lastCheckEncoded[vault][user];
        require(encoded.length > 0, "NO_CHECK_STORED");
        (result, previewShares, previewAssets) = abi.decode(encoded, (VaultGuardResult, uint256, uint256));
        blockNumber = lastCheckBlock[vault][user];
    }

    function getWhitelistedVaults() external view returns (address[] memory) {
        return whitelistedVaults;
    }

    function isWhitelisted(address vault) public view returns (bool) {
        return isVaultWhitelisted[vault];
    }

    /**
     * @notice Standalone view-style check . Uses msg.sender for cap checks.
     */
    function checkVault(address vault, uint256 amount, bool isDeposit)
        external
        returns (VaultGuardResult memory result, uint256 previewShares, uint256 previewAssets)
    {
        emit VaultCheckPerformed(vault, msg.sender);
        return _checkVault(vault, amount, isDeposit, msg.sender);
    }

    // EXTERNAL FUNCTIONS (STATE-CHANGING) //
    /**
     * @notice Records the vault state fingerprint for the caller in this block.
     *         Must be called in the same block as guardedDeposit / guardedWithdraw.
     *
     */
    function storeCheck(address vault, address user, uint256 amount, bool isDeposit)
        external
        nonReentrant
        onlyAuthorizedRouter
        returns (VaultGuardResult memory result, uint256 previewShares, uint256 previewAssets)
    {
        (VaultGuardResult memory res, uint256 pShares, uint256 pAssets) = _checkVault(vault, amount, isDeposit, user);

        lastCheckEncoded[vault][user] = abi.encode(res, pShares, pAssets);
        lastCheckBlock[vault][user] = block.number;

        emit CheckStored(vault, user, block.number);
        return (res, pShares, pAssets);
    }

    // INTERNAL FUNCTIONS

    /**
     * @notice Core check function that performs all validations and returns a comprehensive result struct.
     * @dev This is called by both the external checkVault (for off-chain use) and the internal storeCheck (before encoding).
     * @param vault     ERC4626 vault address
     * @param amount    Assets (for deposit) or shares (for redeem)
     * @param isDeposit true = deposit flow; false = redeem flow
     * @param user      Address performing the operation (used for cap checks)
     */
    function _checkVault(address vault, uint256 amount, bool isDeposit, address user)
        internal
        view
        returns (VaultGuardResult memory result, uint256 previewShares, uint256 previewAssets)
    {
        IERC4626 v = IERC4626(vault);
        address asset = v.asset();

        result.tokenResult = tokenGuard.checkToken(asset);

        uint256 totalAssets = v.totalAssets();
        uint256 totalSupply = v.totalSupply();

        if (!isVaultWhitelisted[vault]) {
            result.VAULT_NOT_WHITELISTED = true;
        }

        if (totalSupply == 0) {
            result.VAULT_ZERO_SUPPLY = true;
            if (totalAssets > DONATION_THRESHOLD) {
                result.DONATION_ATTACK = true;
            }
        }

        // Balance mismatch (undercollateralisation
        // The risk is realBalance < totalAssets: vault is promising more than it holds.
        uint256 realBalance = IERC20(asset).balanceOf(vault);
        if (realBalance < totalAssets) {
            result.VAULT_BALANCE_MISMATCH = true;
        }

        // Even with supply > 0, a manipulator can push assets-per-share very high,
        // causing future depositors to receive rounding-down to 0 shares.
        if (totalSupply > 0) {
            uint8 assetDec = _safeDecimals(asset);
            uint8 vaultDec = _safeDecimals(vault);
            uint256 normAssets = _normalize(totalAssets, assetDec);
            uint256 normSupply = _normalize(totalSupply, vaultDec);
            // assetsPerShare in 1e18
            uint256 assetsPerShare = (normAssets * 1e18) / normSupply;
            // Ideally 1:1 in normalised terms.
            // Flag if ratio > INFLATION_FACTOR × expected.
            if (assetsPerShare > INFLATION_FACTOR * 1e18) {
                result.SHARE_INFLATION_RISK = true;
            }
        }

        if (totalSupply > 0 && totalAssets > 0) {
            uint8 assetDec = _safeDecimals(asset);
            uint8 vaultDec = _safeDecimals(vault);
            uint256 normAssets = _normalize(totalAssets, assetDec);
            uint256 normSupply = _normalize(totalSupply, vaultDec);
            // Vault-level exchange rate (normalised, 1e18 precision)
            uint256 vaultRate = (normAssets * 1e18) / normSupply;

            if (isDeposit) {
                try v.maxDeposit(user) returns (uint256 cap) {
                    if (amount > cap) result.EXCEEDS_MAX_DEPOSIT = true;
                } catch {}

                try v.previewDeposit(amount) returns (uint256 s) {
                    previewShares = s;
                } catch {
                    result.PREVIEW_REVERT = true;
                    return (result, 0, 0);
                }

                if (previewShares == 0) result.ZERO_SHARES_OUT = true;
                if (previewShares < MIN_SHARES) result.DUST_SHARES = true;

                if (previewShares > 0) {
                    uint256 normShares = _normalize(previewShares, vaultDec);
                    uint256 normAmount = _normalize(amount, assetDec);
                    uint256 opRate = (normAmount * 1e18) / normShares;
                    if (_bpsDelta(vaultRate, opRate) > MAX_DEVIATION_BPS) {
                        result.EXCHANGE_RATE_ANOMALY = true;
                    }
                }

                // Cross-check previewDeposit vs convertToShares
                // They must agree within PREVIEW_TOLERANCE_BPS.
                try v.convertToShares(amount) returns (uint256 converted) {
                    if (
                        previewShares > 0 && converted > 0
                            && _bpsDelta(previewShares, converted) > PREVIEW_TOLERANCE_BPS
                    ) {
                        result.PREVIEW_CONVERT_MISMATCH = true;
                    }
                } catch {}
            } else {
                try v.maxRedeem(user) returns (uint256 cap) {
                    if (amount > cap) result.EXCEEDS_MAX_REDEEM = true;
                } catch {}

                try v.previewRedeem(amount) returns (uint256 a) {
                    previewAssets = a;
                } catch {
                    result.PREVIEW_REVERT = true;
                    return (result, 0, 0);
                }

                if (previewAssets == 0) result.ZERO_ASSETS_OUT = true;
                if (previewAssets < MIN_ASSETS) result.DUST_ASSETS = true;

                if (previewAssets > 0) {
                    uint256 normAssetsOut = _normalize(previewAssets, assetDec);
                    uint256 normShares = _normalize(amount, vaultDec);
                    uint256 opRate = (normAssetsOut * 1e18) / normShares;
                    if (_bpsDelta(vaultRate, opRate) > MAX_DEVIATION_BPS) {
                        result.EXCHANGE_RATE_ANOMALY = true;
                    }
                }

                // Cross-check previewRedeem vs convertToAssets
                try v.convertToAssets(amount) returns (uint256 converted) {
                    if (
                        previewAssets > 0 && converted > 0
                            && _bpsDelta(previewAssets, converted) > PREVIEW_TOLERANCE_BPS
                    ) {
                        result.PREVIEW_CONVERT_MISMATCH = true;
                    }
                } catch {}
            }
        }
    }

    function _validate(address vault, address user, uint256 amount, bool isDeposit) internal view {
        require(lastCheckBlock[vault][user] == block.number, "STALE_CHECK");

        (VaultGuardResult memory res, uint256 pShares, uint256 pAssets) = _checkVault(vault, amount, isDeposit, user);

        bytes32 currentFingerprint = keccak256(abi.encode(res, pShares, pAssets));
        bytes32 storedFingerprint = keccak256(lastCheckEncoded[vault][user]);

        require(currentFingerprint == storedFingerprint, "VAULT_STATE_CHANGED");
    }

    // OWNER-ONLY FUNCTIONS

    function whitelistVault(address vault) external onlyOwner {
        require(vault != address(0), "ZERO_ADDRESS");
        require(!isVaultWhitelisted[vault], "ALREADY_WHITELISTED");
        isVaultWhitelisted[vault] = true;
        vaultIndex[vault] = whitelistedVaults.length;
        whitelistedVaults.push(vault);
        emit VaultWhitelisted(vault);
    }

    function addWhitelistedVaults(address[] calldata vaults) external onlyOwner {
        for (uint256 i = 0; i < vaults.length;) {
            address v = vaults[i];
            if (v != address(0) && !isVaultWhitelisted[v]) {
                isVaultWhitelisted[v] = true;
                vaultIndex[v] = whitelistedVaults.length;
                whitelistedVaults.push(v);
                emit VaultWhitelisted(v);
            }
            unchecked {
                ++i;
            }
        }
    }

    function removeWhitelistedVault(address vault) external onlyOwner {
        require(isVaultWhitelisted[vault], "NOT_WHITELISTED");
        uint256 idx = vaultIndex[vault];
        uint256 lastIdx = whitelistedVaults.length - 1;
        address lastVault = whitelistedVaults[lastIdx];

        whitelistedVaults[idx] = lastVault;
        vaultIndex[lastVault] = idx;
        whitelistedVaults.pop();

        delete vaultIndex[vault];
        delete isVaultWhitelisted[vault];
        emit VaultRemoved(vault);
    }

    function setAuthorizedRouter(address router, bool authorized) external onlyOwner {
        require(router != address(0), "ZERO_ADDRESS");
        authorizedRouters[router] = authorized;
        emit RouterAuthorized(router, authorized);
    }

    // INTERNAL HELPER FUNCTIONS

    function _safeDecimals(address token) internal view returns (uint8) {
        try IERC20Metadata(token).decimals() returns (uint8 d) {
            return d;
        } catch {
            return 18;
        }
    }

    function _normalize(uint256 value, uint8 decimals) internal pure returns (uint256) {
        if (decimals == 18) return value;
        if (decimals < 18) return value * (10 ** (18 - decimals));
        return value / (10 ** (decimals - 18));
    }

    /// @dev Returns basis-point difference of |a - b| relative to a.
    function _bpsDelta(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0 || b == 0) return 0;
        uint256 diff = a > b ? a - b : b - a;
        return (diff * MAX_BPS) / a;
    }
}
