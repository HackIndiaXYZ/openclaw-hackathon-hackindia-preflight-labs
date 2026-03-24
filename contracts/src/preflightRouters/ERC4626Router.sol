// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/**
 * @notice Deposit assets into vault after validating state is unchanged.
 * @param vault     ERC4626 vault
 * @param user      Address performing the deposit
 * @param amount    Asset amount to deposit
 * @param receiver  Address to receive shares
 * @param minShares Slippage protection — revert if shares minted < minShares
 * @return shares   Shares minted
 */
function guardedDeposit(address vault, address user, uint256 amount, address receiver, uint256 minShares)
    external
    nonReentrant
    onlyAuthorizedRouter
    returns (uint256 shares)
{
    _validate(vault, user, amount, true);

    IERC20 asset = IERC20(IERC4626(vault).asset());
    require(asset.balanceOf(address(this)) >= amount, "INSUFFICIENT_BALANCE");

    //Use forceApprove to handle tokens that require approval reset before re-approve.
    asset.forceApprove(vault, amount);

    shares = IERC4626(vault).deposit(amount, receiver);

    require(shares > 0, "ZERO_SHARES_MINTED");
    require(shares >= minShares, "SLIPPAGE_TOO_HIGH");
}

/**
 * @notice Redeem shares from vault after validating state is unchanged.
 *
 * @param vault      ERC4626 vault
 * @param user       Address performing the redeem
 * @param shares     Share amount to burn
 * @param receiver   Address to receive assets
 * @param minAssets  Slippage protection — revert if assets received < minAssets
 * @return assets    Assets received
 */
function guardedRedeem(address vault, address user, uint256 shares, address receiver, uint256 minAssets)
    external
    nonReentrant
    onlyAuthorizedRouter
    returns (uint256 assets)
{
    _validate(vault, user, shares, false);
    require(IERC20(vault).balanceOf(address(this)) >= shares, "INSUFFICIENT_SHARES");

    //Use forceApprove to handle tokens that require approval reset before re-approve.
    IERC20(vault).forceApprove(vault, shares);

    assets = IERC4626(vault).redeem(shares, receiver, address(this));

    require(assets > 0, "ZERO_ASSETS_RETURNED");
    require(assets >= minAssets, "SLIPPAGE_TOO_HIGH");
}




