// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console2.sol";

import "../src/guards/VaultGuard.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployVaultGuard is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        // 1️⃣ Deploy Implementation
        VaultGuard implementation = new VaultGuard();

        // 2️⃣ Encode initializer
        bytes memory initData = abi.encodeWithSelector(VaultGuard.initialize.selector);

        // 3️⃣ Deploy Proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        // 4️⃣ Cast proxy to VaultGuard interface
        VaultGuard vaultGuard = VaultGuard(address(proxy));

        vm.stopBroadcast();

        // 5️⃣ Logs
        console2.log("VaultGuard Implementation:", address(implementation));
        console2.log("VaultGuard Proxy:", address(proxy));
        console2.log("VaultGuard Owner:", vaultGuard.owner());
    }
}
