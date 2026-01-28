// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/BTCPriceOracle.sol";

contract DeployScript is Script {
    function run() external {
        vm.startBroadcast();

        // Deploy with deployer as initial oracle (will update later)
        address registryAddress = vm.envOr("REGISTRY_CONTRACT", msg.sender);
        BTCPriceOracle oracle = new BTCPriceOracle(registryAddress, msg.sender);

        console.log("BTCPriceOracle deployed to:", address(oracle));
        console.log("Initial oracle (deployer):", msg.sender);
        console.log("");
        console.log("Next steps:");
        console.log("1. make set-contract-address CONTRACT=<above_address>");
        console.log("2. make deploy-enclave");
        console.log("3. make get-address");
        console.log("4. make set-oracle ORACLE=<enclave_address>");

        vm.stopBroadcast();
    }
}
