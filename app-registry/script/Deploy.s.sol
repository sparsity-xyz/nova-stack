// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {
    ZkCoProcessorConfig,
    ZkCoProcessorType,
    INitroEnclaveVerifier
} from "../src/interfaces/INitroEnclaveVerifier.sol";
import {NitroEnclaveVerifier} from "../src/NitroEnclaveVerifier.sol";
import {SparsityAppRegistry} from "../src/SparsityAppRegistry.sol";
import {SP1Verifier} from "@sp1-contracts/v5.0.0/SP1VerifierGroth16.sol";
import {LibString} from "@solady/utils/LibString.sol";

/**
 * @title Deploy
 * @notice Single script to deploy all contracts atomically
 *
 * Usage:
 *   forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
 *
 * This script deploys:
 * 1. SP1 Verifier
 * 2. NitroEnclaveVerifier
 * 3. SparsityAppRegistry
 * 4. Configures everything and registers verifier
 */
contract DeployScript is Script {
    using LibString for string;
    using LibString for uint256;

    // Deployment addresses
    address public sp1Verifier;
    address public nitroVerifier;
    address public registry;

    function run() public {
        console.log("====================================");
        console.log("Starting Full Deployment");
        console.log("====================================");
        console.log("Chain ID:", block.chainid);
        console.log("Deployer:", msg.sender);
        console.log("");

        vm.startBroadcast();

        // 1. Deploy SP1 Verifier
        console.log("1/4: Deploying SP1 Verifier...");
        sp1Verifier = address(new SP1Verifier());
        console.log("  SP1 Verifier:", sp1Verifier);

        // 2. Deploy NitroEnclaveVerifier
        console.log("2/4: Deploying NitroEnclaveVerifier...");
        NitroEnclaveVerifier verifier = new NitroEnclaveVerifier(
            108000,
            new bytes32[](0)
        );
        nitroVerifier = address(verifier);
        console.log("  NitroEnclaveVerifier:", nitroVerifier);

        // 3. Set root certificate and configure SP1
        console.log("3/4: Configuring NitroEnclaveVerifier...");

        bytes memory rootCert = vm.readFileBinary("samples/aws_root.der");
        bytes32 rootCertHash = sha256(rootCert);
        verifier.setRootCert(rootCertHash);
        console.log("  Root cert hash:");
        console.logBytes32(rootCertHash);

        // SP1 Configuration
        string memory sp1Json = vm.readFile("samples/sp1_program_id.json");
        bytes32 sp1VerifierId = vm.parseJsonBytes32(
            sp1Json,
            ".program_id.verifier_id"
        );
        bytes32 sp1VerifierProofId = vm.parseJsonBytes32(
            sp1Json,
            ".program_id.verifier_proof_id"
        );
        bytes32 sp1AggregatorId = vm.parseJsonBytes32(
            sp1Json,
            ".program_id.aggregator_id"
        );

        verifier.setZkConfiguration(
            ZkCoProcessorType.Succinct,
            ZkCoProcessorConfig({
                verifierId: sp1VerifierId,
                verifierProofId: sp1VerifierProofId,
                aggregatorId: sp1AggregatorId,
                zkVerifier: sp1Verifier
            })
        );
        console.log("  SP1 configured");

        // 4. Deploy SparsityAppRegistry and register verifier
        console.log("4/4: Deploying SparsityAppRegistry...");
        SparsityAppRegistry appRegistry = new SparsityAppRegistry();
        registry = address(appRegistry);
        console.log("  SparsityAppRegistry:", registry);

        appRegistry.setZKVerifier(nitroVerifier);
        console.log("  Verifier registered with registry");

        vm.stopBroadcast();

        // Save deployment addresses
        saveDeployment();

        console.log("");
        console.log("====================================");
        console.log("Deployment Complete!");
        console.log("====================================");
    }

    function saveDeployment() internal {
        // Ensure deployments directory exists
        if (!vm.exists("deployments")) {
            vm.createDir("deployments", false);
        }

        string memory chainId = block.chainid.toString();
        string memory fp = string(
            abi.encodePacked("deployments/", chainId, ".json")
        );

        string memory deployment = "deployment";
        vm.serializeAddress(deployment, "SP1_VERIFIER", sp1Verifier);
        vm.serializeAddress(deployment, "VERIFIER", nitroVerifier);
        deployment = vm.serializeAddress(deployment, "REGISTRY", registry);

        vm.writeFile(fp, deployment);

        console.log("");
        console.log("Deployment saved to:", fp);
        console.log(deployment);
    }
}
