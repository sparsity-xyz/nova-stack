// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.33;

import {Script, console} from "forge-std/Script.sol";
import {
    ZkCoProcessorConfig,
    ZkCoProcessorType
} from "../src/interfaces/INitroEnclaveVerifier.sol";
import {NitroEnclaveVerifier} from "../src/NitroEnclaveVerifier.sol";
import {NovaAppRegistry} from "../src/NovaAppRegistry.sol";
import {SP1Verifier} from "@sp1-contracts/v5.0.0/SP1VerifierGroth16.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {LibString} from "@solady/utils/LibString.sol";

/**
 * @title DeployNova
 * @notice Deploy script for NovaAppRegistry with UUPS upgradeable pattern
 *
 * Usage:
 *   forge script script/DeployNova.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
 *
 * This script deploys:
 * 1. SP1 Verifier
 * 2. NitroEnclaveVerifier
 * 3. NovaAppRegistry (Implementation)
 * 4. ERC1967Proxy pointing to NovaAppRegistry
 * 5. Configures everything
 */
contract DeployNovaScript is Script {
    using LibString for string;
    using LibString for uint256;

    // Deployment addresses
    address public sp1Verifier;
    address public nitroVerifier;
    address public registryImplementation;
    address public registryProxy;

    function run() public {
        console.log("====================================");
        console.log("Starting Nova Platform Deployment");
        console.log("====================================");
        console.log("Chain ID:", block.chainid);
        console.log("Deployer:", msg.sender);
        console.log("");

        vm.startBroadcast();

        // 1. Deploy SP1 Verifier
        console.log("1/5: Deploying SP1 Verifier...");
        sp1Verifier = address(new SP1Verifier());
        console.log("  SP1 Verifier:", sp1Verifier);

        // 2. Deploy NitroEnclaveVerifier
        console.log("2/5: Deploying NitroEnclaveVerifier...");
        NitroEnclaveVerifier verifier = new NitroEnclaveVerifier(
            108000,
            new bytes32[](0)
        );
        nitroVerifier = address(verifier);
        console.log("  NitroEnclaveVerifier:", nitroVerifier);

        // 3. Configure NitroEnclaveVerifier
        console.log("3/5: Configuring NitroEnclaveVerifier...");
        configureVerifier(verifier);

        // 4. Deploy NovaAppRegistry Implementation
        console.log("4/5: Deploying NovaAppRegistry Implementation...");
        NovaAppRegistry implementation = new NovaAppRegistry();
        registryImplementation = address(implementation);
        console.log("  Implementation:", registryImplementation);

        // 5. Deploy ERC1967Proxy with initialization
        console.log("5/5: Deploying Proxy and Initializing...");
        bytes memory initData = abi.encodeCall(
            NovaAppRegistry.initialize,
            (nitroVerifier)
        );

        ERC1967Proxy proxy = new ERC1967Proxy(registryImplementation, initData);
        registryProxy = address(proxy);
        console.log("  Proxy:", registryProxy);

        vm.stopBroadcast();

        // Verify initialization
        NovaAppRegistry registry = NovaAppRegistry(registryProxy);
        console.log("  Owner:", registry.owner());
        console.log("  ZK Verifier:", registry.zkVerifier());

        // Save deployment addresses
        saveDeployment();

        console.log("");
        console.log("====================================");
        console.log("Nova Platform Deployment Complete!");
        console.log("====================================");
    }

    function configureVerifier(NitroEnclaveVerifier verifier) internal {
        // Set root certificate
        // forge-lint: disable-next-line(unsafe-cheatcode)
        bytes memory rootCert = vm.readFileBinary("samples/aws_root.der");
        bytes32 rootCertHash = sha256(rootCert);
        verifier.setRootCert(rootCertHash);
        console.log("  Root cert hash:");
        console.logBytes32(rootCertHash);

        // SP1 Configuration
        // forge-lint: disable-next-line(unsafe-cheatcode)
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
    }

    function saveDeployment() internal {
        // Ensure deployments directory exists
        if (!vm.exists("deployments")) {
            vm.createDir("deployments", false);
        }

        string memory chainId = block.chainid.toString();
        string memory fp = string(
            abi.encodePacked("deployments/", chainId, "_nova.json")
        );

        string memory deployment = "deployment";
        vm.serializeAddress(deployment, "SP1_VERIFIER", sp1Verifier);
        vm.serializeAddress(deployment, "VERIFIER", nitroVerifier);
        vm.serializeAddress(
            deployment,
            "REGISTRY_IMPLEMENTATION",
            registryImplementation
        );
        deployment = vm.serializeAddress(
            deployment,
            "REGISTRY_PROXY",
            registryProxy
        );

        // forge-lint: disable-next-line(unsafe-cheatcode)
        vm.writeFile(fp, deployment);

        console.log("");
        console.log("Deployment saved to:", fp);
        console.log(deployment);
    }
}

/**
 * @title UpgradeNova
 * @notice Upgrade script for NovaAppRegistry
 *
 * Usage:
 *   PROXY=<proxy_addr> forge script script/DeployNova.s.sol:UpgradeNovaScript --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
 */
contract UpgradeNovaScript is Script {
    using LibString for uint256;

    function run() public {
        address proxyAddr = vm.envAddress("PROXY");
        require(proxyAddr != address(0), "PROXY env var required");

        console.log("====================================");
        console.log("Upgrading NovaAppRegistry");
        console.log("====================================");
        console.log("Proxy:", proxyAddr);

        NovaAppRegistry existingProxy = NovaAppRegistry(proxyAddr);
        console.log("Current owner:", existingProxy.owner());

        vm.startBroadcast();

        // Deploy new implementation
        console.log("Deploying new implementation...");
        NovaAppRegistry newImplementation = new NovaAppRegistry();
        address newImpl = address(newImplementation);
        console.log("New implementation:", newImpl);

        // Upgrade proxy to new implementation
        console.log("Upgrading proxy...");
        existingProxy.upgradeToAndCall(newImpl, "");

        vm.stopBroadcast();

        console.log("====================================");
        console.log("Upgrade Complete!");
        console.log("====================================");

        _saveUpgradedDeployment(proxyAddr, newImpl);
    }

    function _saveUpgradedDeployment(
        address proxyAddr,
        address newImpl
    ) internal {
        if (!vm.exists("deployments")) {
            vm.createDir("deployments", false);
        }

        string memory chainId = block.chainid.toString();
        string memory fp = string(
            abi.encodePacked("deployments/", chainId, "_nova.json")
        );

        address sp1Verifier = address(0);
        address nitroVerifier = address(0);

        if (vm.exists(fp)) {
            // forge-lint: disable-next-line(unsafe-cheatcode)
            string memory existing = vm.readFile(fp);
            if (vm.keyExistsJson(existing, ".SP1_VERIFIER")) {
                sp1Verifier = vm.parseJsonAddress(existing, ".SP1_VERIFIER");
            }
            if (vm.keyExistsJson(existing, ".VERIFIER")) {
                nitroVerifier = vm.parseJsonAddress(existing, ".VERIFIER");
            }
        }

        string memory deployment = "deployment";
        if (sp1Verifier != address(0)) {
            vm.serializeAddress(deployment, "SP1_VERIFIER", sp1Verifier);
        }
        if (nitroVerifier != address(0)) {
            vm.serializeAddress(deployment, "VERIFIER", nitroVerifier);
        }
        vm.serializeAddress(deployment, "REGISTRY_IMPLEMENTATION", newImpl);
        string memory out = vm.serializeAddress(
            deployment,
            "REGISTRY_PROXY",
            proxyAddr
        );

        // forge-lint: disable-next-line(unsafe-cheatcode)
        vm.writeFile(fp, out);
        console.log("Deployment updated:", fp);
        console.log(out);
    }
}
