// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {
    ZkCoProcessorType,
    INitroEnclaveVerifier
} from "../src/interfaces/INitroEnclaveVerifier.sol";
import {SparsityAppRegistry} from "../src/SparsityAppRegistry.sol";
import {LibString} from "@solady/utils/LibString.sol";

contract SparsityAppRegistryScript is Script {
    using LibString for string;
    using LibString for uint256;

    function readDeployed(string memory key) internal view returns (address) {
        address addr = vm.envOr(key, address(0));
        if (addr != address(0)) {
            console.log(
                string(abi.encodePacked("read ", key, " from env:")),
                addr
            );
            return addr;
        }

        string memory fp = string(
            abi.encodePacked("deployments/", block.chainid.toString(), ".json")
        );
        if (vm.exists(fp)) {
            string memory deployment = vm.readFile(fp);
            string memory jsonKey = string(abi.encodePacked(".", key));
            if (vm.keyExistsJson(deployment, jsonKey)) {
                addr = vm.parseJsonAddress(deployment, jsonKey);
                console.log(
                    string(abi.encodePacked("read ", key, " from deployment:")),
                    addr
                );
                return addr;
            }
        }

        revert(
            string(
                abi.encodePacked(
                    "No deployment found for ",
                    key,
                    " from file or env, chainid:",
                    block.chainid.toString()
                )
            )
        );
    }

    function isDeployed(string memory key) internal view returns (bool) {
        string memory fp = string(
            abi.encodePacked("deployments/", block.chainid.toString(), ".json")
        );
        if (vm.exists(fp)) {
            string memory deployment = vm.readFile(fp);
            string memory jsonKey = string(abi.encodePacked(".", key));
            return vm.keyExistsJson(deployment, jsonKey);
        }
        return false;
    }

    function saveDeployed(string memory key, address addr) internal {
        // Ensure deployments directory exists
        if (!vm.exists("deployments")) {
            vm.createDir("deployments", false);
        }

        string memory fp = string(
            abi.encodePacked("deployments/", block.chainid.toString(), ".json")
        );
        string memory deployment = "{}";
        if (vm.exists(fp)) {
            deployment = vm.readFile(fp);
            string[] memory keys = vm.parseJsonKeys(deployment, ".");
            for (uint256 i = 0; i < keys.length; i++) {
                if (keys[i].eq("remark")) {
                    continue;
                }
                string memory keyPath = string(abi.encodePacked(".", keys[i]));
                vm.serializeAddress(
                    deployment,
                    keys[i],
                    vm.parseJsonAddress(deployment, keyPath)
                );
            }
        }
        vm.serializeAddress(deployment, key, addr);

        deployment = vm.serializeString(deployment, "remark", "deployments");
        console.log(
            string(abi.encodePacked("save file ", fp, ": ", deployment))
        );
        vm.writeFile(fp, deployment);
    }

    function _getZkType(
        string memory zktype
    ) internal pure returns (ZkCoProcessorType zkType) {
        if (zktype.eq("Succinct")) {
            zkType = ZkCoProcessorType.Succinct;
        } else if (zktype.eq("RiscZero")) {
            zkType = ZkCoProcessorType.RiscZero;
        } else {
            revert("unknown zkType");
        }
    }

    function deployRegistry() public {
        vm.startBroadcast();
        SparsityAppRegistry registry = new SparsityAppRegistry();
        vm.stopBroadcast();
        console.log("SparsityAppRegistry deployed at", address(registry));
        saveDeployed("REGISTRY", address(registry));
    }

    function setVerifier() public {
        address verifier = readDeployed("VERIFIER");
        address registry = readDeployed("REGISTRY");

        vm.startBroadcast();
        SparsityAppRegistry(registry).setZKVerifier(verifier);
        vm.stopBroadcast();

        console.log("NitroEnclaveVerifier registered with SparsityAppRegistry");
        console.log("Verifier:", verifier);
        console.log("Registry:", registry);
    }

    function registerApp(
        string memory proofPath,
        string memory url,
        string memory teeArchStr,
        address contractAddr,
        string memory metadataUri,
        string memory buildAttestationUrl,
        string memory buildAttestationSha256,
        string memory buildGithubRunId
    ) public returns (uint256) {
        address registry = readDeployed("REGISTRY");

        // Convert TEE arch string to bytes32
        bytes32 teeArch = bytes32(bytes(teeArchStr));

        // Read and parse proof JSON
        string memory proofJson = vm.readFile(proofPath);
        bytes memory journal = vm.parseJsonBytes(
            proofJson,
            ".raw_proof.journal"
        );
        bytes memory proof = vm.parseJsonBytes(proofJson, ".onchain_proof");
        string memory proofType = vm.parseJsonString(proofJson, ".proof_type");

        // Verify it's a single proof (not batch)
        if (!proofType.eq("Verifier")) {
            revert(
                string(
                    abi.encodePacked(
                        "Expected single proof (Verifier), got: ",
                        proofType
                    )
                )
            );
        }

        // Get ZK coprocessor type
        ZkCoProcessorType zkType = _getZkType(
            vm.parseJsonString(proofJson, ".zktype")
        );

        console.log("====================================");
        console.log("Registering App with SparsityAppRegistry");
        console.log("====================================");
        console.log("Registry:", registry);
        console.log("URL:", url);
        console.log("TEE Arch (string):", teeArchStr);
        console.log("TEE Arch (bytes32):", vm.toString(teeArch));
        console.log(
            "ZK Type:",
            zkType == ZkCoProcessorType.Succinct ? "SP1" : "RISC0"
        );
        console.log("Contract Addr:", contractAddr);
        console.log("Metadata URI:", metadataUri);
        console.log("Build Attestation URL:", buildAttestationUrl);
        console.log("Build Attestation SHA256:", buildAttestationSha256);
        console.log("Build GitHub Run ID:", buildGithubRunId);
        console.log("");

        // Call registerApp on the registry
        uint256 gas = gasleft();
        vm.startBroadcast();
        uint256 appId = SparsityAppRegistry(registry).registerAppWithZKP(
            url,
            teeArch,
            zkType,
            journal,
            proof,
            contractAddr,
            metadataUri,
            SparsityAppRegistry.BuildAttestation({
                url: buildAttestationUrl,
                sha256: buildAttestationSha256,
                githubRunId: buildGithubRunId
            })
        );
        vm.stopBroadcast();

        console.log("");
        console.log("====================================");
        console.log("App registered successfully!");
        console.log("====================================");
        console.log("App ID:", appId);
        console.log("Gas used:", gas - gasleft());

        return appId;
    }
}
