// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {
    ZkCoProcessorConfig,
    ZkCoProcessorType,
    INitroEnclaveVerifier
} from "../src/interfaces/INitroEnclaveVerifier.sol";
import {NitroEnclaveVerifier} from "../src/NitroEnclaveVerifier.sol";
import {SP1Verifier} from "@sp1-contracts/v5.0.0/SP1VerifierGroth16.sol";
import {
    ControlID,
    RiscZeroGroth16Verifier
} from "@risc0-ethereum/groth16/RiscZeroGroth16Verifier.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {Ownable} from "@solady/auth/Ownable.sol";

contract NitroEnclaveVerifierScript is Script {
    using LibString for string;
    using LibString for uint256;

    function setUp() public {}

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

    function deploySP1Verifier() public {
        if (isDeployed("SP1_VERIFIER")) {
            console.log(
                "SP1Verifier already deployed at",
                readDeployed("SP1_VERIFIER")
            );
            return;
        }

        vm.startBroadcast();
        SP1Verifier sp1Verifier = new SP1Verifier();
        vm.stopBroadcast();
        console.log("SP1Verifier deployed at", address(sp1Verifier));
        saveDeployed("SP1_VERIFIER", address(sp1Verifier));
    }

    function deployRisc0Verifier() public {
        if (isDeployed("RISC0_VERIFIER")) {
            console.log(
                "Risc0Verifier already deployed at",
                readDeployed("RISC0_VERIFIER")
            );
            return;
        }

        vm.startBroadcast();
        RiscZeroGroth16Verifier risc0Verifier = new RiscZeroGroth16Verifier(
            ControlID.CONTROL_ROOT,
            ControlID.BN254_CONTROL_ID
        );
        vm.stopBroadcast();
        console.log("Risc0Verifier deployed at", address(risc0Verifier));
        saveDeployed("RISC0_VERIFIER", address(risc0Verifier));
    }

    function deployVerifier() public {
        if (isDeployed("VERIFIER")) {
            console.log(
                "NitroEnclaveVerifier already deployed at",
                readDeployed("VERIFIER")
            );
            return;
        }

        vm.startBroadcast();
        NitroEnclaveVerifier verifier = new NitroEnclaveVerifier(
            108000,
            new bytes32[](0)
        );
        vm.stopBroadcast();
        console.log("NitroEnclaveVerifier deployed at", address(verifier));
        saveDeployed("VERIFIER", address(verifier));
    }

    function deployAll(
        string memory rootCert,
        string memory sp1Program,
        string memory risc0Program
    ) public {
        if (!isDeployed("VERIFIER")) {
            deployVerifier();
            setRootCert(rootCert);
        }
        setZkVerifier(sp1Program);
        setZkVerifier(risc0Program);
    }

    function setRootCert(string memory path) public {
        INitroEnclaveVerifier verifier = INitroEnclaveVerifier(
            readDeployed("VERIFIER")
        );
        bytes memory _rootCert = vm.readFileBinary(path);
        vm.startBroadcast();
        verifier.setRootCert(sha256(_rootCert));
        vm.stopBroadcast();
        console.log("Root certificate set to");
        console.logBytes32(sha256(_rootCert));
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

    function setZkVerifier(string memory path) public {
        string memory proofJson = vm.readFile(path);
        bytes32 verifierId = vm.parseJsonBytes32(
            proofJson,
            ".program_id.verifier_id"
        );
        bytes32 verifierProofId = vm.parseJsonBytes32(
            proofJson,
            ".program_id.verifier_proof_id"
        );
        bytes32 aggregatorId = vm.parseJsonBytes32(
            proofJson,
            ".program_id.aggregator_id"
        );
        string memory zktype = vm.parseJsonString(proofJson, ".zktype");
        ZkCoProcessorType zkType = _getZkType(zktype);
        ZkCoProcessorConfig memory config = ZkCoProcessorConfig({
            verifierId: verifierId,
            verifierProofId: verifierProofId,
            aggregatorId: aggregatorId,
            zkVerifier: address(0)
        });
        if (zkType == ZkCoProcessorType.RiscZero) {
            config.zkVerifier = readDeployed("RISC0_VERIFIER");
        } else if (zkType == ZkCoProcessorType.Succinct) {
            config.zkVerifier = readDeployed("SP1_VERIFIER");
        } else {
            revert("unknown zkType");
        }
        console.log(Ownable(readDeployed("VERIFIER")).owner());
        console.log(msg.sender);
        vm.startBroadcast();
        INitroEnclaveVerifier(readDeployed("VERIFIER")).setZkConfiguration(
            zkType,
            config
        );
        vm.stopBroadcast();
    }

    function verify(string memory path) public {
        string memory proofJson = vm.readFile(path);
        bytes memory journal = vm.parseJsonBytes(
            proofJson,
            ".raw_proof.journal"
        );
        bytes memory proof = vm.parseJsonBytes(proofJson, ".onchain_proof");
        string memory proofType = vm.parseJsonString(proofJson, ".proof_type");
        if (!proofType.eq("Verifier")) {
            revert(
                string(
                    abi.encodePacked(
                        "Unsupported proof type: ",
                        proofType,
                        ", please use batchVerify() instead."
                    )
                )
            );
        }
        ZkCoProcessorType zkType = _getZkType(
            vm.parseJsonString(proofJson, ".zktype")
        );

        uint256 gas = gasleft();
        INitroEnclaveVerifier(readDeployed("VERIFIER")).verify(
            journal,
            zkType,
            proof
        );
        console.log(path, "verify gas:", gas - gasleft());
    }

    function batchVerify(string memory path) public {
        string memory proofJson = vm.readFile(path);
        bytes memory journal = vm.parseJsonBytes(
            proofJson,
            ".raw_proof.journal"
        );
        bytes memory proof = vm.parseJsonBytes(proofJson, ".onchain_proof");
        ZkCoProcessorType zkType = _getZkType(
            vm.parseJsonString(proofJson, ".zktype")
        );
        string memory proofType = vm.parseJsonString(proofJson, ".proof_type");
        if (!proofType.eq("Aggregator")) {
            revert(
                string(
                    abi.encodePacked(
                        "Unsupported proof type: ",
                        proofType,
                        ", please use verify() instead."
                    )
                )
            );
        }

        uint256 gas = gasleft();
        INitroEnclaveVerifier(readDeployed("VERIFIER")).batchVerify(
            journal,
            zkType,
            proof
        );
        console.log(path, "batch verify gas:", gas - gasleft());
    }
}
