// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Ownable} from "@solady/auth/Ownable.sol";
import {
    INitroEnclaveVerifier,
    ZkCoProcessorType,
    VerifierJournal,
    VerificationResult
} from "./interfaces/INitroEnclaveVerifier.sol";
import {ISparsityApp} from "./interfaces/ISparsityApp.sol";
import {JsonParser} from "./libraries/JsonParser.sol";

/// @title SparsityAppRegistry
/// @notice Registry for Nova Apps with TEE attestation verification.
/// @dev Manages registration, updates, and removal of Nova Apps. Verifies TEE attestations using NitroEnclaveVerifier.
contract SparsityAppRegistry is Ownable {
    // ========== Errors ==========

    /// @notice Thrown when the ZK Verifier address is invalid.
    error InvalidZkVerifier();

    /// @notice Thrown when the attestation verification fails.
    error AttestationFailed();

    /// @notice Thrown when the app is not found.
    error AppNotFound();

    /// @notice Thrown when the caller is not the owner of the app.
    error NotAppOwner();

    /// @notice Thrown when JSON parsing of userData fails.
    error JsonParsingFailed();

    /// @notice Thrown when trying to register an app with a duplicate key (codeMeasurement + appUrl).
    error DuplicateAppKey();

    /// @notice Thrown when a duplicate PCR index is encountered during attestation verification.
    error DuplicatePCRIndex(uint64 index);

    /// @notice Thrown when TEE wallet address is zero.
    error InvalidTEEWalletAddress();

    /// @notice Thrown when code measurement is zero.
    error InvalidCodeMeasurement();

    /// @notice Thrown when TEE public key has invalid length.
    error InvalidTEEPubkeyLength();

    /// @notice Thrown when app URL is empty.
    error InvalidAppUrl();

    // ========== Structs & Enums ==========

    /// @dev Build attestation data from GitHub Actions
    struct BuildAttestation {
        /// @dev URL to build-attestation.json in GitHub Release. Immutable.
        string url;
        /// @dev SHA256 hash of build-attestation.json. Immutable.
        string sha256;
        /// @dev GitHub Actions run ID for the build workflow. Immutable.
        string githubRunId;
    }

    struct SparsityApp {
        /// @dev The owner of the app. Immutable.
        address owner;
        /// @dev The unique ID of the app. Immutable.
        uint256 appId;
        /// @dev The TEE architecture (e.g., "nitro"). Immutable.
        bytes32 teeArch;
        /// @dev The code measurement hash. Immutable (part of the unique key).
        bytes32 codeMeasurement;
        /// @dev The TEE public key. Updatable by owner on restart.
        bytes teePubkey;
        /// @dev The TEE wallet address. Updatable by owner on restart.
        address teeWalletAddress;
        /// @dev The application URL. Immutable (part of the unique key).
        string appUrl;
        /// @dev The optional contract address. Immutable.
        address contractAddr;
        /// @dev The metadata URI. Immutable.
        string metadataUri;
        /// @dev Whether the app was verified via ZKP. Immutable.
        bool zkVerified;
        /// @dev Build attestation data (URL, SHA256, GitHub run ID). Immutable.
        BuildAttestation buildAttestation;
    }

    // ========== State Variables ==========

    /// @notice Address of the NitroEnclaveVerifier contract.
    address public zkVerifier;

    /// @notice Mapping from App ID to SparsityApp struct.
    mapping(uint256 => SparsityApp) public apps;

    /// @notice Mapping from App ID to index in appList for O(1) removals.
    mapping(uint256 => uint256) private appIndex;

    /// @notice Mapping from app key (keccak256(codeMeasurement, appUrl)) to appId (0 = not registered).
    mapping(bytes32 => uint256) private appKeyToId;

    /// @notice List of all active App IDs.
    uint256[] private appList;

    /// @notice Counter for generating App IDs.
    uint256 private nextAppId;

    /// @notice Gas limit for registerTEEWallet calls.
    uint256 public gasLimit = 50000;

    // ========== Events ==========

    event ZKVerifierChange(address indexed verifier);
    event GasLimitChange(uint256 gasLimit);

    event AppRegistered(
        uint256 indexed appId,
        bytes32 teeArch,
        bytes32 codeMeasurement,
        bytes teePubkey,
        address teeWalletAddress,
        string appUrl,
        address zkVerifier,
        address indexed owner,
        address contractAddr,
        bool zkVerified,
        bool hasBuildAttestation
    );

    event AppRemoved(uint256 indexed appId, address indexed owner);

    event AppUpdated(
        uint256 indexed appId,
        bytes oldTeePubkey,
        bytes newTeePubkey,
        address oldWallet,
        address newWallet,
        address indexed owner
    );

    event TEEWalletCallbackFailed(
        uint256 indexed appId,
        address indexed contractAddr
    );

    event TEEWalletCallbackSuccess(
        uint256 indexed appId,
        address indexed contractAddr,
        address teeWalletAddress
    );

    // ========== Constructor ==========

    constructor() {
        _initializeOwner(msg.sender);
        nextAppId = 1; // Start IDs from 1
    }

    // ========== Admin Functions ==========

    /// @notice Sets the ZK Verifier contract address.
    /// @param verifier The address of the new verifier.
    function setZKVerifier(address verifier) external onlyOwner {
        if (verifier == address(0) || verifier.code.length == 0)
            revert InvalidZkVerifier();

        // Note: We don't validate the interface with a test call because:
        // 1. The verify() function requires valid proof data which we don't have
        // 2. Any misconfiguration will be caught during actual registration attempts
        // 3. Owner can update if needed

        zkVerifier = verifier;
        emit ZKVerifierChange(verifier);
    }

    /// @notice Sets the gas limit for registerTEEWallet calls.
    /// @param _gasLimit The new gas limit (min 10,000, max 500,000).
    function setGasLimit(uint256 _gasLimit) external onlyOwner {
        require(
            _gasLimit >= 10000 && _gasLimit <= 500000,
            "Gas limit out of range"
        );
        gasLimit = _gasLimit;
        emit GasLimitChange(_gasLimit);
    }

    // ========== Internal Helpers ==========

    /// @dev Computes keccak256 hash of (codeMeasurement, appUrl) using inline assembly for gas efficiency.
    function _computeAppKey(
        bytes32 codeMeasurement,
        string memory appUrl
    ) private pure returns (bytes32 result) {
        assembly {
            // Get free memory pointer
            let ptr := mload(0x40)
            // Store codeMeasurement at ptr
            mstore(ptr, codeMeasurement)
            // Get appUrl length and data pointer
            let urlLen := mload(appUrl)
            let urlData := add(appUrl, 0x20)
            // Copy appUrl bytes after codeMeasurement (at ptr + 32)
            let dst := add(ptr, 0x20)
            for {
                let i := 0
            } lt(i, urlLen) {
                i := add(i, 0x20)
            } {
                mstore(add(dst, i), mload(add(urlData, i)))
            }
            // Compute hash over (32 + urlLen) bytes
            result := keccak256(ptr, add(0x20, urlLen))
        }
    }

    /// @dev Calls registerTEEWallet on a contract if contractAddr is provided.
    /// @param appId The app ID for event emission.
    /// @param contractAddr The contract to call.
    /// @param teeWalletAddress The TEE wallet address to register.
    function _callRegisterTEEWallet(
        uint256 appId,
        address contractAddr,
        address teeWalletAddress
    ) private {
        if (contractAddr == address(0)) return;

        // Verify contract has code
        require(contractAddr.code.length > 0, "Invalid contract address");

        // Use try-catch to handle failures gracefully
        try
            ISparsityApp(contractAddr).registerTEEWallet{gas: gasLimit}(
                teeWalletAddress
            )
        {
            // Success - emit event for transparency
            emit TEEWalletCallbackSuccess(
                appId,
                contractAddr,
                teeWalletAddress
            );
        } catch {
            // Log but don't revert - allows registration to succeed even if callback fails
            emit TEEWalletCallbackFailed(appId, contractAddr);
        }
    }

    /// @dev Internal helper to upsert or create an app.
    /// @return appId The app ID.
    /// @return isUpdate True if the app was updated, false if created.
    function _upsertOrCreateApp(
        string memory appUrl,
        bytes32 teeArch,
        bytes32 codeMeasurement,
        bytes memory teePubkey,
        address teeWalletAddress,
        address contractAddr,
        string memory metadataUri,
        bool zkVerified,
        BuildAttestation memory buildAttestation
    ) internal returns (uint256, bool) {
        // Check if app already exists with this key (upsert logic)
        bytes32 key = _computeAppKey(codeMeasurement, appUrl);
        uint256 existingAppId = appKeyToId[key];

        if (existingAppId != 0) {
            // UPDATE existing app - only owner can update
            SparsityApp storage app = apps[existingAppId];
            if (app.owner != msg.sender && msg.sender != owner())
                revert NotAppOwner();

            // Capture old values for audit trail
            bytes memory oldTeePubkey = app.teePubkey;
            address oldWallet = app.teeWalletAddress;

            // Update only pubkey and wallet address
            app.teePubkey = teePubkey;
            app.teeWalletAddress = teeWalletAddress;

            // Call registerTEEWallet on update as well (TEE wallet may have changed)
            _callRegisterTEEWallet(
                existingAppId,
                app.contractAddr,
                teeWalletAddress
            );

            emit AppUpdated(
                existingAppId,
                oldTeePubkey,
                teePubkey,
                oldWallet,
                teeWalletAddress,
                app.owner
            );
            return (existingAppId, true);
        }

        // CREATE new app
        uint256 appId = nextAppId++;

        apps[appId] = SparsityApp({
            owner: msg.sender,
            appId: appId,
            teeArch: teeArch,
            codeMeasurement: codeMeasurement,
            teePubkey: teePubkey,
            teeWalletAddress: teeWalletAddress,
            appUrl: appUrl,
            contractAddr: contractAddr,
            metadataUri: metadataUri,
            zkVerified: zkVerified,
            buildAttestation: buildAttestation
        });
        appKeyToId[key] = appId;

        // Track index for O(1) removals later
        appIndex[appId] = appList.length;
        appList.push(appId);

        // Call registerTEEWallet only on first registration
        _callRegisterTEEWallet(appId, contractAddr, teeWalletAddress);

        return (appId, false);
    }

    /// @dev Verifies the attestation and extracts code measurement, public key, and TEE wallet address.
    function _verifyAndProcessAttestation(
        ZkCoProcessorType zkCoprocessor,
        bytes calldata publicValues,
        bytes calldata proofBytes
    )
        private
        returns (
            bytes32 codeMeasurement,
            bytes memory pubkey,
            address teeWalletAddress
        )
    {
        if (zkVerifier == address(0)) revert InvalidZkVerifier();

        // Verify the attestation using NitroEnclaveVerifier
        VerifierJournal memory journal = INitroEnclaveVerifier(zkVerifier)
            .verify(publicValues, zkCoprocessor, proofBytes);

        // Check verification result
        if (journal.result != VerificationResult.Success)
            revert AttestationFailed();

        // Compute the hash of PCR values 0, 1, 2 in canonical order for reproducible codeMeasurement
        bytes32[3] memory pcrFirst;
        bytes16[3] memory pcrSecond;
        bool[3] memory pcrSeen;

        for (uint256 i = 0; i < journal.pcrs.length; i++) {
            uint64 idx = journal.pcrs[i].index;
            if (idx <= 2) {
                if (pcrSeen[idx]) revert DuplicatePCRIndex(idx);
                pcrSeen[idx] = true;
                pcrFirst[idx] = journal.pcrs[i].value.first;
                pcrSecond[idx] = journal.pcrs[i].value.second;
            }
        }

        codeMeasurement = keccak256(
            abi.encodePacked(
                pcrFirst[0],
                pcrSecond[0],
                pcrFirst[1],
                pcrSecond[1],
                pcrFirst[2],
                pcrSecond[2]
            )
        );
        pubkey = journal.publicKey;

        // Parse JSON userData to extract eth_addr field
        // Expected format: {"eth_addr":"0x1234...5678", ...}
        try this.parseEthAddr(journal.userData) returns (address parsed) {
            teeWalletAddress = parsed;
        } catch {
            revert JsonParsingFailed();
        }
    }

    /// @notice External wrapper for JSON parsing (used with try-catch)
    /// @param userData The raw JSON bytes containing eth_addr
    /// @return The extracted Ethereum address
    function parseEthAddr(
        bytes calldata userData
    ) external pure returns (address) {
        return JsonParser.extractEthAddr(userData);
    }

    // ========== Public Functions ==========

    /// @notice Registers a new Nova App with ZK proof verification.
    /// @param appUrl The URL of the app.
    /// @param teeArch The TEE architecture (e.g., "nitro").
    /// @param zkCoprocessor The ZK coprocessor type used for proof.
    /// @param publicValues The public values for the proof.
    /// @param proofBytes The proof data.
    /// @param contractAddr Optional address of a contract implementing ISparsityApp.
    /// @param metadataUri URI to metadata JSON (relative or absolute).
    /// @param buildAttestation Build attestation data (URL, SHA256, GitHub run ID).
    /// @return appId The ID of the newly registered app.
    function registerAppWithZKP(
        string calldata appUrl,
        bytes32 teeArch,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata publicValues,
        bytes calldata proofBytes,
        address contractAddr,
        string calldata metadataUri,
        BuildAttestation calldata buildAttestation
    ) public returns (uint256) {
        (
            bytes32 codeMeasurement,
            bytes memory teePubkey,
            address teeWalletAddress
        ) = _verifyAndProcessAttestation(
                zkCoprocessor,
                publicValues,
                proofBytes
            );

        (uint256 appId, bool isUpdate) = _upsertOrCreateApp(
            appUrl,
            teeArch,
            codeMeasurement,
            teePubkey,
            teeWalletAddress,
            contractAddr,
            metadataUri,
            true, // zkVerified
            buildAttestation
        );

        if (!isUpdate) {
            emit AppRegistered(
                appId,
                teeArch,
                codeMeasurement,
                teePubkey,
                teeWalletAddress,
                appUrl,
                zkVerifier,
                msg.sender,
                contractAddr,
                true, // zkVerified
                bytes(buildAttestation.url).length > 0 // hasBuildAttestation
            );
        }

        return appId;
    }

    /// @notice Registers a new Sparsity App WITHOUT ZK proof verification.
    /// @dev This method skips ZK verification and directly registers with provided values.
    ///      The app will be marked as zkVerified=false to indicate it was not verified.
    /// @param appUrl The URL of the app.
    /// @param teeArch The TEE architecture (e.g., "nitro").
    /// @param codeMeasurement The code measurement hash (e.g., hash of PCR values).
    /// @param teePubkey The TEE public key.
    /// @param teeWalletAddress The TEE wallet address.
    /// @param contractAddr Optional address of a contract implementing ISparsityApp.
    /// @param metadataUri URI to metadata JSON (relative or absolute).
    /// @param buildAttestation Build attestation data (URL, SHA256, GitHub run ID).
    /// @return appId The ID of the newly registered app.
    function registerAppWithoutZKP(
        string calldata appUrl,
        bytes32 teeArch,
        bytes32 codeMeasurement,
        bytes calldata teePubkey,
        address teeWalletAddress,
        address contractAddr,
        string calldata metadataUri,
        BuildAttestation calldata buildAttestation
    ) public returns (uint256) {
        // Input validation
        if (teeWalletAddress == address(0)) revert InvalidTEEWalletAddress();
        if (codeMeasurement == bytes32(0)) revert InvalidCodeMeasurement();
        if (teePubkey.length == 0 || teePubkey.length > 128)
            revert InvalidTEEPubkeyLength();
        if (bytes(appUrl).length == 0) revert InvalidAppUrl();

        (uint256 appId, bool isUpdate) = _upsertOrCreateApp(
            appUrl,
            teeArch,
            codeMeasurement,
            teePubkey,
            teeWalletAddress,
            contractAddr,
            metadataUri,
            false, // zkVerified
            buildAttestation
        );

        if (!isUpdate) {
            emit AppRegistered(
                appId,
                teeArch,
                codeMeasurement,
                teePubkey,
                teeWalletAddress,
                appUrl,
                address(0), // No zkVerifier used
                msg.sender,
                contractAddr,
                false, // zkVerified = false
                bytes(buildAttestation.url).length > 0 // hasBuildAttestation
            );
        }

        return appId;
    }

    /// @notice Removes a Nova App.
    /// @param appId The ID of the app to remove.
    function removeApp(uint256 appId) public {
        if (apps[appId].owner == address(0)) revert AppNotFound();
        if (apps[appId].owner != msg.sender && msg.sender != owner())
            revert NotAppOwner();

        // Clear app key mapping for this app
        bytes32 key = _computeAppKey(
            apps[appId].codeMeasurement,
            apps[appId].appUrl
        );
        if (appKeyToId[key] == appId) {
            delete appKeyToId[key];
        }

        // Remove from appList using swap-and-pop with O(1) complexity
        uint256 idx = appIndex[appId];
        uint256 lastIdx = appList.length - 1;
        if (idx != lastIdx) {
            uint256 lastId = appList[lastIdx];
            appList[idx] = lastId;
            appIndex[lastId] = idx;
        }
        appList.pop();
        delete appIndex[appId];

        // Delete from mapping
        delete apps[appId];

        emit AppRemoved(appId, msg.sender);
    }

    /// @notice Checks if an app exists.
    /// @param appId The ID of the app.
    /// @return True if the app exists, false otherwise.
    function appExists(uint256 appId) public view returns (bool) {
        return apps[appId].owner != address(0);
    }

    /// @notice Returns the latest 20 app IDs (from most recent to older).
    function getAppList() public view returns (uint256[] memory) {
        return getAppList(0, 20);
    }

    /// @notice Returns app IDs in reverse order (most recent first), with pagination.
    /// @param offset Number of most-recent items to skip (0 means start from latest).
    /// @param limit Max number of IDs to return (max 100).
    function getAppList(
        uint256 offset,
        uint256 limit
    ) public view returns (uint256[] memory ids) {
        require(limit <= 100, "Limit too high");
        uint256 len = appList.length;
        if (limit == 0 || offset >= len) {
            return new uint256[](0);
        }
        uint256 maxCount = len - offset;
        if (limit > maxCount) limit = maxCount;
        ids = new uint256[](limit);
        // Fill from tail with offset, with explicit bounds checking
        for (uint256 i = 0; i < limit; i++) {
            uint256 index = len - 1 - offset - i;
            // Explicit bounds check for clarity (though Solidity 0.8+ has overflow protection)
            require(index < len, "Index out of bounds");
            ids[i] = appList[index];
        }
    }

    /// @notice Returns the total number of registered apps.
    function getAppCount() public view returns (uint256) {
        return appList.length;
    }

    /// @notice Returns a single app by ID.
    /// @param appId The ID of the app.
    function getApp(uint256 appId) external view returns (SparsityApp memory) {
        return apps[appId];
    }

    /// @notice Batch getter for apps.
    /// @param ids The list of app IDs to fetch.
    function getApps(
        uint256[] calldata ids
    ) external view returns (SparsityApp[] memory result) {
        result = new SparsityApp[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = apps[ids[i]];
        }
    }

    /// @notice Get appId by PCR values (PCR0, PCR1, PCR2) and appUrl.
    /// @dev Computes codeMeasurement = keccak256(pcr0 || pcr1 || pcr2) and looks up.
    /// @param pcr0 PCR0 value bytes.
    /// @param pcr1 PCR1 value bytes.
    /// @param pcr2 PCR2 value bytes.
    /// @param appUrl The app URL.
    /// @return appId The app ID if found, 0 if not registered.
    function getAppIdByPCRs(
        bytes calldata pcr0,
        bytes calldata pcr1,
        bytes calldata pcr2,
        string calldata appUrl
    ) public view returns (uint256) {
        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        return appKeyToId[_computeAppKey(codeMeasurement, appUrl)];
    }

    /// @notice Get appId by codeMeasurement and appUrl directly.
    /// @param codeMeasurement The code measurement hash.
    /// @param appUrl The app URL.
    /// @return appId The app ID if found, 0 if not registered.
    function getAppIdByCodeMeasurement(
        bytes32 codeMeasurement,
        string calldata appUrl
    ) public view returns (uint256) {
        return appKeyToId[_computeAppKey(codeMeasurement, appUrl)];
    }
}
