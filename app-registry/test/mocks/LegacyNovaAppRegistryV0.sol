// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {
    UUPSUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
    OwnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {
    Initializable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {
    INitroEnclaveVerifier,
    ZkCoProcessorType,
    VerifierJournal,
    VerificationResult
} from "../../src/interfaces/INitroEnclaveVerifier.sol";
import {INovaAppInterface} from "../../src/interfaces/INovaAppInterface.sol";
import {JsonParser} from "../../src/libraries/JsonParser.sol";

/// @title NovaAppRegistry
/// @notice Registry for Nova Apps with 3-layer hierarchy: App -> Version -> Instance.
/// @dev Uses UUPS upgradeable pattern. Manages app registration, version enrollment, and instance lifecycle.
contract LegacyNovaAppRegistryV0 is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable
{
    // ========== Errors ==========

    error InvalidZkVerifier();
    error AttestationFailed();
    error AppNotFound();
    error VersionNotFound();
    error InstanceNotFound();
    error NotAppOwner();
    error NotInstanceOperator();
    error JsonParsingFailed();
    error DuplicateCodeMeasurement();
    error DuplicateTEEWallet();
    error DuplicatePCRIndex(uint64 index);
    error MissingPCRIndex(uint64 index);
    error InvalidPCRLength(uint64 index, uint256 length);
    error InvalidTEEWalletAddress();
    error InvalidTEEPubkeyLength();
    error InvalidInstanceUrl();
    error VersionNotEnrolled();
    error VersionRevoked();
    error CodeMeasurementMismatch();
    error InvalidStatusTransition();
    error InvalidMetadataUri();
    error InvalidVersionName();
    error InvalidImageUri();
    error AppNotActive();

    // ========== Enums ==========

    enum VersionStatus {
        // Normal state: can register new instances.
        ENROLLED,
        // Deprecated state: cannot register new instances, existing instances keep their own status.
        DEPRECATED,
        // Revoked state: cannot register new instances; consumers should treat existing instances as unusable.
        REVOKED
    }

    enum AppStatus {
        ACTIVE,
        INACTIVE,
        REVOKED
    }

    enum InstanceStatus {
        ACTIVE,
        STOPPED,
        FAILED
    }

    // ========== Structs ==========

    /// @dev Application entity - the top level of the hierarchy
    struct App {
        uint256 appId;
        address owner;
        bytes32 teeArch;
        address dappContract;
        string metadataUri;
        uint256 latestVersionId;
        uint256 createdAt;
        AppStatus status;
    }

    /// @dev Version entity - represents a specific build/code measurement
    struct AppVersion {
        uint256 versionId;
        string versionName;
        bytes32 codeMeasurement;
        string imageUri;
        string auditUrl;
        string auditHash;
        string githubRunId;
        VersionStatus status;
        uint256 enrolledAt;
        address enrolledBy;
    }

    /// @dev Runtime instance - a running enclave
    struct RuntimeInstance {
        uint256 instanceId;
        uint256 appId;
        uint256 versionId;
        address operator;
        string instanceUrl;
        bytes teePubkey;
        address teeWalletAddress;
        bool zkVerified;
        InstanceStatus status;
        uint256 registeredAt;
    }

    /// @dev Packed storage layout for runtime instances (gas optimized).
    ///
    /// Slot packing:
    /// - `operator` (20 bytes) + `registeredAt` (8) + `status` (1) + `zkVerified` (1) = 30 bytes in one slot.
    /// - Keep dynamic fields last.
    struct RuntimeInstanceStorage {
        uint256 instanceId;
        uint256 appId;
        uint256 versionId;
        address operator;
        uint64 registeredAt;
        uint8 status;
        bool zkVerified;
        address teeWalletAddress;
        string instanceUrl;
        bytes teePubkey;
    }

    // ========== State Variables ==========

    /// @notice Address of the NitroEnclaveVerifier contract
    address public zkVerifier;

    /// @notice Gas limit for dApp callback calls
    uint256 public callbackGasLimit;

    // === App Storage ===
    mapping(uint256 => App) public apps;
    mapping(address => uint256[]) public ownerApps;
    uint256 public nextAppId;

    // === Version Storage ===
    mapping(uint256 => mapping(uint256 => AppVersion)) public appVersions;
    mapping(uint256 => uint256) public appVersionCount;
    /// @dev keccak256(appId, codeMeasurement) -> (appId, versionId)
    mapping(bytes32 => uint256) private codeMeasurementToVersionId;

    // === Instance Storage ===
    mapping(uint256 => RuntimeInstanceStorage) private _instances;
    mapping(address => uint256) public walletToInstance;
    mapping(uint256 => mapping(uint256 => uint256[])) public versionInstances;
    uint256 public nextInstanceId;
    address[] private _activeInstanceWallets;
    mapping(address => uint256) private _activeInstanceWalletIndexPlusOne;

    // ========== Events ==========

    event ZKVerifierChanged(address indexed verifier);
    event CallbackGasLimitChanged(uint256 gasLimit);
    event AppStatusChanged(
        uint256 indexed appId,
        AppStatus newStatus,
        address indexed updatedBy
    );

    event AppCreated(
        uint256 indexed appId,
        address indexed owner,
        bytes32 teeArch,
        address dappContract,
        string metadataUri
    );

    event VersionEnrolled(
        uint256 indexed appId,
        uint256 indexed versionId,
        string versionName,
        bytes32 codeMeasurement,
        string imageUri
    );

    event VersionStatusChanged(
        uint256 indexed appId,
        uint256 indexed versionId,
        VersionStatus newStatus
    );

    event InstanceRegistered(
        uint256 indexed instanceId,
        uint256 indexed appId,
        uint256 indexed versionId,
        address teeWalletAddress,
        string instanceUrl,
        bool zkVerified
    );

    /// @notice Allows efficient indexing of instances by TEE wallet address.
    /// @dev We cannot index `teeWalletAddress` in InstanceRegistered due to the 3-indexed-params limit.
    event InstanceWalletBound(
        address indexed teeWalletAddress,
        uint256 indexed instanceId,
        uint256 indexed appId
    );

    event InstanceStatusChanged(
        uint256 indexed instanceId,
        InstanceStatus newStatus
    );

    event OperatorCallbackFailed(
        uint256 indexed appId,
        address indexed dappContract,
        string reason
    );

    event OperatorCallbackSuccess(
        uint256 indexed appId,
        address indexed dappContract,
        address teeWalletAddress
    );

    // ========== Initializer ==========

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _zkVerifier) public initializer {
        __Ownable_init(msg.sender);

        zkVerifier = _zkVerifier;
        callbackGasLimit = 100000;
        nextAppId = 1;
        nextInstanceId = 1;
    }

    // ========== UUPS Authorization ==========

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========== Admin Functions ==========

    function setZkVerifier(address verifier) external onlyOwner {
        if (verifier == address(0) || verifier.code.length == 0)
            revert InvalidZkVerifier();
        zkVerifier = verifier;
        emit ZKVerifierChanged(verifier);
    }

    function setCallbackGasLimit(uint256 _gasLimit) external onlyOwner {
        require(
            _gasLimit >= 50000 && _gasLimit <= 500000,
            "Gas limit out of range"
        );
        callbackGasLimit = _gasLimit;
        emit CallbackGasLimitChanged(_gasLimit);
    }

    // ========== App Management ==========

    /// @notice Creates a new application
    /// @param teeArch TEE architecture identifier (e.g., "nitro")
    /// @param dappContract Optional address of contract implementing INovaAppInterface
    /// @param metadataUri URI to off-chain metadata
    /// @return appId The newly created app ID
    function createApp(
        bytes32 teeArch,
        address dappContract,
        string calldata metadataUri
    ) external returns (uint256 appId) {
        if (bytes(metadataUri).length == 0) revert InvalidMetadataUri();
        appId = nextAppId++;

        apps[appId] = App({
            appId: appId,
            owner: msg.sender,
            teeArch: teeArch,
            dappContract: dappContract,
            metadataUri: metadataUri,
            latestVersionId: 0,
            createdAt: block.timestamp,
            status: AppStatus.ACTIVE
        });

        ownerApps[msg.sender].push(appId);

        emit AppCreated(appId, msg.sender, teeArch, dappContract, metadataUri);
    }

    /// @notice Updates the status of an app
    /// @param appId The application ID
    /// @param newStatus The new status
    function updateAppStatus(uint256 appId, AppStatus newStatus) external {
        App storage app = apps[appId];
        if (app.owner == address(0)) revert AppNotFound();

        if (msg.sender == owner()) {
            // Registry Owner can set to REVOKED, or recover from REVOKED to INACTIVE
            if (newStatus == AppStatus.REVOKED) {
                // Always allowed
            } else if (
                app.status == AppStatus.REVOKED &&
                newStatus == AppStatus.INACTIVE
            ) {
                // Recovery allowed
            } else {
                revert InvalidStatusTransition();
            }
        } else if (msg.sender == app.owner) {
            // App Owner cannot touch a REVOKED app
            if (app.status == AppStatus.REVOKED) {
                revert InvalidStatusTransition();
            }
            // Can toggle between ACTIVE and INACTIVE
            if (
                newStatus != AppStatus.ACTIVE && newStatus != AppStatus.INACTIVE
            ) {
                revert InvalidStatusTransition();
            }
        } else {
            revert NotAppOwner();
        }

        app.status = newStatus;
        emit AppStatusChanged(appId, newStatus, msg.sender);
    }

    // ========== Version Management ==========

    /// @notice Enrolls a new version for an app
    /// @param appId The application ID
    /// @param versionName Semantic version string (e.g., "1.0.0")
    /// @param pcr0 PCR0 value from build
    /// @param pcr1 PCR1 value from build
    /// @param pcr2 PCR2 value from build
    /// @param imageUri Container image URI
    /// @param auditUrl URL to build attestation
    /// @param auditHash SHA256 hash of attestation file
    /// @param githubRunId GitHub Actions run ID
    /// @return versionId The newly enrolled version ID
    function enrollVersion(
        uint256 appId,
        string calldata versionName,
        bytes calldata pcr0,
        bytes calldata pcr1,
        bytes calldata pcr2,
        string memory imageUri,
        string memory auditUrl,
        string memory auditHash,
        string memory githubRunId
    ) external returns (uint256 versionId) {
        if (bytes(versionName).length == 0) revert InvalidVersionName();
        if (bytes(imageUri).length == 0) revert InvalidImageUri();

        App storage app = apps[appId];
        if (app.owner == address(0)) revert AppNotFound();
        if (app.owner != msg.sender) revert NotAppOwner();
        if (app.status != AppStatus.ACTIVE) revert AppNotActive();

        // PCR values must be exactly 48 bytes each.
        if (pcr0.length != 48) revert InvalidPCRLength(0, pcr0.length);
        if (pcr1.length != 48) revert InvalidPCRLength(1, pcr1.length);
        if (pcr2.length != 48) revert InvalidPCRLength(2, pcr2.length);

        // Compute code measurement from PCRs
        bytes32 codeMeasurement = _computeVersionMeasurement(pcr0, pcr1, pcr2);

        // Check for duplicate code measurement within this app
        if (
            codeMeasurementToVersionId[
                _computeMeasurementKey(appId, codeMeasurement)
            ] != 0
        ) {
            revert DuplicateCodeMeasurement();
        }

        // Create new version
        versionId = ++appVersionCount[appId];

        appVersions[appId][versionId] = AppVersion({
            versionId: versionId,
            versionName: versionName,
            codeMeasurement: codeMeasurement,
            imageUri: imageUri,
            auditUrl: auditUrl,
            auditHash: auditHash,
            githubRunId: githubRunId,
            status: VersionStatus.ENROLLED,
            enrolledAt: block.timestamp,
            enrolledBy: msg.sender
        });

        // Update mappings
        codeMeasurementToVersionId[
            _computeMeasurementKey(appId, codeMeasurement)
        ] = versionId;
        app.latestVersionId = versionId;

        emit VersionEnrolled(
            appId,
            versionId,
            versionName,
            codeMeasurement,
            imageUri
        );
    }

    /// @notice Marks a version as deprecated
    function deprecateVersion(uint256 appId, uint256 versionId) external {
        _validateVersionOwnership(appId, versionId);
        appVersions[appId][versionId].status = VersionStatus.DEPRECATED;
        emit VersionStatusChanged(appId, versionId, VersionStatus.DEPRECATED);
    }

    /// @notice Revokes a version (cannot be used for new registrations)
    function revokeVersion(uint256 appId, uint256 versionId) external {
        App storage app = apps[appId];
        if (app.owner == address(0)) revert AppNotFound();
        // Allow app owner OR registry owner to revoke
        if (app.owner != msg.sender && msg.sender != owner())
            revert NotAppOwner();

        AppVersion storage version = appVersions[appId][versionId];
        if (version.versionId == 0) revert VersionNotFound();

        version.status = VersionStatus.REVOKED;
        emit VersionStatusChanged(appId, versionId, VersionStatus.REVOKED);
    }

    // ========== Instance Management ==========

    /// @notice Registers an instance with ZK proof verification
    /// @param appId The application ID
    /// @param versionId The version ID
    /// @param instanceUrl The instance endpoint URL
    /// @param zkCoprocessor The ZK coprocessor type (SP1/RISC0)
    /// @param publicValues The journal from proof
    /// @param proofBytes The ZK proof payload
    /// @return instanceId The newly registered instance ID
    function registerInstance(
        uint256 appId,
        uint256 versionId,
        string calldata instanceUrl,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external returns (uint256 instanceId) {
        // Validate app status
        App storage app = apps[appId];
        if (app.status != AppStatus.ACTIVE) revert AppNotActive();

        // Validate version
        AppVersion storage version = appVersions[appId][versionId];
        if (version.versionId == 0) revert VersionNotFound();
        if (version.status == VersionStatus.REVOKED) revert VersionRevoked();
        if (version.status != VersionStatus.ENROLLED) {
            revert VersionNotEnrolled();
        }

        // Verify attestation and extract data
        (
            bytes32 codeMeasurement,
            bytes memory teePubkey,
            address teeWalletAddress
        ) = _verifyAndProcessAttestation(
                zkCoprocessor,
                publicValues,
                proofBytes
            );

        // Validate code measurement matches enrolled version
        if (codeMeasurement != version.codeMeasurement) {
            revert CodeMeasurementMismatch();
        }

        // Create instance
        instanceId = _createInstance(
            appId,
            versionId,
            instanceUrl,
            teePubkey,
            teeWalletAddress,
            true // zkVerified
        );
    }

    /// @notice Updates instance status (ACTIVE -> STOPPED/FAILED only)
    /// @param instanceId The instance ID
    /// @param newStatus The new status (must be STOPPED or FAILED)
    function updateInstanceStatus(
        uint256 instanceId,
        InstanceStatus newStatus
    ) external {
        RuntimeInstanceStorage storage instance = _instances[instanceId];
        if (instance.instanceId == 0) revert InstanceNotFound();

        App storage app = apps[instance.appId];

        // Only instance operator or app owner can update
        if (
            instance.operator != msg.sender &&
            app.owner != msg.sender &&
            msg.sender != owner()
        ) {
            revert NotInstanceOperator();
        }

        // Validate state transition: only ACTIVE -> STOPPED/FAILED allowed
        if (InstanceStatus(instance.status) != InstanceStatus.ACTIVE) {
            revert InvalidStatusTransition();
        }
        if (
            newStatus != InstanceStatus.STOPPED &&
            newStatus != InstanceStatus.FAILED
        ) {
            revert InvalidStatusTransition();
        }

        instance.status = uint8(newStatus);
        _removeActiveInstanceWallet(instance.teeWalletAddress);

        // Call removeOperator on dApp if configured
        if (app.dappContract != address(0)) {
            _callRemoveOperator(
                app.appId,
                app.dappContract,
                instance.teeWalletAddress,
                instance.versionId,
                instanceId
            );
        }

        emit InstanceStatusChanged(instanceId, newStatus);
    }

    // ========== View Functions ==========

    function getApp(uint256 appId) external view returns (App memory) {
        return apps[appId];
    }

    function getAppsByOwner(
        address owner_
    ) external view returns (uint256[] memory) {
        return ownerApps[owner_];
    }

    function getAppCount() external view returns (uint256) {
        if (nextAppId == 0) return 0;
        return nextAppId - 1;
    }

    function getVersion(
        uint256 appId,
        uint256 versionId
    ) external view returns (AppVersion memory) {
        return appVersions[appId][versionId];
    }

    function getVersionByCodeMeasurement(
        uint256 appId,
        bytes32 codeMeasurement
    ) external view returns (uint256) {
        bytes32 measurementKey = _computeMeasurementKey(appId, codeMeasurement);
        return codeMeasurementToVersionId[measurementKey];
    }

    function getLatestVersion(
        uint256 appId
    ) external view returns (AppVersion memory) {
        uint256 latestId = apps[appId].latestVersionId;
        return appVersions[appId][latestId];
    }

    function getVersionCount(uint256 appId) external view returns (uint256) {
        return appVersionCount[appId];
    }

    /// @notice Compatibility getter for off-chain consumers.
    /// @dev Historically this contract exposed `instances` as a public mapping.
    ///      After packing storage for gas efficiency, we keep this view function
    ///      to preserve the previous ABI shape (tuple of fields).
    function instances(
        uint256 instanceId
    )
        external
        view
        returns (
            uint256 _instanceId,
            uint256 appId,
            uint256 versionId,
            address operator,
            string memory instanceUrl,
            bytes memory teePubkey,
            address teeWalletAddress,
            bool zkVerified,
            InstanceStatus status,
            uint256 registeredAt
        )
    {
        RuntimeInstanceStorage storage s = _instances[instanceId];
        return (
            s.instanceId,
            s.appId,
            s.versionId,
            s.operator,
            s.instanceUrl,
            s.teePubkey,
            s.teeWalletAddress,
            s.zkVerified,
            InstanceStatus(s.status),
            uint256(s.registeredAt)
        );
    }

    function getInstance(
        uint256 instanceId
    ) external view returns (RuntimeInstance memory) {
        RuntimeInstanceStorage storage s = _instances[instanceId];
        return
            RuntimeInstance({
                instanceId: s.instanceId,
                appId: s.appId,
                versionId: s.versionId,
                operator: s.operator,
                instanceUrl: s.instanceUrl,
                teePubkey: s.teePubkey,
                teeWalletAddress: s.teeWalletAddress,
                zkVerified: s.zkVerified,
                status: InstanceStatus(s.status),
                registeredAt: uint256(s.registeredAt)
            });
    }

    function getInstanceByWallet(
        address teeWalletAddress
    ) external view returns (RuntimeInstance memory) {
        uint256 instanceId = walletToInstance[teeWalletAddress];
        RuntimeInstanceStorage storage s = _instances[instanceId];
        return
            RuntimeInstance({
                instanceId: s.instanceId,
                appId: s.appId,
                versionId: s.versionId,
                operator: s.operator,
                instanceUrl: s.instanceUrl,
                teePubkey: s.teePubkey,
                teeWalletAddress: s.teeWalletAddress,
                zkVerified: s.zkVerified,
                status: InstanceStatus(s.status),
                registeredAt: uint256(s.registeredAt)
            });
    }

    function getInstancesForVersion(
        uint256 appId,
        uint256 versionId
    ) external view returns (uint256[] memory) {
        return versionInstances[appId][versionId];
    }

    /// @notice Returns wallet addresses of instances currently in ACTIVE instance status.
    /// @dev This list does not check app/version status. Consumers should validate status separately.
    function getActiveInstances() external view returns (address[] memory) {
        return _activeInstanceWallets;
    }

    // ========== Internal Functions ==========

    function _validateVersionOwnership(
        uint256 appId,
        uint256 versionId
    ) private view {
        App storage app = apps[appId];
        if (app.owner == address(0)) revert AppNotFound();
        if (app.owner != msg.sender) revert NotAppOwner();

        AppVersion storage version = appVersions[appId][versionId];
        if (version.versionId == 0) revert VersionNotFound();
    }

    function _createInstance(
        uint256 appId,
        uint256 versionId,
        string calldata instanceUrl,
        bytes memory teePubkey,
        address teeWalletAddress,
        bool zkVerified
    ) private returns (uint256 instanceId) {
        if (teeWalletAddress == address(0)) revert InvalidTEEWalletAddress();
        if (walletToInstance[teeWalletAddress] != 0)
            revert DuplicateTEEWallet();
        if (teePubkey.length == 0 || teePubkey.length > 128)
            revert InvalidTEEPubkeyLength();
        _validateInstanceUrl(instanceUrl);

        instanceId = nextInstanceId++;

        _instances[instanceId] = RuntimeInstanceStorage({
            instanceId: instanceId,
            appId: appId,
            versionId: versionId,
            operator: msg.sender,
            registeredAt: uint64(block.timestamp),
            status: uint8(InstanceStatus.ACTIVE),
            zkVerified: zkVerified,
            teeWalletAddress: teeWalletAddress,
            instanceUrl: instanceUrl,
            teePubkey: teePubkey
        });

        walletToInstance[teeWalletAddress] = instanceId;
        versionInstances[appId][versionId].push(instanceId);
        _activeInstanceWalletIndexPlusOne[teeWalletAddress] =
            _activeInstanceWallets.length +
            1;
        _activeInstanceWallets.push(teeWalletAddress);

        emit InstanceWalletBound(teeWalletAddress, instanceId, appId);

        // Call addOperator on dApp if configured
        App storage app = apps[appId];
        if (app.dappContract != address(0)) {
            _callAddOperator(
                appId,
                app.dappContract,
                teeWalletAddress,
                versionId,
                instanceId
            );
        }

        emit InstanceRegistered(
            instanceId,
            appId,
            versionId,
            teeWalletAddress,
            instanceUrl,
            zkVerified
        );
    }

    function _removeActiveInstanceWallet(address teeWalletAddress) private {
        uint256 indexPlusOne = _activeInstanceWalletIndexPlusOne[
            teeWalletAddress
        ];
        if (indexPlusOne == 0) return;

        uint256 index = indexPlusOne - 1;
        uint256 lastIndex = _activeInstanceWallets.length - 1;

        if (index != lastIndex) {
            address movedWallet = _activeInstanceWallets[lastIndex];
            _activeInstanceWallets[index] = movedWallet;
            _activeInstanceWalletIndexPlusOne[movedWallet] = index + 1;
        }

        _activeInstanceWallets.pop();
        delete _activeInstanceWalletIndexPlusOne[teeWalletAddress];
    }

    function _validateInstanceUrl(string calldata instanceUrl) private pure {
        bytes memory s = bytes(instanceUrl);
        if (s.length == 0) revert InvalidInstanceUrl();

        bytes1 h = 0x68;
        bytes1 H = 0x48;
        bytes1 t = 0x74;
        bytes1 T = 0x54;
        bytes1 p = 0x70;
        bytes1 P = 0x50;
        bytes1 sL = 0x73;
        bytes1 S = 0x53;
        bytes1 colon = 0x3a;
        bytes1 slash = 0x2f;

        // Minimal sanity check: require http(s) scheme.
        // Avoids obvious malformed URLs without heavy parsing.
        bool isHttp = s.length >= 7 &&
            (s[0] == h || s[0] == H) &&
            (s[1] == t || s[1] == T) &&
            (s[2] == t || s[2] == T) &&
            (s[3] == p || s[3] == P) &&
            s[4] == colon &&
            s[5] == slash &&
            s[6] == slash;

        bool isHttps = s.length >= 8 &&
            (s[0] == h || s[0] == H) &&
            (s[1] == t || s[1] == T) &&
            (s[2] == t || s[2] == T) &&
            (s[3] == p || s[3] == P) &&
            (s[4] == sL || s[4] == S) &&
            s[5] == colon &&
            s[6] == slash &&
            s[7] == slash;

        if (!isHttp && !isHttps) revert InvalidInstanceUrl();
    }

    function _callAddOperator(
        uint256 appId,
        address dappContract,
        address teeWalletAddress,
        uint256 versionId,
        uint256 instanceId
    ) private {
        if (dappContract.code.length == 0) return;

        try
            INovaAppInterface(dappContract).addOperator{gas: callbackGasLimit}(
                teeWalletAddress,
                appId,
                versionId,
                instanceId
            )
        {
            emit OperatorCallbackSuccess(appId, dappContract, teeWalletAddress);
        } catch {
            emit OperatorCallbackFailed(
                appId,
                dappContract,
                "addOperator failed"
            );
        }
    }

    function _callRemoveOperator(
        uint256 appId,
        address dappContract,
        address teeWalletAddress,
        uint256 versionId,
        uint256 instanceId
    ) private {
        if (dappContract.code.length == 0) return;

        try
            INovaAppInterface(dappContract).removeOperator{
                gas: callbackGasLimit
            }(teeWalletAddress, appId, versionId, instanceId)
        {
            emit OperatorCallbackSuccess(appId, dappContract, teeWalletAddress);
        } catch {
            emit OperatorCallbackFailed(
                appId,
                dappContract,
                "removeOperator failed"
            );
        }
    }

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

        VerifierJournal memory journal = INitroEnclaveVerifier(zkVerifier)
            .verify(publicValues, zkCoprocessor, proofBytes);

        if (journal.result != VerificationResult.Success)
            revert AttestationFailed();

        // Compute code measurement from PCRs
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

        if (!pcrSeen[0]) revert MissingPCRIndex(0);
        if (!pcrSeen[1]) revert MissingPCRIndex(1);
        if (!pcrSeen[2]) revert MissingPCRIndex(2);

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

        // Parse JSON userData to extract eth_addr
        try this.parseEthAddr(journal.userData) returns (address parsed) {
            teeWalletAddress = parsed;
        } catch {
            revert JsonParsingFailed();
        }
        if (teeWalletAddress == address(0)) revert InvalidTEEWalletAddress();
        if (pubkey.length == 0 || pubkey.length > 128)
            revert InvalidTEEPubkeyLength();
    }

    /// @notice External wrapper for JSON parsing (used with try-catch)
    function parseEthAddr(
        bytes calldata userData
    ) external pure returns (address) {
        return JsonParser.extractEthAddr(userData);
    }

    // ========== Internal Helpers ==========

    function _computeVersionMeasurement(
        bytes calldata pcr0,
        bytes calldata pcr1,
        bytes calldata pcr2
    ) internal pure returns (bytes32 codeMeasurement) {
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, pcr0.offset, 48)
            calldatacopy(add(ptr, 48), pcr1.offset, 48)
            calldatacopy(add(ptr, 96), pcr2.offset, 48)
            codeMeasurement := keccak256(ptr, 144)
        }
    }

    function _computeMeasurementKey(
        uint256 appId,
        bytes32 codeMeasurement
    ) internal pure returns (bytes32 measurementKey) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, appId)
            mstore(add(ptr, 0x20), codeMeasurement)
            measurementKey := keccak256(ptr, 0x40)
        }
    }
}
