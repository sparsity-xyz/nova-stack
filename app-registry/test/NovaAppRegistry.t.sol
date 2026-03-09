// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Test} from "forge-std/Test.sol";
import {NovaAppRegistry} from "../src/NovaAppRegistry.sol";
import {INovaAppInterface} from "../src/interfaces/INovaAppInterface.sol";
import {
    ZkCoProcessorType,
    VerifierJournal,
    VerificationResult,
    Pcr,
    Bytes48
} from "../src/interfaces/INitroEnclaveVerifier.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {LegacyNovaAppRegistryV0} from "./mocks/LegacyNovaAppRegistryV0.sol";

contract MockNitroEnclaveVerifier {
    function verify(
        bytes calldata output,
        ZkCoProcessorType,
        bytes calldata
    ) external pure returns (VerifierJournal memory) {
        (
            bytes32[3] memory pcrFirst,
            bytes16[3] memory pcrSecond,
            bytes memory userData,
            bytes memory publicKey,
            VerificationResult result
        ) = abi.decode(
                output,
                (bytes32[3], bytes16[3], bytes, bytes, VerificationResult)
            );

        Pcr[] memory pcrs = new Pcr[](3);
        for (uint64 i = 0; i < 3; i++) {
            pcrs[i] = Pcr({
                index: i,
                value: Bytes48({first: pcrFirst[i], second: pcrSecond[i]})
            });
        }

        return
            VerifierJournal({
                result: result,
                trustedCertsPrefixLen: 0,
                timestamp: 0,
                certs: new bytes32[](0),
                userData: userData,
                nonce: "",
                publicKey: publicKey,
                pcrs: pcrs,
                moduleId: ""
            });
    }
}

contract MockNovaApp is INovaAppInterface {
    address public override novaAppRegistry;

    address public lastAddedOperator;
    address public lastRemovedOperator;
    uint256 public lastAppId;
    uint256 public lastVersionId;
    uint256 public lastInstanceId;

    bool public shouldRevertAdd;
    bool public shouldRevertRemove;

    function setRevertAdd(bool v) external {
        shouldRevertAdd = v;
    }

    function setRevertRemove(bool v) external {
        shouldRevertRemove = v;
    }

    function addOperator(
        address operator,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) external {
        if (shouldRevertAdd) revert("addOperator revert");
        lastAddedOperator = operator;
        lastAppId = appId;
        lastVersionId = versionId;
        lastInstanceId = instanceId;
    }

    function removeOperator(
        address operator,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) external {
        if (shouldRevertRemove) revert("removeOperator revert");
        lastRemovedOperator = operator;
        lastAppId = appId;
        lastVersionId = versionId;
        lastInstanceId = instanceId;
    }

    function setNovaAppRegistry(address registry) external {
        novaAppRegistry = registry;
    }
}

contract GasGuzzlerNovaApp is INovaAppInterface {
    address public override novaAppRegistry;

    // Intentionally burns all provided gas.
    function addOperator(address, uint256, uint256, uint256) external pure {
        while (true) {}
    }

    // Intentionally burns all provided gas.
    function removeOperator(address, uint256, uint256, uint256) external pure {
        while (true) {}
    }

    function setNovaAppRegistry(address registry) external {
        novaAppRegistry = registry;
    }
}

contract MalformedNitroEnclaveVerifier {
    enum Mode {
        DuplicatePcrZero,
        MissingPcrOne
    }

    Mode public mode;

    function setMode(Mode m) external {
        mode = m;
    }

    function verify(
        bytes calldata,
        ZkCoProcessorType,
        bytes calldata
    ) external view returns (VerifierJournal memory) {
        Pcr[] memory pcrs;
        if (mode == Mode.DuplicatePcrZero) {
            pcrs = new Pcr[](3);
            pcrs[0] = _mkPcr(0, 1);
            pcrs[1] = _mkPcr(0, 2);
            pcrs[2] = _mkPcr(2, 3);
        } else {
            pcrs = new Pcr[](2);
            pcrs[0] = _mkPcr(0, 1);
            pcrs[1] = _mkPcr(2, 3);
        }

        return
            VerifierJournal({
                result: VerificationResult.Success,
                trustedCertsPrefixLen: 0,
                timestamp: 0,
                certs: new bytes32[](0),
                userData: bytes(
                    '{"eth_addr":"0x1111111111111111111111111111111111111111"}'
                ),
                nonce: "",
                publicKey: hex"1122",
                pcrs: pcrs,
                moduleId: ""
            });
    }

    function _mkPcr(uint64 index, uint8 firstByte) private pure returns (Pcr memory) {
        return
            Pcr({
                index: index,
                value: Bytes48({
                    first: bytes32(bytes1(firstByte)),
                    second: bytes16(0)
                })
            });
    }
}

contract NovaAppRegistryTest is Test {
    bytes32 constant NITRO_ARCH = "nitro";
    event ZKVerifierChanged(address indexed verifier);
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
        NovaAppRegistry.VersionStatus newStatus
    );

    event InstanceRegistered(
        uint256 indexed instanceId,
        uint256 indexed appId,
        uint256 indexed versionId,
        address teeWalletAddress,
        string instanceUrl,
        bool zkVerified
    );

    event InstanceWalletBound(
        address indexed teeWalletAddress,
        uint256 indexed instanceId,
        uint256 indexed appId
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

    event InstanceStatusChanged(
        uint256 indexed instanceId,
        NovaAppRegistry.InstanceStatus newStatus
    );

    event CallbackGasLimitChanged(uint256 gasLimit);
    event AppStatusChanged(
        uint256 indexed appId,
        NovaAppRegistry.AppStatus newStatus,
        address indexed updatedBy
    );
    event AppWalletSet(uint256 indexed appId, address indexed appWallet);

    NovaAppRegistry private registry;
    MockNovaApp private mockDapp;
    GasGuzzlerNovaApp private gasGuzzler;
    MockNitroEnclaveVerifier private mockVerifier;

    address private alice = address(0xA11CE);
    address private bob = address(0xB0B);

    function setUp() public {
        mockVerifier = new MockNitroEnclaveVerifier();
        NovaAppRegistry impl = new NovaAppRegistry();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(NovaAppRegistry.initialize, (address(mockVerifier)))
        );
        registry = NovaAppRegistry(address(proxy));
        mockDapp = new MockNovaApp();
        gasGuzzler = new GasGuzzlerNovaApp();
    }

    function _mkPcr(uint8 firstByte) private pure returns (bytes memory out) {
        out = new bytes(48);
        out[0] = bytes1(firstByte);
    }

    function _addressToHex(address a) private pure returns (string memory) {
        bytes memory chars = "0123456789abcdef";
        bytes memory out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        uint160 value = uint160(a);
        for (uint256 i = 0; i < 20; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8 b = uint8(value >> (8 * (19 - i)));
            out[2 + i * 2] = chars[b >> 4];
            out[3 + i * 2] = chars[b & 0x0f];
        }
        return string(out);
    }

    function _registerInstanceWithMockProof(
        uint256 appId,
        uint256 versionId,
        string memory instanceUrl,
        bytes memory teePubkey,
        address teeWallet,
        bytes32 codeMeasurement
    ) private returns (uint256) {
        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);
        assertEq(
            keccak256(abi.encodePacked(pcr0, pcr1, pcr2)),
            codeMeasurement
        );

        bytes memory publicValues = _buildMockPublicValues(teePubkey, teeWallet);

        return _registerInstanceWithPublicValues(
            appId,
            versionId,
            instanceUrl,
            publicValues
        );
    }

    function _createAppAndEnrollDefaultVersion(
        address dappContract
    ) private returns (uint256 appId, uint256 versionId, bytes32 codeMeasurement) {
        vm.prank(alice);
        appId = registry.createApp(NITRO_ARCH, dappContract, "ipfs://meta");

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);
        codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.prank(alice);
        versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );
    }

    function _setupAppWithDefaultVersion(
        address dappContract
    ) private returns (uint256 appId, uint256 versionId) {
        bytes32 ignoredCodeMeasurement;
        (appId, versionId, ignoredCodeMeasurement) = _createAppAndEnrollDefaultVersion(
            dappContract
        );
    }

    function _registerDefaultInstanceForAppWalletTests(
        uint256 appId,
        uint256 versionId,
        string memory instanceUrl,
        bytes memory teePubkey,
        address teeWallet
    ) private returns (uint256 instanceId) {
        bytes memory publicValues = _buildMockPublicValues(teePubkey, teeWallet);
        vm.prank(alice);
        instanceId = _registerInstanceWithPublicValues(
            appId,
            versionId,
            instanceUrl,
            publicValues
        );
    }

    function _deriveDeterministicTestWallet(
        string memory label,
        uint256 appId
    ) private pure returns (address) {
        uint256 walletPk = uint256(keccak256(abi.encodePacked(label, appId)));
        return vm.addr(walletPk);
    }

    function _buildMockPublicValues(
        bytes memory teePubkey,
        address teeWallet
    ) private pure returns (bytes memory) {
        return
            _buildMockPublicValuesWithResult(
                teePubkey,
                teeWallet,
                VerificationResult.Success
            );
    }

    function _buildMockPublicValuesWithResult(
        bytes memory teePubkey,
        address teeWallet,
        VerificationResult result
    ) private pure returns (bytes memory publicValues) {
        bytes memory userData = bytes(
            string.concat('{"eth_addr":"', _addressToHex(teeWallet), '"}')
        );
        publicValues = _buildMockPublicValuesRaw(teePubkey, userData, result);
    }

    function _buildMockPublicValuesRaw(
        bytes memory teePubkey,
        bytes memory userData,
        VerificationResult result
    ) private pure returns (bytes memory publicValues) {
        bytes32[3] memory pcrFirst = [
            bytes32(bytes1(uint8(1))),
            bytes32(bytes1(uint8(2))),
            bytes32(bytes1(uint8(3)))
        ];
        bytes16[3] memory pcrSecond;

        publicValues = abi.encode(
            pcrFirst,
            pcrSecond,
            userData,
            teePubkey,
            result
        );
    }

    function _registerInstanceWithPublicValues(
        uint256 appId,
        uint256 versionId,
        string memory instanceUrl,
        bytes memory publicValues
    ) private returns (uint256) {
        return
            registry.registerInstance(
                appId,
                versionId,
                instanceUrl,
                ZkCoProcessorType.RiscZero,
                publicValues,
                hex""
            );
    }

    function test_enrollVersion_revertsOnInvalidPcrLengths() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = new bytes(47);
        bytes memory pcr1 = new bytes(48);
        bytes memory pcr2 = new bytes(48);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                NovaAppRegistry.InvalidPCRLength.selector,
                uint64(0),
                uint256(47)
            )
        );
        registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );
    }

    function test_enrollVersion_preventsDuplicateCodeMeasurement() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 v1 = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );
        assertEq(v1, 1);

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.DuplicateCodeMeasurement.selector);
        registry.enrollVersion(
            appId,
            "1.0.1",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run2"
        );
    }

    function test_registerInstance_bindsWalletAndCallsDapp() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        bytes memory teePubkey = hex"112233";
        address teeWallet = address(0x1234567890AbcdEF1234567890aBcdef12345678);

        vm.expectEmit(true, true, true, true);
        emit InstanceWalletBound(teeWallet, 1, appId);

        vm.expectEmit(true, true, true, true);
        emit InstanceRegistered(
            1,
            appId,
            versionId,
            teeWallet,
            "http://1.2.3.4:8000",
            true
        );

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://1.2.3.4:8000",
            teePubkey,
            teeWallet,
            codeMeasurement
        );
        assertEq(instanceId, 1);

        NovaAppRegistry.RuntimeInstance memory instance = registry.getInstance(
            instanceId
        );
        assertEq(instance.teeWalletAddress, teeWallet);
        assertEq(instance.operator, alice);

        // Wallet lookup returns the instance.
        NovaAppRegistry.RuntimeInstance memory byWallet = registry
            .getInstanceByWallet(teeWallet);
        assertEq(byWallet.instanceId, instanceId);

        // dApp callback executed.
        assertEq(mockDapp.lastAddedOperator(), teeWallet);
        assertEq(mockDapp.lastAppId(), appId);
        assertEq(mockDapp.lastVersionId(), versionId);
        assertEq(mockDapp.lastInstanceId(), instanceId);
    }

    function test_registerInstance_doesNotSetAppWallet() public {
        (
            uint256 appId,
            uint256 versionId,
            bytes32 codeMeasurement
        ) = _createAppAndEnrollDefaultVersion(address(mockDapp));

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://1.2.3.4:8000",
            hex"112233",
            address(0x1234567890AbcdEF1234567890aBcdef12345678),
            codeMeasurement
        );
        assertGt(instanceId, 0);

        NovaAppRegistry.App memory appInfo = registry.getApp(appId);
        assertEq(appInfo.appWallet, address(0));
    }

    function test_registerInstance_keepsAppWalletUnsetBeforeAnchoring() public {
        (uint256 appId, uint256 versionId) = _setupAppWithDefaultVersion(
            address(mockDapp)
        );

        uint256 instanceId = _registerDefaultInstanceForAppWalletTests(
            appId,
            versionId,
            "http://no-app-wallet",
            hex"cafebabe",
            address(0x1111111111111111111111111111111111111111)
        );
        assertGt(instanceId, 0);

        NovaAppRegistry.App memory appInfo = registry.getApp(appId);
        assertEq(appInfo.appWallet, address(0));
    }

    function test_setAppWalletIfUnset_setsWalletAfterUnsetRegistration() public {
        (uint256 appId, uint256 versionId) = _setupAppWithDefaultVersion(
            address(mockDapp)
        );

        uint256 instanceId = _registerDefaultInstanceForAppWalletTests(
            appId,
            versionId,
            "http://no-app-wallet",
            hex"cafebabe",
            address(0x1111111111111111111111111111111111111111)
        );
        assertGt(instanceId, 0);

        address appWallet = _deriveDeterministicTestWallet(
            "post-set-app-wallet",
            appId
        );

        vm.expectEmit(true, true, false, true);
        emit AppWalletSet(appId, appWallet);

        vm.prank(alice);
        registry.setAppWalletIfUnset(appId, appWallet);

        NovaAppRegistry.App memory appInfo = registry.getApp(appId);
        assertEq(appInfo.appWallet, appWallet);
    }

    function test_setAppWalletIfUnset_revertsForNonOwner() public {
        (uint256 appId, uint256 versionId) = _setupAppWithDefaultVersion(
            address(mockDapp)
        );

        _registerDefaultInstanceForAppWalletTests(
            appId,
            versionId,
            "http://no-app-wallet",
            hex"cafebabe",
            address(0x1111111111111111111111111111111111111111)
        );

        address appWallet = _deriveDeterministicTestWallet(
            "post-set-app-wallet",
            appId
        );

        vm.prank(bob);
        vm.expectRevert(NovaAppRegistry.NotAppOwner.selector);
        registry.setAppWalletIfUnset(appId, appWallet);
        assertEq(registry.getApp(appId).appWallet, address(0));
    }

    function test_setAppWalletIfUnset_revertsWhenAlreadySet() public {
        (uint256 appId, uint256 versionId) = _setupAppWithDefaultVersion(
            address(mockDapp)
        );

        _registerDefaultInstanceForAppWalletTests(
            appId,
            versionId,
            "http://no-app-wallet",
            hex"cafebabe",
            address(0x1111111111111111111111111111111111111111)
        );

        address appWallet = _deriveDeterministicTestWallet(
            "post-set-app-wallet",
            appId
        );

        vm.prank(alice);
        registry.setAppWalletIfUnset(appId, appWallet);

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.AppWalletMismatch.selector);
        registry.setAppWalletIfUnset(appId, appWallet);

        address otherWallet = _deriveDeterministicTestWallet(
            "post-set-app-wallet-other",
            appId
        );
        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.AppWalletMismatch.selector);
        registry.setAppWalletIfUnset(appId, otherWallet);
        assertEq(registry.getApp(appId).appWallet, appWallet);
    }

    function test_registerInstance_worksAfterAppWalletAnchoring() public {
        (uint256 appId, uint256 versionId) = _setupAppWithDefaultVersion(
            address(mockDapp)
        );

        _registerDefaultInstanceForAppWalletTests(
            appId,
            versionId,
            "http://a",
            hex"112233",
            address(0x1111111111111111111111111111111111111111)
        );
        address anchoredAppWallet = _deriveDeterministicTestWallet(
            "anchored-wallet",
            appId
        );

        vm.prank(alice);
        registry.setAppWalletIfUnset(appId, anchoredAppWallet);

        address secondTeeWallet = address(
            0x2222222222222222222222222222222222222222
        );
        bytes memory secondPublicValues = _buildMockPublicValues(
            hex"445566",
            secondTeeWallet
        );

        vm.prank(alice);
        uint256 secondInstanceId = _registerInstanceWithPublicValues(
            appId,
            versionId,
            "http://b",
            secondPublicValues
        );
        assertGt(secondInstanceId, 0);
        assertEq(registry.getApp(appId).appWallet, anchoredAppWallet);
    }

    function test_setAppWalletIfUnset_revertsOnZeroWallet() public {
        (uint256 appId, uint256 versionId) = _setupAppWithDefaultVersion(
            address(mockDapp)
        );

        _registerDefaultInstanceForAppWalletTests(
            appId,
            versionId,
            "http://zero-wallet",
            hex"778899",
            address(0x3333333333333333333333333333333333333333)
        );

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidAppWalletAddress.selector);
        registry.setAppWalletIfUnset(appId, address(0));
    }

    function test_registerInstance_revertsOnDuplicateWallet() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        bytes memory teePubkey = hex"112233";
        address teeWallet = address(0x1234567890AbcdEF1234567890aBcdef12345678);

        vm.prank(alice);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://a",
            teePubkey,
            teeWallet,
            codeMeasurement
        );

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.DuplicateTEEWallet.selector);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://b",
            teePubkey,
            teeWallet,
            codeMeasurement
        );
    }

    function test_registerInstance_revertsOnBadUrlScheme() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        bytes memory teePubkey = hex"112233";
        address teeWallet = address(0x1234567890AbcdEF1234567890aBcdef12345678);

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidInstanceUrl.selector);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "ftp://1.2.3.4",
            teePubkey,
            teeWallet,
            codeMeasurement
        );
    }

    function test_registerInstance_allowsHttpSchemeCaseInsensitive() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        bytes memory teePubkey = hex"112233";
        address teeWallet = address(0x1234567890AbcdEF1234567890aBcdef12345678);

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "HTTP://EXAMPLE",
            teePubkey,
            teeWallet,
            codeMeasurement
        );
        assertGt(instanceId, 0);
    }

    function test_updateInstanceStatus_onlyAllowsActiveToStoppedOrFailed()
        public
    {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        bytes memory teePubkey = hex"112233";
        address teeWallet = address(0x1234567890AbcdEF1234567890aBcdef12345678);

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://ok",
            teePubkey,
            teeWallet,
            codeMeasurement
        );

        vm.prank(alice);
        registry.updateInstanceStatus(
            instanceId,
            NovaAppRegistry.InstanceStatus.STOPPED
        );

        // removeOperator called.
        assertEq(mockDapp.lastRemovedOperator(), teeWallet);

        // Cannot transition again.
        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidStatusTransition.selector);
        registry.updateInstanceStatus(
            instanceId,
            NovaAppRegistry.InstanceStatus.FAILED
        );
    }

    function test_dappCallbackFailure_addOperator_emitsFailureButDoesNotRevert()
        public
    {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );
        assertEq(versionId, 1);

        mockDapp.setRevertAdd(true);

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.expectEmit(true, true, false, true);
        emit OperatorCallbackFailed(
            appId,
            address(mockDapp),
            "addOperator failed"
        );

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://ok",
            hex"112233",
            address(0x1234567890AbcdEF1234567890aBcdef12345678),
            codeMeasurement
        );
        assertEq(instanceId, 1);
    }

    function test_dappCallbackGasExhaustion_addOperator_emitsFailureButDoesNotRevert()
        public
    {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(gasGuzzler),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );
        assertEq(versionId, 1);

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        // Callback burns the full stipend (default 100k), must not revert registration.
        vm.expectEmit(true, true, false, true);
        emit OperatorCallbackFailed(
            appId,
            address(gasGuzzler),
            "addOperator failed"
        );

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://ok",
            hex"112233",
            address(0x1234567890AbcdEF1234567890aBcdef12345678),
            codeMeasurement
        );
        assertEq(instanceId, 1);

        // Instance still exists.
        NovaAppRegistry.RuntimeInstance memory instance = registry.getInstance(
            instanceId
        );
        assertEq(instance.instanceId, instanceId);
        assertEq(instance.appId, appId);
        assertEq(instance.versionId, versionId);
    }

    function test_dappCallbackGasExhaustion_removeOperator_emitsFailureButDoesNotRevert()
        public
    {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(gasGuzzler),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        address teeWallet = address(0x1234567890AbcdEF1234567890aBcdef12345678);

        // addOperator will also OOG, but ignore it for this test.
        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://ok",
            hex"112233",
            teeWallet,
            codeMeasurement
        );
        assertEq(instanceId, 1);

        vm.expectEmit(true, true, false, true);
        emit OperatorCallbackFailed(
            appId,
            address(gasGuzzler),
            "removeOperator failed"
        );

        vm.expectEmit(true, true, false, true);
        emit InstanceStatusChanged(
            instanceId,
            NovaAppRegistry.InstanceStatus.STOPPED
        );

        vm.prank(alice);
        registry.updateInstanceStatus(
            instanceId,
            NovaAppRegistry.InstanceStatus.STOPPED
        );

        NovaAppRegistry.RuntimeInstance memory instance = registry.getInstance(
            instanceId
        );
        assertEq(
            uint8(instance.status),
            uint8(NovaAppRegistry.InstanceStatus.STOPPED)
        );
    }

    function test_versionLifecycle_enrolledThenDeprecatedThenRevoked_emitsEvents()
        public
    {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);
        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.expectEmit(true, true, false, true);
        emit VersionEnrolled(appId, 1, "1.0.0", codeMeasurement, "img");

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );
        assertEq(versionId, 1);

        NovaAppRegistry.AppVersion memory v = registry.getVersion(
            appId,
            versionId
        );
        assertEq(
            uint8(v.status),
            uint8(NovaAppRegistry.VersionStatus.ENROLLED)
        );

        vm.expectEmit(true, true, false, true);
        emit VersionStatusChanged(
            appId,
            versionId,
            NovaAppRegistry.VersionStatus.DEPRECATED
        );

        vm.prank(alice);
        registry.deprecateVersion(appId, versionId);

        v = registry.getVersion(appId, versionId);
        assertEq(
            uint8(v.status),
            uint8(NovaAppRegistry.VersionStatus.DEPRECATED)
        );

        vm.expectEmit(true, true, false, true);
        emit VersionStatusChanged(
            appId,
            versionId,
            NovaAppRegistry.VersionStatus.REVOKED
        );

        vm.prank(alice);
        registry.revokeVersion(appId, versionId);

        v = registry.getVersion(appId, versionId);
        assertEq(uint8(v.status), uint8(NovaAppRegistry.VersionStatus.REVOKED));
    }

    function test_registerInstance_revertsOnDeprecatedVersion() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        vm.prank(alice);
        registry.deprecateVersion(appId, versionId);

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.VersionNotEnrolled.selector);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://deprecated-ok",
            hex"112233",
            address(0x2222222222222222222222222222222222222222),
            codeMeasurement
        );
    }

    function test_multipleInstancesPerVersion_getInstancesForVersion_returnsAll()
        public
    {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.prank(alice);
        uint256 i1 = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://one",
            hex"112233",
            address(0x1111111111111111111111111111111111111111),
            codeMeasurement
        );
        vm.prank(alice);
        uint256 i2 = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://two",
            hex"445566",
            address(0x2222222222222222222222222222222222222222),
            codeMeasurement
        );

        assertEq(i1, 1);
        assertEq(i2, 2);

        uint256[] memory ids = registry.getInstancesForVersion(
            appId,
            versionId
        );
        assertEq(ids.length, 2);
        assertEq(ids[0], i1);
        assertEq(ids[1], i2);
    }

    function test_setCallbackGasLimit_emitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit CallbackGasLimitChanged(150000);
        registry.setCallbackGasLimit(150000);
        assertEq(registry.callbackGasLimit(), 150000);
    }

    function test_ownerOnly_adminFunctions() public {
        vm.prank(alice);
        vm.expectRevert();
        registry.setZkVerifier(address(0xBEEF));

        vm.prank(alice);
        vm.expectRevert();
        registry.setCallbackGasLimit(123456);
    }

    function test_registerInstance_revertsOnRevokedVersion() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        vm.prank(alice);
        registry.revokeVersion(appId, versionId);

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.VersionRevoked.selector);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://ok",
            hex"112233",
            address(0x1234567890AbcdEF1234567890aBcdef12345678),
            codeMeasurement
        );
    }

    function test_registerInstance_revertsForNonOwner() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.prank(bob);
        vm.expectRevert(NovaAppRegistry.NotAppOwner.selector);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://ok",
            hex"112233",
            address(0x1234567890AbcdEF1234567890aBcdef12345678),
            codeMeasurement
        );
    }

    function test_activeInstances_addsOnRegister_removesOnStopped() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        address w1 = address(0x1111111111111111111111111111111111111111);
        address w2 = address(0x2222222222222222222222222222222222222222);

        vm.prank(alice);
        uint256 i1 = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://one",
            hex"112233",
            w1,
            codeMeasurement
        );

        vm.prank(alice);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://two",
            hex"445566",
            w2,
            codeMeasurement
        );

        address[] memory active = registry.getActiveInstances(appId);
        assertEq(active.length, 2);

        vm.prank(alice);
        registry.updateInstanceStatus(
            i1,
            NovaAppRegistry.InstanceStatus.STOPPED
        );

        active = registry.getActiveInstances(appId);
        assertEq(active.length, 1);
        assertEq(active[0], w2);
    }

    function test_revokeVersion_removesInstancesFromActiveList() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        bytes memory pcr0 = _mkPcr(1);
        bytes memory pcr1 = _mkPcr(2);
        bytes memory pcr2 = _mkPcr(3);

        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        address wallet = address(0x1234567890AbcdEF1234567890aBcdef12345678);

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://active",
            hex"112233",
            wallet,
            codeMeasurement
        );

        vm.prank(alice);
        registry.revokeVersion(appId, versionId);

        address[] memory active = registry.getActiveInstances(appId);
        assertEq(active.length, 0);

        // Status should still be ACTIVE
        NovaAppRegistry.RuntimeInstance memory instance = registry.getInstance(
            instanceId
        );
        assertEq(
            uint8(instance.status),
            uint8(NovaAppRegistry.InstanceStatus.ACTIVE)
        );
    }

    // ============================================================================================
    //                                     NEW TESTS
    // ============================================================================================

    function test_getAppCount_returnsCorrectCount() public {
        // Initially 0 (after fix)
        assertEq(registry.getAppCount(), 0);

        vm.prank(alice);
        registry.createApp(NITRO_ARCH, address(mockDapp), "ipfs://1");
        assertEq(registry.getAppCount(), 1);

        vm.prank(alice);
        registry.createApp(NITRO_ARCH, address(mockDapp), "ipfs://2");
        assertEq(registry.getAppCount(), 2);
    }

    function test_updateInstanceStatus_revertsForUnauthorizedUser() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );
        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0",
            _mkPcr(1),
            _mkPcr(2),
            _mkPcr(3),
            "img",
            "url",
            "hash",
            "run"
        );

        bytes32 cm = keccak256(
            abi.encodePacked(_mkPcr(1), _mkPcr(2), _mkPcr(3))
        );
        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://url",
            hex"11",
            address(0x111),
            cm
        );

        // Bob tries to update status -> revert
        vm.prank(bob);
        vm.expectRevert(NovaAppRegistry.NotInstanceOperator.selector);
        registry.updateInstanceStatus(
            instanceId,
            NovaAppRegistry.InstanceStatus.STOPPED
        );
    }

    function test_deprecateVersion_revertsForUnauthorizedUser() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );
        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0",
            _mkPcr(1),
            _mkPcr(2),
            _mkPcr(3),
            "img",
            "url",
            "hash",
            "run"
        );

        // Bob tries to deprecate -> revert
        vm.prank(bob);
        vm.expectRevert(NovaAppRegistry.NotAppOwner.selector);
        registry.deprecateVersion(appId, versionId);
    }

    function test_revokeVersion_revertsForUnauthorizedUser() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );
        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0",
            _mkPcr(1),
            _mkPcr(2),
            _mkPcr(3),
            "img",
            "url",
            "hash",
            "run"
        );

        // Bob tries to revoke -> revert
        vm.prank(bob);
        vm.expectRevert(NovaAppRegistry.NotAppOwner.selector);
        registry.revokeVersion(appId, versionId);
    }

    function test_enrollVersion_revertsOnEmptyStrings() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );

        // Empty version name -> revert
        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidVersionName.selector);
        registry.enrollVersion(
            appId,
            "",
            _mkPcr(1),
            _mkPcr(2),
            _mkPcr(3),
            "img",
            "url",
            "hash",
            "run"
        );

        // Empty image URI -> revert
        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidImageUri.selector);
        registry.enrollVersion(
            appId,
            "1.0",
            _mkPcr(1),
            _mkPcr(2),
            _mkPcr(3),
            "",
            "url",
            "hash",
            "run"
        );
    }

    function test_createApp_revertsOnInvalidMetadata() public {
        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(NITRO_ARCH, address(mockDapp), "invalid");
    }

    function test_createApp_allowsEmptyMetadata() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(NITRO_ARCH, address(mockDapp), "");
        assertEq(registry.getApp(appId).metadataUri, "");
    }

    function test_createApp_allowsHttpsMetadata_caseInsensitive() public {
        vm.prank(alice);
        uint256 appId1 = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "https://example.com"
        );
        assertEq(registry.getApp(appId1).metadataUri, "https://example.com");

        vm.prank(alice);
        uint256 appId2 = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "HTTPS://EXAMPLE.COM"
        );
        assertEq(registry.getApp(appId2).metadataUri, "HTTPS://EXAMPLE.COM");

        vm.prank(alice);
        uint256 appId3 = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "HttPs://Example.Com"
        );
        assertEq(registry.getApp(appId3).metadataUri, "HttPs://Example.Com");
    }

    function test_createApp_allowsIpfsMetadata_caseInsensitive() public {
        vm.prank(alice);
        uint256 appId1 = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://Qm123"
        );
        assertEq(registry.getApp(appId1).metadataUri, "ipfs://Qm123");

        vm.prank(alice);
        uint256 appId2 = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "IPFS://Qm456"
        );
        assertEq(registry.getApp(appId2).metadataUri, "IPFS://Qm456");

        vm.prank(alice);
        uint256 appId3 = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "IpFs://Qm789"
        );
        assertEq(registry.getApp(appId3).metadataUri, "IpFs://Qm789");
    }

    function test_createApp_revertsOnInvalidSchemes() public {
        vm.startPrank(alice);

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(NITRO_ARCH, address(mockDapp), "http://example.com");

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(NITRO_ARCH, address(mockDapp), "ftp://example.com");

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(NITRO_ARCH, address(mockDapp), "ipfs:/Qm123");

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(NITRO_ARCH, address(mockDapp), "https//example.com");

        vm.stopPrank();
    }

    function test_createApp_revertsOnWhitespace() public {
        vm.startPrank(alice);

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            " https://example.com"
        );

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "https://example.com "
        );

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "h ttps://example.com"
        );

        vm.stopPrank();
    }

    function test_createApp_revertsOnShortUris() public {
        vm.startPrank(alice);

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(NITRO_ARCH, address(mockDapp), "https:/");

        vm.expectRevert(NovaAppRegistry.InvalidMetadataUri.selector);
        registry.createApp(NITRO_ARCH, address(mockDapp), "ipfs://"); // length 7, but only scheme

        vm.stopPrank();
    }

    function test_registerInstance_revertsOnZeroAddressWallet() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );
        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0",
            _mkPcr(1),
            _mkPcr(2),
            _mkPcr(3),
            "img",
            "url",
            "hash",
            "run"
        );
        bytes32 cm = keccak256(
            abi.encodePacked(_mkPcr(1), _mkPcr(2), _mkPcr(3))
        );

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidTEEWalletAddress.selector);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://url",
            hex"11",
            address(0),
            cm
        );
    }

    function test_updateInstanceStatus_revertsOnInvalidTransitions() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "ipfs://meta"
        );
        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0",
            _mkPcr(1),
            _mkPcr(2),
            _mkPcr(3),
            "img",
            "url",
            "hash",
            "run"
        );
        bytes32 cm = keccak256(
            abi.encodePacked(_mkPcr(1), _mkPcr(2), _mkPcr(3))
        );

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://url",
            hex"11",
            address(0x111),
            cm
        );

        // Active -> Active
        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidStatusTransition.selector);
        registry.updateInstanceStatus(
            instanceId,
            NovaAppRegistry.InstanceStatus.ACTIVE
        );

        // Active -> Stopped (OK)
        vm.prank(alice);
        registry.updateInstanceStatus(
            instanceId,
            NovaAppRegistry.InstanceStatus.STOPPED
        );

        // Stopped -> Active
        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidStatusTransition.selector);
        registry.updateInstanceStatus(
            instanceId,
            NovaAppRegistry.InstanceStatus.ACTIVE
        );
    }

    function test_updateAppStatus_permissions() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(0),
            "ipfs://meta"
        );

        // App owner can toggle ACTIVE -> INACTIVE
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit AppStatusChanged(appId, NovaAppRegistry.AppStatus.INACTIVE, alice);
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.INACTIVE);
        assertEq(
            uint8(registry.getApp(appId).status),
            uint8(NovaAppRegistry.AppStatus.INACTIVE)
        );

        // App owner can toggle INACTIVE -> ACTIVE
        vm.prank(alice);
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.ACTIVE);
        assertEq(
            uint8(registry.getApp(appId).status),
            uint8(NovaAppRegistry.AppStatus.ACTIVE)
        );

        // Random user cannot change status
        vm.prank(bob);
        vm.expectRevert(NovaAppRegistry.NotAppOwner.selector);
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.INACTIVE);

        // Registry owner can force REVOKED
        vm.expectEmit(true, false, false, true);
        emit AppStatusChanged(
            appId,
            NovaAppRegistry.AppStatus.REVOKED,
            address(this)
        );
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.REVOKED);
        assertEq(
            uint8(registry.getApp(appId).status),
            uint8(NovaAppRegistry.AppStatus.REVOKED)
        );

        // App owner cannot change back from REVOKED
        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidStatusTransition.selector);
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.ACTIVE);
    }

    function test_updateAppStatus_recoveryByRegistryOwner() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(0),
            "ipfs://meta"
        );

        // Force REVOKED
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.REVOKED);

        // Registry owner can recover REVOKED -> INACTIVE
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.INACTIVE);
        assertEq(
            uint8(registry.getApp(appId).status),
            uint8(NovaAppRegistry.AppStatus.INACTIVE)
        );

        // App owner can now re-activate
        vm.prank(alice);
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.ACTIVE);
        assertEq(
            uint8(registry.getApp(appId).status),
            uint8(NovaAppRegistry.AppStatus.ACTIVE)
        );
    }

    function test_statusEnforcement_enrollVersion() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(0),
            "ipfs://meta"
        );

        vm.prank(alice);
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.INACTIVE);

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.AppNotActive.selector);
        registry.enrollVersion(
            appId,
            "1.0.0",
            _mkPcr(0),
            _mkPcr(0),
            _mkPcr(0),
            "img",
            "a",
            "h",
            "r"
        );
    }

    function test_statusEnforcement_registerInstance() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(0),
            "ipfs://meta"
        );
        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            _mkPcr(1),
            _mkPcr(2),
            _mkPcr(3),
            "img",
            "a",
            "h",
            "r"
        );

        vm.prank(alice);
        registry.updateAppStatus(appId, NovaAppRegistry.AppStatus.INACTIVE);

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.AppNotActive.selector);
        _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://a",
            hex"11",
            ADDRESS1,
            keccak256(abi.encodePacked(_mkPcr(1), _mkPcr(2), _mkPcr(3)))
        );
    }

    function test_setZkVerifier_updatesAndEmitsEvent() public {
        MockNitroEnclaveVerifier replacementVerifier = new MockNitroEnclaveVerifier();

        vm.expectEmit(true, false, false, true);
        emit ZKVerifierChanged(address(replacementVerifier));
        registry.setZkVerifier(address(replacementVerifier));

        assertEq(address(registry.zkVerifier()), address(replacementVerifier));
    }

    function test_setZkVerifier_revertsForZeroAndEoa() public {
        vm.expectRevert(NovaAppRegistry.InvalidZkVerifier.selector);
        registry.setZkVerifier(address(0));

        vm.expectRevert(NovaAppRegistry.InvalidZkVerifier.selector);
        registry.setZkVerifier(alice);
    }

    function test_getAppsByOwner_returnsOwnedAppIdsInOrder() public {
        vm.prank(alice);
        registry.createApp(NITRO_ARCH, address(0), "ipfs://alice-1");

        vm.prank(bob);
        registry.createApp(NITRO_ARCH, address(0), "ipfs://bob-1");

        vm.prank(alice);
        registry.createApp(NITRO_ARCH, address(0), "ipfs://alice-2");

        uint256[] memory aliceApps = registry.getAppsByOwner(alice);
        assertEq(aliceApps.length, 2);
        assertEq(aliceApps[0], 1);
        assertEq(aliceApps[1], 3);

        uint256[] memory bobApps = registry.getAppsByOwner(bob);
        assertEq(bobApps.length, 1);
        assertEq(bobApps[0], 2);
    }

    function test_versionGetters_returnLatestAndMeasurementIndex() public {
        (uint256 appId, uint256 v1, bytes32 cm1) = _createAppAndEnrollDefaultVersion(
            address(mockDapp)
        );
        assertEq(v1, 1);
        assertEq(registry.getVersionCount(appId), 1);
        assertEq(registry.getVersionByCodeMeasurement(appId, cm1), v1);

        bytes memory pcr0 = _mkPcr(4);
        bytes memory pcr1 = _mkPcr(5);
        bytes memory pcr2 = _mkPcr(6);
        bytes32 cm2 = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.prank(alice);
        uint256 v2 = registry.enrollVersion(
            appId,
            "2.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img-2",
            "audit-2",
            "hash-2",
            "run-2"
        );

        NovaAppRegistry.AppVersion memory latest = registry.getLatestVersion(appId);
        assertEq(v2, 2);
        assertEq(latest.versionId, v2);
        assertEq(latest.codeMeasurement, cm2);
        assertEq(registry.getVersionCount(appId), 2);
        assertEq(registry.getVersionByCodeMeasurement(appId, cm2), v2);
    }

    function test_instancesCompatibilityGetter_matchesGetInstance() public {
        (uint256 appId, uint256 versionId, bytes32 codeMeasurement) = _createAppAndEnrollDefaultVersion(
            address(mockDapp)
        );
        address teeWallet = address(0x1234567890AbcdEF1234567890aBcdef12345678);

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "http://instance-compat",
            hex"123456",
            teeWallet,
            codeMeasurement
        );

        (
            uint256 rawInstanceId,
            uint256 rawAppId,
            uint256 rawVersionId,
            address rawOperator,
            string memory rawUrl,
            bytes memory rawPubkey,
            address rawWallet,
            bool rawZkVerified,
            NovaAppRegistry.InstanceStatus rawStatus,
            uint256 rawRegisteredAt
        ) = registry.instances(instanceId);

        NovaAppRegistry.RuntimeInstance memory full = registry.getInstance(instanceId);
        assertEq(rawInstanceId, full.instanceId);
        assertEq(rawAppId, full.appId);
        assertEq(rawVersionId, full.versionId);
        assertEq(rawOperator, full.operator);
        assertEq(rawUrl, full.instanceUrl);
        assertEq(rawPubkey, full.teePubkey);
        assertEq(rawWallet, full.teeWalletAddress);
        assertEq(rawZkVerified, full.zkVerified);
        assertEq(uint8(rawStatus), uint8(full.status));
        assertEq(rawRegisteredAt, full.registeredAt);
    }

    function test_registerInstance_allowsHttpsSchemeCaseInsensitive() public {
        (uint256 appId, uint256 versionId, bytes32 codeMeasurement) = _createAppAndEnrollDefaultVersion(
            address(mockDapp)
        );

        vm.prank(alice);
        uint256 instanceId = _registerInstanceWithMockProof(
            appId,
            versionId,
            "hTtPs://EXAMPLE",
            hex"1122",
            address(0x1111111111111111111111111111111111111111),
            codeMeasurement
        );
        assertGt(instanceId, 0);
    }

    function test_registerInstance_revertsOnCodeMeasurementMismatch() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(NITRO_ARCH, address(mockDapp), "ipfs://meta");

        bytes memory pcr0 = _mkPcr(4);
        bytes memory pcr1 = _mkPcr(5);
        bytes memory pcr2 = _mkPcr(6);
        vm.prank(alice);
        uint256 versionId = registry.enrollVersion(
            appId,
            "1.0.0",
            pcr0,
            pcr1,
            pcr2,
            "img",
            "audit",
            "hash",
            "run"
        );

        address teeWallet = address(0x1111111111111111111111111111111111111111);

        bytes memory publicValues = _buildMockPublicValues(hex"112233", teeWallet);

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.CodeMeasurementMismatch.selector);
        _registerInstanceWithPublicValues(
            appId,
            versionId,
            "http://mismatch",
            publicValues
        );
    }

    function test_registerInstance_revertsOnAttestationFailureResult() public {
        (uint256 appId, uint256 versionId, ) = _createAppAndEnrollDefaultVersion(
            address(mockDapp)
        );
        address teeWallet = address(0x1111111111111111111111111111111111111111);

        bytes memory publicValues = _buildMockPublicValuesWithResult(
            hex"11",
            teeWallet,
            VerificationResult.InvalidTimestamp
        );

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.AttestationFailed.selector);
        _registerInstanceWithPublicValues(
            appId,
            versionId,
            "http://attestation-fail",
            publicValues
        );
    }

    function test_registerInstance_revertsOnJsonParsingFailure() public {
        (uint256 appId, uint256 versionId, ) = _createAppAndEnrollDefaultVersion(
            address(mockDapp)
        );
        bytes memory publicValues = _buildMockPublicValuesRaw(
            hex"11",
            bytes("not-a-json-payload"),
            VerificationResult.Success
        );

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.JsonParsingFailed.selector);
        _registerInstanceWithPublicValues(
            appId,
            versionId,
            "http://json-fail",
            publicValues
        );
    }

    function test_registerInstance_revertsOnInvalidTeePubkeyLength() public {
        (uint256 appId, uint256 versionId, ) = _createAppAndEnrollDefaultVersion(
            address(mockDapp)
        );
        address teeWallet = address(0x1111111111111111111111111111111111111111);

        bytes memory publicValues = _buildMockPublicValues(hex"", teeWallet);

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.InvalidTEEPubkeyLength.selector);
        _registerInstanceWithPublicValues(
            appId,
            versionId,
            "http://invalid-pubkey",
            publicValues
        );
    }

    function test_registerInstance_revertsOnDuplicatePcrIndexFromVerifier() public {
        (uint256 appId, uint256 versionId, ) = _createAppAndEnrollDefaultVersion(
            address(mockDapp)
        );

        MalformedNitroEnclaveVerifier malformed = new MalformedNitroEnclaveVerifier();
        registry.setZkVerifier(address(malformed));

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                NovaAppRegistry.DuplicatePCRIndex.selector,
                uint64(0)
            )
        );
        registry.registerInstance(
            appId,
            versionId,
            "http://dup-pcr",
            ZkCoProcessorType.RiscZero,
            hex"",
            hex""
        );
    }

    function test_registerInstance_revertsOnMissingPcrIndexFromVerifier() public {
        (uint256 appId, uint256 versionId, ) = _createAppAndEnrollDefaultVersion(
            address(mockDapp)
        );

        MalformedNitroEnclaveVerifier malformed = new MalformedNitroEnclaveVerifier();
        malformed.setMode(MalformedNitroEnclaveVerifier.Mode.MissingPcrOne);
        registry.setZkVerifier(address(malformed));

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                NovaAppRegistry.MissingPCRIndex.selector,
                uint64(1)
            )
        );
        registry.registerInstance(
            appId,
            versionId,
            "http://missing-pcr",
            ZkCoProcessorType.RiscZero,
            hex"",
            hex""
        );
    }

    function test_updateInstanceStatus_revertsWhenInstanceNotFound() public {
        vm.expectRevert(NovaAppRegistry.InstanceNotFound.selector);
        registry.updateInstanceStatus(999999, NovaAppRegistry.InstanceStatus.STOPPED);
    }

    function test_upgradeCompatibility_preservesLegacyStorageLayout() public {
        LegacyNovaAppRegistryV0 legacyImpl = new LegacyNovaAppRegistryV0();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(legacyImpl),
            abi.encodeCall(
                LegacyNovaAppRegistryV0.initialize,
                (address(mockVerifier))
            )
        );

        LegacyNovaAppRegistryV0 legacy = LegacyNovaAppRegistryV0(
            address(proxy)
        );
        assertEq(legacy.nextInstanceId(), 1);

        // Old layout slot for nextInstanceId is 11.
        vm.store(address(proxy), bytes32(uint256(11)), bytes32(uint256(7)));
        assertEq(legacy.nextInstanceId(), 7);

        NovaAppRegistry newImpl = new NovaAppRegistry();
        legacy.upgradeToAndCall(address(newImpl), "");

        NovaAppRegistry upgraded = NovaAppRegistry(address(proxy));
        assertEq(upgraded.nextInstanceId(), 7);

        // New storage starts after legacy fields and should be clean on first upgrade.
        address[] memory active = upgraded.getActiveInstances(1);
        assertEq(active.length, 0);
        assertEq(upgraded.callbackGasLimit(), 100000);
    }

    address constant ADDRESS1 = address(0x1);
}
