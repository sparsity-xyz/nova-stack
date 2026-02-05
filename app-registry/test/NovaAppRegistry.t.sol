// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Test} from "forge-std/Test.sol";
import {NovaAppRegistry} from "../src/NovaAppRegistry.sol";
import {INovaAppInterface} from "../src/interfaces/INovaAppInterface.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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

contract NovaAppRegistryTest is Test {
    bytes32 constant NITRO_ARCH = "nitro";
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

    NovaAppRegistry private registry;
    MockNovaApp private mockDapp;
    GasGuzzlerNovaApp private gasGuzzler;

    address private alice = address(0xA11CE);
    address private bob = address(0xB0B);

    function setUp() public {
        NovaAppRegistry impl = new NovaAppRegistry();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(NovaAppRegistry.initialize, (address(0x1234)))
        );
        registry = NovaAppRegistry(address(proxy));
        mockDapp = new MockNovaApp();
        gasGuzzler = new GasGuzzlerNovaApp();
    }

    function _mkPcr(uint8 firstByte) private pure returns (bytes memory out) {
        out = new bytes(48);
        out[0] = bytes1(firstByte);
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

    function test_registerInstanceWithoutProof_bindsWalletAndCallsDapp()
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

        vm.expectEmit(true, true, true, true);
        emit InstanceWalletBound(teeWallet, 1, appId);

        vm.expectEmit(true, true, true, true);
        emit InstanceRegistered(
            1,
            appId,
            versionId,
            teeWallet,
            "http://1.2.3.4:8000",
            false
        );

        vm.prank(alice);
        uint256 instanceId = registry.registerInstanceWithoutProof(
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

    function test_registerInstanceWithoutProof_revertsOnDuplicateWallet()
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
        registry.registerInstanceWithoutProof(
            appId,
            versionId,
            "http://a",
            teePubkey,
            teeWallet,
            codeMeasurement
        );

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.DuplicateTEEWallet.selector);
        registry.registerInstanceWithoutProof(
            appId,
            versionId,
            "http://b",
            teePubkey,
            teeWallet,
            codeMeasurement
        );
    }

    function test_registerInstanceWithoutProof_revertsOnBadUrlScheme() public {
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
        registry.registerInstanceWithoutProof(
            appId,
            versionId,
            "ftp://1.2.3.4",
            teePubkey,
            teeWallet,
            codeMeasurement
        );
    }

    function test_registerInstanceWithoutProof_allowsHttpSchemeCaseInsensitive()
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
        uint256 instanceId = registry.registerInstanceWithoutProof(
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
        uint256 instanceId = registry.registerInstanceWithoutProof(
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
        uint256 instanceId = registry.registerInstanceWithoutProof(
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
        uint256 instanceId = registry.registerInstanceWithoutProof(
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
        uint256 instanceId = registry.registerInstanceWithoutProof(
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

    function test_registerInstanceWithoutProof_allowsDeprecatedVersion()
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

        vm.prank(alice);
        registry.deprecateVersion(appId, versionId);

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));
        uint256 instanceId;

        vm.prank(alice);
        instanceId = registry.registerInstanceWithoutProof(
            appId,
            versionId,
            "http://deprecated-ok",
            hex"112233",
            address(0x2222222222222222222222222222222222222222),
            codeMeasurement
        );

        assertEq(instanceId, 1);
        NovaAppRegistry.RuntimeInstance memory instance = registry.getInstance(
            instanceId
        );
        assertEq(instance.versionId, versionId);
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
        uint256 i1 = registry.registerInstanceWithoutProof(
            appId,
            versionId,
            "http://one",
            hex"112233",
            address(0x1111111111111111111111111111111111111111),
            codeMeasurement
        );
        vm.prank(alice);
        uint256 i2 = registry.registerInstanceWithoutProof(
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

    function test_registerInstanceWithoutProof_revertsOnRevokedVersion()
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

        vm.prank(alice);
        registry.revokeVersion(appId, versionId);

        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.prank(alice);
        vm.expectRevert(NovaAppRegistry.VersionRevoked.selector);
        registry.registerInstanceWithoutProof(
            appId,
            versionId,
            "http://ok",
            hex"112233",
            address(0x1234567890AbcdEF1234567890aBcdef12345678),
            codeMeasurement
        );
    }

    function test_registerInstanceWithoutProof_requiresOwnerOrRegistryOwner()
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

        vm.prank(bob);
        vm.expectRevert(NovaAppRegistry.NotAppOwner.selector);
        registry.registerInstanceWithoutProof(
            appId,
            versionId,
            "http://ok",
            hex"112233",
            address(0x1234567890AbcdEF1234567890aBcdef12345678),
            codeMeasurement
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
            "meta"
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
        uint256 instanceId = registry.registerInstanceWithoutProof(
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
            "meta"
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
            "meta"
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
            "meta"
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
        registry.createApp(NITRO_ARCH, address(mockDapp), "");
    }

    function test_registerInstance_revertsOnZeroAddressWallet() public {
        vm.prank(alice);
        uint256 appId = registry.createApp(
            NITRO_ARCH,
            address(mockDapp),
            "meta"
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
        registry.registerInstanceWithoutProof(
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
            "meta"
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
        uint256 instanceId = registry.registerInstanceWithoutProof(
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
        uint256 appId = registry.createApp(NITRO_ARCH, address(0), "meta");

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
        uint256 appId = registry.createApp(NITRO_ARCH, address(0), "meta");

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
        uint256 appId = registry.createApp(NITRO_ARCH, address(0), "meta");

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
        uint256 appId = registry.createApp(NITRO_ARCH, address(0), "meta");
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
        registry.registerInstanceWithoutProof(
            appId,
            versionId,
            "http://a",
            hex"11",
            ADDRESS1,
            keccak256(abi.encodePacked(_mkPcr(1), _mkPcr(2), _mkPcr(3)))
        );
    }

    address constant ADDRESS1 = address(0x1);
}
