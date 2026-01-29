// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/SparsityAppRegistry.sol";
import "../src/interfaces/ISparsityApp.sol";

/// @title SparsityAppRegistry Unit Tests
/// @notice Tests for the SparsityAppRegistry contract
contract SparsityAppRegistryTest is Test {
    SparsityAppRegistry public registry;

    address public owner;
    address public user1;
    address public user2;

    // Test data
    bytes32 constant TEE_ARCH = bytes32("nitro");
    bytes32 constant CODE_MEASUREMENT = keccak256("test-code-measurement");
    bytes constant TEE_PUBKEY =
        hex"04abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
    address constant TEE_WALLET =
        address(0x1234567890123456789012345678901234567890);
    string constant APP_URL = "https://example.com";
    address constant CONTRACT_ADDR = address(0);
    string constant METADATA_URI = "/metadata.json";
    string constant BUILD_ATTESTATION_URL =
        "https://github.com/test/test/releases/download/v1.0.0/build-attestation.json";
    string constant BUILD_ATTESTATION_SHA256 =
        "abc123def456abc123def456abc123def456abc123def456abc123def456abc1";
    string constant BUILD_GITHUB_RUN_ID = "12345678";

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

    function setUp() public {
        owner = address(this);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");

        registry = new SparsityAppRegistry();
    }

    // ========== Admin Functions Tests ==========

    function test_constructor_setsOwner() public view {
        assertEq(registry.owner(), owner);
    }

    function test_setZKVerifier_success() public {
        // Deploy a mock verifier (just needs to have code)
        MockVerifier verifier = new MockVerifier();

        registry.setZKVerifier(address(verifier));
        assertEq(registry.zkVerifier(), address(verifier));
    }

    function test_setZKVerifier_revertOnZeroAddress() public {
        vm.expectRevert(SparsityAppRegistry.InvalidZkVerifier.selector);
        registry.setZKVerifier(address(0));
    }

    function test_setZKVerifier_revertOnEOA() public {
        vm.expectRevert(SparsityAppRegistry.InvalidZkVerifier.selector);
        registry.setZKVerifier(user1);
    }

    function test_setZKVerifier_revertOnNonOwner() public {
        MockVerifier verifier = new MockVerifier();

        vm.prank(user1);
        vm.expectRevert();
        registry.setZKVerifier(address(verifier));
    }

    function test_setGasLimit_success() public {
        registry.setGasLimit(100000);
        assertEq(registry.gasLimit(), 100000);
    }

    function test_setGasLimit_revertOnNonOwner() public {
        vm.prank(user1);
        vm.expectRevert();
        registry.setGasLimit(100000);
    }

    // ========== registerAppWithoutZKP Tests ==========

    function test_registerAppWithoutZKP_success() public {
        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        assertEq(appId, 1);

        SparsityAppRegistry.SparsityApp memory app = registry.getApp(appId);
        assertEq(app.owner, user1);
        assertEq(app.appId, 1);
        assertEq(app.teeArch, TEE_ARCH);
        assertEq(app.codeMeasurement, CODE_MEASUREMENT);
        assertEq(app.teePubkey, TEE_PUBKEY);
        assertEq(app.teeWalletAddress, TEE_WALLET);
        assertEq(app.appUrl, APP_URL);
        assertEq(app.contractAddr, CONTRACT_ADDR);
        assertEq(app.metadataUri, METADATA_URI);
        assertEq(app.zkVerified, false);
    }

    function test_registerAppWithoutZKP_emitsEvent() public {
        vm.prank(user1);

        vm.expectEmit(true, true, true, true);
        emit AppRegistered(
            1, // appId
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            APP_URL,
            address(0), // zkVerifier = 0 for non-ZKP registration
            user1,
            CONTRACT_ADDR,
            false, // zkVerified
            true // hasBuildAttestation
        );

        registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );
    }

    function test_registerAppWithoutZKP_incrementsAppId() public {
        vm.startPrank(user1);

        uint256 appId1 = registry.registerAppWithoutZKP(
            "https://app1.com",
            TEE_ARCH,
            keccak256("code1"),
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        uint256 appId2 = registry.registerAppWithoutZKP(
            "https://app2.com",
            TEE_ARCH,
            keccak256("code2"),
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        vm.stopPrank();

        assertEq(appId1, 1);
        assertEq(appId2, 2);
    }

    function test_registerAppWithoutZKP_revertOnZeroTEEWallet() public {
        vm.prank(user1);
        vm.expectRevert(SparsityAppRegistry.InvalidTEEWalletAddress.selector);
        registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            address(0), // Zero address
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );
    }

    function test_registerAppWithoutZKP_revertOnZeroCodeMeasurement() public {
        vm.prank(user1);
        vm.expectRevert(SparsityAppRegistry.InvalidCodeMeasurement.selector);
        registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            bytes32(0), // Zero code measurement
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );
    }

    function test_registerAppWithoutZKP_revertOnEmptyPubkey() public {
        vm.prank(user1);
        vm.expectRevert(SparsityAppRegistry.InvalidTEEPubkeyLength.selector);
        registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            "", // Empty pubkey
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );
    }

    function test_registerAppWithoutZKP_revertOnEmptyAppUrl() public {
        vm.prank(user1);
        vm.expectRevert(SparsityAppRegistry.InvalidAppUrl.selector);
        registry.registerAppWithoutZKP(
            "", // Empty URL
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );
    }

    function test_registerAppWithoutZKP_revertOnNotOwnerUpdate() public {
        vm.prank(user1);
        registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        // Different user trying to update existing app should fail
        vm.prank(user2);
        vm.expectRevert(SparsityAppRegistry.NotAppOwner.selector);
        registry.registerAppWithoutZKP(
            APP_URL, // Same URL
            TEE_ARCH,
            CODE_MEASUREMENT, // Same code measurement
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );
    }

    function test_registerAppWithoutZKP_ownerCanUpdate() public {
        // First registration
        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        // Define new values
        bytes
            memory newPubkey = hex"05abcdef9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef9876543210cd";
        address newWallet = address(0x9876543210987654321098765432109876543210);

        // Owner updates same key - should succeed and return same appId
        vm.expectEmit(true, true, false, true);
        emit AppUpdated(
            appId,
            TEE_PUBKEY, // Old pubkey
            newPubkey, // New pubkey
            TEE_WALLET, // Old wallet
            newWallet, // New wallet
            user1 // Owner
        );

        vm.prank(user1);
        uint256 updatedAppId = registry.registerAppWithoutZKP(
            APP_URL, // Same URL
            TEE_ARCH,
            CODE_MEASUREMENT, // Same code measurement
            newPubkey, // New pubkey
            newWallet, // New wallet
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        // Should return same appId
        assertEq(updatedAppId, appId);

        // Verify values were updated
        SparsityAppRegistry.SparsityApp memory app = registry.getApp(appId);
        assertEq(app.teePubkey, newPubkey);
        assertEq(app.teeWalletAddress, newWallet);

        // App count should still be 1
        assertEq(registry.getAppCount(), 1);
    }

    function test_registerAppWithoutZKP_allowsSameCodeDifferentUrl() public {
        vm.startPrank(user1);

        uint256 appId1 = registry.registerAppWithoutZKP(
            "https://app1.com",
            TEE_ARCH,
            CODE_MEASUREMENT, // Same code
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        uint256 appId2 = registry.registerAppWithoutZKP(
            "https://app2.com", // Different URL
            TEE_ARCH,
            CODE_MEASUREMENT, // Same code
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        vm.stopPrank();

        assertEq(appId1, 1);
        assertEq(appId2, 2);
    }

    function test_registerAppWithoutZKP_allowsSameUrlDifferentCode() public {
        vm.startPrank(user1);

        uint256 appId1 = registry.registerAppWithoutZKP(
            APP_URL, // Same URL
            TEE_ARCH,
            keccak256("code1"),
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        uint256 appId2 = registry.registerAppWithoutZKP(
            APP_URL, // Same URL
            TEE_ARCH,
            keccak256("code2"), // Different code
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        vm.stopPrank();

        assertEq(appId1, 1);
        assertEq(appId2, 2);
    }

    // ========== removeApp Tests ==========

    function test_removeApp_success() public {
        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        vm.prank(user1);
        registry.removeApp(appId);

        assertEq(registry.appExists(appId), false);
        assertEq(registry.getAppCount(), 0);
    }

    function test_removeApp_emitsEvent() public {
        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        vm.prank(user1);
        vm.expectEmit(true, true, true, true);
        emit AppRemoved(appId, user1);
        registry.removeApp(appId);
    }

    function test_removeApp_revertOnNotFound() public {
        vm.prank(user1);
        vm.expectRevert(SparsityAppRegistry.AppNotFound.selector);
        registry.removeApp(999);
    }

    function test_removeApp_revertOnNotOwner() public {
        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        vm.prank(user2);
        vm.expectRevert(SparsityAppRegistry.NotAppOwner.selector);
        registry.removeApp(appId);
    }

    function test_removeApp_allowsReRegistration() public {
        // Register
        vm.prank(user1);
        uint256 appId1 = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        // Remove
        vm.prank(user1);
        registry.removeApp(appId1);

        // Re-register with same key should work
        vm.prank(user2);
        uint256 appId2 = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        assertEq(appId2, 2); // New ID
        assertEq(registry.appExists(appId2), true);
    }

    // ========== Getter Functions Tests ==========

    function test_appExists_returnsTrueForExisting() public {
        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        assertEq(registry.appExists(appId), true);
    }

    function test_appExists_returnsFalseForNonExisting() public view {
        assertEq(registry.appExists(999), false);
    }

    function test_getAppCount_initiallyZero() public view {
        assertEq(registry.getAppCount(), 0);
    }

    function test_getAppCount_incrementsOnRegistration() public {
        vm.startPrank(user1);

        registry.registerAppWithoutZKP(
            "https://app1.com",
            TEE_ARCH,
            keccak256("code1"),
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        assertEq(registry.getAppCount(), 1);

        registry.registerAppWithoutZKP(
            "https://app2.com",
            TEE_ARCH,
            keccak256("code2"),
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        assertEq(registry.getAppCount(), 2);

        vm.stopPrank();
    }

    function test_getAppList_returnsInReverseOrder() public {
        vm.startPrank(user1);

        // Register 3 apps
        for (uint i = 1; i <= 3; i++) {
            registry.registerAppWithoutZKP(
                string(abi.encodePacked("https://app", vm.toString(i), ".com")),
                TEE_ARCH,
                keccak256(abi.encodePacked("code", i)),
                TEE_PUBKEY,
                TEE_WALLET,
                CONTRACT_ADDR,
                METADATA_URI,
                SparsityAppRegistry.BuildAttestation({
                    url: BUILD_ATTESTATION_URL,
                    sha256: BUILD_ATTESTATION_SHA256,
                    githubRunId: BUILD_GITHUB_RUN_ID
                })
            );
        }

        vm.stopPrank();

        uint256[] memory ids = registry.getAppList();

        assertEq(ids.length, 3);
        assertEq(ids[0], 3); // Most recent first
        assertEq(ids[1], 2);
        assertEq(ids[2], 1);
    }

    function test_getAppList_withPagination() public {
        vm.startPrank(user1);

        // Register 5 apps
        for (uint i = 1; i <= 5; i++) {
            registry.registerAppWithoutZKP(
                string(abi.encodePacked("https://app", vm.toString(i), ".com")),
                TEE_ARCH,
                keccak256(abi.encodePacked("code", i)),
                TEE_PUBKEY,
                TEE_WALLET,
                CONTRACT_ADDR,
                METADATA_URI,
                SparsityAppRegistry.BuildAttestation({
                    url: BUILD_ATTESTATION_URL,
                    sha256: BUILD_ATTESTATION_SHA256,
                    githubRunId: BUILD_GITHUB_RUN_ID
                })
            );
        }

        vm.stopPrank();

        // Get first 2 (offset=0, limit=2)
        uint256[] memory first2 = registry.getAppList(0, 2);
        assertEq(first2.length, 2);
        assertEq(first2[0], 5);
        assertEq(first2[1], 4);

        // Get next 2 (offset=2, limit=2)
        uint256[] memory next2 = registry.getAppList(2, 2);
        assertEq(next2.length, 2);
        assertEq(next2[0], 3);
        assertEq(next2[1], 2);

        // Get last 1 (offset=4, limit=2)
        uint256[] memory last1 = registry.getAppList(4, 2);
        assertEq(last1.length, 1);
        assertEq(last1[0], 1);
    }

    function test_getAppList_emptyWhenNoApps() public view {
        uint256[] memory ids = registry.getAppList();
        assertEq(ids.length, 0);
    }

    function test_getApps_batchGetter() public {
        vm.startPrank(user1);

        registry.registerAppWithoutZKP(
            "https://app1.com",
            TEE_ARCH,
            keccak256("code1"),
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            "/meta1.json",
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        registry.registerAppWithoutZKP(
            "https://app2.com",
            TEE_ARCH,
            keccak256("code2"),
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            "/meta2.json",
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        vm.stopPrank();

        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;

        SparsityAppRegistry.SparsityApp[] memory apps = registry.getApps(ids);

        assertEq(apps.length, 2);
        assertEq(apps[0].appUrl, "https://app1.com");
        assertEq(apps[1].appUrl, "https://app2.com");
    }
    function test_getAppIdByCodeMeasurement_success() public {
        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        // Found
        uint256 foundId = registry.getAppIdByCodeMeasurement(
            CODE_MEASUREMENT,
            APP_URL
        );
        assertEq(foundId, appId);

        // Not found (wrong code)
        uint256 notFoundId = registry.getAppIdByCodeMeasurement(
            keccak256("wrong"),
            APP_URL
        );
        assertEq(notFoundId, 0);

        // Not found (wrong url)
        uint256 notFoundId2 = registry.getAppIdByCodeMeasurement(
            CODE_MEASUREMENT,
            "wrong"
        );
        assertEq(notFoundId2, 0);
    }

    function test_getAppIdByPCRs_success() public {
        bytes memory pcr0 = hex"1111";
        bytes memory pcr1 = hex"2222";
        bytes memory pcr2 = hex"3333";
        bytes32 codeMeasurement = keccak256(abi.encodePacked(pcr0, pcr1, pcr2));

        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            codeMeasurement,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: BUILD_ATTESTATION_URL,
                sha256: BUILD_ATTESTATION_SHA256,
                githubRunId: BUILD_GITHUB_RUN_ID
            })
        );

        // Found
        uint256 foundId = registry.getAppIdByPCRs(pcr0, pcr1, pcr2, APP_URL);
        assertEq(foundId, appId);

        // Not found (wrong pcr)
        uint256 notFoundId = registry.getAppIdByPCRs(
            pcr0,
            pcr1,
            hex"9999",
            APP_URL
        );
        assertEq(notFoundId, 0);
    }

    function test_registerApp_emptyBuildAttestation() public {
        vm.prank(user1);
        uint256 appId = registry.registerAppWithoutZKP(
            APP_URL,
            TEE_ARCH,
            CODE_MEASUREMENT,
            TEE_PUBKEY,
            TEE_WALLET,
            CONTRACT_ADDR,
            METADATA_URI,
            SparsityAppRegistry.BuildAttestation({
                url: "",
                sha256: "",
                githubRunId: ""
            })
        );

        assertTrue(appId > 0);

        SparsityAppRegistry.SparsityApp memory app = registry.getApp(appId);
        assertEq(app.buildAttestation.url, "");
        assertEq(app.buildAttestation.sha256, "");
        assertEq(app.buildAttestation.githubRunId, "");
    }
}

/// @notice Mock verifier contract for testing
contract MockVerifier {
    // Just needs to exist as a contract
}

/// @notice Mock ISparsityApp implementation for testing TEE wallet callback
contract MockSparsityApp is ISparsityApp {
    address public registeredWallet;
    bool public shouldRevert;

    function setRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function registerTEEWallet(address teeWalletAddress) external override {
        if (shouldRevert) {
            revert("Mock revert");
        }
        registeredWallet = teeWalletAddress;
    }
}
