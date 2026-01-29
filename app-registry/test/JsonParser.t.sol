// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/libraries/JsonParser.sol";

contract JsonParserTest is Test {
    // External wrapper function to allow expectRevert to work
    function externalExtractEthAddr(
        bytes memory json
    ) external pure returns (address) {
        return JsonParser.extractEthAddr(json);
    }

    function test_extractEthAddr_validJson() public pure {
        // Standard format with eth_addr field
        bytes memory json = bytes(
            '{"eth_addr":"0x1234567890abcdef1234567890abcdef12345678"}'
        );
        // Proper checksum: 0x1234567890AbcdEF1234567890aBcdef12345678
        address expected = 0x1234567890AbcdEF1234567890aBcdef12345678;

        address result = JsonParser.extractEthAddr(json);
        assertEq(result, expected);
    }

    function test_extractEthAddr_withOtherFields() public pure {
        // JSON with multiple fields
        bytes memory json = bytes(
            '{"name":"test","eth_addr":"0xabcdef0123456789abcdef0123456789abcdef01","version":1}'
        );
        // Correct checksum from compiler
        address expected = 0xabCDeF0123456789AbcdEf0123456789aBCDEF01;

        address result = JsonParser.extractEthAddr(json);
        assertEq(result, expected);
    }

    function test_extractEthAddr_zeroAddress() public pure {
        // Zero address
        bytes memory json = bytes(
            '{"eth_addr":"0x0000000000000000000000000000000000000000"}'
        );
        address expected = address(0);

        address result = JsonParser.extractEthAddr(json);
        assertEq(result, expected);
    }

    function test_extractEthAddr_revert_invalidFormat_tooShort() public {
        // Too short JSON
        bytes memory json = bytes('{"eth_addr":"0x123"}');

        vm.expectRevert(JsonParser.InvalidJsonFormat.selector);
        this.externalExtractEthAddr(json);
    }

    function test_extractEthAddr_revert_fieldNotFound() public {
        // Missing eth_addr field - but long enough to not trigger InvalidJsonFormat
        bytes memory json = bytes(
            '{"address":"0x1234567890abcdef1234567890abcdef12345678"}'
        );

        vm.expectRevert(JsonParser.FieldNotFound.selector);
        this.externalExtractEthAddr(json);
    }

    function test_extractEthAddr_revert_invalidHexCharacter() public {
        // Invalid hex character 'g'
        bytes memory json = bytes(
            '{"eth_addr":"0x123456789gabcdef1234567890abcdef12345678"}'
        );

        vm.expectRevert(JsonParser.InvalidAddressFormat.selector);
        this.externalExtractEthAddr(json);
    }

    function test_extractEthAddr_fieldAtEnd() public pure {
        // eth_addr at the end of JSON
        bytes memory json = bytes(
            '{"name":"app","version":2,"eth_addr":"0xdeadbEef0123456789abcdef0123456789deadbe"}'
        );
        // Correct checksum from compiler
        address expected = 0xdeADbEef0123456789abcDeF0123456789DeAdbE;

        address result = JsonParser.extractEthAddr(json);
        assertEq(result, expected);
    }

    function test_extractEthAddr_hexAddress() public pure {
        // Use a simple address pattern
        bytes memory json = bytes(
            '{"eth_addr":"0xaaaabbbbccccddddeeeeffff0000111122223333"}'
        );
        // Correct checksum from compiler
        address expected = 0xAAAabbbbcccCDdDdEEeeFfff0000111122223333;

        address result = JsonParser.extractEthAddr(json);
        assertEq(result, expected);
    }
}
