// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

/// @title JsonParser
/// @notice Gas-optimized library to extract eth_addr from JSON userData
/// @dev Parses JSON bytes and extracts Ethereum address from eth_addr field
library JsonParser {
    /// @notice Thrown when the JSON format is invalid
    error InvalidJsonFormat();

    /// @notice Thrown when the eth_addr field is not found
    error FieldNotFound();

    /// @notice Thrown when the address format is invalid
    error InvalidAddressFormat();

    /// @notice Extracts eth_addr from JSON bytes
    /// @dev Searches for "eth_addr":"0x followed by 40 hex characters
    /// @param json The raw JSON bytes (e.g., {"eth_addr":"0x..."})
    /// @return addr The extracted Ethereum address
    function extractEthAddr(
        bytes memory json
    ) internal pure returns (address addr) {
        uint256 len = json.length;

        // Minimum: {"eth_addr":"0x" + 40 chars + "} = 55 chars
        if (len < 55) revert InvalidJsonFormat();

        // Pattern to search for: "eth_addr":"0x
        // Length: 14 bytes
        uint256 patternLen = 14;

        // Search for the pattern in the JSON
        uint256 addrStart = 0;
        bool found = false;

        // We need at least patternLen + 40 hex chars remaining
        uint256 searchLimit = len - patternLen - 40 + 1;

        for (uint256 i = 0; i < searchLimit; i++) {
            // Check if pattern matches at position i
            // Pattern: "eth_addr":"0x
            if (
                json[i] == 0x22 && // "
                json[i + 1] == 0x65 && // e
                json[i + 2] == 0x74 && // t
                json[i + 3] == 0x68 && // h
                json[i + 4] == 0x5f && // _
                json[i + 5] == 0x61 && // a
                json[i + 6] == 0x64 && // d
                json[i + 7] == 0x64 && // d
                json[i + 8] == 0x72 && // r
                json[i + 9] == 0x22 && // "
                json[i + 10] == 0x3a && // :
                json[i + 11] == 0x22 && // "
                json[i + 12] == 0x30 && // 0
                json[i + 13] == 0x78 // x
            ) {
                addrStart = i + patternLen;
                found = true;
                break;
            }
        }

        if (!found) revert FieldNotFound();

        // Parse the 40 hex characters into an address
        uint160 result = 0;

        for (uint256 i = 0; i < 40; i++) {
            uint8 digit = _hexCharToDigit(json[addrStart + i]);
            result = result * 16 + digit;
        }

        return address(result);
    }

    /// @notice Converts a hex character to its numeric value
    /// @param c The hex character (0-9, a-f, A-F)
    /// @return digit The numeric value (0-15)
    function _hexCharToDigit(bytes1 c) private pure returns (uint8 digit) {
        uint8 val = uint8(c);

        // 0-9: ASCII 48-57
        if (val >= 48 && val <= 57) {
            return val - 48;
        }
        // a-f: ASCII 97-102
        if (val >= 97 && val <= 102) {
            return val - 87; // 97 - 10 = 87
        }
        // A-F: ASCII 65-70
        if (val >= 65 && val <= 70) {
            return val - 55; // 65 - 10 = 55
        }

        revert InvalidAddressFormat();
    }
}
