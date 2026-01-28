// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./RandomNumberGenerator.sol";

/// @title Test RNG Callback Contract
/// @notice Simple callback contract for testing RNG callbacks
contract TestRNGCallback is IRNGCallback {

    // RNG contract address
    address public rngContract;

    // Stored random numbers by request ID
    mapping(uint256 => uint256[]) public randomNumbersByRequest;

    // Request fulfillment status
    mapping(uint256 => bool) public requestFulfilled;

    // Last received random numbers
    uint256[] public lastRandomNumbers;
    uint256 public lastRequestId;

    // Events
    event RandomNumbersReceived(uint256 indexed requestId, uint256[] randomNumbers);

    constructor(address _rngContract) {
        rngContract = _rngContract;
    }

    /// @notice Callback function called by RNG contract
    /// @param requestId Request ID
    /// @param randomNumbers Array of random numbers
    function onRandomNumberFulfilled(
        uint256 requestId,
        uint256[] calldata randomNumbers
    ) external override {
        require(msg.sender == rngContract, "Only RNG contract can call");

        // Store random numbers
        randomNumbersByRequest[requestId] = randomNumbers;
        requestFulfilled[requestId] = true;

        // Store last result for easy access
        lastRequestId = requestId;
        delete lastRandomNumbers;
        for (uint256 i = 0; i < randomNumbers.length; i++) {
            lastRandomNumbers.push(randomNumbers[i]);
        }

        emit RandomNumbersReceived(requestId, randomNumbers);
    }

    /// @notice Get random numbers for a specific request
    /// @param requestId Request ID
    /// @return Random numbers array
    function getRandomNumbers(uint256 requestId) external view returns (uint256[] memory) {
        return randomNumbersByRequest[requestId];
    }

    /// @notice Get last received random numbers
    /// @return Last random numbers array
    function getLastRandomNumbers() external view returns (uint256[] memory) {
        return lastRandomNumbers;
    }

    /// @notice Check if request was fulfilled
    /// @param requestId Request ID
    /// @return True if fulfilled
    function isFulfilled(uint256 requestId) external view returns (bool) {
        return requestFulfilled[requestId];
    }
}