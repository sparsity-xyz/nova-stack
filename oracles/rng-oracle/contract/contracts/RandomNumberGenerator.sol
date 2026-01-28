// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ISparsityApp.sol";

/// @title RNG Callback Interface
/// @notice User contracts need to implement this interface to receive random number callbacks
interface IRNGCallback {
    /// @notice Random number callback function
    /// @param requestId Request ID
    /// @param randomNumbers Array of generated random numbers
    function onRandomNumberFulfilled(
        uint256 requestId,
        uint256[] calldata randomNumbers
    ) external;
}

/// @title True Random Number Generator
/// @author chuwt
/// @notice Off-chain true random number generator (with callback support)
/// @dev User request → Emit event → Off-chain generation → Callback on-chain → Callback user contract
contract RandomNumberGenerator is Ownable, ISparsityApp {
    // ========== State Variables ==========
    // Nova registry
    address public novaRegistryAddress;

    // Authorized operators (off-chain service)
    mapping(address => bool) public operators;

    // Request counter
    uint256 private requestCounter;

    // Request status
    enum RequestStatus {
        Pending, // Waiting
        Fulfilled, // Completed
        Cancelled // Cancelled
    }

    // Random number request
    struct RandomRequest {
        address requester; // Requester
        uint256 timestamp; // Request time
        uint256 min; // Minimum value
        uint256 max; // Maximum value
        uint256 count; // Count
        RequestStatus status; // Status
        uint256[] randomNumbers; // Result (filled after completion)
        uint256 fulfilledAt; // Completion time
        address callbackContract; // Callback contract address (if any)
        bool callbackExecuted; // Whether callback has been executed
    }

    // requestId => RandomRequest
    mapping(uint256 => RandomRequest) public requests;

    // User request history
    mapping(address => uint256[]) public userRequests;

    // Callback gas limit
    uint256 public callbackGasLimit = 200000;

    // ========== Events ==========

    /// @notice Random number request event (off-chain service listens to this event)
    event RandomNumberRequested(
        uint256 indexed requestId,
        address indexed requester,
        uint256 min,
        uint256 max,
        uint256 count,
        address callbackContract,
        uint256 timestamp
    );

    /// @notice Random number generated event
    event RandomNumberFulfilled(
        uint256 indexed requestId,
        address indexed requester,
        uint256[] randomNumbers,
        uint256 timestamp
    );

    /// @notice Callback execution event
    event CallbackExecuted(
        uint256 indexed requestId,
        address indexed callbackContract,
        bool success,
        bytes returnData
    );

    /// @notice Operator update event
    event OperatorUpdated(address indexed operator, bool status);
    event SetNovaRegistry(address indexed novaRegistry);

    /// @notice Callback gas limit update event
    event CallbackGasLimitUpdated(uint256 oldLimit, uint256 newLimit);

    // ========== Modifiers ==========

    modifier onlyOperator() {
        require(operators[msg.sender], "Not authorized operator");
        _;
    }

    modifier onlyRegistry() {
        require(msg.sender == novaRegistryAddress, "Not registry contract");
        _;
    }

    // ========== Constructor ==========

    constructor(address registryAddress) Ownable(msg.sender) {
        requestCounter = 0;
        novaRegistryAddress = registryAddress;
    }

    // ========== User Functions (without callback) ==========

    /// @notice Request single random number (without callback)
    /// @param max Maximum value (exclusive)
    /// @return requestId Request ID
    function requestRandom(uint256 max) external returns (uint256) {
        return _requestRandomRange(0, max, 1, address(0));
    }

    /// @notice Request random numbers in specified range (without callback)
    /// @param min Minimum value (inclusive)
    /// @param max Maximum value (exclusive)
    /// @param count Count
    /// @return requestId Request ID
    function requestRandomRange(
        uint256 min,
        uint256 max,
        uint256 count
    ) public returns (uint256) {
        return _requestRandomRange(min, max, count, address(0));
    }

    // ========== User Functions (with callback) ==========

    /// @notice Request random number (with callback)
    /// @param max Maximum value (exclusive)
    /// @param callbackContract Callback contract address (must implement IRNGCallback)
    /// @return requestId Request ID
    function requestRandomWithCallback(
        uint256 max,
        address callbackContract
    ) external returns (uint256) {
        require(callbackContract != address(0), "Invalid callback contract");
        return _requestRandomRange(0, max, 1, callbackContract);
    }

    /// @notice Request random numbers in specified range (with callback)
    /// @param min Minimum value (inclusive)
    /// @param max Maximum value (exclusive)
    /// @param count Count
    /// @param callbackContract Callback contract address
    /// @return requestId Request ID
    function requestRandomRangeWithCallback(
        uint256 min,
        uint256 max,
        uint256 count,
        address callbackContract
    ) public returns (uint256) {
        require(callbackContract != address(0), "Invalid callback contract");
        return _requestRandomRange(min, max, count, callbackContract);
    }

    /// @notice Internal request function
    function _requestRandomRange(
        uint256 min,
        uint256 max,
        uint256 count,
        address callbackContract
    ) internal returns (uint256) {
        require(max > min, "Invalid range");
        require(count > 0 && count <= 100, "Count must be 1-100");

        requestCounter++;
        uint256 requestId = requestCounter;

        requests[requestId] = RandomRequest({
            requester: msg.sender,
            timestamp: block.timestamp,
            min: min,
            max: max,
            count: count,
            status: RequestStatus.Pending,
            randomNumbers: new uint256[](0),
            fulfilledAt: 0,
            callbackContract: callbackContract,
            callbackExecuted: false
        });

        userRequests[msg.sender].push(requestId);

        // Emit event, off-chain service listens to this event
        emit RandomNumberRequested(
            requestId,
            msg.sender,
            min,
            max,
            count,
            callbackContract,
            block.timestamp
        );

        return requestId;
    }

    /// @notice Query request status
    /// @param requestId Request ID
    function getRequest(
        uint256 requestId
    )
        external
        view
        returns (
            RequestStatus status,
            uint256[] memory randomNumbers,
            address requester,
            uint256 timestamp,
            uint256 fulfilledAt,
            address callbackContract,
            bool callbackExecuted,
            uint256 min,
            uint256 max,
            uint256 count
        )
    {
        RandomRequest memory req = requests[requestId];
        return (
            req.status,
            req.randomNumbers,
            req.requester,
            req.timestamp,
            req.fulfilledAt,
            req.callbackContract,
            req.callbackExecuted,
            req.min,
            req.max,
            req.count
        );
    }

    /// @notice Get all requests from a user
    /// @param user User address
    /// @return requestIds Array of request IDs
    function getUserRequests(
        address user
    ) external view returns (uint256[] memory) {
        return userRequests[user];
    }

    /// @notice Cancel pending request (requester only)
    /// @param requestId Request ID
    function cancelRequest(uint256 requestId) external {
        RandomRequest storage req = requests[requestId];
        require(req.requester == msg.sender, "Not requester");
        require(req.status == RequestStatus.Pending, "Cannot cancel");

        req.status = RequestStatus.Cancelled;
    }

    // ========== Operator Functions (called by off-chain service) ==========

    /// @notice Fulfill random number result (operator only)
    /// @param requestId Request ID
    /// @param randomNumbers Generated random numbers
    function fulfillRandomNumber(
        uint256 requestId,
        uint256[] calldata randomNumbers
    ) external onlyOperator {
        RandomRequest storage req = requests[requestId];

        require(req.status == RequestStatus.Pending, "Request not pending");
        require(randomNumbers.length == req.count, "Invalid count");

        // Verify random numbers are within range
        for (uint256 i = 0; i < randomNumbers.length; i++) {
            require(
                randomNumbers[i] >= req.min && randomNumbers[i] < req.max,
                "Random number out of range"
            );
        }

        req.randomNumbers = randomNumbers;
        req.status = RequestStatus.Fulfilled;
        req.fulfilledAt = block.timestamp;

        emit RandomNumberFulfilled(
            requestId,
            req.requester,
            randomNumbers,
            block.timestamp
        );

        // If callback contract exists, execute callback
        if (req.callbackContract != address(0) && !req.callbackExecuted) {
            _executeCallback(requestId, req.callbackContract, randomNumbers);
        }
    }

    /// @notice Execute user contract callback
    /// @param requestId Request ID
    /// @param callbackContract Callback contract address
    /// @param randomNumbers Random numbers
    function _executeCallback(
        uint256 requestId,
        address callbackContract,
        uint256[] memory randomNumbers
    ) internal {
        RandomRequest storage req = requests[requestId];
        req.callbackExecuted = true;

        try
            IRNGCallback(callbackContract).onRandomNumberFulfilled{
                gas: callbackGasLimit
            }(requestId, randomNumbers)
        {
            emit CallbackExecuted(requestId, callbackContract, true, "");
        } catch Error(string memory reason) {
            emit CallbackExecuted(
                requestId,
                callbackContract,
                false,
                bytes(reason)
            );
        } catch (bytes memory lowLevelData) {
            emit CallbackExecuted(
                requestId,
                callbackContract,
                false,
                lowLevelData
            );
        }
    }

    /// @notice Manually retry callback (if automatic callback failed)
    /// @param requestId Request ID
    function retryCallback(uint256 requestId) external onlyOperator {
        RandomRequest storage req = requests[requestId];

        require(req.status == RequestStatus.Fulfilled, "Not fulfilled");
        require(req.callbackContract != address(0), "No callback contract");

        // Allow retry
        req.callbackExecuted = false;
        _executeCallback(requestId, req.callbackContract, req.randomNumbers);
    }

    // ========== Owner Functions ==========

    /// @notice Add operator
    /// @param operator Operator address
    function addOperator(address operator) external onlyOwner {
        require(operator != address(0), "Invalid address");
        operators[operator] = true;
        emit OperatorUpdated(operator, true);
    }

    /// @notice Remove operator
    /// @param operator Operator address
    function removeOperator(address operator) external onlyOwner {
        operators[operator] = false;
        emit OperatorUpdated(operator, false);
    }

    /// @notice Update callback gas limit
    /// @param newLimit New gas limit
    function setCallbackGasLimit(uint256 newLimit) external onlyOwner {
        require(newLimit >= 50000 && newLimit <= 500000, "Invalid gas limit");
        uint256 oldLimit = callbackGasLimit;
        callbackGasLimit = newLimit;
        emit CallbackGasLimitUpdated(oldLimit, newLimit);
    }

    // ========== Query Functions ==========

    /// @notice Get total number of requests
    function getTotalRequests() external view returns (uint256) {
        return requestCounter;
    }

    /// @notice Check if address is operator
    function isOperator(address addr) external view returns (bool) {
        return operators[addr];
    }

    function setNovaRegistry(address registryAddress) public onlyOwner {
        novaRegistryAddress = registryAddress;
        emit SetNovaRegistry(novaRegistryAddress);
    }

    function registerTEEWallet(address teeWalletAddress) public onlyRegistry {
        operators[teeWalletAddress] = true;
        emit OperatorUpdated(teeWalletAddress, true);
    }
}
