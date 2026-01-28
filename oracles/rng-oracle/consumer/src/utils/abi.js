/**
 * RNG Contract ABI
 * Contains the function signatures and events for interacting with RandomNumberGenerator contract
 */

export const RNG_ABI = [
    // Request functions
    "function requestRandom(uint256 max) external returns (uint256)",
    "function requestRandomRange(uint256 min, uint256 max, uint256 count) external returns (uint256)",

    // Query functions
    "function getRequest(uint256 requestId) external view returns (uint8 status, uint256[] memory randomNumbers, address requester, uint256 timestamp, uint256 fulfilledAt, address callbackContract, bool callbackExecuted, uint256 min, uint256 max, uint256 count)",
    "function getTotalRequests() external view returns (uint256)",
    "function getUserRequests(address user) external view returns (uint256[] memory)",

    // Events
    "event RandomNumberRequested(uint256 indexed requestId, address indexed requester, uint256 min, uint256 max, uint256 count, address callbackContract, uint256 timestamp)",
    "event RandomNumberFulfilled(uint256 indexed requestId, address indexed requester, uint256[] randomNumbers, uint256 timestamp)"
];

// Request status enum matching the contract
export const RequestStatus = {
    PENDING: 0,
    FULFILLED: 1,
    CANCELLED: 2
};
