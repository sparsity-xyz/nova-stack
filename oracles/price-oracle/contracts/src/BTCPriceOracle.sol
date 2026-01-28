// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BTCPriceOracle
/// @notice A Nova-compatible BTC price oracle contract that allows registered TEE wallets to update prices
/// @dev Implements INovaApp pattern to integrate with the Nova platform
contract BTCPriceOracle {
    address public registry;
    uint256 public btcPrice;
    address public oracle;
    address public owner;
    uint256 public lastUpdated;

    mapping(address => bool) public isTEEWallet;

    event PriceUpdated(uint256 newPrice, uint256 timestamp);
    event OracleUpdated(address newOracle);
    event TEEWalletRegistered(address indexed wallet);

    error OnlyRegistry();
    error OnlyOracle();
    error OnlyOwner();

    modifier onlyOracle() {
        if (msg.sender != oracle && !isTEEWallet[msg.sender]) revert OnlyOracle();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor(address _registry, address _oracle) {
        registry = _registry;
        owner = msg.sender;
        oracle = _oracle;
    }

    /// @notice Register a TEE wallet address that can update prices
    /// @dev Implements INovaApp interface pattern - can only be called by registry
    /// @param teeWalletAddress The address of the TEE wallet to register
    function registerTEEWallet(address teeWalletAddress) external {
        if (msg.sender != registry) revert OnlyRegistry();
        isTEEWallet[teeWalletAddress] = true;
        emit TEEWalletRegistered(teeWalletAddress);
    }

    /// @notice Update the BTC price
    /// @dev Can be called by oracle address or any registered TEE wallet
    /// @param _price The new BTC price (in cents for 2 decimal precision)
    function setPrice(uint256 _price) external onlyOracle {
        btcPrice = _price;
        lastUpdated = block.timestamp;
        emit PriceUpdated(_price, block.timestamp);
    }

    /// @notice Get the current BTC price
    /// @return The current BTC price
    function getPrice() external view returns (uint256) {
        return btcPrice;
    }

    /// @notice Set a new oracle address
    /// @dev Only owner can call this
    /// @param _oracle The new oracle address
    function setOracle(address _oracle) external onlyOwner {
        oracle = _oracle;
        emit OracleUpdated(_oracle);
    }

    /// @notice Transfer ownership to a new address
    /// @dev Only owner can call this
    /// @param newOwner The new owner address
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
