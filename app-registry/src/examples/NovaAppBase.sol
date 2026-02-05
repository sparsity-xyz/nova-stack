// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Ownable} from "@solady/auth/Ownable.sol";
import {INovaAppInterface} from "../interfaces/INovaAppInterface.sol";

/// @title NovaAppBase
/// @notice Abstract base contract implementing INovaAppInterface with registry access control and operator management.
/// @dev Inherit from this contract to implement a Nova-compatible dApp. TEE wallets are automatically added/removed as operators.
abstract contract NovaAppBase is INovaAppInterface, Ownable {
    // ========== State Variables ==========

    address private _novaAppRegistry;

    /// @notice Set of addresses that are authorized TEE operators
    mapping(address => bool) private _operators;

    /// @notice List of all operator addresses (for enumeration)
    address[] private _operatorList;

    /// @notice Mapping from operator address to index in _operatorList (for O(1) removal)
    mapping(address => uint256) private _operatorIndex;

    // ========== Errors ==========

    error OnlyNovaAppRegistry();
    error InvalidRegistryAddress();
    error OnlyOperator();

    // ========== Events ==========

    event NovaAppRegistrySet(address indexed registry);
    event OperatorAdded(
        address indexed operator,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    );
    event OperatorRemoved(
        address indexed operator,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    );

    // ========== Modifiers ==========

    /// @notice Restricts function access to NovaAppRegistry only
    modifier onlyNovaAppRegistry() {
        _onlyNovaAppRegistry();
        _;
    }

    function _onlyNovaAppRegistry() internal view {
        if (msg.sender != _novaAppRegistry) revert OnlyNovaAppRegistry();
    }

    /// @notice Restricts function access to registered TEE operators only
    /// @dev Use this modifier for functions that should only be callable by TEE instances
    modifier onlyOperator() {
        _onlyOperator();
        _;
    }

    function _onlyOperator() internal view {
        if (!_operators[msg.sender]) revert OnlyOperator();
    }

    // ========== Constructor ==========

    constructor() {
        _initializeOwner(msg.sender);
    }

    // ========== INovaAppInterface Implementation ==========

    /// @inheritdoc INovaAppInterface
    function setNovaAppRegistry(address registry) external onlyOwner {
        if (registry == address(0)) revert InvalidRegistryAddress();
        _novaAppRegistry = registry;
        emit NovaAppRegistrySet(registry);
    }

    /// @inheritdoc INovaAppInterface
    function novaAppRegistry() external view returns (address) {
        return _novaAppRegistry;
    }

    /// @inheritdoc INovaAppInterface
    /// @dev Called by NovaAppRegistry when a new TEE instance registers. Adds the wallet as an operator.
    function addOperator(
        address teeWalletAddress,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) external virtual onlyNovaAppRegistry {
        // Add TEE wallet to operators set
        _addOperatorInternal(teeWalletAddress);

        // Hook for derived contracts to implement custom logic
        _onOperatorAdded(teeWalletAddress, appId, versionId, instanceId);

        emit OperatorAdded(teeWalletAddress, appId, versionId, instanceId);
    }

    /// @inheritdoc INovaAppInterface
    /// @dev Called by NovaAppRegistry when a TEE instance is stopped/failed. Removes the wallet from operators.
    function removeOperator(
        address teeWalletAddress,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) external virtual onlyNovaAppRegistry {
        // Remove TEE wallet from operators set
        _removeOperatorInternal(teeWalletAddress);

        // Hook for derived contracts to implement custom logic
        _onOperatorRemoved(teeWalletAddress, appId, versionId, instanceId);

        emit OperatorRemoved(teeWalletAddress, appId, versionId, instanceId);
    }

    // ========== View Functions ==========

    /// @notice Check if an address is a registered operator
    function isOperator(address account) public view returns (bool) {
        return _operators[account];
    }

    /// @notice Get the total number of operators
    function operatorCount() public view returns (uint256) {
        return _operatorList.length;
    }

    /// @notice Get operator address at a specific index
    function operatorAt(uint256 index) public view returns (address) {
        require(index < _operatorList.length, "Index out of bounds");
        return _operatorList[index];
    }

    /// @notice Get all operator addresses
    function getOperators() public view returns (address[] memory) {
        return _operatorList;
    }

    // ========== Internal Functions ==========

    /// @dev Internal function to add an operator to the set
    function _addOperatorInternal(address operator) internal {
        if (_operators[operator]) return; // Already an operator, skip silently

        _operators[operator] = true;
        _operatorIndex[operator] = _operatorList.length;
        _operatorList.push(operator);
    }

    /// @dev Internal function to remove an operator from the set
    function _removeOperatorInternal(address operator) internal {
        if (!_operators[operator]) return; // Not an operator, skip silently (idempotent)

        // Swap-and-pop for O(1) removal
        uint256 index = _operatorIndex[operator];
        uint256 lastIndex = _operatorList.length - 1;

        if (index != lastIndex) {
            address lastOperator = _operatorList[lastIndex];
            _operatorList[index] = lastOperator;
            _operatorIndex[lastOperator] = index;
        }

        _operatorList.pop();
        delete _operatorIndex[operator];
        delete _operators[operator];
    }

    /// @dev Hook called after an operator is added. Override in derived contracts.
    /// @param teeWalletAddress The registered TEE wallet address
    /// @param appId The app ID from the registry
    /// @param versionId The version ID of the running code
    /// @param instanceId The instance ID
    function _onOperatorAdded(
        address teeWalletAddress,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) internal virtual {
        // Override in derived contract to add custom logic
    }

    /// @dev Hook called after an operator is removed. Override in derived contracts.
    /// @param teeWalletAddress The removed TEE wallet address
    /// @param appId The app ID from the registry
    /// @param versionId The version ID
    /// @param instanceId The instance ID being deactivated
    function _onOperatorRemoved(
        address teeWalletAddress,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) internal virtual {
        // Override in derived contract to add custom cleanup logic
    }
}
