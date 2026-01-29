// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {ISparsityApp} from "../interfaces/ISparsityApp.sol";

contract SampleNovaApp is ISparsityApp {
    address public registry;
    mapping(address => bool) public isTEEWallet;
    address public lastRegisteredWallet;

    event TEEWalletRegistered(address indexed wallet);

    error OnlyRegistry();

    constructor(address _registry) {
        registry = _registry;
    }

    function registerTEEWallet(address teeWalletAddress) external override {
        if (msg.sender != registry) revert OnlyRegistry();
        isTEEWallet[teeWalletAddress] = true;
        lastRegisteredWallet = teeWalletAddress;
        emit TEEWalletRegistered(teeWalletAddress);
    }
}
