// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

contract HashchainBulletinBoard {
    uint counter;
    bytes32 digest;
    address payable owner;

    constructor() { owner = payable(msg.sender); }

    function post(bytes32 x) public {
        require(msg.sender == owner, "Only owner can post");
        digest = keccak256(abi.encodePacked(digest, x));
        counter = counter + 1;
    }
}