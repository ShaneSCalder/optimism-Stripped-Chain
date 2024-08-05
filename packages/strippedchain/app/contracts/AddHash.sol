// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract AddHash is Ownable {
    mapping(uint256 => bytes16) private _hashes;
    uint256 public hashCounter = 0;

    constructor() {}

    event HashAdded(uint256 indexed itemId, bytes16 indexed hash);

    // Function to add a hash for a specific item
    function addHash(bytes16 hash) public onlyOwner {
        _hashes[hashCounter] = hash;
        emit HashAdded(hashCounter, hash);
        hashCounter++;
    }

    // Function to retrieve the hash of an item
    function getHash(uint256 itemId) public view returns (bytes16) {
        require(_hashes[itemId] != bytes16(0), "Hash does not exist.");
        return _hashes[itemId];
    }
}
