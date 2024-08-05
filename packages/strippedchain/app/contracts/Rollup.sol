// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Rollup is Ownable {
    uint256 public constant MAX_HASHES = 100;
    bytes16[] private pendingHashes;
    mapping(uint256 => bytes32) private _merkleRoots;
    uint256 public rollupCounter = 0;

    constructor() {}

    event MerkleRootAdded(uint256 indexed rollupId, bytes32 indexed merkleRoot);

    // Function to add multiple hashes
    function addHashes(bytes16[] memory hashes) public onlyOwner {
        for (uint256 i = 0; i < hashes.length; i++) {
            pendingHashes.push(hashes[i]);
            if (pendingHashes.length >= MAX_HASHES) {
                processRollup();
            }
        }
    }

    // Function to process the rollup when enough hashes are accumulated
    function processRollup() private {
        require(pendingHashes.length >= MAX_HASHES, "Not enough hashes to process rollup.");

        // Calculate the Merkle root of the accumulated hashes
        bytes32 merkleRoot = calculateMerkleRoot(pendingHashes);

        // Store the Merkle root and clear pending hashes
        _merkleRoots[rollupCounter] = merkleRoot;
        emit MerkleRootAdded(rollupCounter, merkleRoot);

        rollupCounter++;
        delete pendingHashes;
    }

    // Function to calculate the Merkle root from an array of hashes
    function calculateMerkleRoot(bytes16[] memory hashes) private pure returns (bytes32) {
        // Simplified Merkle tree calculation (for demonstration purposes)
        while (hashes.length > 1) {
            if (hashes.length % 2 != 0) {
                hashes.push(hashes[hashes.length - 1]);
            }
            bytes16[] memory newLevel = new bytes16[](hashes.length / 2);
            for (uint256 i = 0; i < hashes.length; i += 2) {
                newLevel[i / 2] = bytes16(keccak256(abi.encodePacked(hashes[i], hashes[i + 1])));
            }
            hashes = newLevel;
        }
        return bytes32(hashes[0]);
    }

    // Function to retrieve the Merkle root of a rollup
    function getMerkleRoot(uint256 rollupId) public view returns (bytes32) {
        require(_merkleRoots[rollupId] != bytes32(0), "Merkle root does not exist.");
        return _merkleRoots[rollupId];
    }
}
