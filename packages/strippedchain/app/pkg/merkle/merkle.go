package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// GenerateMerkleLeaf generates the Merkle leaf for a specific chunk of the encrypted file data
func GenerateMerkleLeaf(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateMerkleRoot generates the Merkle root from the encrypted file data
func GenerateMerkleRoot(chunks [][]byte) (string, error) {
	if len(chunks) == 0 {
		return "", errors.New("no data chunks provided")
	}

	// Generate leaf hashes
	leafHashes := make([]string, len(chunks))
	for i, chunk := range chunks {
		leafHashes[i] = GenerateMerkleLeaf(chunk)
	}

	// Build the Merkle tree
	for len(leafHashes) > 1 {
		if len(leafHashes)%2 != 0 {
			leafHashes = append(leafHashes, leafHashes[len(leafHashes)-1]) // Duplicate the last element if odd number of hashes
		}

		var newLevel []string
		for i := 0; i < len(leafHashes); i += 2 {
			combinedHash := sha256.Sum256([]byte(leafHashes[i] + leafHashes[i+1]))
			newLevel = append(newLevel, hex.EncodeToString(combinedHash[:]))
		}
		leafHashes = newLevel
	}

	return leafHashes[0], nil // The root of the tree
}

// SplitDataIntoChunks splits the data into chunks for Merkle tree generation
func SplitDataIntoChunks(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for len(data) > chunkSize {
		chunks = append(chunks, data[:chunkSize])
		data = data[chunkSize:]
	}
	chunks = append(chunks, data)
	return chunks
}
