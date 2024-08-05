package hash

import (
	"crypto/sha256"
	"encoding/hex"
)

// CombineHashes combines the file location hash, customer ID, Merkle root, and leaf into composite hashes
func CombineHashes(fileLocationHash, customerID, merkleRoot, merkleLeaf string) (string, string, error) {
	compositeHash1 := sha256.Sum256([]byte(fileLocationHash + customerID))
	compositeHash2 := sha256.Sum256([]byte(merkleRoot + merkleLeaf))

	return hex.EncodeToString(compositeHash1[:]), hex.EncodeToString(compositeHash2[:]), nil
}

// GenerateFinalHash combines composite hashes into a final 256-bit hash
func GenerateFinalHash(compositeHash1, compositeHash2 string) (string, error) {
	finalHash := sha256.Sum256([]byte(compositeHash1 + compositeHash2))
	return hex.EncodeToString(finalHash[:]), nil
}

// CalculateHash calculates the SHA-256 hash of a given string
func CalculateHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
