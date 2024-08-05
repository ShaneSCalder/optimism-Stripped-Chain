package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

// VaultMetadata contains information about the vault
type VaultMetadata struct {
	VaultID        string         `json:"vault_id"`
	CustomerID     string         `json:"customer_id"`
	Key            string         `json:"key"`
	Nonce          string         `json:"nonce"`
	EncryptedFiles []FileMetadata `json:"encrypted_files"`
	MerkleRoot     string         `json:"merkle_root"`
}

// FileMetadata contains information about the encrypted files in the vault
type FileMetadata struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Size          int64  `json:"size"`
	Key           string `json:"key"`
	Nonce         string `json:"nonce"`
	EncryptedData string `json:"encrypted_data"`
	MerkleLeaf    string `json:"merkle_leaf"`
	Note          string `json:"note,omitempty"` // Optional note field
}

// CreateVaultMetadata initializes a new vault metadata structure
func CreateVaultMetadata(customerID string) (*VaultMetadata, error) {
	vaultID := generateVaultID()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	newVault := &VaultMetadata{
		VaultID:        vaultID,
		CustomerID:     customerID,
		Key:            hex.EncodeToString(key),
		Nonce:          hex.EncodeToString(nonce),
		EncryptedFiles: []FileMetadata{},
	}

	return newVault, nil
}

// AddFileMetadata adds metadata for a new file to the vault
func (vm *VaultMetadata) AddFileMetadata(fileMetadata FileMetadata) {
	vm.EncryptedFiles = append(vm.EncryptedFiles, fileMetadata)
	vm.updateMerkleRoot()
}

// RemoveFileMetadata removes metadata for a file from the vault
func (vm *VaultMetadata) RemoveFileMetadata(fileName string) {
	for i, file := range vm.EncryptedFiles {
		if file.Name == fileName {
			vm.EncryptedFiles = append(vm.EncryptedFiles[:i], vm.EncryptedFiles[i+1:]...)
			break
		}
	}
	vm.updateMerkleRoot()
}

// updateMerkleRoot updates the Merkle root based on the current files in the vault
func (vm *VaultMetadata) updateMerkleRoot() {
	var leaves []string
	for _, file := range vm.EncryptedFiles {
		leaves = append(leaves, file.MerkleLeaf)
	}
	root, _ := GenerateMerkleRoot(leaves)
	vm.MerkleRoot = root
}

// GenerateMerkleRoot generates a Merkle root from a list of leaf hashes
func GenerateMerkleRoot(leaves []string) (string, error) {
	if len(leaves) == 0 {
		return "", errors.New("no leaves provided")
	}

	for len(leaves) > 1 {
		if len(leaves)%2 != 0 {
			leaves = append(leaves, leaves[len(leaves)-1])
		}

		var newLevel []string
		for i := 0; i < len(leaves); i += 2 {
			combinedHash := sha256.Sum256([]byte(leaves[i] + leaves[i+1]))
			newLevel = append(newLevel, hex.EncodeToString(combinedHash[:]))
		}
		leaves = newLevel
	}

	return leaves[0], nil
}

// SaveMetadataToFile saves the vault metadata to a file for persistence
func SaveMetadataToFile(vault *VaultMetadata) error {
	data, err := json.Marshal(vault)
	if err != nil {
		return err
	}

	vaultsDir := "data/vaults"
	if err := os.MkdirAll(vaultsDir, os.ModePerm); err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(vaultsDir, vault.VaultID+".json"), data, 0644)
}

// LoadMetadataFromFile loads the vault metadata from a file
func LoadMetadataFromFile(vaultID string) (*VaultMetadata, error) {
	vaultsDir := "data/vaults"
	data, err := ioutil.ReadFile(filepath.Join(vaultsDir, vaultID+".json"))
	if err != nil {
		return nil, err
	}

	var vault VaultMetadata
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, err
	}

	return &vault, nil
}

// generateVaultID generates a unique ID for a new vault
func generateVaultID() string {
	return hex.EncodeToString(randomBytes(16))
}

// randomBytes generates random bytes of a specified length
func randomBytes(length int) []byte {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}
