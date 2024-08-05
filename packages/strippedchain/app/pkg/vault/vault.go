package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ShaneSCalder/optimism-Stripped-Chain/app/pkg/encryption"
	"github.com/ShaneSCalder/optimism-Stripped-Chain/app/pkg/hash"
)

var vaults = make(map[string]*VaultMetadata) // In-memory storage for demonstration

// CreateVault creates a new vault for a customer if it doesn’t exist
func CreateVault(customerID string) (*VaultMetadata, error) {
	for _, vault := range vaults {
		if vault.CustomerID == customerID {
			return vault, nil
		}
	}

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
		EncryptedFiles: []encryption.FileMetadata{},
	}

	vaults[vaultID] = newVault
	return newVault, nil
}

// SaveFileToVault encrypts and saves a file to the customer's vault
func SaveFileToVault(customerID, filePath string) error {
	vault, err := CreateVault(customerID)
	if err != nil {
		return err
	}

	metadata, err := encryption.EncryptFile(filePath)
	if err != nil {
		return err
	}

	vault.EncryptedFiles = append(vault.EncryptedFiles, *metadata)
	err = saveVaultToFile(vault)
	if err != nil {
		return err
	}

	return nil
}

// RetrieveFileFromVault retrieves and decrypts a file from the customer's vault
func RetrieveFileFromVault(customerID, fileName string) ([]byte, error) {
	vault, err := getVaultByCustomerID(customerID)
	if err != nil {
		return nil, err
	}

	for _, fileMetadata := range vault.EncryptedFiles {
		if fileMetadata.Name == fileName {
			return encryption.DecryptFile(&fileMetadata)
		}
	}

	return nil, errors.New("file not found in vault")
}

// GenerateFileLocationHash creates a hash of the file location
func GenerateFileLocationHash(filePath string) (string, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "", err
	}
	return hash.CalculateHash(absPath), nil
}

// getVaultByCustomerID searches for a vault by customer ID
func getVaultByCustomerID(customerID string) (*VaultMetadata, error) {
	for _, vault := range vaults {
		if vault.CustomerID == customerID {
			return vault, nil
		}
	}
	return nil, errors.New("vault not found")
}

// saveVaultToFile saves the vault metadata to a file (persistence)
func saveVaultToFile(vault *VaultMetadata) error {
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
