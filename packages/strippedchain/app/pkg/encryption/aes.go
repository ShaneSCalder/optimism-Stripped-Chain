package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
)

// FileType represents the type of the file
type FileType string

const (
	PDF  FileType = "PDF"
	CSV  FileType = "CSV"
	XLSX FileType = "XLSX"
)

// FileMetadata contains information about the file
type FileMetadata struct {
	Name          string   `json:"name"`
	Type          FileType `json:"type"`
	Size          int64    `json:"size"`
	Key           string   `json:"key"`
	Nonce         string   `json:"nonce"`
	EncryptedData string   `json:"encrypted_data"`
}

// EncryptFile encrypts a file and returns its metadata and encrypted data in JSON format
func EncryptFile(filepath string) (*FileMetadata, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	fileType := identifyFileType(filepath)

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encryptedData := aesgcm.Seal(nil, nonce, data, nil)

	metadata := &FileMetadata{
		Name:          stat.Name(),
		Type:          fileType,
		Size:          stat.Size(),
		Key:           hex.EncodeToString(key),
		Nonce:         hex.EncodeToString(nonce),
		EncryptedData: hex.EncodeToString(encryptedData),
	}

	return metadata, nil
}

// DecryptFile decrypts the encrypted data using the provided key and nonce
func DecryptFile(metadata *FileMetadata) ([]byte, error) {
	key, err := hex.DecodeString(metadata.Key)
	if err != nil {
		return nil, err
	}

	nonce, err := hex.DecodeString(metadata.Nonce)
	if err != nil {
		return nil, err
	}

	encryptedData, err := hex.DecodeString(metadata.EncryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	data, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// identifyFileType identifies the file type based on the file extension
func identifyFileType(filepath string) FileType {
	switch {
	case filepath[len(filepath)-4:] == ".pdf":
		return PDF
	case filepath[len(filepath)-4:] == ".csv":
		return CSV
	case filepath[len(filepath)-5:] == ".xlsx":
		return XLSX
	default:
		return ""
	}
}
