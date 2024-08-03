package testing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
)

func EncryptData(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func DecryptData(encryptedData []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encryptedData, encryptedData)

	return encryptedData, nil
}

func SaveToLocal(filename, passphrase string) error {
	data := []byte("This is a test data for local storage.")
	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, encryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func LoadFromLocal(filename, passphrase string) ([]byte, error) {
	encryptedData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data, err := DecryptData(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	return data, nil
}
