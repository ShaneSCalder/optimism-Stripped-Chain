package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"
	"github.com/ShaneSCalder/optimism-Stripped-Chain/packages/strippedchain/pkg/blockchain"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/joho/godotenv"
)

func loadEnv() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}
}

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

func UploadToS3(filename, bucket, key, passphrase string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")),
		Credentials: credentials.NewStaticCredentials(
			os.Getenv("AWS_ACCESS_KEY_ID"),
			os.Getenv("AWS_SECRET_ACCESS_KEY"),
			"",
		),
	})
	svc := s3.New(sess)

	_, err = svc.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(encryptedData),
	})
	return err
}

func UploadToGoogleCloud(filename, bucket, object, passphrase string) error {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	wc := client.Bucket(bucket).Object(object).NewWriter(ctx)
	if _, err := wc.Write(encryptedData); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}

	return nil
}

func SaveToLocal(filename, passphrase string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("encrypted_"+filename, encryptedData, 0644)
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

func main() {
	loadEnv()

	// Parse command-line arguments
	var useTesting bool
	flag.BoolVar(&useTesting, "testing", false, "Use local testing storage")
	flag.Parse()

	// Create a new blockchain
	bc := blockchain.NewBlockchain()

	// Process data files
	dataFiles, err := filepath.Glob("data/*.txt")
	if err != nil {
		fmt.Println("Error reading data files:", err)
		return
	}

	var transactions []blockchain.DataRecord
	for _, file := range dataFiles {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", file, err)
			continue
		}

		dataHash := sha256.Sum256(data)
		transactions = append(transactions, blockchain.DataRecord{
			DataID:       filepath.Base(file),
			DataHash:     hex.EncodeToString(dataHash[:]),
			MetadataHash: "",        // Add metadata hash if needed
			Owner:        "0xOwner", // Replace with actual owner address
			Timestamp:    time.Now().String(),
		})
	}

	// Add a new block to the blockchain
	bc.AddBlock(transactions)

	// Display the blockchain
	for _, block := range bc.Blocks {
		fmt.Printf("Index: %d\n", block.Index)
		fmt.Printf("Timestamp: %s\n", block.Timestamp)
		fmt.Printf("Hash: %s\n", block.Hash)
		fmt.Printf("Previous Hash: %s\n", block.PreviousHash)
		fmt.Printf("Transactions: %v\n", block.Transactions)
		fmt.Println()
	}

	// Encrypt and store data
	passphrase := os.Getenv("ENCRYPTION_PASSPHRASE")

	if useTesting {
		// Local testing storage
		for _, file := range dataFiles {
			err := SaveToLocal(file, passphrase)
			if err != nil {
				fmt.Printf("Error saving %s to local storage: %v\n", file, err)
			} else {
				fmt.Printf("Data successfully saved to local storage: %s\n", file)
			}

			data, err := LoadFromLocal("encrypted_"+file, passphrase)
			if err != nil {
				fmt.Printf("Error loading from local storage: %v\n", err)
			} else {
				fmt.Printf("Data successfully loaded from local storage: %s\n", string(data))
			}
		}
	} else {
		for _, file := range dataFiles {
			// AWS S3 storage
			bucket := "your-aws-bucket"
			key := "encrypted_" + filepath.Base(file)

			err := UploadToS3(file, bucket, key, passphrase)
			if err != nil {
				fmt.Printf("Error uploading %s to S3: %v\n", file, err)
			} else {
				fmt.Printf("Data successfully uploaded to S3: %s\n", file)
			}

			// Google Cloud Storage
			bucket = "your-google-cloud-bucket"
			object := "encrypted_" + filepath.Base(file)

			err = UploadToGoogleCloud(file, bucket, object, passphrase)
			if err != nil {
				fmt.Printf("Error uploading %s to Google Cloud: %v\n", file, err)
			} else {
				fmt.Printf("Data successfully uploaded to Google Cloud: %s\n", file)
			}
		}
	}
}
