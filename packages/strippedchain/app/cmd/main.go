package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/ShaneSCalder/optimism-Stripped-Chain/packages/strippedchain/pkg/blockchain"
	"github.com/ShaneSCalder/optimism-Stripped-Chain/packages/strippedchain/pkg/encryption"
	"github.com/ShaneSCalder/optimism-Stripped-Chain/packages/strippedchain/pkg/hash"
	"github.com/ShaneSCalder/optimism-Stripped-Chain/packages/strippedchain/pkg/merkle"
	"github.com/ShaneSCalder/optimism-Stripped-Chain/packages/strippedchain/pkg/vault"
	"github.com/joho/godotenv"
)

func loadEnv() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}
}

func main() {
	loadEnv()

	// Parse command-line arguments
	var useTesting bool
	flag.BoolVar(&useTesting, "testing", false, "Use local testing storage")
	flag.Parse()

	// Create a new blockchain or load an existing one
	var bc *blockchain.Blockchain
	if _, err := os.Stat("data/blockchain.json"); os.IsNotExist(err) {
		bc = blockchain.NewBlockchain()
	} else {
		bc, err = blockchain.LoadBlockchain("data/blockchain.json")
		if err != nil {
			fmt.Println("Error loading blockchain:", err)
			return
		}
	}

	// Process data files
	dataFiles, err := filepath.Glob("data/*.txt")
	if err != nil {
		fmt.Println("Error reading data files:", err)
		return
	}

	// Encrypt and store data, generate hashes, and create vaults
	customerID := "0x123456789abcdef" // Example customer ID
	passphrase := os.Getenv("ENCRYPTION_PASSPHRASE")

	var transactions []blockchain.DataRecord
	for _, file := range dataFiles {
		// Read file
		data, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", file, err)
			continue
		}

		// Encrypt data
		encryptedData, err := encryption.EncryptData(data, passphrase)
		if err != nil {
			fmt.Printf("Error encrypting file %s: %v\n", file, err)
			continue
		}

		// Save encrypted data locally or to cloud storage
		if useTesting {
			err := vault.SaveToLocal(file, encryptedData)
			if err != nil {
				fmt.Printf("Error saving %s to local storage: %v\n", file, err)
				continue
			}
			fmt.Printf("Data successfully saved to local storage: %s\n", file)
		} else {
			bucket := "your-aws-bucket"
			key := "encrypted_" + filepath.Base(file)

			err := vault.UploadToS3(file, bucket, key, encryptedData)
			if err != nil {
				fmt.Printf("Error uploading %s to S3: %v\n", file, err)
				continue
			}
			fmt.Printf("Data successfully uploaded to S3: %s\n", file)
		}

		// Generate Merkle leaf and root
		chunks := merkle.SplitDataIntoChunks(encryptedData, 1024) // 1KB chunk size
		merkleRoot, err := merkle.GenerateMerkleRoot(chunks)
		if err != nil {
			fmt.Printf("Error generating Merkle root: %v\n", err)
			continue
		}
		merkleLeaf := merkle.GenerateMerkleLeaf(chunks[0]) // Example for the first chunk

		// Generate file location hash
		fileLocationHash, err := vault.GenerateFileLocationHash(file)
		if err != nil {
			fmt.Printf("Error generating file location hash: %v\n", err)
			continue
		}

		// Combine hashes
		compositeHash1, compositeHash2, err := hash.CombineHashes(fileLocationHash, customerID, merkleRoot, merkleLeaf)
		if err != nil {
			fmt.Printf("Error combining hashes: %v\n", err)
			continue
		}

		// Generate final hash
		finalHash, err := hash.GenerateFinalHash(compositeHash1, compositeHash2)
		if err != nil {
			fmt.Printf("Error generating final hash: %v\n", err)
			continue
		}

		// Create a data record and add to the blockchain
		dataRecord := blockchain.DataRecord{
			DataID:       filepath.Base(file),
			DataHash:     finalHash,
			MetadataHash: "", // Add metadata hash if needed
			Owner:        customerID,
			Timestamp:    time.Now().String(),
		}
		transactions = append(transactions, dataRecord)
	}

	// Add a new block to the blockchain
	bc.AddBlock(transactions)

	// Save the updated blockchain
	err = bc.SaveBlockchain("data/blockchain.json")
	if err != nil {
		fmt.Println("Error saving blockchain:", err)
		return
	}

	// Display the blockchain
	for _, block := range bc.Blocks {
		fmt.Printf("Index: %d\n", block.Index)
		fmt.Printf("Timestamp: %s\n", block.Timestamp)
		fmt.Printf("Hash: %s\n", block.Hash)
		fmt.Printf("Previous Hash: %s\n", block.PreviousHash)
		fmt.Printf("Transactions: %v\n", block.Transactions)
		fmt.Println()
	}
}
