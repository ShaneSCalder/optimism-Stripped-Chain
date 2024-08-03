package blockchain

import (
	"app/pkg/hash"
	"fmt"
	"time"
)

type DataRecord struct {
	DataID       string
	DataHash     string
	MetadataHash string
	Owner        string
	Timestamp    string
}

type Block struct {
	Index        int
	Timestamp    string
	Hash         string
	PreviousHash string
	Transactions []DataRecord
}

type Blockchain struct {
	Blocks []Block
}

// calculateHash calculates the hash for a block
func calculateHash(block Block) string {
	record := fmt.Sprintf("%d%s%s%v", block.Index, block.Timestamp, block.PreviousHash, block.Transactions)
	return hash.CalculateHash(record)
}

// CreateGenesisBlock creates the first block in the blockchain
func CreateGenesisBlock() Block {
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now().String(),
		PreviousHash: "0",
	}
	genesisBlock.Hash = calculateHash(genesisBlock)
	return genesisBlock
}

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(transactions []DataRecord) {
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now().String(),
		PreviousHash: prevBlock.Hash,
		Transactions: transactions,
	}
	newBlock.Hash = calculateHash(newBlock)
	bc.Blocks = append(bc.Blocks, newBlock)
}

// NewBlockchain creates a new blockchain with the genesis block
func NewBlockchain() *Blockchain {
	genesisBlock := CreateGenesisBlock()
	return &Blockchain{Blocks: []Block{genesisBlock}}
}
