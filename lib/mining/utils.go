package mining

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// HashMeetsDifficulty checks if a hash meets the specified difficulty target
func HashMeetsDifficulty(hashHex string, difficulty float64) bool {
	// Convert difficulty to target
	target := DifficultyToTarget(difficulty)

	// Compare hash with target (hash must be less than or equal to target)
	// In Bitcoin, lower numeric value of hash = higher "difficulty" achieved
	hashInt, _ := new(big.Int).SetString(hashHex, 16)
	targetInt, _ := new(big.Int).SetString(target, 16)

	// Return true if hash <= target
	return hashInt.Cmp(targetInt) <= 0
}

// ValidateShare checks if a submitted share is valid
func ValidateShare(submission *ShareSubmission, job *MiningJob, extraNonce1 string) (bool, bool) {
	// First boolean: valid for client difficulty
	// Second boolean: meets pool difficulty

	// Verify the job ID matches
	if submission.JobID != job.JobID {
		return false, false
	}

	// Reconstruct the block header and verify the hash
	coinbaseTx := job.Coinbase1 + extraNonce1 + submission.ExtraNonce2 + job.Coinbase2

	// Hash the coinbase transaction
	coinbaseHash := DoubleSHA256(coinbaseTx)

	// Calculate merkle root
	merkleRoot := CalculateMerkleRoot(coinbaseHash, job.MerkleBranches)

	// Construct block header
	blockHeader := job.Version + job.PrevHash + merkleRoot + submission.NTime + job.NBits + submission.Nonce

	// Calculate the block hash
	blockHash := DoubleSHA256(blockHeader)

	// Reverse the hash for comparison (Bitcoin uses little-endian)
	blockHashReversed := ReverseHex(blockHash)

	// Compare with the submitted hash
	if blockHashReversed != submission.Hash {
		return false, false
	}

	println("blockHashReversed", blockHashReversed)
	println("job.ClientDifficulty", job.ClientDifficulty)
	println("job.PoolDifficulty", job.PoolDifficulty)

	// Check if hash meets client difficulty
	validClient := HashMeetsDifficulty(blockHashReversed, job.ClientDifficulty)

	// Check if hash meets pool difficulty
	validPool := HashMeetsDifficulty(blockHashReversed, job.PoolDifficulty)

	return validClient, validPool
}

// DoubleSHA256 performs a double SHA-256 hash on the input string
func DoubleSHA256(input string) string {
	// Decode hex string to bytes
	bytes, err := hex.DecodeString(input)
	if err != nil {
		return ""
	}

	// First SHA-256
	firstHash := sha256.Sum256(bytes)

	// Second SHA-256
	secondHash := sha256.Sum256(firstHash[:])

	// Return as hex string
	return hex.EncodeToString(secondHash[:])
}

// CalculateMerkleRoot calculates the merkle root from the coinbase hash and merkle branches
func CalculateMerkleRoot(coinbaseHash string, branches []string) string {
	hash := coinbaseHash

	for _, branch := range branches {
		// Concatenate hash and branch
		combined := hash + branch

		// Decode hex to bytes
		bytes, err := hex.DecodeString(combined)
		if err != nil {
			return ""
		}

		// Double SHA-256
		firstHash := sha256.Sum256(bytes)
		secondHash := sha256.Sum256(firstHash[:])

		// Convert back to hex
		hash = hex.EncodeToString(secondHash[:])
	}

	return hash
}

// ReverseHex reverses the byte order of a hex string
func ReverseHex(hexStr string) string {
	if len(hexStr)%2 != 0 {
		return hexStr
	}

	var reversed strings.Builder
	reversed.Grow(len(hexStr))

	for i := len(hexStr) - 2; i >= 0; i -= 2 {
		reversed.WriteString(hexStr[i : i+2])
	}

	return reversed.String()
}

// DifficultyToTarget converts a difficulty value to a Bitcoin target
func DifficultyToTarget(difficulty float64) string {
	// The highest possible target (difficulty 1) in Bitcoin
	maxTargetHex := "00000000FFFF0000000000000000000000000000000000000000000000000000"
	maxTarget, _ := new(big.Int).SetString(maxTargetHex, 16)

	// Calculate the actual target based on difficulty (target = maxTarget / difficulty)
	if difficulty <= 0 {
		return maxTargetHex
	}

	diffBig := new(big.Float).SetFloat64(difficulty)
	targetFloat := new(big.Float).Quo(new(big.Float).SetInt(maxTarget), diffBig)

	// Convert to integer
	targetInt := new(big.Int)
	targetFloat.Int(targetInt)

	// Convert to hex with proper padding
	targetHex := fmt.Sprintf("%064x", targetInt)

	return targetHex
}
