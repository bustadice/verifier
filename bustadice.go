package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
)

const (
	AuditSeed  = "e73bc3548830473a43431840c5bb63c7cf3e4ff15c3cf32b56ea841c602f79c2"
	GameSeed   = "f21c380b8b05cf3918178d5cbd96a9e273c2689b0d99b1685b2426ca7bbe0a06"
	ClientSeed = "hospitable belligerent carriage"
	Nonce      = 1
)

func main() {
	result := GameResult(AuditSeed, GameSeed, ClientSeed, Nonce)
	fmt.Println(result) // should be 2.07x
}

func GameResult(auditSeed, gameSeed, clientSeed string, nonce uint64) uint {
	const nBits = 52

	auditWagerSeed := hmacSha256(auditSeed, fmt.Sprint(nonce))
	gameHashString := hmacSha256(fmt.Sprintf("%s|%s|%d", gameSeed, clientSeed, nonce), auditWagerSeed)
	gameHash, err := hex.DecodeString(gameHashString)
	if err != nil {
		panic(err)
	}

	random := new(big.Int).SetBytes(gameHash)
	random.Rsh(random, sha256.Size*8-nBits)
	r := random.Uint64()

	X := float64(r) / math.Pow(2, nBits) // uniformly distributed in [0; 1)

	result := math.Floor(99 / (1 - X))
	result = math.Max(100, math.Min(result, 100000000))
	return uint(result)
}

func hmacSha256(key, message string) string {
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(message))
	return hex.EncodeToString(hash.Sum(nil))
}
