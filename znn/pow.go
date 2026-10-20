package znn

import (
	"context"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"math/big"
)

// PoW follows go-zenon pow/pow.go. The data hash is sha3(address ‖ previous
// hash); a nonce is valid when the first 8 bytes of sha3(nonce ‖ dataHash),
// read little-endian, reach 2^64 − 2^64/difficulty.

func PoWDataHash(addr Address, previous Hash) Hash {
	return Sha3(addr[:], previous[:])
}

func powThreshold(difficulty uint64) uint64 {
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	return new(big.Int).Sub(two64, new(big.Int).Quo(two64, new(big.Int).SetUint64(difficulty))).Uint64()
}

// CheckPoW reports whether nonce satisfies difficulty for dataHash.
func CheckPoW(difficulty uint64, dataHash Hash, nonce Nonce) bool {
	if difficulty == 0 {
		return true
	}
	buf := make([]byte, 40)
	copy(buf, nonce[:])
	copy(buf[8:], dataHash[:])
	sum := sha3.Sum256(buf)
	return binary.LittleEndian.Uint64(sum[:8]) >= powThreshold(difficulty)
}

// GeneratePoW searches for a nonce. It is CPU-bound — tens of seconds for an
// ordinary send at devnet difficulty — which is why every service account the
// ZVM runs is fused instead.
func GeneratePoW(ctx context.Context, difficulty uint64, dataHash Hash) (Nonce, error) {
	var n Nonce
	if difficulty == 0 {
		return n, nil
	}
	threshold := powThreshold(difficulty)
	buf := make([]byte, 40)
	if _, err := rand.Read(buf[:8]); err != nil {
		return n, err
	}
	copy(buf[8:], dataHash[:])
	for i := uint64(0); ; i++ {
		if i&0xffff == 0 {
			if err := ctx.Err(); err != nil {
				return n, err
			}
		}
		sum := sha3.Sum256(buf)
		if binary.LittleEndian.Uint64(sum[:8]) >= threshold {
			copy(n[:], buf[:8])
			return n, nil
		}
		for j := 0; j < 8; j++ {
			buf[j]++
			if buf[j] != 0 {
				break
			}
		}
	}
}
