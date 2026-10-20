// Package devnet names the roles the ZVM prototype gives to indexes of
// go-zenon's committed devnet mnemonic. Every key here is public and devnet
// only; the table exists so the L1 genesis, the services and the benchmark
// agree on who is who without passing keys around.
package devnet

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

const (
	// L1ChainID is a ZVM devnet's NoM network: go-zenon's devnet chain id, with
	// dynamic plasma active, so momentums are version 2 as on go-zenon's dev
	// branch, which NoM is moving to. Chain 70, the version 1 ruleset of
	// go-zenon's master branch, is deprecated: `l1-genesis -chain-id 70
	// -dynamic-plasma=false` still writes one.
	L1ChainID = 69

	// L2ChainID is 7340400 + the L1 chain id; 73404 is ZNN's SLIP-44 coin type.
	L2ChainID = 7340400 + L1ChainID

	// GenesisTimestampSec is 2026-09-14T00:00:00Z: the default only, and a poor
	// one for a network started much later.
	//
	// go-zenon schedules momentum ticks from the genesis timestamp, so a genesis
	// far in the past leaves a single pillar producing in only some of the ticks:
	// measured 2026-09-16, a genesis 2.75 days old gave alternating 10 s and 20 s
	// momentums — a 15 s average — where a fresh one gives a steady 10 s. Both
	// `zvm l1-genesis` and `zvm l2-genesis` take -timestamp for that reason, and
	// a new devnet should pass `-timestamp now`.
	GenesisTimestampSec = 1789344000
)

// Mnemonic indexes and their roles.
const (
	PillarProducer = 0 // also the account the Syrius extension in this tree holds
	DevOwner       = 1 // pillar owner, general dev funder
	Dev3           = 3
	Dev8           = 8
	Dev9           = 9

	Vault          = 200 // bridge vault: holds deposited ZNN/QSR, pays withdrawals
	Faucet         = 201
	RelayerBase    = 202 // relayers 202..209
	NumRelayers    = 8
	BenchFunder    = 210
	BenchNative    = 1000 // native-lane benchmark wallets 1000..1199
	NumBenchNative = 200
)

// Account is one genesis allocation on the L1.
type Account struct {
	Index   uint32
	Role    string
	ZNN     int64 // whole units
	QSR     int64 // whole units
	FuseQSR int64 // whole units fused to the account itself
}

// L1Accounts is the L1 genesis allocation table.
func L1Accounts() []Account {
	accts := []Account{
		{PillarProducer, "pillar producer / Syrius extension account", 10_000, 100_000, 5_000},
		{DevOwner, "pillar owner / dev funder", 1_000_000, 10_000_000, 5_000},
		{Dev3, "dev account", 50_000, 500_000, 1_000},
		{Dev8, "dev account", 50_000, 500_000, 1_000},
		{Dev9, "dev account", 50_000, 500_000, 1_000},
		// 1,000 of NoM's 5,000-unit per-account ceiling, so the withdrawal fee
		// has somewhere to go: the bridge fuses what it earns to the vault (D8).
		{Vault, "bridge vault", 0, 0, 1_000},
		{Faucet, "faucet", 10_000_000, 100_000_000, 5_000},
		{BenchFunder, "benchmark funder", 5_000_000, 50_000_000, 5_000},
	}
	for i := uint32(0); i < NumRelayers; i++ {
		accts = append(accts, Account{RelayerBase + i, "relayer", 0, 0, 5_000})
	}
	for i := uint32(0); i < NumBenchNative; i++ {
		accts = append(accts, Account{BenchNative + i, "native-lane benchmark wallet", 1_000, 0, 500})
	}
	return accts
}

// Units converts whole ZNN/QSR to base units (8 decimals).
func Units(whole int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(whole), znn.OneZNN)
}

// EVMKey is a deterministic secp256k1 dev key: keccak256("zvm-dev-evm-<i>").
// Like the mnemonic, these keys are public; they stand in for MetaMask and
// Rabby accounts in tests and benchmarks.
func EVMKey(i uint32) *ecdsa.PrivateKey {
	key, err := crypto.ToECDSA(crypto.Keccak256([]byte(fmt.Sprintf("zvm-dev-evm-%d", i))))
	if err != nil {
		panic(err)
	}
	return key
}

var wallet = znn.MustDevWallet()

// Key returns the dev key at index.
func Key(index uint32) *znn.KeyPair { return wallet.Key(index) }

func RelayerKey(i uint32) *znn.KeyPair { return wallet.Key(RelayerBase + i) }
