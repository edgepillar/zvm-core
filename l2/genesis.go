package l2

import (
	"embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
)

// Runtime code placed directly in the genesis state. L1Block and the
// preinstalls were read off OP Mainnet with eth_getCode (2026-09-14); the
// bridge and QSR token are compiled from contracts/src.
//
//go:embed predeploys/*.hex
var predeployFS embed.FS

type predeploy struct {
	name string
	addr common.Address
}

var predeploys = []predeploy{
	{"L1Block", rollup.L1BlockAddr},
	// Isthmus sets the header's withdrawalsRoot to this account's storage
	// root, so the account has to exist — otherwise each client invents its
	// own answer for a missing one and they build different genesis blocks.
	// op-geth used the zero hash and op-reth the empty-trie root, which is
	// exactly the divergence that blocked the migration (D2). This chain does
	// not use OP's withdrawal path — value leaves through ZVMBridge — so the
	// account is here to be read, not to be called; its storage stays empty
	// and both clients now hash the same empty-trie root.
	{"L2ToL1MessagePasser", common.HexToAddress("0x4200000000000000000000000000000000000016")},
	{"ZVMBridge", rollup.BridgeAddr},
	{"WrappedQSR", rollup.QSRTokenAddr},
	{"Multicall3", common.HexToAddress("0xcA11bde05977b3631167028862bE2a173976CA11")},
	{"Create2Deployer_Arachnid", common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")},
	{"BeaconRoots_4788", params.BeaconRootsAddress},
	{"HistoryStorage_2935", params.HistoryStorageAddress},
	{"Permit2", common.HexToAddress("0x000000000022D473030F116dDEE9F6B43aC78BA3")},
	{"EntryPoint_v07", common.HexToAddress("0x0000000071727De22E5E9d8BAf0edAc6f37da032")},
	{"SenderCreator_v07", common.HexToAddress("0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C")},
	{"SafeSingletonFactory", common.HexToAddress("0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7")},
}

// Predeploys lists the genesis contracts by name, for the explorer.
func Predeploys() map[string]common.Address {
	out := make(map[string]common.Address, len(predeploys))
	for _, p := range predeploys {
		out[p.name] = p.addr
	}
	return out
}

// PredeployCode is one predeploy's deployed bytecode, by the name Predeploys
// keys on. It is exported so that anything needing the same bytes — a test
// chain, a tool that checks a live account against genesis — reads the copy
// genesis is built from rather than its own path to the same file.
func PredeployCode(name string) ([]byte, error) { return predeployCode(name) }

func predeployCode(name string) ([]byte, error) {
	raw, err := predeployFS.ReadFile("predeploys/" + name + ".hex")
	if err != nil {
		return nil, err
	}
	s := strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x")
	code, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("predeploy %s: %w", name, err)
	}
	if len(code) == 0 {
		return nil, fmt.Errorf("predeploy %s: empty code", name)
	}
	return code, nil
}

// EIP-1559 parameters: OP Stack's post-Canyon defaults.
const (
	eip1559Denominator       = 50
	eip1559DenominatorCanyon = 250
	eip1559Elasticity        = 6
)

// ChainConfig activates the OP Stack forks this chain runs, at genesis.
//
// The Ethereum forks are paired as the clients require (Shanghai=Canyon,
// Cancun=Ecotone, Prague=Isthmus, Osaka=Karst) and a mismatch is refused at
// startup. "isthmus" is what op-geth can follow; "karst" adds Jovian and Karst
// — the Osaka EVM, EIP-7825's 2²⁴ per-transaction gas cap, and a configurable
// minimum base fee — and **needs op-reth**: Optimism states op-geth cannot
// follow Karst (D2, D3).
func ChainConfig(cfg *rollup.Config) *params.ChainConfig {
	zero := uint64(0)
	canyon := uint64(eip1559DenominatorCanyon)
	c := &params.ChainConfig{
		ChainID:             new(big.Int).SetUint64(cfg.L2ChainID),
		HomesteadBlock:      common.Big0,
		EIP150Block:         common.Big0,
		EIP155Block:         common.Big0,
		EIP158Block:         common.Big0,
		ByzantiumBlock:      common.Big0,
		ConstantinopleBlock: common.Big0,
		PetersburgBlock:     common.Big0,
		IstanbulBlock:       common.Big0,
		MuirGlacierBlock:    common.Big0,
		BerlinBlock:         common.Big0,
		LondonBlock:         common.Big0,
		ArrowGlacierBlock:   common.Big0,
		GrayGlacierBlock:    common.Big0,
		MergeNetsplitBlock:  common.Big0,
		ShanghaiTime:        &zero,
		CancunTime:          &zero,
		PragueTime:          &zero,
		BedrockBlock:        common.Big0,
		RegolithTime:        &zero,
		CanyonTime:          &zero,
		EcotoneTime:         &zero,
		FjordTime:           &zero,
		GraniteTime:         &zero,
		HoloceneTime:        &zero,
		IsthmusTime:         &zero,

		TerminalTotalDifficulty: common.Big0,
		Optimism: &params.OptimismConfig{
			EIP1559Elasticity:        eip1559Elasticity,
			EIP1559Denominator:       eip1559Denominator,
			EIP1559DenominatorCanyon: &canyon,
		},
	}
	if cfg.IsKarst() {
		c.OsakaTime = &zero
		c.JovianTime = &zero
		c.KarstTime = &zero
	}
	return c
}

// ExtraData is the header encoding of the EIP-1559 parameters. With Holocene
// active at genesis, block 1's base fee is computed from the genesis header's
// extraData, so the genesis must carry it: 9 bytes through Isthmus, and 17
// from Jovian, which appends the minimum base fee (D3).
func ExtraData(cfg *rollup.Config) []byte {
	if cfg.IsKarst() {
		extra := make([]byte, 17)
		extra[0] = 0x01 // Jovian's version byte
		binary.BigEndian.PutUint32(extra[1:5], eip1559DenominatorCanyon)
		binary.BigEndian.PutUint32(extra[5:9], eip1559Elasticity)
		binary.BigEndian.PutUint64(extra[9:], cfg.MinBaseFee)
		return extra
	}
	extra := make([]byte, 9)
	binary.BigEndian.PutUint32(extra[1:5], eip1559DenominatorCanyon)
	binary.BigEndian.PutUint32(extra[5:9], eip1559Elasticity)
	return extra
}

// BuildGenesis builds op-geth's genesis. No ZNN is allocated: every wei on
// the ZVM entered through the bridge vault, so L2 supply can be audited
// against the vault's L1 balance.
func BuildGenesis(cfg *rollup.Config, timestamp uint64) (*core.Genesis, error) {
	alloc := types.GenesisAlloc{}
	for _, p := range predeploys {
		code, err := predeployCode(p.name)
		if err != nil {
			return nil, err
		}
		alloc[p.addr] = types.Account{Code: code, Balance: new(big.Int), Nonce: 1}
	}
	// The bridge has no constructor, so its fee parameters are genesis storage.
	// Zero slots are left out rather than written as zero: an empty slot and a
	// zero one hash the same, and leaving them out keeps a fee-less genesis
	// byte-identical to one written before the fee existed.
	if f := cfg.BridgeFee; f != nil {
		storage := map[common.Hash]common.Hash{}
		for slot, v := range map[int64]uint64{
			rollup.BridgeSlotFeeBps: f.BPS, rollup.BridgeSlotMinFeeZNN: f.MinZNN, rollup.BridgeSlotMinFeeQSR: f.MinQSR,
		} {
			if v != 0 {
				storage[common.BigToHash(big.NewInt(slot))] = common.BigToHash(new(big.Int).SetUint64(v))
			}
		}
		if len(storage) > 0 {
			acct := alloc[rollup.BridgeAddr]
			acct.Storage = storage
			alloc[rollup.BridgeAddr] = acct
		}
	}
	zero := uint64(0)
	return &core.Genesis{
		Config:        ChainConfig(cfg),
		Timestamp:     timestamp,
		ExtraData:     ExtraData(cfg),
		GasLimit:      cfg.GasLimit,
		Difficulty:    common.Big0,
		Alloc:         alloc,
		BaseFee:       big.NewInt(params.InitialBaseFee),
		ExcessBlobGas: &zero,
		BlobGasUsed:   &zero,
	}, nil
}
