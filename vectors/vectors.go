// Package vectors pins the ZVM's encodings. Everything here is computed from
// the same code the node runs, written to spec/vectors.json, and checked by a
// test — so an encoding cannot move without someone noticing.
package vectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/l2"
	"github.com/Zenoglyphs-VM/zvm-core/orderbook"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Version 3 adds the exchange section: EIP-712 order hashing and bulk proofs
// (D28), and the mandatory-message deferral's share is in params.
const Version = 3

type Message struct {
	Name    string `json:"name"`
	Encoded string `json:"encoded"`
	Note    string `json:"note,omitempty"`
}

type SourceHash struct {
	Domain uint64 `json:"domain"`
	L1Hash string `json:"l1Hash"`
	Index  uint64 `json:"index"`
	Hash   string `json:"hash"`
}

type DerivedTx struct {
	Name     string `json:"name"`
	NomBlock string `json:"nomBlock"`
	TxHash   string `json:"txHash"`
	Gas      uint64 `json:"gas"`
	Mint     string `json:"mint,omitempty"`
	Encoded  string `json:"encoded"`
}

type GasCase struct {
	UsedPlasma uint64 `json:"usedPlasma"`
	Requested  uint64 `json:"requested"`
	Gas        uint64 `json:"gas"`
}

// FeeCase pins the burned-fee rule: what an amount buys, what gas costs, and
// the whole budget for a block that burned it.
type FeeCase struct {
	Note       string `json:"note"`
	Momentum   uint64 `json:"momentum"`
	Timestamp  uint64 `json:"timestamp"`
	Epoch      uint64 `json:"epoch"`
	Token      string `json:"token"`
	Burned     string `json:"burned"`
	DataLen    int    `json:"dataLen"`
	BasePlasma uint64 `json:"basePlasma"`
	PaidPlasma uint64 `json:"paidPlasma"`
	Price      uint64 `json:"price"`
	Requested  uint64 `json:"requested"`
	FeeGas     uint64 `json:"feeGas"`
	Gas        uint64 `json:"gas"`
	CostOfGas  string `json:"costOfGas"`
}

type File struct {
	Version      int                          `json:"version"`
	Params       map[string]uint64            `json:"params"`
	Addresses    map[string]map[string]string `json:"addresses"`
	Messages     []Message                    `json:"messages"`
	SourceHashes []SourceHash                 `json:"sourceHashes"`
	L1Info       map[string]string            `json:"l1Info"`
	Derived      []DerivedTx                  `json:"derived"`
	Gas          []GasCase                    `json:"gas"`
	Fee          *FeeSection                  `json:"fee"`
	Forks        *ForkSection                 `json:"forks"`
	Exchange     *ExchangeSection             `json:"exchange"`
}

// ExchangeSection pins the EIP-712 hashing the NFT market rests on (D28). An
// order is only ever a signature, so a browser that hashed one differently from
// the node and the contract would collect signatures nothing can fill.
type ExchangeSection struct {
	Note          string      `json:"note"`
	OrderTypeHash string      `json:"orderTypeHash"`
	RootTypeHash  string      `json:"rootTypeHash"`
	ChainID       uint64      `json:"chainId"`
	Exchange      string      `json:"exchange"`
	Domain        string      `json:"domainSeparator"`
	Orders        []OrderCase `json:"orders"`
	Bulk          BulkCase    `json:"bulk"`
}

type OrderCase struct {
	Name   string          `json:"name"`
	Order  orderbook.Order `json:"order"`
	Hash   string          `json:"hash"`
	Digest string          `json:"digest"`
}

// BulkCase is Blur's bulk listing: many orders under one signature, each filled
// with its own proof.
type BulkCase struct {
	Root   string     `json:"root"`
	Digest string     `json:"digest"`
	Leaves []string   `json:"leaves"`
	Proofs [][]string `json:"proofs"`
}

// ForkSection pins what changes at each activation height: the fifth call
// item, the elastic share, chunk gas, the span layout and the derived fee
// split. Everything in it is inert on a chain whose forks are unset, which is
// what the "before" cases show.
type ForkSection struct {
	Note      string      `json:"note"`
	GasFrom   uint64      `json:"gasFrom"`
	WireFrom  uint64      `json:"wireFrom"`
	Share     ShareCase   `json:"share"`
	Boost     []BoostCase `json:"boost"`
	Span      SpanCase    `json:"span"`
	FeeSplit  SplitCase   `json:"feeSplit"`
	BurnMagic string      `json:"burnMagic"`
	Chunk     ChunkCase   `json:"chunkGas"`
}

// ShareCase is D10's elastic split of one block.
type ShareCase struct {
	GasLimit     uint64 `json:"gasLimit"`
	NativeFloor  uint64 `json:"nativeFloor"`
	NativeCeil   uint64 `json:"nativeCeiling"`
	RelayedCeil  uint64 `json:"relayedCeiling"`
	NativeBefore uint64 `json:"nativeBeforeTheFork"`
}

// BoostCase pins the fifth item's encoding and what it buys.
type BoostCase struct {
	Note     string `json:"note"`
	Encoded  string `json:"encoded"`
	Burned   string `json:"burned"`
	Boost    string `json:"boost"`
	FeeGas   uint64 `json:"feeGas"`
	BoostGas uint64 `json:"boostGas"`
	Gas      uint64 `json:"gas"`
}

// SpanCase pins the columnar layout: the payload a decoder is handed, after
// decompression, and the transactions it must produce. The compressed bytes
// are not pinned — brotli is a standard, and only what comes out of it is
// this protocol's business.
type SpanCase struct {
	Note    string   `json:"note"`
	Payload string   `json:"payload"`
	Txs     []string `json:"txs"`
}

// SplitCase pins the derived fee-split call.
type SplitCase struct {
	Splitter string   `json:"splitter"`
	Salt     string   `json:"salt"`
	InitHash string   `json:"initCodeHash"`
	Burn     string   `json:"burnAddress"`
	Momentum uint64   `json:"momentum"`
	Relayers []string `json:"relayers"`
	Weights  []uint64 `json:"weights"`
	Calldata string   `json:"calldata"`
	Gas      uint64   `json:"gas"`
}

// ChunkCase pins that a chunk contributes the base plasma of its own block.
type ChunkCase struct {
	Note         string `json:"note"`
	ChunkBytes   int    `json:"chunkBytes"`
	ChunkPlasma  uint64 `json:"chunkPlasma"`
	AssemblePl   uint64 `json:"assemblePlasma"`
	GasBefore    uint64 `json:"gasBeforeTheFork"`
	GasAfterFork uint64 `json:"gasAfterTheFork"`
}

// FeeSection is the fee schedule the cases are computed against, so an
// implementation can reproduce them from this file alone.
type FeeSection struct {
	FromHeight       uint64    `json:"fromHeight"`
	GasPerSupply     int64     `json:"gasPerSupply"`
	GenesisTimestamp int64     `json:"genesisTimestamp"`
	RefEpoch         uint64    `json:"refEpoch"`
	RefZNN           string    `json:"refZnn"`
	RefQSR           string    `json:"refQsr"`
	SupplyAtRef      []string  `json:"supplyAtRefPlusYear"`
	Cases            []FeeCase `json:"cases"`
}

// testConfig is the configuration the vectors are computed against. It is
// fixed here rather than read from a file: a vector that moves with someone's
// configuration pins nothing.
func testConfig() *rollup.Config {
	return &rollup.Config{
		L1ChainID: 70, L2ChainID: 7_340_470,
		Inbox: rollup.Inbox, Vault: devnet.Key(devnet.Vault).Address,
		L1StartHeight: 2, GasLimit: 300_000_000, GasPerPlasma: 16,
		MaxNativeGas: 16_777_216, MaxNativeGasPerBlock: 150_000_000, MaxTxGas: 30_000_000,
		ChunkTTL: 8_640, MaxAssembledBytes: 512 * 1024, MaxBatchBytes: 4 * 1024 * 1024, FinalityDepth: 6,
	}
}

// fixedBlock is a deterministic NoM send to the inbox: the carrier the
// derived-transaction vectors are computed from.
func fixedBlock(to znn.Address, zts znn.TokenStandard, amount *big.Int, data []byte) *znn.AccountBlock {
	b := &znn.AccountBlock{
		Version: 1, ChainIdentifier: 70, BlockType: znn.BlockTypeUserSend, Height: 42,
		PreviousHash:         znn.Sha3([]byte("zvm-vectors-previous")),
		MomentumAcknowledged: znn.HashHeight{Hash: znn.Sha3([]byte("zvm-vectors-momentum")), Height: 1_000},
		Address:              devnet.Key(1).Address,
		ToAddress:            to, TokenStandard: zts, Amount: znn.NewBigInt(amount), Data: data,
		DescendantBlocks: []*znn.AccountBlock{},
	}
	b.BasePlasma = znn.BaseSendPlasma(len(data))
	b.FusedPlasma, b.UsedPlasma = b.BasePlasma, b.BasePlasma
	b.Hash = b.ComputeHash()
	return b
}

func hexs(b []byte) string { return "0x" + hex.EncodeToString(b) }

// Build computes every vector.
func Build() (*File, error) {
	cfg := testConfig()
	f := &File{
		Version: Version,
		Params: map[string]uint64{
			"l1ChainId": cfg.L1ChainID, "l2ChainId": cfg.L2ChainID, "gasPerPlasma": cfg.GasPerPlasma,
			"maxNativeGas": cfg.MaxNativeGas, "gasLimit": cfg.GasLimit, "finalityDepth": cfg.FinalityDepth,
			"chunkTtl": cfg.ChunkTTL,
		},
		Addresses: map[string]map[string]string{},
		L1Info:    map[string]string{},
	}
	for name, addr := range map[string]znn.Address{
		"inbox": rollup.Inbox, "vault": cfg.Vault, "devKey1": devnet.Key(1).Address,
	} {
		f.Addresses[name] = map[string]string{"nom": addr.String(), "evm": addr.Hex()}
	}
	for name, addr := range map[string]common.Address{
		"bridge": rollup.BridgeAddr, "wrappedQsr": rollup.QSRTokenAddr, "l1Block": rollup.L1BlockAddr,
		"l1InfoDepositor": rollup.L1InfoDepositor, "systemDepositor": rollup.SystemDepositor,
	} {
		f.Addresses[name] = map[string]string{"nom": znn.Address(addr).String(), "evm": addr.Hex()}
	}

	// Messages.
	target := common.HexToAddress("0x4200000000000000000000000000000000000100")
	transferData := common.FromHex("0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000002a")
	call := derive.Call{To: &target, Value: big.NewInt(1_500_000_000_000_000_000), Gas: 60_000, Data: transferData}
	f.Messages = append(f.Messages,
		Message{Name: "call", Encoded: hexs(derive.EncodeCall(call)),
			Note: "0x01 ‖ rlp([to, value, gas, data]) — an ERC-20 transfer with 1.5 ZNN attached"},
		Message{Name: "call.create", Encoded: hexs(derive.EncodeCall(derive.Call{Value: new(big.Int), Data: []byte{0x60, 0x80, 0x60, 0x40}})),
			Note: "empty 'to' deploys the data"},
		Message{Name: "call.zero", Encoded: hexs(derive.EncodeCall(derive.Call{Value: new(big.Int)})),
			Note: "every field at its zero value"},
		Message{Name: "chunk", Encoded: hexs(derive.SplitChunks(bytes.Repeat([]byte{0xab}, 40))[0])},
		Message{Name: "assemble", Encoded: hexs(derive.EncodeAssemble([]znn.Hash{
			znn.Sha3([]byte("chunk-a")), znn.Sha3([]byte("chunk-b")),
		}))},
	)
	rawBatch, err := derive.EncodeBatch([][]byte{common.FromHex("0x02f86e01"), common.FromHex("0x01f8")}, derive.BatchRaw)
	if err != nil {
		return nil, err
	}
	f.Messages = append(f.Messages, Message{Name: "batch.raw", Encoded: hexs(rawBatch),
		Note: "0x02 ‖ 0x00 ‖ rlp([tx, …]); compressed batches use flags 0x01 zlib, 0x02 brotli and 0x03 span, and are not pinned as bytes, since only the decoder is consensus"})
	f.Messages = append(f.Messages, Message{
		Name: "call.boost",
		Encoded: hexs(derive.EncodeCall(derive.Call{
			To: &target, Value: big.NewInt(1_500_000_000_000_000_000), Gas: 60_000, Data: transferData,
			Boost: big.NewInt(250_000),
		})),
		Note: "0x01 ‖ rlp([to, value, gas, data, boost]) — the same call with a fifth item, valid only from the gas fork",
	})

	// Source hashes.
	l1Hash := znn.Sha3([]byte("zvm-vectors-source"))
	for _, c := range []struct {
		domain uint64
		index  uint64
	}{{l2.DomainUserDeposit, 0}, {l2.DomainL1Info, 0}, {l2.DomainSystem, 0}, {l2.DomainUserDeposit, 7}} {
		f.SourceHashes = append(f.SourceHashes, SourceHash{
			Domain: c.domain, L1Hash: l1Hash.String(), Index: c.index,
			Hash: l2.SourceHash(c.domain, l1Hash, c.index).Hex(),
		})
	}

	// L1 info.
	m := &znn.Momentum{Version: 1, ChainIdentifier: 70, Height: 123_456, Timestamp: 1_789_440_000,
		Hash: znn.Sha3([]byte("zvm-vectors-l1info"))}
	f.L1Info["momentumHash"] = m.Hash.String()
	f.L1Info["momentumHeight"] = fmt.Sprint(m.Height)
	f.L1Info["momentumTimestamp"] = fmt.Sprint(m.Timestamp)
	f.L1Info["calldata"] = hexs(l2.L1InfoData(cfg, m))
	infoTx := l2.L1InfoTx(cfg, m)
	f.L1Info["txHash"] = infoTx.Hash().Hex()
	// On karst the same momentum is 178 bytes with Jovian's selector and a
	// zero DA-footprint scalar (D3).
	karst := testConfig()
	karst.EVM = rollup.EVMKarst
	karst.MaxTxGas = rollup.EIP7825MaxTxGas
	f.L1Info["calldataKarst"] = hexs(l2.L1InfoData(karst, m))
	f.L1Info["txHashKarst"] = l2.L1InfoTx(karst, m).Hash().Hex()

	// Derived transactions.
	carrier := fixedBlock(rollup.Inbox, znn.ZeroTokenStandard, new(big.Int), derive.EncodeCall(call))
	nativeTx := derive.NativeTx(cfg, carrier, call)
	nativeRaw, err := nativeTx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	deposit := fixedBlock(cfg.Vault, znn.ZNN, big.NewInt(12_345_678_900), nil)
	depositTx := derive.DepositTx(deposit)
	depositRaw, err := depositTx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	f.Derived = append(f.Derived,
		DerivedTx{Name: "native call", NomBlock: carrier.Hash.String(), TxHash: nativeTx.Hash().Hex(),
			Gas: nativeTx.Gas(), Encoded: hexs(nativeRaw)},
		DerivedTx{Name: "znn deposit", NomBlock: deposit.Hash.String(), TxHash: depositTx.Hash().Hex(),
			Gas: depositTx.Gas(), Mint: depositTx.Mint().String(), Encoded: hexs(depositRaw)},
	)

	// The gas rule.
	for _, c := range []struct{ used, requested uint64 }{
		{21_000, 0}, {23_312, 0}, {23_312, 50_000}, {1_135_112, 0}, {1_135_112, 30_000_000}, {21_000, 1_000},
	} {
		f.Gas = append(f.Gas, GasCase{UsedPlasma: c.used, Requested: c.requested,
			Gas: derive.NativeGas(cfg, c.used, c.requested)})
	}

	// The burned fee, against mainnet's supply anchor.
	feeCfg := testConfig()
	fee := rollup.MainnetSupplyAnchor
	fee.FromHeight = 1_000
	if err := fee.Check(); err != nil {
		return nil, err
	}
	feeCfg.Fee = &fee
	feeCfg.MaxDepositCallGas = 1_000_000
	znnYear, qsrYear := fee.SupplyAt(fee.RefEpoch + 365)
	section := &FeeSection{
		FromHeight: fee.FromHeight, GasPerSupply: fee.GasPerSupply, GenesisTimestamp: fee.GenesisTimestamp,
		RefEpoch: fee.RefEpoch, RefZNN: fee.RefZNN, RefQSR: fee.RefQSR,
		SupplyAtRef: []string{znnYear.String(), qsrYear.String()},
	}
	// 1788991540 is the timestamp the anchor was read at: epoch 1750.
	const anchorTime = 1_788_991_540
	for _, c := range []struct {
		note      string
		momentum  uint64
		timestamp uint64
		token     znn.TokenStandard
		burned    string
		dataLen   int
		paid      uint64
		requested uint64
	}{
		{"before the activation height: plasma alone, no burn needed", 999, anchorTime, znn.ZeroTokenStandard, "0", 100, 0, 200_000},
		{"1 ZNN buys gas at the anchor epoch", 1_000, anchorTime, znn.ZNN, "100000000", 100, 0, 16_777_216},
		{"the same burn in QSR buys less, because QSR's supply is larger", 1_000, anchorTime, znn.QSR, "100000000", 100, 0, 16_777_216},
		{"a small burn is the binding limit", 1_000, anchorTime, znn.ZNN, "10000", 100, 0, 16_777_216},
		{"congestion: a block that paid 2.5x its base plasma buys 2.5x less gas", 1_000, anchorTime, znn.ZNN, "100000000", 100, znn.BaseSendPlasma(100) * 5 / 2, 16_777_216},
		{"one year on, the same burn buys slightly less: supply has grown", 1_000, anchorTime + 365*86_400, znn.ZNN, "100000000", 100, 0, 16_777_216},
		{"nothing burned: no gas, whatever the plasma", 1_000, anchorTime, znn.ZeroTokenStandard, "0", 100, 0, 200_000},
	} {
		m := &znn.Momentum{Height: c.momentum, Timestamp: c.timestamp}
		b := derive.QuoteBlock(c.dataLen)
		b.TokenStandard = c.token
		amount, _ := new(big.Int).SetString(c.burned, 10)
		b.Amount = znn.NewBigInt(amount)
		if c.paid != 0 {
			b.FusedPlasma = c.paid
		}
		price := rollup.PriceOf(b)
		epoch := fee.EpochAt(int64(c.timestamp))
		section.Cases = append(section.Cases, FeeCase{
			Note: c.note, Momentum: c.momentum, Timestamp: c.timestamp, Epoch: epoch,
			Token: c.token.String(), Burned: c.burned, DataLen: c.dataLen,
			BasePlasma: b.BasePlasma, PaidPlasma: b.FusedPlasma, Price: price.Scaled(),
			Requested: c.requested,
			FeeGas:    fee.GasFor(amount, c.token, epoch, price),
			Gas:       derive.NativeGasAt(feeCfg, m, b, c.requested),
			CostOfGas: fee.Cost(1_000_000, c.token, epoch, price).String(),
		})
	}
	f.Fee = section

	forks, err := buildForks(feeCfg, fee)
	if err != nil {
		return nil, err
	}
	f.Forks = forks
	f.Exchange = buildExchange(cfg.L2ChainID)
	return f, nil
}

// buildExchange pins order hashing against a fixed exchange address, so the
// vectors do not move with a deployment.
func buildExchange(chainID uint64) *ExchangeSection {
	exchange := common.HexToAddress("0x00000000000000000000000000000000000e5c4a")
	domain := orderbook.Domain(chainID, exchange)
	w := znn.MustDevWallet()
	order := func(side uint8, token int64, price int64, anyToken bool, payment common.Address) orderbook.Order {
		return orderbook.Order{
			Trader: common.Address(w.Key(uint32(1000 + token)).Address), Side: side,
			Collection: common.HexToAddress("0x00000000000000000000000000000000c0113c71"),
			TokenID:    orderbook.U(token), AnyToken: anyToken, Amount: orderbook.U(1), PaymentToken: payment,
			Price:       orderbook.B(new(big.Int).Mul(big.NewInt(price), big.NewInt(1e18))),
			ListingTime: 1_789_000_000, ExpirationTime: 1_789_600_000, Nonce: orderbook.U(0), Salt: orderbook.U(token * 7919),
		}
	}
	var qsr common.Address
	copy(qsr[:], rollup.QSRTokenAddr[:])
	cases := []struct {
		name  string
		order orderbook.Order
	}{
		{"listing in ZNN", order(orderbook.SideSell, 1, 5, false, common.Address{})},
		{"listing in QSR", order(orderbook.SideSell, 2, 9, false, qsr)},
		{"collection bid", order(orderbook.SideBuy, 3, 4, true, qsr)},
	}
	out := &ExchangeSection{
		Note: "EIP-712 order hashing: the same order must hash the same in the node, the browser and ZVMExchange. " +
			"A bulk listing is one signature over the Merkle root of many orders, each filled with its own proof.",
		OrderTypeHash: orderbook.OrderTypeHash.Hex(), RootTypeHash: orderbook.RootTypeHash.Hex(),
		ChainID: chainID, Exchange: exchange.Hex(), Domain: domain.Hex(),
	}
	var leaves []common.Hash
	for _, c := range cases {
		o := c.order
		h := o.Hash()
		out.Orders = append(out.Orders, OrderCase{Name: c.name, Order: o, Hash: h.Hex(), Digest: orderbook.OrderDigest(domain, h).Hex()})
		leaves = append(leaves, h)
	}
	root, proofs := orderbook.Tree(leaves)
	out.Bulk = BulkCase{Root: root.Hex(), Digest: orderbook.RootDigest(domain, root).Hex()}
	for i, leaf := range leaves {
		out.Bulk.Leaves = append(out.Bulk.Leaves, leaf.Hex())
		hexProof := []string{}
		for _, p := range proofs[i] {
			hexProof = append(hexProof, p.Hex())
		}
		out.Bulk.Proofs = append(out.Bulk.Proofs, hexProof)
	}
	return out
}

// buildForks pins the gas and wire forks. feeCfg is the fee-priced
// configuration the fee cases were computed against; here it also gets the
// fork heights, so every number below is what a chain past both activations
// produces from the same inputs.
func buildForks(feeCfg *rollup.Config, fee rollup.Fee) (*ForkSection, error) {
	cfg := *feeCfg
	cfg.Forks = &rollup.Forks{Gas: 2_000, Wire: 2_000}
	cfg.NativeFloorBP, cfg.NativeCeilBP = 2_500, 7_500
	cfg.MandatoryShareBP = 5_000
	cfg.FeeSplitter = rollup.FeeSplitterAddr

	out := &ForkSection{
		Note: "what each activation height changes. Every case below is computed against the fee section's " +
			"schedule, with the gas and wire forks at momentum 2,000.",
		GasFrom:  cfg.Forks.Gas,
		WireFrom: cfg.Forks.Wire,
		Share: ShareCase{
			GasLimit: cfg.GasLimit, NativeFloor: cfg.NativeFloor(), NativeCeil: cfg.NativeCeil(),
			RelayedCeil: cfg.GasLimit - cfg.NativeFloor(), NativeBefore: cfg.MaxNativeGasPerBlock,
		},
		BurnMagic: "0x" + hex.EncodeToString(rollup.BurnMagic),
	}

	// The boost: the same burn split between gas and priority.
	const boostTime = 1_788_991_540
	epoch := fee.EpochAt(boostTime)
	for _, c := range []struct {
		note  string
		burn  string
		boost int64
		gas   uint64
	}{
		{"no fifth item: the whole burn buys gas", "100000000", 0, 16_777_216},
		{"a quarter of the burn bought priority instead of gas", "100000000", 25_000_000, 16_777_216},
		{"the boost is what the lane is ordered by, in gas-equivalents", "100000000", 50_000_000, 16_777_216},
	} {
		call := derive.Call{To: &common.Address{}, Value: new(big.Int), Gas: c.gas}
		if c.boost > 0 {
			call.Boost = big.NewInt(c.boost)
		}
		amount, _ := new(big.Int).SetString(c.burn, 10)
		b := derive.QuoteBlock(len(derive.EncodeCall(call)))
		b.TokenStandard, b.Amount = znn.ZNN, znn.NewBigInt(amount)
		price := rollup.PriceOf(b)
		forFee := new(big.Int).Sub(amount, big.NewInt(c.boost))
		feeGas := fee.GasFor(forFee, znn.ZNN, epoch, price)
		out.Boost = append(out.Boost, BoostCase{
			Note: c.note, Encoded: hexs(derive.EncodeCall(call)), Burned: c.burn,
			Boost:  new(big.Int).SetInt64(c.boost).String(),
			FeeGas: feeGas, BoostGas: fee.GasFor(big.NewInt(c.boost), znn.ZNN, epoch, price),
			Gas: min(feeGas, min(b.UsedPlasma*cfg.GasPerPlasma, c.gas)),
		})
	}

	// The span layout, pinned before compression: brotli is a standard, and
	// what this protocol defines is the columns inside it. Two dev-key
	// transfers, so the chain id, gas price and gas limit columns repeat —
	// which is the whole point of the layout.
	var raws [][]byte
	signer := types.LatestSignerForChainID(cfg.L2ChainIDBig())
	for i := uint32(0); i < 2; i++ {
		to := common.BigToAddress(big.NewInt(int64(0xaa00 + i)))
		tx := types.MustSignNewTx(devnet.EVMKey(i), signer, &types.DynamicFeeTx{
			ChainID: cfg.L2ChainIDBig(), Nonce: uint64(i), GasTipCap: big.NewInt(1_000_000),
			GasFeeCap: big.NewInt(2_000_000_000), Gas: 21_000, To: &to, Value: big.NewInt(1_000_000_000_000_000),
		})
		raw, err := tx.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raws = append(raws, raw)
	}
	payload, decoded, err := derive.SpanVector(raws)
	if err != nil {
		return nil, err
	}
	out.Span = SpanCase{
		Note: "flag 0x03 is brotli over this payload: the transactions' fields column by column, " +
			"rebuilt and re-encoded by the decoder, which must reproduce them byte for byte",
		Payload: hexs(payload),
	}
	for _, raw := range decoded {
		out.Span.Txs = append(out.Span.Txs, hexs(raw))
	}

	// The derived fee split.
	relayers := []common.Address{
		common.Address(znn.MustDevWallet().Key(202).Address),
		common.Address(znn.MustDevWallet().Key(203).Address),
	}
	weights := []uint64{200_000, 100_000}
	out.FeeSplit = SplitCase{
		Splitter: rollup.FeeSplitterAddr.Hex(),
		Salt:     rollup.FeesSalt.Hex(),
		InitHash: crypto.Keccak256Hash(rollup.FeesArtifact.InitCode()).Hex(),
		Burn:     rollup.BurnAddr.Hex(),
		Momentum: 2_001, Relayers: []string{relayers[0].Hex(), relayers[1].Hex()}, Weights: weights,
		Calldata: hexs(derive.EncodeSettle(2_001, relayers, weights)),
		Gas:      rollup.FeeSettleGas(len(relayers)),
	}

	// Chunk gas: a chunk contributes the base plasma of its own NoM block.
	chunk := &derive.Chunk{Data: make([]byte, 16_383)}
	assemble := derive.EncodeAssemble([]znn.Hash{znn.Sha3([]byte("chunk-a")), znn.Sha3([]byte("chunk-b"))})
	assemblePlasma := znn.BaseSendPlasma(len(assemble))
	out.Chunk = ChunkCase{
		Note: "gas(assemble) = (plasma(assemble) + Σ plasma(chunk)) × gasPerPlasma, each chunk spent once; " +
			"a chunk's plasma is recomputed from its bytes, not read from a stored field",
		ChunkBytes: len(chunk.Data), ChunkPlasma: chunk.Plasma(), AssemblePl: assemblePlasma,
		GasBefore:    derive.NativeGas(&cfg, assemblePlasma, 0),
		GasAfterFork: derive.NativeGas(&cfg, assemblePlasma+2*chunk.Plasma(), 0),
	}
	return out, nil
}

func Write(path string) error {
	f, err := Build()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// Check compares the committed vectors against what the code produces now.
func Check(path string) error {
	want, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f, err := Build()
	if err != nil {
		return err
	}
	got, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		var a, b any
		json.Unmarshal(want, &a)
		json.Unmarshal(got, &b)
		return fmt.Errorf("%s does not match the current encodings — an encoding moved, or the vectors need regenerating with `zvm vectors -write`", path)
	}
	return nil
}
