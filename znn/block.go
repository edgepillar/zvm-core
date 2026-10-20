package znn

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"math/big"
)

const (
	BlockTypeGenesisReceive  = 1
	BlockTypeUserSend        = 2
	BlockTypeUserReceive     = 3
	BlockTypeContractSend    = 4
	BlockTypeContractReceive = 5

	// Plasma constants, from go-zenon vm/constants/plasma.go.
	AccountBlockBasePlasma   = 21000
	ByteDataPlasma           = 68
	EmbeddedSimplePlasma     = 52500
	PoWDifficultyPerPlasma   = 1500
	MaxDataLength            = 16 * 1024
	PlasmaPerFusionUnit      = 2100
	MaxFusionUnitsPerAccount = 5000
	MaxPoWPlasmaForBlock     = 94500

	// DPMaxFusionUnitsPerAccount is what dynamic plasma raises
	// MaxFusionUnitsPerAccount to: four orders of magnitude more, which is no
	// practical ceiling at all (dp/dp.go:24 against vm/constants/plasma.go:51).
	// Read it through MaxFusedAmountForAccount rather than picking one.
	DPMaxFusionUnitsPerAccount = 100_000_000

	// MaxAccountBlocksInMomentum is the v1 (pre-dynamic-plasma) momentum cap, a
	// count rather than a byte budget (chain/account_pool.go).
	MaxAccountBlocksInMomentum = 100

	// PriceScaleFactor is how go-zenon quotes a dynamic-plasma resource price:
	// 1000 is the minimum, an uncongested network (dp/dp.go:32).
	PriceScaleFactor = 1000
	// MaxDifficultyForAccountBlock is MaxPoWPlasmaForBlock × PoWDifficultyPerPlasma.
	MaxDifficultyForAccountBlock = MaxPoWPlasmaForBlock * PoWDifficultyPerPlasma
)

// OneZNN and OneQSR are 10^8 base units: both tokens have 8 decimals.
var (
	OneZNN = big.NewInt(100_000_000)
	OneQSR = big.NewInt(100_000_000)
)

// AccountBlock is go-zenon's account block in its RPC JSON shape. The last
// three fields are RPC decorations: present on reads, ignored on publish.
type AccountBlock struct {
	Version         uint64 `json:"version"`
	ChainIdentifier uint64 `json:"chainIdentifier"`
	BlockType       uint64 `json:"blockType"`

	Hash                 Hash       `json:"hash"`
	PreviousHash         Hash       `json:"previousHash"`
	Height               uint64     `json:"height"`
	MomentumAcknowledged HashHeight `json:"momentumAcknowledged"`

	Address       Address       `json:"address"`
	ToAddress     Address       `json:"toAddress"`
	Amount        *BigInt       `json:"amount"`
	TokenStandard TokenStandard `json:"tokenStandard"`

	FromBlockHash    Hash            `json:"fromBlockHash"`
	DescendantBlocks []*AccountBlock `json:"descendantBlocks"`
	Data             []byte          `json:"data"`

	FusedPlasma uint64 `json:"fusedPlasma"`
	Difficulty  uint64 `json:"difficulty"`
	Nonce       Nonce  `json:"nonce"`
	BasePlasma  uint64 `json:"basePlasma"`
	UsedPlasma  uint64 `json:"usedPlasma"`
	ChangesHash Hash   `json:"changesHash"`

	PublicKey []byte `json:"publicKey"`
	Signature []byte `json:"signature"`

	ConfirmationDetail *ConfirmationDetail `json:"confirmationDetail,omitempty"`
	PairedAccountBlock *AccountBlock       `json:"pairedAccountBlock,omitempty"`
}

type ConfirmationDetail struct {
	NumConfirmations  uint64 `json:"numConfirmations"`
	MomentumHeight    uint64 `json:"momentumHeight"`
	MomentumHash      Hash   `json:"momentumHash"`
	MomentumTimestamp uint64 `json:"momentumTimestamp"`
}

func (b *AccountBlock) IsSend() bool {
	return b.BlockType == BlockTypeUserSend || b.BlockType == BlockTypeContractSend
}

func (b *AccountBlock) AmountBig() *big.Int { return b.Amount.Big() }

// ComputeHash reproduces nom.AccountBlock.ComputeHash byte for byte
// (go-zenon chain/nom/account_block.go:180). BasePlasma, UsedPlasma,
// ChangesHash, PublicKey and Signature are not part of it.
func (b *AccountBlock) ComputeHash() Hash {
	var desc []byte
	for _, d := range b.DescendantBlocks {
		desc = append(desc, d.Hash[:]...)
	}
	amount := make([]byte, 32)
	if a := b.Amount.Big(); a.Sign() > 0 {
		a.FillBytes(amount)
	}
	buf := make([]byte, 0, 8*3+32+8+40+20+20+32+10+32+32+32+8+8+8)
	buf = binary.BigEndian.AppendUint64(buf, b.Version)
	buf = binary.BigEndian.AppendUint64(buf, b.ChainIdentifier)
	buf = binary.BigEndian.AppendUint64(buf, b.BlockType)
	buf = append(buf, b.PreviousHash[:]...)
	buf = binary.BigEndian.AppendUint64(buf, b.Height)
	buf = append(buf, b.MomentumAcknowledged.Bytes()...)
	buf = append(buf, b.Address[:]...)
	buf = append(buf, b.ToAddress[:]...)
	buf = append(buf, amount...)
	buf = append(buf, b.TokenStandard[:]...)
	buf = append(buf, b.FromBlockHash[:]...)
	descHash := Sha3(desc)
	buf = append(buf, descHash[:]...)
	dataHash := Sha3(b.Data)
	buf = append(buf, dataHash[:]...)
	buf = binary.BigEndian.AppendUint64(buf, b.FusedPlasma)
	buf = binary.BigEndian.AppendUint64(buf, b.Difficulty)
	buf = append(buf, b.Nonce[:]...)
	return Sha3(buf)
}

// Sign fixes the hash and signs it. Everything the hash covers must already be
// final, proof of work included.
func (b *AccountBlock) Sign(k *KeyPair) {
	b.Hash = b.ComputeHash()
	b.PublicKey = append([]byte(nil), k.Public...)
	b.Signature = k.Sign(b.Hash[:])
}

// Verify checks the hash, the signature, and that the key owns the address.
func (b *AccountBlock) Verify() error {
	if b.ComputeHash() != b.Hash {
		return errors.New("account block hash does not match its contents")
	}
	if len(b.PublicKey) != ed25519.PublicKeySize {
		return errors.New("account block has no public key")
	}
	if !ed25519.Verify(b.PublicKey, b.Hash[:], b.Signature) {
		return errors.New("account block signature does not verify")
	}
	if PubKeyToAddress(b.PublicKey) != b.Address {
		return errors.New("account block public key does not own its address")
	}
	return nil
}

// DifficultyToPlasma is the plasma a block's proof of work stands in for
// (go-zenon dp/dp.go:244).
func DifficultyToPlasma(difficulty uint64) uint64 {
	if difficulty == 0 {
		return 0
	}
	if difficulty > MaxDifficultyForAccountBlock {
		return MaxPoWPlasmaForBlock
	}
	return difficulty / PoWDifficultyPerPlasma
}

// BaseSendPlasma is the base plasma of a user send to a non-embedded address.
// Sends to embedded contracts are priced per method instead; ask the node.
func BaseSendPlasma(dataLen int) uint64 {
	return AccountBlockBasePlasma + ByteDataPlasma*uint64(dataLen)
}

// AccountHeader names a block inside momentum content.
type AccountHeader struct {
	Address Address `json:"address"`
	Hash    Hash    `json:"hash"`
	Height  uint64  `json:"height"`
}

// Momentum is a NoM momentum in RPC JSON shape. NextFusionPrice and
// NextWorkPrice exist only on version-2 (dynamic plasma) momentums.
type Momentum struct {
	Version         uint64          `json:"version"`
	ChainIdentifier uint64          `json:"chainIdentifier"`
	Hash            Hash            `json:"hash"`
	PreviousHash    Hash            `json:"previousHash"`
	Height          uint64          `json:"height"`
	Timestamp       uint64          `json:"timestamp"`
	Data            []byte          `json:"data"`
	Content         []AccountHeader `json:"content"`
	ChangesHash     Hash            `json:"changesHash"`
	PublicKey       []byte          `json:"publicKey"`
	Signature       []byte          `json:"signature"`
	Producer        Address         `json:"producer"`
	NextFusionPrice *uint64         `json:"nextFusionPrice,omitempty"`
	NextWorkPrice   *uint64         `json:"nextWorkPrice,omitempty"`
}

// FusionPrice is the price a block must meet to be admitted, in units of
// PriceScaleFactor. A momentum from a network without the dynamic-plasma spork
// carries no price at all, and a v2 momentum never goes below the minimum — so
// both answer 1000, and one formula covers both rulesets.
func (m *Momentum) FusionPrice() uint64 {
	if m == nil || m.NextFusionPrice == nil || *m.NextFusionPrice < PriceScaleFactor {
		return PriceScaleFactor
	}
	return *m.NextFusionPrice
}

// DynamicPlasma reports whether the momentum was produced under the
// dynamic-plasma ruleset. Version 2 is what go-zenon stamps once the spork is
// enforced, and it is the only signal a client gets: the spork itself is not
// visible on the momentum.
func (m *Momentum) DynamicPlasma() bool { return m != nil && m.Version >= 2 }

// MaxFusedAmountForAccount is the most QSR that usefully fuses to one account
// under the ruleset the momentum was produced by. Anything above it is accepted
// and simply buys no further plasma.
//
// This is deliberately not a constant. Under mainnet's rules the ceiling is
// 5,000 QSR (10,500,000 plasma); dynamic plasma raises go-zenon's own constant
// to DPMaxFusionUnitsPerAccount, so on such a network there is effectively no
// ceiling at all — measured 2026-09-17 on the shared devnet, one account held
// 10,300 QSR fused for 21,630,000 plasma, twice what v1 permits. Code that
// hardcodes the v1 figure concludes that a perfectly ordinary account is
// already at the ceiling.
func MaxFusedAmountForAccount(m *Momentum) *big.Int {
	units := int64(MaxFusionUnitsPerAccount)
	if m.DynamicPlasma() {
		units = DPMaxFusionUnitsPerAccount
	}
	return new(big.Int).Mul(big.NewInt(units), OneQSR)
}

// RequiredFusedPlasma is ceil(base × price / PriceScaleFactor): what go-zenon's
// dp.ValidPrice demands of a block that pays in fused plasma alone. On a v1
// network the price is the minimum and this is exactly base.
//
// Paying less is the wedge in zenon-docs/protocol/facts/plasma-wedging.md: the
// block is not rejected outright, it sits unconfirmed and freezes the account
// until the price decays back to it.
func RequiredFusedPlasma(base, price uint64) uint64 {
	if price <= PriceScaleFactor {
		return base
	}
	v := new(big.Int).Mul(new(big.Int).SetUint64(base), new(big.Int).SetUint64(price))
	v.Add(v, big.NewInt(PriceScaleFactor-1))
	v.Div(v, big.NewInt(PriceScaleFactor))
	if !v.IsUint64() {
		return ^uint64(0)
	}
	return v.Uint64()
}

// DetailedMomentum pairs a momentum with its account blocks. Blocks is
// index-parallel to Momentum.Content.
type DetailedMomentum struct {
	Blocks   []*AccountBlock `json:"blocks"`
	Momentum *Momentum       `json:"momentum"`
}
