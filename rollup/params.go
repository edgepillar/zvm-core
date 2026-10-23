// Package rollup holds what every ZVM node must agree on: the fixed protocol
// addresses and the per-chain configuration written at genesis.
package rollup

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

var (
	// Inbox is where NoM blocks carrying ZVM transactions are sent. Its type
	// byte (0x13) is one no key and no embedded contract can have, so ZNN sent
	// here is unspendable by anyone, the operator included.
	Inbox = znn.MustAddressFromBody("zvmxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

	// L1InfoDepositor is OP Stack's depositor account; the L1Block predeploy
	// accepts its setter only from this address.
	L1InfoDepositor = common.HexToAddress("0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001")
	// SystemDepositor sends the bridge's derived calls.
	SystemDepositor = common.HexToAddress("0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0002")

	L1BlockAddr       = common.HexToAddress("0x4200000000000000000000000000000000000015")
	SequencerFeeVault = common.HexToAddress("0x4200000000000000000000000000000000000011")
	BaseFeeVault      = common.HexToAddress("0x4200000000000000000000000000000000000019")
	L1FeeVault        = common.HexToAddress("0x420000000000000000000000000000000000001a")
	BridgeAddr        = common.HexToAddress("0x4200000000000000000000000000000000000100")
	QSRTokenAddr      = common.HexToAddress("0x4200000000000000000000000000000000000101")

	// ZNNScale converts NoM base units (8 decimals) to wei (18 decimals).
	ZNNScale = big.NewInt(10_000_000_000)

	// PayoutMagic prefixes the data of a vault send that pays a withdrawal:
	// "ZVMW" then the 32-byte withdrawal id.
	PayoutMagic = []byte("ZVMW")
)

const (
	// L1InfoGas is the gas of the first deposit in every block.
	L1InfoGas = 1_000_000
	// SystemGas is the gas of each derived bridge call.
	SystemGas = 250_000
	// DepositGas is the gas of a plain ZNN deposit (a mint and nothing else).
	DepositGas = 21_000

	// EIP7825MaxTxGas is Osaka's per-transaction gas cap, 2²⁴, which Karst
	// brings to the OP Stack. A chain on Karst cannot admit a transaction
	// declaring more, so its maxTxGas may not exceed this.
	EIP7825MaxTxGas = 16_777_216
)

// EVM fork lines this rollup can be configured for. The name selects the
// execution client's rules; it is written at genesis and never moves, because
// moving it is a re-derivation.
const (
	EVMIsthmus = "isthmus" // Prague EVM, op-geth or op-reth
	EVMKarst   = "karst"   // Osaka EVM, Jovian's minimum base fee: op-reth only
)

// Forks are this chain's own activation heights — momentum heights at which a
// derivation rule changes. Zero means the rule never activates, which is every
// chain derived before it existed.
//
// Two are defined (DECISIONS.md D7, D9, D10, D19, and *Still open*):
//
//   - **Gas**: `mine_boost` as a fifth item of a native call, the elastic
//     native share, chunk gas counting the whole payload with each chunk
//     consumed once, and the relayed fee split. All of them change what a
//     block contains, so they share one height and one re-derivation.
//   - **Wire**: brotli as compression flag 0x02 and span batches as 0x03. Both
//     are additive — old batches keep decoding — but a node that accepted them
//     early would build a block its peers would not.
//
// They may be set to the same height; nothing requires it.
type Forks struct {
	Gas  uint64 `json:"gas,omitempty"`
	Wire uint64 `json:"wire,omitempty"`
}

// GasActive reports whether the gas fork covers a momentum.
func (f *Forks) GasActive(momentum uint64) bool {
	return f != nil && f.Gas != 0 && momentum >= f.Gas
}

// GasScheduled reports whether the gas fork has a height at all — what a
// client asks before it offers a boost, since the chain, not the client,
// decides whether a five-item call is a call.
func (f *Forks) GasScheduled() bool { return f != nil && f.Gas != 0 }

// WireActive reports whether the wire fork covers a momentum.
func (f *Forks) WireActive(momentum uint64) bool {
	return f != nil && f.Wire != 0 && momentum >= f.Wire
}

// FeeMarket is one step of the fee-market schedule: from this momentum, these
// EIP-1559 parameters. It is a schedule rather than a single pair because
// parameters that are worth tuning are worth tuning twice, and the blocks built
// under the old ones still have to be re-derivable — a node syncing from
// genesis must reproduce each period exactly as it was.
type FeeMarket struct {
	Momentum    uint64 `json:"momentum"`
	Denominator uint32 `json:"denominator"`
	Elasticity  uint32 `json:"elasticity"`
	// MinBaseFee is Jovian's floor under the base fee from this momentum, in
	// wei. Zero keeps the previous entry's, or the chain's own MinBaseFee
	// before the schedule starts. On a chain that sits below its target the
	// floor *is* the price, so this is the number that decides what a relayed
	// transaction costs.
	MinBaseFee uint64 `json:"minBaseFee,omitempty"`
}

// Config is fixed at genesis and read by every service.
type Config struct {
	L1ChainID uint64      `json:"l1ChainId"`
	L2ChainID uint64      `json:"l2ChainId"`
	Inbox     znn.Address `json:"inbox"`
	Vault     znn.Address `json:"vault"`

	// L1StartHeight is the momentum that becomes L2 block 1. L2 block n
	// is momentum L1StartHeight+n-1.
	L1StartHeight uint64 `json:"l1StartHeight"`

	L2GenesisHash      common.Hash `json:"l2GenesisHash"`
	L2GenesisTimestamp uint64      `json:"l2GenesisTimestamp"`

	// GasLimit is every L2 block's gas limit. The deriver never forces more
	// gas (summed gas limits) than this into one block.
	GasLimit uint64 `json:"gasLimit"`
	// GasPerPlasma prices a native call's gas budget in the plasma its NoM
	// block paid.
	GasPerPlasma uint64 `json:"gasPerPlasma"`
	// MaxNativeGas caps one native call.
	MaxNativeGas uint64 `json:"maxNativeGas"`
	// MaxNativeGasPerBlock caps all native calls in one block, until the gas
	// fork replaces it with the elastic share below. Native calls pay no L2
	// gas — their plasma paid for them — so without a share they could fill
	// every block and price relayed users out through the base fee.
	MaxNativeGasPerBlock uint64 `json:"maxNativeGasPerBlock"`
	// NativeFloorBP and NativeCeilBP are D10's elastic share, in basis points
	// of the block gas limit, from the gas fork: the native lane always gets
	// the floor and may use up to the ceiling when relayed demand leaves room;
	// the relayed lane is guaranteed 1 − ceiling. 2500 and 7500 here.
	NativeFloorBP uint64 `json:"nativeFloorBp,omitempty"`
	NativeCeilBP  uint64 `json:"nativeCeilBp,omitempty"`
	// MandatoryShareBP caps, from the gas fork, how much of a block deposits,
	// payouts and burn mirrors may claim, in basis points of the gas limit.
	// What does not fit is deferred to the next block rather than forced into
	// this one (docs/HALT.md, path 6): without it, a momentum carrying more
	// mandatory messages than the block can hold stops every node at once, and
	// the number of such messages NoM admits is a parameter someone else sets.
	MandatoryShareBP uint64 `json:"mandatoryShareBp,omitempty"`
	// MaxTxGas caps one relayed transaction.
	MaxTxGas uint64 `json:"maxTxGas"`
	// MaxDepositCallGas caps a call carried by a deposit, from the fee rule's
	// activation height. A deposit's amount is bridged rather than burned, so
	// without a cap this would be the way to buy native gas for nothing.
	MaxDepositCallGas uint64 `json:"maxDepositCallGas,omitempty"`

	// ChunkTTL is how many momentums a chunk stays assemblable.
	ChunkTTL uint64 `json:"chunkTtl"`
	// MaxAssembledBytes bounds an assembled payload.
	MaxAssembledBytes int `json:"maxAssembledBytes"`
	// MaxBatchBytes bounds a decompressed batch.
	MaxBatchBytes int `json:"maxBatchBytes"`

	// FinalityDepth is how many momentums deep an L2 block must be before it
	// is labelled finalized (and the bridge pays withdrawals from it).
	FinalityDepth uint64 `json:"finalityDepth"`

	// Fee is the burned ZNN/QSR a native call may pay for gas, from an
	// activation height. Absent, or with fromHeight 0, a native call's gas is
	// its plasma alone. See fee.go.
	Fee *Fee `json:"fee,omitempty"`

	// Forks are this chain's own activation heights. See Forks.
	Forks *Forks `json:"forks,omitempty"`

	// FeeSplitter is where a relayed transaction's priority fee accrues and is
	// split, from the gas fork. It is the block's coinbase from that height, so
	// it is consensus; it is deployed with CREATE2 rather than at genesis, so
	// turning the fork on costs no new chain. See fees.go.
	FeeSplitter common.Address `json:"feeSplitter,omitempty"`

	// EVM names the execution rules this chain runs: "isthmus" (Prague) or
	// "karst" (Osaka, Jovian's minimum base fee — op-reth only). Empty means
	// isthmus, which is every chain written before the name existed.
	EVM string `json:"evm,omitempty"`
	// MinBaseFee is Jovian's floor under EIP-1559's base fee, in wei. Only
	// meaningful on karst; zero leaves the base fee to decay as before.
	MinBaseFee uint64 `json:"minBaseFee,omitempty"`

	// BridgeFee is what a withdrawal pays, written into ZVMBridge's storage at
	// genesis (D8). Absent means no fee.
	BridgeFee *BridgeFee `json:"bridgeFee,omitempty"`

	// FeeMarkets is this chain's own EIP-1559 parameters over time, oldest
	// first (D38). Genesis carries OP's Canyon values — a denominator of 250
	// chosen for two-second blocks, which on a chain deriving one block per
	// momentum damps the base fee about seven times too hard — and each entry
	// replaces them from its momentum.
	//
	//	base fee change per block = (gasUsed − target) / target / denominator
	//	target                    = gasLimit / elasticity
	//
	// Empty means the chain keeps what genesis said, forever.
	FeeMarkets []FeeMarket `json:"feeMarket,omitempty"`
}

// feeMarketAt is the schedule entry in force at a momentum, or nil before the
// first one.
func (c *Config) feeMarketAt(momentum uint64) *FeeMarket {
	var out *FeeMarket
	for i := range c.FeeMarkets {
		if c.FeeMarkets[i].Momentum > momentum {
			break
		}
		out = &c.FeeMarkets[i]
	}
	return out
}

// FeeMarketActive reports whether any of this chain's own parameters are in
// force at a momentum.
func (c *Config) FeeMarketActive(momentum uint64) bool { return c.feeMarketAt(momentum) != nil }

// FeeMarketFrom is the momentum the schedule starts at, or zero.
func (c *Config) FeeMarketFrom() uint64 {
	if len(c.FeeMarkets) == 0 {
		return 0
	}
	return c.FeeMarkets[0].Momentum
}

// FeeParams is the eight-byte EIP-1559 parameter block a payload carries from
// Holocene: denominator then elasticity, big-endian. All zero means the
// execution client keeps the chain config's own, which is what every block
// before forks.market says.
func (c *Config) FeeParams(momentum uint64) [8]byte {
	var out [8]byte
	m := c.feeMarketAt(momentum)
	if m == nil || m.Denominator == 0 || m.Elasticity == 0 {
		return out
	}
	binary.BigEndian.PutUint32(out[0:4], m.Denominator)
	binary.BigEndian.PutUint32(out[4:8], m.Elasticity)
	return out
}

// DefaultTipWei is what every sender in this tree offers as a priority fee:
// 100 gwei per gas. The base fee is burned — it lands in a vault with no code
// — so the tip is the only part of a relayed transaction that can reach the
// account buying the plasma, and a relayer may refuse anything below it
// (relayer.DefaultMinTipWei). The two are the same number on purpose.
const DefaultTipWei = 100_000_000_000

// DefaultTip is that figure as a fresh big.Int, since callers mutate theirs.
func DefaultTip() *big.Int { return big.NewInt(DefaultTipWei) }

// FeeCapBlocks is how many consecutive full blocks a suggested fee cap should
// survive. Four is a minute at this chain's cadence — long enough that a
// transaction caught by a burst still lands, short enough that the cap stays a
// recognisable number.
const FeeCapBlocks = 4

// feeCapCeiling bounds the headroom however aggressive the parameters are.
const feeCapCeiling = 64.0

// SuggestedFeeCap is a maxFeePerGas with room for the base fee to rise under
// *this* chain's parameters. The conventional 2× comes from Ethereum, where a
// full block raises the base fee 12.5 % and 2× therefore covers six blocks; a
// chain that lets the fee more than double in one block needs more, or every
// transaction signed just before a burst falls out and sits.
//
// A cap is a ceiling, not a price — the block charges base fee plus tip — so
// the only cost of headroom is the balance the sender must hold.
//
// It takes no height on purpose. The parameters are used whenever the chain
// has them configured, fork or no fork: before the height the cap is merely
// generous, which costs nothing, and callers do not have to know the momentum
// to sign a transaction.
func (c *Config) SuggestedFeeCap(baseFee, tip *big.Int) *big.Int {
	mult := 2.0
	// The last entry, not the sharpest ever scheduled: a retired period cannot
	// apply to a transaction being signed now, and letting it set the headroom
	// forever would make every cap carry the scars of a market the chain has
	// already left.
	if n := len(c.FeeMarkets); n > 0 {
		m := c.FeeMarkets[n-1]
		if el := uint64(m.Elasticity); el > 0 && m.Denominator > 0 && el <= c.GasLimit {
			target := c.GasLimit / el
			perBlock := 1 + float64(c.GasLimit-target)/float64(target)/float64(m.Denominator)
			mult = math.Pow(perBlock, FeeCapBlocks)
		}
	}
	mult = min(max(mult, 2), feeCapCeiling)
	capped, _ := new(big.Float).Mul(new(big.Float).SetInt(baseFee), big.NewFloat(mult)).Int(nil)
	return new(big.Int).Add(capped, tip)
}

// MinBaseFeeAt is the floor under the base fee at a momentum: the newest
// schedule entry that sets one, falling back to the chain's own.
func (c *Config) MinBaseFeeAt(momentum uint64) uint64 {
	out := c.MinBaseFee
	for i := range c.FeeMarkets {
		if c.FeeMarkets[i].Momentum > momentum {
			break
		}
		if c.FeeMarkets[i].MinBaseFee != 0 {
			out = c.FeeMarkets[i].MinBaseFee
		}
	}
	return out
}

// FeeTarget is the gas a block may use without moving the base fee.
func (c *Config) FeeTarget(momentum uint64) uint64 {
	m := c.feeMarketAt(momentum)
	if m == nil || m.Elasticity == 0 {
		return 0
	}
	return c.GasLimit / uint64(m.Elasticity)
}

// BridgeFee is Zenon's bridge FeePercentage in the same shape: a share of the
// amount in basis points of 10,000, and a floor per token in NoM base units so
// that a small withdrawal still pays for the plasma its payout uses.
type BridgeFee struct {
	BPS    uint64 `json:"bps"`
	MinZNN uint64 `json:"minZnn"`
	MinQSR uint64 `json:"minQsr"`
}

// Storage slots of ZVMBridge's fee parameters, checked against solc's storage
// layout by l2.TestBridgeFeeSlots.
const (
	BridgeSlotFeeBps    = 10
	BridgeSlotMinFeeZNN = 11
	BridgeSlotMinFeeQSR = 12
)

// IsKarst reports whether this chain runs the Osaka EVM and Jovian's rules.
func (c *Config) IsKarst() bool { return c.EVM == EVMKarst }

// NativeFloor and NativeCeil are the elastic share in gas, computed from the
// block gas limit. They are only consulted from the gas fork.
func (c *Config) NativeFloor() uint64 { return c.GasLimit / 10_000 * c.NativeFloorBP }
func (c *Config) NativeCeil() uint64  { return c.GasLimit / 10_000 * c.NativeCeilBP }

// MandatoryCap is the gas deposits, payouts and burn mirrors may reserve in one
// block from the gas fork. The L1 info deposit and the fee settle are outside
// it: both are bounded constants.
func (c *Config) MandatoryCap() uint64 { return c.GasLimit / 10_000 * c.MandatoryShareBP }

func (c *Config) L2ChainIDBig() *big.Int { return new(big.Int).SetUint64(c.L2ChainID) }

// L2BlockForMomentum maps a momentum height to the L2 block derived from it.
func (c *Config) L2BlockForMomentum(height uint64) uint64 {
	if height < c.L1StartHeight {
		return 0
	}
	return height - c.L1StartHeight + 1
}

// MomentumForL2Block is the inverse of L2BlockForMomentum.
func (c *Config) MomentumForL2Block(number uint64) uint64 {
	if number == 0 {
		return c.L1StartHeight - 1
	}
	return c.L1StartHeight + number - 1
}

// decodeConfigJSON accepts one complete value with no unknown struct fields.
// Custom decoders must use it too: DisallowUnknownFields does not inspect the
// object consumed by a nested UnmarshalJSON method.
func decodeConfigJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err != nil {
			return fmt.Errorf("trailing configuration data: %w", err)
		}
		return fmt.Errorf("trailing configuration value")
	}
	return nil
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := decodeConfigJSON(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.L1StartHeight == 0 || c.GasLimit == 0 || c.L2ChainID == 0 {
		return nil, fmt.Errorf("%s: incomplete rollup config", path)
	}
	if err := c.Fee.prepare(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Fee.Active(c.L1StartHeight) && c.MaxDepositCallGas == 0 {
		return nil, fmt.Errorf("%s: maxDepositCallGas is required once the fee rule is active", path)
	}
	if err := c.CheckForks(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// CheckForks refuses a configuration whose activation heights promise
// something the rest of the file cannot deliver. A node that started with one
// of these would derive a different chain from its peers at the fork height,
// which is the one failure this check exists to prevent.
func (c *Config) CheckForks() error {
	switch c.EVM {
	case "", EVMIsthmus, EVMKarst:
	default:
		return fmt.Errorf("evm %q: want %q or %q", c.EVM, EVMIsthmus, EVMKarst)
	}
	if c.IsKarst() && c.MaxTxGas > EIP7825MaxTxGas {
		return fmt.Errorf("maxTxGas %d is above EIP-7825's cap of %d, which karst enforces", c.MaxTxGas, EIP7825MaxTxGas)
	}
	if c.BridgeFee != nil && c.BridgeFee.BPS >= 10_000 {
		return fmt.Errorf("bridgeFee.bps %d would leave nothing to pay", c.BridgeFee.BPS)
	}
	for i, m := range c.FeeMarkets {
		if m.Momentum == 0 {
			return fmt.Errorf("feeMarket[%d] needs a momentum: the height it takes effect at", i)
		}
		if m.Denominator == 0 || m.Elasticity == 0 {
			return fmt.Errorf("feeMarket[%d] needs both denominator and elasticity", i)
		}
		// A zero denominator divides; an elasticity above the gas limit leaves a
		// target of zero, and a target of zero divides too. Both are rejected
		// here rather than discovered by the execution client mid-block.
		if uint64(m.Elasticity) > c.GasLimit {
			return fmt.Errorf("feeMarket[%d] elasticity %d is above the gas limit %d, which leaves no target", i, m.Elasticity, c.GasLimit)
		}
		// Ascending and distinct, or feeMarketAt would not describe the chain
		// that was built: every period has to be re-derivable exactly.
		if i > 0 && m.Momentum <= c.FeeMarkets[i-1].Momentum {
			return fmt.Errorf("feeMarket[%d] starts at %d, which is not after feeMarket[%d] at %d", i, m.Momentum, i-1, c.FeeMarkets[i-1].Momentum)
		}
	}
	if c.Forks == nil || c.Forks.Gas == 0 {
		return nil
	}
	if c.NativeFloorBP == 0 || c.NativeCeilBP == 0 {
		return fmt.Errorf("the gas fork needs nativeFloorBp and nativeCeilBp")
	}
	if c.NativeFloorBP > c.NativeCeilBP || c.NativeCeilBP > 10_000 {
		return fmt.Errorf("nativeFloorBp %d and nativeCeilBp %d must satisfy floor ≤ ceiling ≤ 10000", c.NativeFloorBP, c.NativeCeilBP)
	}
	if c.FeeSplitter == (common.Address{}) {
		return fmt.Errorf("the gas fork needs feeSplitter: the address the relayed fee is split at")
	}
	// Path 6's cap has to admit at least one message, or the queue never
	// drains, and together with the two bounded system calls it has to fit the
	// block, or it caps nothing.
	if c.MandatoryCap() < SystemGas {
		return fmt.Errorf("the gas fork needs mandatoryShareBp large enough for one mandatory message (%d gas); it gives %d", SystemGas, c.MandatoryCap())
	}
	if L1InfoGas+c.MandatoryCap()+FeeSettleGas(MaxFeeSplitAuthors) > c.GasLimit {
		return fmt.Errorf("mandatoryShareBp %d leaves no room for the L1 info deposit and the fee settle in a %d gas block", c.MandatoryShareBP, c.GasLimit)
	}
	// mine_boost is a share of the burn, and the split's burn side is the
	// other half of D9. A gas fork without the fee rule would accept a fifth
	// message item that buys nothing.
	if !c.Fee.Active(c.Forks.Gas) {
		return fmt.Errorf("the gas fork at momentum %d needs the burned fee active by then (fee.fromHeight is %d)",
			c.Forks.Gas, feeFrom(c.Fee))
	}
	return nil
}

func feeFrom(f *Fee) uint64 {
	if f == nil {
		return 0
	}
	return f.FromHeight
}
