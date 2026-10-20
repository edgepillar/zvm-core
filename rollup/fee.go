package rollup

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// The burned fee for native calls (DECISIONS.md D9).
//
// A native call pays nothing on the ZVM: its gas is what its NoM block's plasma
// bought. Plasma stops compute being free but does not price it — plasma is
// rented with fused QSR and costs nothing to use. This adds a price: the call
// may also destroy ZNN or QSR, and the gas it gets is the lesser of what its
// plasma allows and what its burn bought.
//
//	gas = min( usedPlasma × gasPerPlasma ,      the byte bound, unchanged
//	           gasFor(amount, token, epoch) ,   what the burn bought
//	           maxNativeGas , requested )
//
// **The burn needs no burn address.** The inbox's type byte (0x13) is one no
// key and no embedded contract can produce, so value sent to it is already
// unspendable by everyone, the operator included (D5). The fee is simply the
// carrier block's own amount, which derivation ignored until now.
//
// The arithmetic is zenoglyphs' (projects/zenoglyphs/internal/evm/fee.go, live
// on its devnet since momentum 55,100; the design is that project's
// research/evm-fee-design.md). Two properties shape all of it:
//
//   - **Determinism.** Two nodes deriving the same momentum years apart, offline,
//     must charge the same fee, so the price cannot come from an oracle, a pool
//     or any observed value. It comes from NoM's published emission schedule,
//     which is a pure function of the momentum's timestamp. No floats anywhere.
//
//   - **No exchange rate.** Each token's fee is the same fraction of *its own*
//     supply, so the ZNN:QSR ratio is emergent rather than configured. There is
//     no rate to keep in sync, and nothing to get wrong when it moves.
//
// What follows from that, and is worth knowing before turning it on: users pay
// in whichever token the formula overprices relative to the market, so this
// burns the cheaper of the two rather than both.

// Emission, mirrored from go-zenon vm/constants/embedded.go. Mirrored rather
// than imported because a node must compute a fee from a momentum alone.
// If go-zenon changes these, the fee schedule changes with them, and that is a
// consensus event for this chain rather than a silent follow.
const (
	// EpochSeconds is consensus.EpochDuration: an epoch is a day, and the
	// reward schedule is indexed by epoch, derived from the timestamp.
	EpochSeconds int64 = 24 * 60 * 60
	// RewardTickEpochs is constants.RewardTickDurationInEpochs.
	RewardTickEpochs uint64 = 30

	tokenDecimals     int64 = 100_000_000
	momentumsPerEpoch int64 = 3600 / 10 * 24 // 8640
)

// Past the end of each table the last entry repeats forever, so both tokens
// inflate perpetually and neither is capped.
var (
	znnRewardPerEpoch = []int64{
		10 * momentumsPerEpoch / 6 * tokenDecimals,
		6 * momentumsPerEpoch / 6 * tokenDecimals,
		5 * momentumsPerEpoch / 6 * tokenDecimals,
		7 * momentumsPerEpoch / 6 * tokenDecimals,
		5 * momentumsPerEpoch / 6 * tokenDecimals,
		4 * momentumsPerEpoch / 6 * tokenDecimals,
		7 * momentumsPerEpoch / 6 * tokenDecimals,
		4 * momentumsPerEpoch / 6 * tokenDecimals,
		3 * momentumsPerEpoch / 6 * tokenDecimals,
		7 * momentumsPerEpoch / 6 * tokenDecimals,
		3 * momentumsPerEpoch / 6 * tokenDecimals, // tail: 4,320 ZNN/epoch
	}
	qsrRewardPerEpoch = []int64{
		20000 * tokenDecimals,
		20000 * tokenDecimals,
		20000 * tokenDecimals,
		20000 * tokenDecimals,
		15000 * tokenDecimals,
		15000 * tokenDecimals,
		15000 * tokenDecimals,
		5000 * tokenDecimals, // tail: 5,000 QSR/epoch
	}
)

// DefaultGasPerSupply is the one policy knob: the gas the entire supply of a
// token buys if it were all burned. Dimensionless, so the fee stays the same
// fraction of supply while supply inflates — a fee fixed in coins would get
// cheaper in real terms every year.
//
// **Measured on this engine, 2026-09-16.** zenoglyphs picked 1.37e14 against
// ~55,000 gas/ms of node CPU, measured on its own interpreter; that was never a
// measurement of op-geth, and D9 left it as the last consensus value in the fee
// rule taken on trust. Over 6,432 derived momentums on chain 70 — 27.2 billion
// gas in 666 s of build time — the loaded blocks (≥ 1 M gas, 517 of them) built
// at **46,088 gas/ms**, and the busiest band (> 50 M gas, 207 blocks) at 47,654.
//
// That figure is the whole derivation step, not `evm.Call` alone: building the
// payload, executing it, hashing it, committing it and recording it. That is
// deliberate — what a node operator pays for is the derive loop, not the
// interpreter inside it — and it is why the number is lower than an
// EVM-only benchmark would report.
//
// Holding zenoglyphs' intent (the whole supply buys about 29 days of compute)
// at the measured rate gives 46,088 × 29 × 86,400 × 1000 ≈ 1.15e14. So the
// default drops from 1.37e14 to 1.15e14, which makes gas about 19 % dearer in
// ZNN than zenoglyphs' calibration would have. On mainnet's supply that is
// ~1.2e-7 ZNN per gas: an ERC-20 transfer costs about 0.0015 ZNN.
//
// A chain that has already written a `fee.gasPerSupply` keeps it; this is the
// default for the next genesis.
const DefaultGasPerSupply int64 = 115_000_000_000_000

// Fee is the per-chain part of the rule, written in rollup.json. The supply
// anchor is a consensus value: every node must use the same one or they compute
// different budgets and build different blocks.
//
// FromHeight 0 means the rule is off and a native call's gas is its plasma
// alone — which is every chain derived before this existed.
type Fee struct {
	FromHeight       uint64 `json:"fromHeight"`
	GasPerSupply     int64  `json:"gasPerSupply"`
	GenesisTimestamp int64  `json:"genesisTimestamp"`
	RefEpoch         uint64 `json:"refEpoch"`
	RefZNN           string `json:"refZnn"`
	RefQSR           string `json:"refQsr"`

	refZNN, refQSR *big.Int
}

// MainnetSupplyAnchor is NoM mainnet's supply, read from node.zenonhub.io at
// momentum 14,154,189 on 2026-09-09 (epoch 1750). Kept here so a mainnet
// config is written from a checked constant rather than retyped.
var MainnetSupplyAnchor = Fee{
	GasPerSupply:     DefaultGasPerSupply,
	GenesisTimestamp: 1637755200, // 2021-11-24 12:00 UTC
	RefEpoch:         1750,
	RefZNN:           "1366728966519283",
	RefQSR:           "3118999966129297",
}

// Check validates and derives the big.Int anchors; exported for tools that
// build a Fee rather than load one.
func (f *Fee) Check() error { return f.prepare() }

func (f *Fee) prepare() error {
	if f == nil || f.FromHeight == 0 {
		return nil
	}
	if f.GasPerSupply <= 0 {
		return fmt.Errorf("fee: gasPerSupply must be positive")
	}
	if f.GenesisTimestamp <= 0 {
		return fmt.Errorf("fee: genesisTimestamp is required")
	}
	var ok bool
	if f.refZNN, ok = new(big.Int).SetString(f.RefZNN, 10); !ok || f.refZNN.Sign() <= 0 {
		return fmt.Errorf("fee: refZnn %q is not a positive integer", f.RefZNN)
	}
	if f.refQSR, ok = new(big.Int).SetString(f.RefQSR, 10); !ok || f.refQSR.Sign() <= 0 {
		return fmt.Errorf("fee: refQsr %q is not a positive integer", f.RefQSR)
	}
	return nil
}

// Active reports whether a momentum is at or past the activation height.
func (f *Fee) Active(momentum uint64) bool {
	return f != nil && f.FromHeight != 0 && momentum >= f.FromHeight
}

// EpochAt is the epoch a momentum timestamp falls in. go-zenon derives the
// epoch from the timestamp, not the height, so this needs nothing else.
func (f *Fee) EpochAt(unixSeconds int64) uint64 {
	if unixSeconds <= f.GenesisTimestamp {
		return 0
	}
	return uint64((unixSeconds - f.GenesisTimestamp) / EpochSeconds)
}

// SupplyAt is the declared supply at an epoch, in NoM base units.
//
// Declared, not observed: real supply also moves by sinks the schedule does not
// model (the 1 ZNN issuance fee, accelerator flows), and a fee that tracked
// actual supply would need archive state and would drift between
// implementations. Declaring the curve makes it exact by definition and
// identical everywhere, while tracking reality closely because emission
// dominates.
func (f *Fee) SupplyAt(epoch uint64) (znnSupply, qsrSupply *big.Int) {
	znnSupply = new(big.Int).Set(f.refZNN)
	qsrSupply = new(big.Int).Set(f.refQSR)
	if epoch <= f.RefEpoch {
		return znnSupply, qsrSupply
	}
	znnSupply.Add(znnSupply, sumRewards(f.RefEpoch, epoch, znnRewardPerEpoch))
	qsrSupply.Add(qsrSupply, sumRewards(f.RefEpoch, epoch, qsrRewardPerEpoch))
	return znnSupply, qsrSupply
}

// sumRewards totals a schedule over [from, to). The tail is closed-form: past
// the last table entry the rate never changes again, so an epoch thousands of
// ticks out costs the same work as one near genesis.
func sumRewards(from, to uint64, schedule []int64) *big.Int {
	total := new(big.Int)
	if to <= from || len(schedule) == 0 {
		return total
	}
	tailStart := uint64(len(schedule)-1) * RewardTickEpochs
	for e := from; e < to && e < tailStart; e++ {
		total.Add(total, big.NewInt(schedule[e/RewardTickEpochs]))
	}
	lo := from
	if tailStart > lo {
		lo = tailStart
	}
	if to > lo {
		n := new(big.Int).SetUint64(to - lo)
		total.Add(total, n.Mul(n, big.NewInt(schedule[len(schedule)-1])))
	}
	return total
}

// supplyOf is the supply behind a token standard. An unknown one has none and
// so buys no gas, which is the safe direction: a fee paid in some other ZTS is
// worth nothing rather than worth something.
func (f *Fee) supplyOf(zts znn.TokenStandard, epoch uint64) *big.Int {
	znnSupply, qsrSupply := f.SupplyAt(epoch)
	switch zts {
	case znn.ZNN:
		return znnSupply
	case znn.QSR:
		return qsrSupply
	default:
		return new(big.Int)
	}
}

// Price is the congestion multiplier for one block, held as the exact rational
// Paid/Base rather than as a rounded price.
//
// **It is read off the carrier block, not off the momentum header.** Under
// dynamic plasma a block must pay ceil(basePlasma × fusionPrice / 1000) of
// fused plasma, or the proof-of-work equivalent, or a mix — so the ratio of
// what a block paid to what its bytes nominally cost already is the price it
// met. Both numbers are committed by the block hash, mixed payment needs no
// rule, and a node holding the block needs nothing else.
//
// Floored at 1, which is why the rule needs no separate activation for the fee
// market: on a v1 momentum, and on an uncongested v2 one, it is exactly 1.
// Overpaying plasma raises the multiplier and so raises the payer's own fee, so
// it can be pushed up only by its payer, never ground down.
type Price struct {
	Base uint64 // nominal plasma for the block's bytes: 21000 + 68n
	Paid uint64 // fused plasma, plus the plasma its proof of work stood in for
}

// PriceOf reads the multiplier off a block's hashed plasma fields. Base is
// recomputed from the data length rather than read from the block, because
// basePlasma is not part of the block hash.
func PriceOf(b *znn.AccountBlock) Price {
	return Price{Base: znn.BaseSendPlasma(len(b.Data)), Paid: b.FusedPlasma + znn.DifficultyToPlasma(b.Difficulty)}
}

func (p Price) ratio() (num, den uint64) {
	if p.Base == 0 || p.Paid <= p.Base {
		return 1, 1
	}
	return p.Paid, p.Base
}

// Scaled is the multiplier the way go-zenon quotes a resource price: 1000 is an
// uncongested network, 2500 is 2.5×. For display only.
func (p Price) Scaled() uint64 {
	num, den := p.ratio()
	return num * znn.PriceScaleFactor / den
}

// Cost is what gas costs, in base units of zts, rounded up so that no gas is
// ever free through truncation.
func (f *Fee) Cost(gas uint64, zts znn.TokenStandard, epoch uint64, price Price) *big.Int {
	supply := f.supplyOf(zts, epoch)
	if supply.Sign() == 0 || gas == 0 {
		return new(big.Int)
	}
	num, den := price.ratio()
	n := new(big.Int).Mul(new(big.Int).SetUint64(gas), supply)
	n.Mul(n, new(big.Int).SetUint64(num))
	d := new(big.Int).Mul(big.NewInt(f.GasPerSupply), new(big.Int).SetUint64(den))
	q, r := new(big.Int).QuoRem(n, d, new(big.Int))
	if r.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

// GasFor is the inverse: the gas a burned amount buys, rounded down. The pair
// must never let a caller extract more gas than they paid for.
func (f *Fee) GasFor(amount *big.Int, zts znn.TokenStandard, epoch uint64, price Price) uint64 {
	supply := f.supplyOf(zts, epoch)
	if amount == nil || amount.Sign() <= 0 || supply.Sign() == 0 {
		return 0
	}
	num, den := price.ratio()
	gas := new(big.Int).Mul(amount, big.NewInt(f.GasPerSupply))
	gas.Mul(gas, new(big.Int).SetUint64(den))
	gas.Quo(gas, new(big.Int).Mul(supply, new(big.Int).SetUint64(num)))
	if !gas.IsUint64() {
		return ^uint64(0) // saturate; the caller's own caps still apply
	}
	return gas.Uint64()
}

// UnmarshalJSON keeps the derived big.Ints in step with the file.
func (f *Fee) UnmarshalJSON(b []byte) error {
	type raw Fee
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*f = Fee(r)
	return f.prepare()
}
