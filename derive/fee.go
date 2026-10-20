package derive

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// The publishing half of the burned fee (rollup/fee.go, DECISIONS.md D9).
//
// Once the rule is active, a native call's gas is the lesser of what its
// plasma bought and what the ZNN or QSR it sent to the inbox bought. That makes
// every publisher — this CLI, the browser, the faucet, the benchmark — a payer,
// and a publisher that was not taught to pay keeps producing blocks the chain
// accepts and derives to a call with no gas. zenoglyphs shipped exactly that
// bug on its own activation day (its faucet), which is why the quote lives
// here rather than in each caller.

// FeeMarginBP is how much more than the quote a publisher burns, in basis
// points. The fee depends on the epoch of the momentum that *includes* the
// block, which a publisher cannot know: it quotes against the frontier. An
// epoch boundary between quote and inclusion raises supply by one day's
// emission (about 0.03 % of ZNN), and there are no refunds, so a small margin
// is cheaper than a call that lands one block short of its gas.
const FeeMarginBP = 50 // 0.5 %

// FeePayer quotes the burn for one native call. Gas is the call's declared gas
// limit: with the fee rule on, choosing the fee *is* choosing the gas limit, so
// a publisher must name it rather than take what its plasma allows.
type FeePayer struct {
	Cfg   *rollup.Config
	Token znn.TokenStandard
	Gas   uint64
	// Boost is added to the burn on top of what the gas costs. It buys
	// admission priority rather than gas (D7), so it is not part of the quote
	// — but it does have to be in the block's amount, or derivation reads a
	// boost larger than the burn and refuses the message.
	Boost *big.Int
}

// Hook is the znn.FeeFunc that pays for a call (0x01) or for the assemble that
// completes one (0x04), and never for a chunk, a batch, or a send anywhere but
// the inbox.
func (f FeePayer) Hook() znn.FeeFunc {
	return func(b *znn.AccountBlock, frontier *znn.Momentum) (*big.Int, znn.TokenStandard) {
		if b.ToAddress != f.Cfg.Inbox || len(b.Data) == 0 || frontier == nil {
			return nil, znn.ZeroTokenStandard
		}
		switch b.Data[0] {
		case MsgCall, MsgAssemble:
		default:
			return nil, znn.ZeroTokenStandard
		}
		// The block lands in the next momentum at the earliest.
		if !f.Cfg.Fee.Active(frontier.Height + 1) {
			return nil, znn.ZeroTokenStandard
		}
		quote := FeeQuote(f.Cfg, f.Token, f.Gas, frontier, b)
		if f.Boost != nil && f.Boost.Sign() > 0 {
			quote = new(big.Int).Add(quote, f.Boost)
		}
		return quote, f.Token
	}
}

// FeeQuote is what a block must burn to buy gas, with the margin.
func FeeQuote(cfg *rollup.Config, token znn.TokenStandard, gas uint64, frontier *znn.Momentum, b *znn.AccountBlock) *big.Int {
	cost := cfg.Fee.Cost(gas, token, cfg.Fee.EpochAt(int64(frontier.Timestamp)), rollup.PriceOf(b))
	margin := new(big.Int).Mul(cost, big.NewInt(FeeMarginBP))
	return cost.Add(cost, margin.Div(margin, big.NewInt(10_000)))
}

// QuoteBlock is the block a quote is made against: only its data length and
// the plasma it will pay matter, so a caller that has not built one yet can
// ask for a price with this.
func QuoteBlock(dataLen int) *znn.AccountBlock {
	base := znn.BaseSendPlasma(dataLen)
	return &znn.AccountBlock{Data: make([]byte, dataLen), FusedPlasma: base, BasePlasma: base, UsedPlasma: base}
}

// NativeGasAt is the whole gas rule for a call published to the inbox in block
// b, derived by momentum m: the plasma bound, the burn bound once the rule is
// active, the per-call cap, and what the call asked for.
func NativeGasAt(cfg *rollup.Config, m *znn.Momentum, b *znn.AccountBlock, requested uint64) uint64 {
	gas := NativeGas(cfg, b.UsedPlasma, requested)
	if !cfg.Fee.Active(m.Height) {
		return gas
	}
	feeGas := cfg.Fee.GasFor(b.AmountBig(), b.TokenStandard, cfg.Fee.EpochAt(int64(m.Timestamp)), rollup.PriceOf(b))
	if feeGas < gas {
		return feeGas
	}
	return gas
}

// PublishCall publishes a native call and pays its fee, splitting it into
// chunks and an assemble when it does not fit one NoM block. It returns the
// carrier block — the assemble, when there was one — and the transaction the
// call derives to.
//
// Every publisher goes through here, so that turning the fee rule on does not
// leave one of them quietly publishing calls with no gas.
func PublishCall(ctx context.Context, cfg *rollup.Config, acct *znn.Account, token znn.TokenStandard, c Call) (*znn.AccountBlock, *types.Transaction, error) {
	msg := EncodeCall(c)
	return PublishMessage(ctx, cfg, acct, token, msg, c)
}

// PublishMessage is PublishCall for a message already encoded — a test
// publishing exact bytes, say. c must describe what msg contains.
func PublishMessage(ctx context.Context, cfg *rollup.Config, acct *znn.Account, token znn.TokenStandard, msg []byte, c Call) (*znn.AccountBlock, *types.Transaction, error) {
	payer := FeePayer{Cfg: cfg, Token: token, Gas: c.Gas, Boost: c.Boost}
	if cfg.Fee != nil && cfg.Fee.FromHeight != 0 && c.Gas == 0 {
		return nil, nil, fmt.Errorf("this chain prices native calls in burned %s, so a call must declare its gas", token)
	}
	var carrier *znn.AccountBlock
	var err error
	if len(msg) <= znn.MaxDataLength {
		carrier, err = acct.SendFee(ctx, cfg.Inbox, znn.ZeroTokenStandard, new(big.Int), msg, payer.Hook())
		if err != nil {
			return nil, nil, err
		}
	} else {
		var hashes []znn.Hash
		for _, chunk := range SplitChunks(msg) {
			b, err := acct.Send(ctx, cfg.Inbox, znn.ZeroTokenStandard, new(big.Int), chunk)
			if err != nil {
				return nil, nil, fmt.Errorf("chunk %d: %w", len(hashes), err)
			}
			hashes = append(hashes, b.Hash)
		}
		// Only the assemble pays: it is the block the call derives from.
		carrier, err = acct.SendFee(ctx, cfg.Inbox, znn.ZeroTokenStandard, new(big.Int), EncodeAssemble(hashes), payer.Hook())
		if err != nil {
			return nil, nil, fmt.Errorf("assemble: %w", err)
		}
	}
	return carrier, NativeTx(cfg, carrier, c), nil
}
