package derive

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/Zenoglyphs-VM/zvm-core/l2"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Message kinds and statuses, as recorded per NoM block.
const (
	KindCall     = "call"
	KindBatch    = "batch"
	KindChunk    = "chunk"
	KindAssemble = "assemble"
	KindDeposit  = "deposit"
	KindPayout   = "payout"
	KindBurn     = "burn"
	KindFuse     = "fuse"

	StatusIncluded = "included" // produced at least one transaction
	StatusStored   = "stored"   // a chunk, kept for a later assemble
	StatusDropped  = "dropped"  // valid, but did not fit (or every tx failed)
	StatusInvalid  = "invalid"  // malformed; ignored by every node
	StatusIgnored  = "ignored"  // not a ZVM message (e.g. an unsupported token)
	// StatusDeferred is a deposit, payout or burn mirror the block had no room
	// for. It is carried to the next block, never dropped (docs/HALT.md, path 6).
	StatusDeferred = "deferred"
)

// Transaction lanes.
const (
	LaneSystem  = "system"
	LaneNative  = "native"
	LaneDeposit = "deposit"
	LaneBatch   = "batch"
	LaneFees    = "fees"
)

// Chunk is a chunk message as the chunk store keeps it.
type Chunk struct {
	Hash   znn.Hash
	Author znn.Address
	Height uint64
	Data   []byte
	// Consumed is set by the source when an earlier assemble already spent
	// this chunk. From the gas fork a chunk may be assembled once, so that
	// publishing chunks and assembling them twice cannot buy the gas twice.
	Consumed bool
}

// Plasma is what this chunk's own NoM block cost: 21000 + 68 × (1 + bytes),
// recomputed from the stored bytes rather than read from a field, so that a
// node that kept the chunk before this rule existed reaches the same number as
// one re-deriving today.
func (c *Chunk) Plasma() uint64 { return znn.BaseSendPlasma(len(c.Data) + 1) }

// ChunkSource resolves chunks published in earlier momentums. A missing chunk
// returns (nil, false, nil); storage and decoding failures return an error.
// Operational failures must stop derivation, never classify a message invalid.
type ChunkSource interface {
	Chunk(hash znn.Hash) (*Chunk, bool, error)
}

// DeferredBlock is a mandatory message an earlier momentum had no room for.
type DeferredBlock struct {
	Block *znn.AccountBlock
	// From is the momentum that carried it and Index its place there; the
	// queue is released in that order.
	From  uint64
	Index int
}

// DeferralSource is the queue of mandatory messages earlier momentums deferred
// and no later one has released yet, oldest first. A ChunkSource that also
// implements it — the node's store does — is asked for it from the gas fork.
// Like the chunk store, it is a function of the momentums before this one, so
// every node sees the same queue.
type DeferralSource interface {
	Deferred(before uint64) ([]*DeferredBlock, error)
}

// Message is the outcome of one NoM block that the derivation looked at.
type Message struct {
	NomHash znn.Hash      `json:"nomHash"`
	Author  znn.Address   `json:"author"`
	Index   int           `json:"index"`
	Kind    string        `json:"kind"`
	Status  string        `json:"status"`
	Reason  string        `json:"reason,omitempty"`
	Bytes   int           `json:"bytes"`
	Plasma  uint64        `json:"plasma"`
	Token   string        `json:"token,omitempty"`
	Amount  string        `json:"amount,omitempty"`
	Txs     []common.Hash `json:"txs,omitempty"`
	Dropped []TxDrop      `json:"dropped,omitempty"`

	// Burned is the ZNN or QSR this block sent to the inbox, which nobody can
	// spend, and FeeGas is the gas it bought at the momentum's price. Set only
	// once the fee rule is active.
	Burned    string `json:"burned,omitempty"`
	BurnToken string `json:"burnToken,omitempty"`
	FeeGas    uint64 `json:"feeGas,omitempty"`
	FeePrice  uint64 `json:"feePrice,omitempty"`

	// Boost is the part of the burn that bought admission priority rather than
	// gas, and BoostGas what it is worth in gas — what the native lane is
	// ordered by when it is over-subscribed. From the gas fork.
	Boost    string `json:"boost,omitempty"`
	BoostGas uint64 `json:"boostGas,omitempty"`

	// DeferredFrom is the momentum this message arrived in, when an earlier
	// block had no room for it and this one is where it was finally applied.
	DeferredFrom uint64 `json:"deferredFrom,omitempty"`
}

// TxDrop records a transaction a message carried that did not make the block.
type TxDrop struct {
	Hash   common.Hash `json:"hash"`
	Reason string      `json:"reason"`
}

// PlannedTx is one transaction in block order.
type PlannedTx struct {
	Tx        *types.Transaction
	Lane      string
	Message   int // index into Plan.Messages, -1 for the L1 info deposit
	Mandatory bool
	// Order is the transaction's place in the block: NoM content order, the L1
	// info deposit first and the fee settle last. From the gas fork admission
	// runs out of content order — the native lane is taken in boost order — so
	// the list is sorted by this before the engine sees it.
	Order int
}

// Plan is everything one momentum contributes to its L2 block.
type Plan struct {
	Momentum  *znn.Momentum
	Txs       []*PlannedTx
	Messages  []*Message
	NewChunks []*Chunk
	// UsedChunks are the chunks the assembles in this momentum spent. The
	// store marks them, and a later assemble naming one is invalid.
	UsedChunks []znn.Hash
	// Deferred are this momentum's mandatory messages that did not fit, and
	// Released the earlier ones this block finally applied. The store queues
	// the first and marks the second.
	Deferred []*DeferredBlock
	Released []znn.Hash

	cfg       *rollup.Config
	gas       uint64 // summed gas limits of Txs
	reserved  uint64 // gas still reserved for mandatory txs not yet added
	nativeGas uint64
	batchGas  uint64
	order     int
	gasFork   bool
	wireFork  bool
	seen      map[common.Hash]bool
	local     map[znn.Hash]*Chunk
	claimed   map[znn.Hash]bool
	chunks    ChunkSource

	pendingNative  []*nativeCand
	pendingRelayed []*relayedCand
	chunkClaims    []*chunkClaim
	settleReserve  uint64
	settle         *PlannedTx
}

// chunkClaim is an assemble that named chunks and what became of it. The
// chunks are spent only if the assemble produced something, so an assemble the
// block had no room for leaves them for the next momentum.
type chunkClaim struct {
	msg    *Message
	chunks []znn.Hash
}

// nativeCand is a native call that has been decoded and priced but not yet
// admitted. From the gas fork the native lane gets a pass of its own, ordered
// by boost, so where a call sits in the block and whether it is in the block
// stop being the same question.
type nativeCand struct {
	msg     *Message
	tx      *types.Transaction
	lane    string
	gas     uint64
	boost   uint64
	order   int
	replace int // index into Txs of the mint-only deposit this upgrades, or -1
}

// relayedCand is a batch transaction that passed every check but admission.
type relayedCand struct {
	msg   *Message
	msgIx int
	tx    *types.Transaction
	order int
}

// BuildPlan is the derivation function: a pure function of the rollup
// config, one momentum with its blocks, and the chunks earlier momentums
// stored. Blocks are taken in momentum content order (address ‖ height ‖ hash).
func BuildPlan(cfg *rollup.Config, dm *znn.DetailedMomentum, chunks ChunkSource) (*Plan, error) {
	m := dm.Momentum
	if m == nil {
		return nil, fmt.Errorf("detailed momentum without a momentum")
	}
	if len(dm.Blocks) != len(m.Content) {
		return nil, fmt.Errorf("momentum %d: %d blocks for %d content entries", m.Height, len(dm.Blocks), len(m.Content))
	}
	p := &Plan{
		Momentum: m,
		cfg:      cfg,
		gasFork:  cfg.Forks.GasActive(m.Height),
		wireFork: cfg.Forks.WireActive(m.Height),
		seen:     map[common.Hash]bool{},
		local:    map[znn.Hash]*Chunk{},
		claimed:  map[znn.Hash]bool{},
		chunks:   chunks,
	}
	p.add(&PlannedTx{Tx: l2.L1InfoTx(cfg, m), Lane: LaneSystem, Message: -1, Mandatory: true})

	// Mandatory messages an earlier block had no room for come first, in the
	// order they arrived (path 6).
	var carried []*DeferredBlock
	if ds, ok := chunks.(DeferralSource); ok && p.gasFork {
		var err error
		if carried, err = ds.Deferred(m.Height); err != nil {
			return nil, fmt.Errorf("momentum %d: reading deferred messages: %w", m.Height, err)
		}
	}

	// Deposits, payouts and burn mirrors must never be dropped: the value they
	// record has already moved on NoM. Reserve their gas — and the fee split's
	// — before admitting anything else.
	//
	// From the gas fork they may claim at most MandatoryCap between them, and
	// whatever does not fit waits for the next block. The queue is strictly
	// first in, first out: once one message waits, every later one waits too,
	// so no message overtakes another and a deposit is never applied before a
	// payout that preceded it on NoM.
	var mandatory uint64
	full := false
	fits := func() bool {
		if !p.gasFork {
			return true
		}
		if full || mandatory+rollup.SystemGas > cfg.MandatoryCap() {
			full = true
			return false
		}
		mandatory += rollup.SystemGas
		return true
	}
	var released []*DeferredBlock
	for _, c := range carried {
		if !fits() {
			break
		}
		p.reserved += rollup.SystemGas
		released = append(released, c)
	}
	deferred := map[int]bool{}
	posters := map[znn.Address]bool{}
	for i, b := range dm.Blocks {
		if b == nil || b.Hash != m.Content[i].Hash {
			return nil, fmt.Errorf("momentum %d: block %d does not match its content entry", m.Height, i)
		}
		switch p.classify(b) {
		case KindDeposit, KindPayout, KindBurn, KindFuse:
			if !fits() {
				deferred[i] = true
				continue
			}
			p.reserved += rollup.SystemGas
		case "inbox":
			if p.gasFork && len(b.Data) > 0 && (b.Data[0] == MsgBatch || b.Data[0] == MsgAssemble) {
				posters[b.Address] = true
			}
		}
	}
	if p.gasFork && len(posters) > 0 {
		p.settleReserve = rollup.FeeSettleGas(len(posters))
		p.reserved += p.settleReserve
	}

	for _, c := range released {
		p.mandatoryMessage(c.Index, c.Block, c.From)
		p.Released = append(p.Released, c.Block.Hash)
	}

	// One pass in content order: record every message, produce the mandatory
	// transactions, and either admit the optional ones (before the gas fork,
	// which is how every block until then was built) or stage them.
	for i, b := range dm.Blocks {
		kind := p.classify(b)
		if deferred[i] {
			msg := p.newMessage(i, b, kind)
			msg.Status, msg.Reason = StatusDeferred, "the block's share for deposits and payouts is full; applied in a later block"
			msg.Token, msg.Amount = b.TokenStandard.String(), b.AmountBig().String()
			p.Deferred = append(p.Deferred, &DeferredBlock{Block: b, From: m.Height, Index: i})
			continue
		}
		switch kind {
		case KindPayout, KindBurn, KindDeposit, KindFuse:
			p.mandatoryMessage(i, b, 0)
		case "inbox":
			if err := p.inbox(i, b); err != nil {
				return nil, fmt.Errorf("momentum %d: %w", m.Height, err)
			}
		}
	}

	// From the gas fork, the two lanes are admitted in passes of their own:
	// the batch lane first, up to its ceiling, then the native lane into what
	// is left — never less than its floor (D10).
	if p.gasFork {
		p.admitRelayed()
		p.admitNative()
		p.finishMessages()
	}
	p.collectChunks()
	p.reserved -= p.settleReserve
	p.settleReserve = 0
	p.buildSettle()
	p.sortTxs()
	return p, nil
}

func (p *Plan) classify(b *znn.AccountBlock) string {
	if b.BlockType != znn.BlockTypeUserSend {
		return ""
	}
	switch {
	case b.Address == p.cfg.Vault:
		switch {
		case bytes.HasPrefix(b.Data, rollup.PayoutMagic):
			return KindPayout
		case p.gasFork && bytes.HasPrefix(b.Data, rollup.BurnMagic) && b.ToAddress == p.cfg.Inbox:
			return KindBurn
		case p.gasFork && b.ToAddress == PlasmaContract && bytes.HasPrefix(b.Data, PlasmaFuseSelector):
			return KindFuse
		}
		return ""
	case b.ToAddress == p.cfg.Inbox:
		return "inbox"
	case b.ToAddress == p.cfg.Vault:
		return KindDeposit
	}
	return ""
}

// mandatoryMessage applies a deposit, payout or burn mirror whose gas has been
// reserved. from is the momentum it arrived in when that is not this one.
func (p *Plan) mandatoryMessage(i int, b *znn.AccountBlock, from uint64) {
	switch p.classify(b) {
	case KindPayout:
		p.payout(i, b)
	case KindBurn:
		p.burnMirror(i, b)
	case KindDeposit:
		p.deposit(i, b)
	case KindFuse:
		p.fuseMirror(i, b)
	default:
		// Only reachable for a queued block whose classification changed,
		// which no rule does; release its reservation rather than hold it.
		p.reserved -= rollup.SystemGas
		return
	}
	if from != 0 {
		p.Messages[len(p.Messages)-1].DeferredFrom = from
	}
}

func (p *Plan) newMessage(i int, b *znn.AccountBlock, kind string) *Message {
	msg := &Message{NomHash: b.Hash, Author: b.Address, Index: i, Kind: kind, Bytes: len(b.Data), Plasma: b.UsedPlasma}
	p.Messages = append(p.Messages, msg)
	return msg
}

func (p *Plan) add(t *PlannedTx) {
	if t.Order == 0 {
		t.Order = p.nextOrder()
	}
	p.Txs = append(p.Txs, t)
	p.gas += t.Tx.Gas()
	p.seen[t.Tx.Hash()] = true
	switch t.Lane {
	case LaneBatch:
		p.batchGas += t.Tx.Gas()
	case LaneNative:
		p.nativeGas += t.Tx.Gas()
	}
	if t.Message >= 0 {
		msg := p.Messages[t.Message]
		msg.Txs = append(msg.Txs, t.Tx.Hash())
		msg.Status = StatusIncluded
	}
}

// nextOrder reserves a place in content order for a transaction that may or
// may not be admitted. Numbers start at 1, so a zero Order means "not yet
// placed"; an unused number is harmless, because the list is only sorted.
func (p *Plan) nextOrder() int {
	p.order++
	return p.order
}

// sortTxs puts the block back into content order after the boost-ordered
// native pass, and the fee settle after everything else.
func (p *Plan) sortTxs() {
	sort.SliceStable(p.Txs, func(i, j int) bool { return p.Txs[i].Order < p.Txs[j].Order })
	if p.settle != nil {
		p.Txs = append(p.Txs, p.settle)
	}
}

// fits reports whether an optional transaction of this gas can be admitted
// without eating into gas reserved for mandatory ones.
func (p *Plan) fits(gas uint64) bool {
	return p.gas+p.reserved+gas <= p.cfg.GasLimit
}

// optional is the gas left for transactions that may be dropped.
func (p *Plan) optional() uint64 {
	used := p.gas + p.reserved
	if used >= p.cfg.GasLimit {
		return 0
	}
	return p.cfg.GasLimit - used
}

func (p *Plan) payout(i int, b *znn.AccountBlock) {
	msg := p.newMessage(i, b, KindPayout)
	p.reserved -= rollup.SystemGas
	msg.Token = b.TokenStandard.String()
	msg.Amount = b.AmountBig().String()
	if len(b.Data) != len(rollup.PayoutMagic)+32 {
		msg.Status, msg.Reason = StatusInvalid, "payout data must be ZVMW followed by a 32-byte id"
		return
	}
	id := new(big.Int).SetBytes(b.Data[len(rollup.PayoutMagic):])
	bridge := rollup.BridgeAddr
	tx := types.NewTx(&types.DepositTx{
		SourceHash: l2.SourceHash(l2.DomainSystem, b.Hash, 0),
		From:       rollup.SystemDepositor,
		To:         &bridge,
		Value:      new(big.Int),
		Gas:        rollup.SystemGas,
		Data:       EncodeMarkPaid(id, b.Hash, l2.EthAddress(b.ToAddress), b.TokenStandard, b.AmountBig()),
	})
	p.add(&PlannedTx{Tx: tx, Lane: LaneSystem, Message: len(p.Messages) - 1, Mandatory: true})
}

// burnMirror is the committee destroying, on NoM, ZNN the fee splitter burned
// on the ZVM: a vault send to the inbox — unspendable by construction — tagged
// ZVMB. It derives to a call that records the match, so the gap between what
// this chain burned and what NoM's supply lost is readable from ZVM state.
func (p *Plan) burnMirror(i int, b *znn.AccountBlock) {
	msg := p.newMessage(i, b, KindBurn)
	p.reserved -= rollup.SystemGas
	amount := b.AmountBig()
	msg.Token = b.TokenStandard.String()
	msg.Amount = amount.String()
	msg.Burned, msg.BurnToken = amount.String(), b.TokenStandard.String()
	if b.TokenStandard != znn.ZNN || amount.Sign() <= 0 {
		msg.Status, msg.Reason = StatusIgnored, "a burn mirror destroys ZNN"
		return
	}
	splitter := p.cfg.FeeSplitter
	p.add(&PlannedTx{Tx: types.NewTx(&types.DepositTx{
		SourceHash: l2.SourceHash(l2.DomainSystem, b.Hash, 0),
		From:       rollup.SystemDepositor,
		To:         &splitter,
		Value:      new(big.Int),
		Gas:        rollup.SystemGas,
		Data:       EncodeMarkBurned(b.Hash, new(big.Int).Mul(amount, rollup.ZNNScale)),
	}), Lane: LaneSystem, Message: len(p.Messages) - 1, Mandatory: true})
}

// fuseMirror records the vault fusing QSR on NoM, so the bridge's fee revenue
// and what has been spent of it are both ZVM state (D8). A malformed fuse is
// still recorded as a movement of the vault's QSR — NoM's plasma contract is
// what decides whether it fused, and a refused fuse is refunded to the vault
// rather than lost, so counting it errs towards fusing less.
func (p *Plan) fuseMirror(i int, b *znn.AccountBlock) {
	msg := p.newMessage(i, b, KindFuse)
	p.reserved -= rollup.SystemGas
	amount := b.AmountBig()
	msg.Token, msg.Amount = b.TokenStandard.String(), amount.String()
	if b.TokenStandard != znn.QSR || amount.Sign() <= 0 {
		msg.Status, msg.Reason = StatusIgnored, "a vault fusion spends QSR"
		return
	}
	var beneficiary common.Address
	if len(b.Data) >= len(PlasmaFuseSelector)+32 {
		beneficiary = common.BytesToAddress(b.Data[len(PlasmaFuseSelector)+12 : len(PlasmaFuseSelector)+32])
	}
	bridge := rollup.BridgeAddr
	p.add(&PlannedTx{Tx: types.NewTx(&types.DepositTx{
		SourceHash: l2.SourceHash(l2.DomainSystem, b.Hash, 0),
		From:       rollup.SystemDepositor,
		To:         &bridge,
		Value:      new(big.Int),
		Gas:        rollup.SystemGas,
		Data:       EncodeMarkFused(b.Hash, beneficiary, amount),
	}), Lane: LaneSystem, Message: len(p.Messages) - 1, Mandatory: true})
}

func (p *Plan) deposit(i int, b *znn.AccountBlock) {
	msg := p.newMessage(i, b, KindDeposit)
	p.reserved -= rollup.SystemGas
	amount := b.AmountBig()
	msg.Token = b.TokenStandard.String()
	msg.Amount = amount.String()
	if amount.Sign() <= 0 {
		msg.Status, msg.Reason = StatusIgnored, "a send to the vault without an amount is not a deposit"
		return
	}
	author := l2.EthAddress(b.Address)
	source := l2.SourceHash(l2.DomainUserDeposit, b.Hash, 0)
	idx := len(p.Messages) - 1

	switch b.TokenStandard {
	case znn.ZNN:
		mint := new(big.Int).Mul(amount, rollup.ZNNScale)
		// A deposit may carry a call: mint first, then execute it with the
		// minted value available. The mint is mandatory and goes in now; the
		// call competes for the native lane, and if it loses the mint stands
		// alone.
		p.add(&PlannedTx{Tx: types.NewTx(&types.DepositTx{
			SourceHash: source, From: author, To: &author, Mint: mint, Value: new(big.Int), Gas: rollup.DepositGas,
		}), Lane: LaneDeposit, Message: idx, Mandatory: true})
		if len(b.Data) == 0 || b.Data[0] != MsgCall {
			return
		}
		c, err := DecodeCall(b.Data[1:], p.gasFork)
		if err != nil {
			msg.Reason = "call undecodable (" + err.Error() + "); minted without it"
			return
		}
		if c.HasBoost() {
			msg.Reason = "a deposit-carried call may not boost; minted without it"
			return
		}
		gas := p.depositCallBudget(b, c.Gas)
		p.offerNative(&nativeCand{
			msg: msg, lane: LaneDeposit, gas: gas, order: p.Txs[len(p.Txs)-1].Order, replace: len(p.Txs) - 1,
			tx: types.NewTx(&types.DepositTx{
				SourceHash: source, From: author, To: c.To, Mint: mint, Value: c.Value, Gas: gas, Data: c.Data,
			}),
		})
	case znn.QSR:
		// WQSR is not native value, so there is nothing for a carried call to
		// spend the way ZNN's can: bridgeMint already takes a recipient
		// (ZVMBridge.depositQSR's `to`), and redirecting a deposit is naming
		// that recipient instead of minting to the sender. Anything beyond a
		// bare `to` in the carried call is not something a QSR deposit can
		// honor, so it is rejected rather than silently dropped.
		to := author
		if len(b.Data) > 0 && b.Data[0] == MsgCall {
			c, err := DecodeCall(b.Data[1:], p.gasFork)
			switch {
			case err != nil:
				msg.Reason = "call undecodable (" + err.Error() + "); minted to the sender"
			case c.To == nil:
				msg.Reason = "a QSR deposit's carried call must name a recipient; minted to the sender"
			case c.HasBoost() || (c.Value != nil && c.Value.Sign() != 0) || len(c.Data) != 0:
				msg.Reason = "a QSR deposit's carried call may only redirect the recipient; minted to the sender"
			default:
				to = *c.To
			}
		}
		bridge := rollup.BridgeAddr
		p.add(&PlannedTx{Tx: types.NewTx(&types.DepositTx{
			SourceHash: source, From: rollup.SystemDepositor, To: &bridge, Value: new(big.Int), Gas: rollup.SystemGas,
			Data: EncodeDepositQSR(b.Hash, to, amount),
		}), Lane: LaneDeposit, Message: idx, Mandatory: true})
	default:
		msg.Status, msg.Reason = StatusIgnored, "only ZNN and QSR are bridged"
	}
}

// depositCallBudget is the gas of a call carried by a deposit. A deposit's
// amount is the value being bridged, so it cannot also be a burned fee — which
// would make this the one way to buy native gas for nothing once the fee rule
// is active. It is therefore capped: the path exists so that value can arrive
// already swapped or staked, which is a call of a few hundred thousand gas.
func (p *Plan) depositCallBudget(b *znn.AccountBlock, requested uint64) uint64 {
	gas := NativeGas(p.cfg, b.UsedPlasma, requested)
	if p.cfg.Fee.Active(p.Momentum.Height) && gas > p.cfg.MaxDepositCallGas {
		gas = p.cfg.MaxDepositCallGas
	}
	return gas
}

// inboxBudget is a native call's gas: the lesser of what the plasma of its NoM
// blocks bought and, once the fee rule is active, what the ZNN or QSR it
// burned to the inbox bought (rollup/fee.go). It records both on the message
// and returns what the boost bought, which is priority rather than gas.
func (p *Plan) inboxBudget(msg *Message, b *znn.AccountBlock, plasma uint64, c Call) (gas, boostGas uint64, err error) {
	gas = NativeGas(p.cfg, plasma, c.Gas)
	if !p.cfg.Fee.Active(p.Momentum.Height) {
		return gas, 0, nil
	}
	price := rollup.PriceOf(b)
	epoch := p.cfg.Fee.EpochAt(int64(p.Momentum.Timestamp))
	amount := b.AmountBig()
	if c.HasBoost() {
		if c.Boost.Cmp(amount) > 0 {
			return 0, 0, fmt.Errorf("boost %s is more than the %s burned", c.Boost, amount)
		}
		amount = new(big.Int).Sub(amount, c.Boost)
		boostGas = p.cfg.Fee.GasFor(c.Boost, b.TokenStandard, epoch, price)
		msg.Boost, msg.BoostGas = c.Boost.String(), boostGas
	}
	feeGas := p.cfg.Fee.GasFor(amount, b.TokenStandard, epoch, price)
	msg.FeeGas, msg.FeePrice = feeGas, price.Scaled()
	if feeGas < gas {
		gas = feeGas
	}
	return gas, boostGas, nil
}

// NativeGas is a native call's gas: what its NoM block's plasma buys, capped
// per call, and lowered to what the call asked for.
func NativeGas(cfg *rollup.Config, usedPlasma, requested uint64) uint64 {
	gas := usedPlasma * cfg.GasPerPlasma
	if gas > cfg.MaxNativeGas {
		gas = cfg.MaxNativeGas
	}
	if requested != 0 && requested < gas {
		gas = requested
	}
	return gas
}

// NativeTx is the transaction a native call in block b derives to, if it is
// admitted. A client that published b can compute its L2 hash from this
// before the block is derived.
func NativeTx(cfg *rollup.Config, b *znn.AccountBlock, c Call) *types.Transaction {
	return types.NewTx(&types.DepositTx{
		SourceHash: l2.SourceHash(l2.DomainUserDeposit, b.Hash, 0),
		From:       l2.EthAddress(b.Address),
		To:         c.To,
		Value:      c.Value,
		Gas:        NativeGas(cfg, b.UsedPlasma, c.Gas),
		Data:       c.Data,
	})
}

// DepositTx is the transaction a plain ZNN deposit in block b derives to.
func DepositTx(b *znn.AccountBlock) *types.Transaction {
	author := l2.EthAddress(b.Address)
	return types.NewTx(&types.DepositTx{
		SourceHash: l2.SourceHash(l2.DomainUserDeposit, b.Hash, 0),
		From:       author,
		To:         &author,
		Mint:       new(big.Int).Mul(b.AmountBig(), rollup.ZNNScale),
		Value:      new(big.Int),
		Gas:        rollup.DepositGas,
	})
}

// DepositCallTx is the transaction a ZNN deposit carrying a call derives to.
func DepositCallTx(cfg *rollup.Config, b *znn.AccountBlock, c Call) *types.Transaction {
	return types.NewTx(&types.DepositTx{
		SourceHash: l2.SourceHash(l2.DomainUserDeposit, b.Hash, 0),
		From:       l2.EthAddress(b.Address),
		To:         c.To,
		Mint:       new(big.Int).Mul(b.AmountBig(), rollup.ZNNScale),
		Value:      c.Value,
		Gas:        NativeGas(cfg, b.UsedPlasma, c.Gas),
		Data:       c.Data,
	})
}

func (p *Plan) inbox(i int, b *znn.AccountBlock) error {
	msg := p.newMessage(i, b, "")
	// Value sent to the inbox is unspendable by anyone (its type byte is one
	// no key can produce), so it is burned whatever the message turns out to
	// be. Only a native call gets anything for it.
	if amount := b.AmountBig(); amount.Sign() > 0 {
		msg.Burned, msg.BurnToken = amount.String(), b.TokenStandard.String()
	}
	if len(b.Data) == 0 {
		msg.Kind, msg.Status, msg.Reason = KindCall, StatusInvalid, "empty data"
		return nil
	}
	switch b.Data[0] {
	case MsgCall:
		msg.Kind = KindCall
		p.call(msg, b, b.Data[1:], b.UsedPlasma)
	case MsgBatch:
		msg.Kind = KindBatch
		p.batch(msg, b.Data[1:])
	case MsgChunk:
		msg.Kind = KindChunk
		c := &Chunk{Hash: b.Hash, Author: b.Address, Height: p.Momentum.Height, Data: append([]byte(nil), b.Data[1:]...)}
		p.local[b.Hash] = c
		p.NewChunks = append(p.NewChunks, c)
		msg.Status = StatusStored
	case MsgAssemble:
		msg.Kind = KindAssemble
		return p.assemble(msg, b)
	default:
		msg.Status, msg.Reason = StatusInvalid, fmt.Sprintf("unknown message type 0x%02x", b.Data[0])
	}
	return nil
}

// call prices a native call and offers it for admission. plasma is what the
// whole payload's NoM blocks paid: the carrier alone for a 0x01 message, the
// carrier plus every chunk for one that arrived in pieces.
func (p *Plan) call(msg *Message, b *znn.AccountBlock, payload []byte, plasma uint64) {
	c, err := DecodeCall(payload, p.gasFork)
	if err != nil {
		msg.Status, msg.Reason = StatusInvalid, err.Error()
		return
	}
	gas, boostGas, err := p.inboxBudget(msg, b, plasma, c)
	if err != nil {
		msg.Status, msg.Reason = StatusInvalid, err.Error()
		return
	}
	if gas == 0 {
		msg.Status, msg.Reason = StatusInvalid, "no fee: a native call burns ZNN or QSR to the inbox for its gas"
		return
	}
	p.offerNative(&nativeCand{
		msg: msg, lane: LaneNative, gas: gas, boost: boostGas, order: p.nextOrder(), replace: -1,
		tx: types.NewTx(&types.DepositTx{
			SourceHash: l2.SourceHash(l2.DomainUserDeposit, b.Hash, 0),
			From:       l2.EthAddress(b.Address),
			To:         c.To,
			Value:      c.Value,
			Gas:        gas,
			Data:       c.Data,
		}),
	})
}

// offerNative admits a native call immediately, which is what every block
// before the gas fork did, or stages it for the lane's own pass.
func (p *Plan) offerNative(c *nativeCand) {
	if p.gasFork {
		p.pendingNative = append(p.pendingNative, c)
		return
	}
	if !p.takeNative(c, p.cfg.MaxNativeGasPerBlock) {
		p.refuseNative(c)
	}
}

// admitNative is the native lane's pass. Calls are taken in descending boost —
// the priority a caller buys by burning more than its gas needs — and ties
// keep content order, so a momentum with no boosts is admitted exactly as it
// would have been before.
func (p *Plan) admitNative() {
	cands := append([]*nativeCand(nil), p.pendingNative...)
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].boost > cands[j].boost })
	// What is left after the batch lane's pass, never below the floor and
	// never above the ceiling (D10).
	budget := min(p.cfg.NativeCeil(), p.optional()+p.nativeGas)
	for _, c := range cands {
		if !p.takeNative(c, budget) {
			p.refuseNative(c)
		}
	}
}

// takeNative admits one candidate if the lane's budget and the block both have
// room for it.
func (p *Plan) takeNative(c *nativeCand, budget uint64) bool {
	replaced := uint64(0)
	if c.replace >= 0 {
		replaced = p.Txs[c.replace].Tx.Gas()
	}
	if p.nativeGas+c.gas > budget || !p.fits(c.gas-replaced) {
		return false
	}
	if c.replace < 0 {
		p.add(&PlannedTx{Tx: c.tx, Lane: c.lane, Message: p.indexOf(c.msg), Order: c.order})
		return true
	}
	// A deposit-carried call: swap the mint-only transaction for the one that
	// also runs the call, keeping its place and its message record.
	old := p.Txs[c.replace]
	p.gas += c.tx.Gas() - old.Tx.Gas()
	p.nativeGas += c.tx.Gas()
	delete(p.seen, old.Tx.Hash())
	p.seen[c.tx.Hash()] = true
	old.Tx = c.tx
	c.msg.Txs = []common.Hash{c.tx.Hash()}
	c.msg.Status = StatusIncluded
	return true
}

func (p *Plan) refuseNative(c *nativeCand) {
	if c.replace >= 0 {
		c.msg.Reason = "call did not fit the block; minted without it"
		return
	}
	c.msg.Status, c.msg.Reason = StatusDropped, "block full"
}

func (p *Plan) indexOf(msg *Message) int {
	for i, m := range p.Messages {
		if m == msg {
			return i
		}
	}
	return -1
}

func (p *Plan) assemble(msg *Message, b *znn.AccountBlock) error {
	hashes, err := DecodeAssemble(b.Data[1:])
	if err != nil {
		msg.Status, msg.Reason = StatusInvalid, err.Error()
		return nil
	}
	var joined []byte
	plasma := b.UsedPlasma
	used := make([]znn.Hash, 0, len(hashes))
	for _, h := range hashes {
		c, ok := p.local[h]
		if !ok && p.chunks != nil {
			c, ok, err = p.chunks.Chunk(h)
			if err != nil {
				return fmt.Errorf("reading chunk %s: %w", h, err)
			}
			if ok && c == nil {
				return fmt.Errorf("reading chunk %s: source returned a nil stored chunk", h)
			}
		}
		switch {
		case !ok:
			msg.Status, msg.Reason = StatusInvalid, "unknown chunk "+h.String()
			return nil
		case c.Author != b.Address:
			msg.Status, msg.Reason = StatusInvalid, "chunk "+h.String()+" was published by another account"
			return nil
		case c.Height > p.Momentum.Height || p.Momentum.Height-c.Height > p.cfg.ChunkTTL:
			msg.Status, msg.Reason = StatusInvalid, "chunk "+h.String()+" has expired"
			return nil
		case p.gasFork && (c.Consumed || p.claimed[h]):
			msg.Status, msg.Reason = StatusInvalid, "chunk "+h.String()+" has already been assembled"
			return nil
		}
		if p.gasFork {
			// The whole payload's plasma buys the gas, each chunk once.
			p.claimed[h] = true
			plasma += c.Plasma()
			used = append(used, h)
		}
		joined = append(joined, c.Data...)
		if len(joined) > p.cfg.MaxAssembledBytes {
			msg.Status, msg.Reason = StatusInvalid, "assembled payload too large"
			return nil
		}
	}
	msg.Bytes = len(joined)
	msg.Plasma = plasma
	if len(joined) == 0 {
		msg.Status, msg.Reason = StatusInvalid, "assembled payload is empty"
		return nil
	}
	if len(used) > 0 {
		p.chunkClaims = append(p.chunkClaims, &chunkClaim{msg: msg, chunks: used})
	}
	switch joined[0] {
	case MsgCall:
		p.call(msg, b, joined[1:], plasma)
	case MsgBatch:
		p.batch(msg, joined[1:])
	default:
		msg.Status, msg.Reason = StatusInvalid, "an assembled payload must be a call or a batch"
	}
	return nil
}

// collectChunks decides which chunks this momentum actually spent: those
// behind an assemble that produced something. An assemble the block had no
// room for leaves its chunks for the next momentum.
func (p *Plan) collectChunks() {
	if !p.gasFork {
		return
	}
	for _, c := range p.chunkClaims {
		if c.msg.Status == StatusIncluded {
			p.UsedChunks = append(p.UsedChunks, c.chunks...)
		}
	}
}

// finishMessages closes the records of messages whose staged transactions all
// failed, which cannot be known until both lanes have had their pass.
func (p *Plan) finishMessages() {
	for _, msg := range p.Messages {
		if msg.Status != "" {
			continue
		}
		msg.Status = StatusDropped
		if msg.Reason == "" {
			msg.Reason = "no transaction in the batch made the block"
		}
	}
}

func (p *Plan) batch(msg *Message, payload []byte) {
	raws, err := DecodeBatch(payload, p.cfg.MaxBatchBytes, p.wireFork)
	if err != nil {
		msg.Status, msg.Reason = StatusInvalid, err.Error()
		return
	}
	idx := p.indexOf(msg)
	chainID := p.cfg.L2ChainIDBig()
	signer := types.LatestSignerForChainID(chainID)
	for _, raw := range raws {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			msg.Dropped = append(msg.Dropped, TxDrop{Hash: common.BytesToHash(nil), Reason: "undecodable: " + err.Error()})
			continue
		}
		drop := func(reason string) { msg.Dropped = append(msg.Dropped, TxDrop{Hash: tx.Hash(), Reason: reason}) }
		switch tx.Type() {
		case types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType, types.SetCodeTxType:
		default:
			// Deposit transactions in particular: a relayed 0x7E would mint.
			drop(fmt.Sprintf("transaction type %d is not accepted", tx.Type()))
			continue
		}
		if tx.Protected() && tx.ChainId().Cmp(chainID) != 0 {
			drop("wrong chain id " + tx.ChainId().String())
			continue
		}
		if tx.Gas() > p.cfg.MaxTxGas {
			drop("gas limit above the per-transaction cap")
			continue
		}
		if _, err := types.Sender(signer, tx); err != nil {
			drop("bad signature: " + err.Error())
			continue
		}
		if p.seen[tx.Hash()] {
			drop("duplicate in this block")
			continue
		}
		if !p.offerRelayed(&relayedCand{msg: msg, msgIx: idx, tx: tx, order: p.nextOrder()}) {
			drop("block full")
		}
	}
	if !p.gasFork && msg.Status == "" {
		msg.Status = StatusDropped
		if msg.Reason == "" && len(raws) > 0 {
			msg.Reason = "no transaction in the batch made the block"
		}
	}
}

// offerRelayed admits a batch transaction immediately, as every block before
// the gas fork did, or stages it for the lane's own pass. Staging marks it
// seen, so a duplicate later in the same momentum is still caught in content
// order.
func (p *Plan) offerRelayed(c *relayedCand) bool {
	if !p.gasFork {
		if !p.fits(c.tx.Gas()) {
			return false
		}
		p.add(&PlannedTx{Tx: c.tx, Lane: LaneBatch, Message: c.msgIx, Order: c.order})
		return true
	}
	p.pendingRelayed = append(p.pendingRelayed, c)
	p.seen[c.tx.Hash()] = true
	return true
}

// admitRelayed is the batch lane's pass, in content order, up to its ceiling —
// which is the block minus the native lane's floor, and the floor is only
// held back to the extent this momentum's native calls actually ask for it.
func (p *Plan) admitRelayed() {
	budget := p.optional()
	floor := min(p.cfg.NativeFloor(), budget)
	var demand uint64
	for _, c := range p.pendingNative {
		demand += c.gas
	}
	reserve := min(demand, floor)
	cap := min(p.cfg.GasLimit-p.cfg.NativeFloor(), budget-reserve)
	for _, c := range p.pendingRelayed {
		if p.batchGas+c.tx.Gas() > cap || !p.fits(c.tx.Gas()) {
			c.msg.Dropped = append(c.msg.Dropped, TxDrop{Hash: c.tx.Hash(), Reason: "block full"})
			delete(p.seen, c.tx.Hash())
			continue
		}
		p.add(&PlannedTx{Tx: c.tx, Lane: LaneBatch, Message: c.msgIx, Order: c.order})
	}
}

// buildSettle is the relayed lane's fee split (D9): one derived call, after
// the user transactions, naming every account that posted a batch in this
// block and what its transactions declared. The contract turns those weights
// into half a share each and burns the rest.
//
// It is rebuilt whenever the plan changes, because a transaction the engine
// refuses changes its author's weight.
func (p *Plan) buildSettle() {
	p.settle = nil
	if !p.gasFork || p.cfg.FeeSplitter == (common.Address{}) {
		return
	}
	weights := map[common.Address]uint64{}
	for _, t := range p.Txs {
		if t.Lane != LaneBatch || t.Message < 0 {
			continue
		}
		weights[l2.EthAddress(p.Messages[t.Message].Author)] += t.Tx.Gas()
	}
	if len(weights) == 0 {
		return
	}
	addrs := make([]common.Address, 0, len(weights))
	for a := range weights {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool {
		if weights[addrs[i]] != weights[addrs[j]] {
			return weights[addrs[i]] > weights[addrs[j]]
		}
		return bytes.Compare(addrs[i][:], addrs[j][:]) < 0
	})
	if len(addrs) > rollup.MaxFeeSplitAuthors {
		addrs = addrs[:rollup.MaxFeeSplitAuthors]
	}
	ws := make([]uint64, len(addrs))
	for i, a := range addrs {
		ws[i] = weights[a]
	}
	to := p.cfg.FeeSplitter
	p.settle = &PlannedTx{
		Tx: types.NewTx(&types.DepositTx{
			SourceHash: l2.SourceHash(l2.DomainFees, p.Momentum.Hash, 0),
			From:       rollup.SystemDepositor,
			To:         &to,
			Value:      new(big.Int),
			Gas:        rollup.FeeSettleGas(len(addrs)),
			Data:       EncodeSettle(p.Momentum.Height, addrs, ws),
		}),
		Lane: LaneFees, Message: -1, Order: 1 << 30,
	}
	p.gas += p.settle.Tx.Gas()
}

// Drop removes an optional transaction after execution rejected it.
func (p *Plan) Drop(hash common.Hash, reason string) error {
	for i, t := range p.Txs {
		if t.Tx.Hash() != hash {
			continue
		}
		if t.Lane == LaneFees {
			// The split is derived from the block rather than sent by anyone:
			// if the engine will not run it, the fees stay for the next block.
			p.Txs = append(p.Txs[:i], p.Txs[i+1:]...)
			p.gas -= t.Tx.Gas()
			p.settle = nil
			return nil
		}
		if t.Mandatory || t.Lane == LaneSystem || t.Lane == LaneNative {
			return fmt.Errorf("transaction %s (%s lane) was rejected by the engine: %s", hash, t.Lane, reason)
		}
		p.Txs = append(p.Txs[:i], p.Txs[i+1:]...)
		p.gas -= t.Tx.Gas()
		if t.Lane == LaneBatch {
			p.batchGas -= t.Tx.Gas()
		}
		msg := p.Messages[t.Message]
		for j, h := range msg.Txs {
			if h == hash {
				msg.Txs = append(msg.Txs[:j], msg.Txs[j+1:]...)
				break
			}
		}
		msg.Dropped = append(msg.Dropped, TxDrop{Hash: hash, Reason: reason})
		if len(msg.Txs) == 0 {
			msg.Status = StatusDropped
		}
		// The split names who posted what, so it moves with the block.
		if p.settle != nil {
			p.removeSettle()
			p.buildSettle()
			p.sortTxs()
		}
		return nil
	}
	return fmt.Errorf("transaction %s is not in the plan", hash)
}

// Missing lists the planned transactions an engine left out of the payload it
// built, in plan order, and reports whether any of them was one the node may
// not lose.
//
// This is the client-agnostic half of D12. op-geth refuses a forced
// transaction by naming it in an error; another client may simply build the
// block without it. Comparing what came back against what was asked for
// catches both, and needs no client's prose.
func (p *Plan) Missing(payload [][]byte) (missing []common.Hash, mandatory bool, err error) {
	got := make(map[common.Hash]bool, len(payload))
	for _, raw := range payload {
		tx := new(types.Transaction)
		if uerr := tx.UnmarshalBinary(raw); uerr != nil {
			return nil, false, fmt.Errorf("the engine returned a transaction this node cannot decode: %w", uerr)
		}
		got[tx.Hash()] = true
	}
	for _, t := range p.Txs {
		if got[t.Tx.Hash()] {
			continue
		}
		missing = append(missing, t.Tx.Hash())
		if t.Mandatory || t.Lane == LaneNative || t.Lane == LaneSystem {
			mandatory = true
		}
	}
	return missing, mandatory, nil
}

// Unplanned lists transactions in a payload that the plan did not ask for. An
// engine that adds one has built a block this node did not derive, and no node
// may accept that silently.
func (p *Plan) Unplanned(payload [][]byte) ([]common.Hash, error) {
	planned := make(map[common.Hash]bool, len(p.Txs))
	for _, t := range p.Txs {
		planned[t.Tx.Hash()] = true
	}
	var extra []common.Hash
	for _, raw := range payload {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			return nil, fmt.Errorf("the engine returned a transaction this node cannot decode: %w", err)
		}
		if !planned[tx.Hash()] {
			extra = append(extra, tx.Hash())
		}
	}
	return extra, nil
}

// Has reports whether a hash is one of this plan's transactions.
func (p *Plan) Has(hash common.Hash) bool {
	for _, t := range p.Txs {
		if t.Tx.Hash() == hash {
			return true
		}
	}
	return false
}

func (p *Plan) removeSettle() {
	for i, t := range p.Txs {
		if t.Lane == LaneFees {
			p.Txs = append(p.Txs[:i], p.Txs[i+1:]...)
			p.gas -= t.Tx.Gas()
			return
		}
	}
}

// Attributes are the Engine API payload attributes for this plan.
func (p *Plan) Attributes() (*engine.PayloadAttributes, error) {
	txs := make([][]byte, len(p.Txs))
	for i, t := range p.Txs {
		raw, err := t.Tx.MarshalBinary()
		if err != nil {
			return nil, err
		}
		txs[i] = raw
	}
	gasLimit := p.cfg.GasLimit
	root := common.Hash(p.Momentum.Hash)
	// From the gas fork the block's coinbase is the fee splitter, so a relayed
	// transaction's priority fee arrives where the split can reach it.
	recipient := rollup.SequencerFeeVault
	if p.gasFork && p.cfg.FeeSplitter != (common.Address{}) {
		recipient = p.cfg.FeeSplitter
	}
	// Holocene carries the fee-market parameters in the payload, so a chain can
	// change them without a new execution rule. All zero until forks.market,
	// which tells the client to keep the ones genesis baked in.
	params := p.cfg.FeeParams(p.Momentum.Height)
	feeParams := params[:]
	attrs := &engine.PayloadAttributes{
		Timestamp:             p.Momentum.Timestamp,
		Random:                common.Hash(p.Momentum.Hash),
		SuggestedFeeRecipient: recipient,
		Withdrawals:           []*types.Withdrawal{},
		BeaconRoot:            &root,
		Transactions:          txs,
		NoTxPool:              true,
		GasLimit:              &gasLimit,
		EIP1559Params:         feeParams,
	}
	if p.cfg.IsKarst() {
		// The floor follows the fee-market schedule, so a chain can reprice
		// without a re-genesis — and so every past block keeps the floor it
		// was actually built with.
		if minBaseFee := p.cfg.MinBaseFeeAt(p.Momentum.Height); minBaseFee != 0 {
			attrs.MinBaseFee = &minBaseFee
		}
	}
	return attrs, nil
}
