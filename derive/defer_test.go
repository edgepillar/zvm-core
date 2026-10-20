package derive

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// memQueue is the deferral queue as the store keeps it, in memory: what a
// momentum deferred, and which momentum released it.
type memQueue struct {
	items    []*DeferredBlock
	released map[znn.Hash]uint64
}

func (q *memQueue) Chunk(znn.Hash) (*Chunk, bool) { return nil, false }

func (q *memQueue) Deferred(before uint64) ([]*DeferredBlock, error) {
	var out []*DeferredBlock
	for _, it := range q.items {
		if it.From < before && q.released[it.Block.Hash] == 0 {
			out = append(out, it)
		}
	}
	return out, nil
}

func (q *memQueue) record(p *Plan) {
	q.items = append(q.items, p.Deferred...)
	for _, h := range p.Released {
		q.released[h] = p.Momentum.Height
	}
}

// deferConfig caps mandatory messages at three a block: 800,000 gas of a 20 M
// block, at 250,000 each.
func deferConfig(t *testing.T) *rollup.Config {
	t.Helper()
	cfg := gasForkConfig(t)
	cfg.GasLimit = 20_000_000
	cfg.MandatoryShareBP = 400 // 800,000 gas: three at 250,000
	if got := cfg.MandatoryCap() / rollup.SystemGas; got != 3 {
		t.Fatalf("test config admits %d mandatory messages, want 3", got)
	}
	return cfg
}

// Path 6: more deposits than the block's share admits are carried, in order,
// and every one of them is applied — none dropped, none reordered.
func TestMandatoryOverflowIsDeferredNotForced(t *testing.T) {
	cfg := deferConfig(t)
	w := znn.MustDevWallet()
	q := &memQueue{released: map[znn.Hash]uint64{}}

	mb := newMomentum(20)
	var sent []*znn.AccountBlock
	for i := 0; i < 5; i++ {
		sent = append(sent, mb.send(w.Key(uint32(1000+i)).Address, cfg.Vault, znn.ZNN, int64(i+1)*100_000_000, nil))
	}
	p, err := BuildPlan(cfg, mb.dm, q)
	if err != nil {
		t.Fatal(err)
	}
	if got := countLane(p, LaneDeposit); got != 3 {
		t.Fatalf("momentum 20 applied %d deposits, want the share's 3", got)
	}
	if len(p.Deferred) != 2 || p.Deferred[0].Block.Hash != sent[3].Hash || p.Deferred[1].Block.Hash != sent[4].Hash {
		t.Fatalf("the last two deposits should wait, in order; got %d deferred", len(p.Deferred))
	}
	for _, m := range p.Messages[3:] {
		if m.Status != StatusDeferred {
			t.Fatalf("a deposit that did not fit is %s, want deferred", m.Status)
		}
	}
	if p.gas > cfg.GasLimit {
		t.Fatalf("the block claims %d gas of %d", p.gas, cfg.GasLimit)
	}
	q.record(p)

	// The next momentum brings two more. The carried pair goes first, and the
	// share then has room for only one of the new ones.
	mb = newMomentum(21)
	late := []*znn.AccountBlock{
		mb.send(w.Key(1010).Address, cfg.Vault, znn.ZNN, 100_000_000, nil),
		mb.send(w.Key(1011).Address, cfg.Vault, znn.ZNN, 100_000_000, nil),
	}
	p, err = BuildPlan(cfg, mb.dm, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Released) != 2 || p.Released[0] != sent[3].Hash || p.Released[1] != sent[4].Hash {
		t.Fatalf("momentum 21 should release the carried pair first, released %v", p.Released)
	}
	if p.Messages[0].DeferredFrom != 20 || p.Messages[0].Status != StatusIncluded {
		t.Fatalf("a released deposit should say where it came from: %+v", p.Messages[0])
	}
	if p.Messages[3].Status != StatusDeferred || len(p.Deferred) != 1 || p.Deferred[0].Block.Hash != late[1].Hash {
		t.Fatalf("the second new deposit should wait behind the carried ones")
	}
	// Carried deposits execute before this momentum's own.
	if p.Txs[1].Tx.To() == nil || *p.Txs[1].Tx.To() != *DepositTx(sent[3]).To() {
		t.Fatalf("the oldest carried deposit must be the first transaction after the L1 info deposit")
	}
	q.record(p)

	// A quiet momentum drains the rest.
	p, err = BuildPlan(cfg, newMomentum(22).dm, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Released) != 1 || p.Released[0] != late[1].Hash || len(p.Deferred) != 0 {
		t.Fatalf("momentum 22 should apply the last one and defer nothing")
	}
}

// Once one message waits, a later one may not overtake it, even if it would fit.
// Here a payout arrives behind a full share and must wait with the deposits.
func TestDeferralIsFirstInFirstOut(t *testing.T) {
	cfg := deferConfig(t)
	w := znn.MustDevWallet()
	mb := newMomentum(20)
	for i := 0; i < 4; i++ {
		mb.send(w.Key(uint32(1000+i)).Address, cfg.Vault, znn.ZNN, 100_000_000, nil)
	}
	payout := mb.send(cfg.Vault, w.Key(3).Address, znn.ZNN, 100_000_000, payoutData(7))
	p, err := BuildPlan(cfg, mb.dm, &memQueue{released: map[znn.Hash]uint64{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Deferred) != 2 || p.Deferred[1].Block.Hash != payout.Hash {
		t.Fatalf("the payout must wait behind the deposit that did not fit")
	}
}

// Before the gas fork nothing is deferred, whatever the share says: blocks
// derived before the rule existed must derive the same way.
func TestNoDeferralBeforeTheFork(t *testing.T) {
	cfg := deferConfig(t)
	cfg.Forks = &rollup.Forks{Gas: 100, Wire: 100}
	w := znn.MustDevWallet()
	mb := newMomentum(20)
	for i := 0; i < 6; i++ {
		mb.send(w.Key(uint32(1000+i)).Address, cfg.Vault, znn.ZNN, 100_000_000, nil)
	}
	q := &memQueue{released: map[znn.Hash]uint64{}}
	q.items = []*DeferredBlock{{Block: newMomentum(1).send(w.Key(5).Address, cfg.Vault, znn.ZNN, 1, nil), From: 19}}
	p, err := BuildPlan(cfg, mb.dm, q)
	if err != nil {
		t.Fatal(err)
	}
	if countLane(p, LaneDeposit) != 6 || len(p.Deferred) != 0 || len(p.Released) != 0 {
		t.Fatalf("pre-fork: %d deposits, %d deferred, %d released", countLane(p, LaneDeposit), len(p.Deferred), len(p.Released))
	}
}

// A vault fusion is a movement of the vault's QSR, so from the gas fork it is
// derived back into the bridge like a payout is — and only a fusion from the
// vault, in QSR, counts.
func TestVaultFusionIsRecorded(t *testing.T) {
	cfg := gasForkConfig(t)
	w := znn.MustDevWallet()
	mb := newMomentum(20)
	fuse := mb.send(cfg.Vault, PlasmaContract, znn.QSR, 20*100_000_000, EncodePlasmaFuse(cfg.Vault))
	mb.send(w.Key(3).Address, PlasmaContract, znn.QSR, 20*100_000_000, EncodePlasmaFuse(w.Key(3).Address))
	mb.send(cfg.Vault, PlasmaContract, znn.ZNN, 1, EncodePlasmaFuse(cfg.Vault))
	p, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Messages) != 2 {
		t.Fatalf("want the two vault sends recorded and the other account's fusion ignored, got %d", len(p.Messages))
	}
	if m := p.Messages[0]; m.Kind != KindFuse || m.Status != StatusIncluded {
		t.Fatalf("vault fusion: %+v", m)
	}
	if m := p.Messages[1]; m.Status != StatusIgnored {
		t.Fatalf("a ZNN send to the plasma contract fuses nothing: %+v", m)
	}
	tx := p.Txs[1]
	if !tx.Mandatory || *tx.Tx.To() != rollup.BridgeAddr ||
		string(tx.Tx.Data()) != string(EncodeMarkFused(fuse.Hash, common.Address(cfg.Vault), fuse.AmountBig())) {
		t.Fatal("the fusion should derive to markFused on the bridge, naming the vault as beneficiary")
	}

	// Before the fork the same send is not a ZVM message at all.
	before := gasForkConfig(t)
	before.Forks = &rollup.Forks{Gas: 21, Wire: 21}
	mb = newMomentum(20)
	mb.send(cfg.Vault, PlasmaContract, znn.QSR, 20*100_000_000, EncodePlasmaFuse(cfg.Vault))
	if p, _ := BuildPlan(before, mb.dm, nil); len(p.Messages) != 0 {
		t.Fatal("a vault fusion before the gas fork must not be derived")
	}
}

func countLane(p *Plan, lane string) int {
	n := 0
	for _, t := range p.Txs {
		if t.Lane == lane {
			n++
		}
	}
	return n
}

func payoutData(id byte) []byte {
	d := append([]byte{}, rollup.PayoutMagic...)
	return append(d, append(make([]byte, 31), id)...)
}
