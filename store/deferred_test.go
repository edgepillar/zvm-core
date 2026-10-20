package store

import (
	"path/filepath"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// The deferral queue is derivation input, like the chunk store: it has to come
// back exactly as it went in, in arrival order, and a rewind has to put it back
// the way it was at that height.
func TestDeferralQueueSurvivesARewind(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "zvm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	w := znn.MustDevWallet()
	block := func(i int) *znn.AccountBlock {
		b := &znn.AccountBlock{
			Version: 1, ChainIdentifier: 70, BlockType: znn.BlockTypeUserSend, Height: uint64(i + 1),
			Address: w.Key(uint32(1000 + i)).Address, ToAddress: w.Key(200).Address,
			TokenStandard: znn.ZNN, Amount: znn.BigIntFromUint64(uint64(i+1) * 100_000_000),
			Data: []byte{0x01, byte(i)}, BasePlasma: 21_000, UsedPlasma: 21_136,
		}
		b.Hash = b.ComputeHash()
		return b
	}
	record := func(height uint64, deferred []*derive.DeferredBlock, released []znn.Hash) {
		t.Helper()
		m := &znn.Momentum{Height: height, Hash: znn.Sha3([]byte{byte(height)}), Timestamp: 1_789_450_000 + height*10}
		plan := &derive.Plan{Momentum: m, Deferred: deferred, Released: released}
		if err := db.RecordDerived(&Derived{Momentum: m, L2Number: height, Plan: plan}, 0); err != nil {
			t.Fatal(err)
		}
	}

	a, b, c := block(0), block(1), block(2)
	record(10, []*derive.DeferredBlock{{Block: b, From: 10, Index: 4}, {Block: a, From: 10, Index: 2}}, nil)
	record(11, []*derive.DeferredBlock{{Block: c, From: 11, Index: 0}}, []znn.Hash{a.Hash})

	// Only what earlier momentums queued counts: c, queued by 11, is not
	// waiting for 11. a was released by 11, so it is not waiting either.
	got, err := db.Deferred(11)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Block.Hash != b.Hash {
		t.Fatalf("at 11 want only b waiting, got %d", len(got))
	}
	got, err = db.Deferred(12)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Block.Hash != b.Hash || got[1].Block.Hash != c.Hash {
		t.Fatalf("at 12 want b then c waiting, got %d", len(got))
	}
	// The block comes back byte for byte: its hash is recomputed from fields.
	if got[0].Block.ComputeHash() != b.Hash || got[0].Block.AmountBig().Cmp(b.AmountBig()) != 0 || got[0].From != 10 || got[0].Index != 4 {
		t.Fatalf("a queued block did not round-trip: %+v", got[0])
	}

	// Rewind to 10: c was never queued and a was never released.
	if err := db.RewindTo(10); err != nil {
		t.Fatal(err)
	}
	got, err = db.Deferred(11)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Block.Hash != a.Hash || got[1].Block.Hash != b.Hash {
		t.Fatalf("after rewinding to 10 want a then b (index order) waiting, got %d", len(got))
	}
}
