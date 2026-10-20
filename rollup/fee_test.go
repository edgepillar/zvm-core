package rollup

import (
	"math/big"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func mainnetFee(t *testing.T, from uint64) *Fee {
	t.Helper()
	f := MainnetSupplyAnchor
	f.FromHeight = from
	if err := f.Check(); err != nil {
		t.Fatal(err)
	}
	return &f
}

func TestSupplyFollowsEmission(t *testing.T) {
	f := mainnetFee(t, 1)
	znnAt, qsrAt := f.SupplyAt(f.RefEpoch)
	if znnAt.String() != f.RefZNN || qsrAt.String() != f.RefQSR {
		t.Fatalf("the anchor epoch must be the anchor: %s, %s", znnAt, qsrAt)
	}
	// The anchor is past both tables, so each epoch adds exactly the tail.
	znnNext, qsrNext := f.SupplyAt(f.RefEpoch + 1)
	if d := new(big.Int).Sub(znnNext, znnAt); d.String() != "432000000000" { // 4,320 ZNN
		t.Fatalf("one epoch of ZNN emission = %s", d)
	}
	if d := new(big.Int).Sub(qsrNext, qsrAt); d.String() != "500000000000" { // 5,000 QSR
		t.Fatalf("one epoch of QSR emission = %s", d)
	}
	// A year later, and supply only grows.
	znnYear, _ := f.SupplyAt(f.RefEpoch + 365)
	if znnYear.Cmp(znnAt) <= 0 {
		t.Fatal("emission never stops, so supply never falls")
	}
}

func TestCostAndGasForAreInverse(t *testing.T) {
	f := mainnetFee(t, 1)
	for _, zts := range []znn.TokenStandard{znn.ZNN, znn.QSR} {
		for _, gas := range []uint64{21_000, 100_000, 16_777_216} {
			cost := f.Cost(gas, zts, f.RefEpoch, Price{})
			got := f.GasFor(cost, zts, f.RefEpoch, Price{})
			if got < gas {
				t.Fatalf("%s: burning the quoted %s for %d gas bought only %d", zts, cost, gas, got)
			}
			// Rounding must never favour the payer by more than one unit's worth.
			if one := f.GasFor(new(big.Int).Sub(cost, big.NewInt(1)), zts, f.RefEpoch, Price{}); one > gas {
				t.Fatalf("%s: a unit less than the quote bought more gas than asked", zts)
			}
		}
	}
}

func TestQSRCostsMoreUnitsThanZNN(t *testing.T) {
	f := mainnetFee(t, 1)
	znnCost := f.Cost(1_000_000, znn.ZNN, f.RefEpoch, Price{})
	qsrCost := f.Cost(1_000_000, znn.QSR, f.RefEpoch, Price{})
	if qsrCost.Cmp(znnCost) <= 0 {
		t.Fatal("QSR's supply is larger, so the same gas must cost more QSR than ZNN")
	}
	// An unknown token buys nothing, rather than buying something for free.
	if g := f.GasFor(big.NewInt(1e9), znn.TokenStandard{}, f.RefEpoch, Price{}); g != 0 {
		t.Fatalf("an unknown ZTS bought %d gas", g)
	}
}

func TestCongestionRaisesTheFee(t *testing.T) {
	f := mainnetFee(t, 1)
	base := znn.BaseSendPlasma(100)
	quiet := Price{Base: base, Paid: base}
	busy := Price{Base: base, Paid: base * 5 / 2}
	if quiet.Scaled() != 1000 {
		t.Fatalf("an uncongested block is price 1000, got %d", quiet.Scaled())
	}
	if busy.Scaled() != 2500 {
		t.Fatalf("a block paying 2.5× is price 2500, got %d", busy.Scaled())
	}
	cheap := f.GasFor(big.NewInt(1_000_000), znn.ZNN, f.RefEpoch, quiet)
	dear := f.GasFor(big.NewInt(1_000_000), znn.ZNN, f.RefEpoch, busy)
	if dear >= cheap || cheap/dear != 2 {
		t.Fatalf("the same burn should buy ~2.5× less gas when busy: %d vs %d", cheap, dear)
	}
	// Underpaying, or a block with no plasma facts at all, is never a discount.
	if g := f.GasFor(big.NewInt(1_000_000), znn.ZNN, f.RefEpoch, Price{Base: base, Paid: 1}); g != cheap {
		t.Fatal("a block that underpaid plasma must not buy gas more cheaply")
	}
	if g := f.GasFor(big.NewInt(1_000_000), znn.ZNN, f.RefEpoch, Price{}); g != cheap {
		t.Fatal("a zero Price must read as uncongested")
	}
}

func TestInactiveBeforeItsHeight(t *testing.T) {
	f := mainnetFee(t, 5_000)
	if f.Active(4_999) || !f.Active(5_000) || !f.Active(5_001) {
		t.Fatal("activation is at the height, not before it")
	}
	var off *Fee
	if off.Active(1) {
		t.Fatal("a chain with no fee configured never activates")
	}
}

func TestEpochFollowsTheTimestamp(t *testing.T) {
	f := mainnetFee(t, 1)
	if e := f.EpochAt(f.GenesisTimestamp); e != 0 {
		t.Fatalf("genesis is epoch 0, got %d", e)
	}
	if e := f.EpochAt(f.GenesisTimestamp + EpochSeconds + 1); e != 1 {
		t.Fatalf("one day after genesis is epoch 1, got %d", e)
	}
	// The mainnet anchor was read at epoch 1750 on 2026-09-09.
	if e := f.EpochAt(1788991540); e != 1750 {
		t.Fatalf("the anchor timestamp is epoch 1750, got %d", e)
	}
}
