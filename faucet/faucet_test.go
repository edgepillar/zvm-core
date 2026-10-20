package faucet

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// A drip pays one layer: Zenon for a Zenon address, the ZVM for anything
// else. The ZVM spelling of a Zenon address is reachable only by a native
// call, so ZVM ZNN paid there went unused.
func TestDripPaysOneLayer(t *testing.T) {
	zenon := znn.MustParseAddress("z1qq6eg8n43g032hanpsfp02qcdmv7zfj3y2lt5d")
	if l1, l2 := skipped(zenon); l1 != "" || l2 == "" {
		t.Fatalf("a Zenon address: l1 skipped %q, l2 skipped %q; want Zenon only", l1, l2)
	}
	evm := znn.Address(common.HexToAddress("0x54528274D9e108D9dfdBa40bCb6de7aF0385b7f3"))
	if l1, l2 := skipped(evm); l1 == "" || l2 != "" {
		t.Fatalf("an EVM address: l1 skipped %q, l2 skipped %q; want the ZVM only", l1, l2)
	}
}

// A new recipient refused because its client was paid recently must not be
// told the recipient was paid.
func TestCooldownNamesWhatWasPaid(t *testing.T) {
	f := New(Config{Cooldown: time.Hour})
	if err := f.claim("addr:A", "client:1"); err != nil {
		t.Fatal(err)
	}
	var ce *CooldownError
	err := f.claim("addr:B", "client:1")
	if !errors.As(err, &ce) || !ce.Client || !strings.Contains(err.Error(), "your connection") {
		t.Fatalf("a new recipient from a served client: %v", err)
	}
	err = f.claim("addr:A", "client:2")
	if !errors.As(err, &ce) || ce.Client || !strings.Contains(err.Error(), "that recipient") {
		t.Fatalf("a served recipient from a new client: %v", err)
	}
}
