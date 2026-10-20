package rollup

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// The fee splitter's address is consensus from the gas fork: it is the block's
// coinbase and the target of a derived call. It is computed from the committed
// creation code and the published salt, so recompiling the contract with
// different settings would move it — which is what this pins.
func TestFeeSplitterAddressIsPinned(t *testing.T) {
	const want = "0xe5e7d41F617F5CDa650d6485056F55f766cB5fC0"
	if FeeSplitterAddr.Hex() != want {
		t.Fatalf("ZVMFees deploys to %s, not %s — the creation code or the salt moved.\n"+
			"If that is intended, a chain past the gas fork must be re-genesised, not reconfigured.",
			FeeSplitterAddr.Hex(), want)
	}
	if FeesSalt != Salt("fees", 1) {
		t.Fatal("the salt is not the published one")
	}
	if got := FeesArtifact.AddressWithSalt(FeesSalt); got != FeeSplitterAddr {
		t.Fatalf("the artifact deploys to %s", got)
	}
	// Arachnid's deployer is in genesis, so nothing new is needed to put it there.
	if Create2Deployer != common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C") {
		t.Fatal("the deterministic deployer moved")
	}
}

func TestFeeSettleGasIsBounded(t *testing.T) {
	if FeeSettleGas(0) != FeeSettleBaseGas {
		t.Fatal("no authors, no per-author gas")
	}
	if FeeSettleGas(MaxFeeSplitAuthors+100) != FeeSettleGas(MaxFeeSplitAuthors) {
		t.Fatal("the settle's gas must be bounded however many relayers a block carries")
	}
}

// A configuration that promises a fork it cannot deliver must be refused at
// load, not discovered at the activation height.
func TestLoadRefusesAnIncoherentFork(t *testing.T) {
	base := map[string]any{
		"l1ChainId": 70, "l2ChainId": 7340470,
		"inbox": Inbox.String(), "vault": Inbox.String(),
		"l1StartHeight": 2, "gasLimit": 300000000, "gasPerPlasma": 16,
		"maxNativeGas": 16777216, "maxNativeGasPerBlock": 150000000, "maxTxGas": 30000000,
		"chunkTtl": 8640, "maxAssembledBytes": 524288, "maxBatchBytes": 4194304, "finalityDepth": 6,
	}
	fee := map[string]any{
		"fromHeight": 10, "gasPerSupply": 137000000000000, "genesisTimestamp": 1637755200,
		"refEpoch": 1750, "refZnn": "1366728966519283", "refQsr": "3118999966129297",
	}
	write := func(t *testing.T, mutate func(map[string]any)) string {
		t.Helper()
		cfg := map[string]any{}
		for k, v := range base {
			cfg[k] = v
		}
		mutate(cfg)
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "rollup.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	for _, c := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"karst above EIP-7825", func(m map[string]any) { m["evm"] = "karst" }, "EIP-7825"},
		{"an unknown evm", func(m map[string]any) { m["evm"] = "shanghai" }, "want"},
		{"a gas fork with no share", func(m map[string]any) {
			m["forks"] = map[string]any{"gas": 100}
			m["fee"] = fee
		}, "nativeFloorBp"},
		{"a gas fork with no splitter", func(m map[string]any) {
			m["forks"] = map[string]any{"gas": 100}
			m["fee"] = fee
			m["nativeFloorBp"], m["nativeCeilBp"] = 2500, 7500
		}, "feeSplitter"},
		{"a gas fork with no mandatory share", func(m map[string]any) {
			m["forks"] = map[string]any{"gas": 100}
			m["fee"] = fee
			m["nativeFloorBp"], m["nativeCeilBp"] = 2500, 7500
			m["feeSplitter"] = FeeSplitterAddr.Hex()
		}, "mandatoryShareBp"},
		{"a mandatory share that leaves no room", func(m map[string]any) {
			m["forks"] = map[string]any{"gas": 100}
			m["fee"] = fee
			m["nativeFloorBp"], m["nativeCeilBp"] = 2500, 7500
			m["feeSplitter"] = FeeSplitterAddr.Hex()
			m["mandatoryShareBp"] = 10000
		}, "no room"},
		{"a gas fork before the fee rule", func(m map[string]any) {
			m["forks"] = map[string]any{"gas": 100}
			m["nativeFloorBp"], m["nativeCeilBp"] = 2500, 7500
			m["mandatoryShareBp"] = 5000
			m["feeSplitter"] = FeeSplitterAddr.Hex()
		}, "burned fee"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(write(t, c.mutate))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error should name %q: %v", c.want, err)
			}
		})
	}

	// And the coherent one loads.
	path := write(t, func(m map[string]any) {
		m["forks"] = map[string]any{"gas": 100, "wire": 100}
		m["fee"] = fee
		m["maxDepositCallGas"] = 1000000
		m["nativeFloorBp"], m["nativeCeilBp"] = 2500, 7500
		m["mandatoryShareBp"] = 5000
		m["feeSplitter"] = FeeSplitterAddr.Hex()
		m["evm"] = "karst"
		m["maxTxGas"] = EIP7825MaxTxGas
	})
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsKarst() || !cfg.Forks.GasActive(100) || cfg.Forks.GasActive(99) {
		t.Fatalf("loaded config: %+v", cfg.Forks)
	}
	if cfg.NativeFloor() != 75_000_000 || cfg.NativeCeil() != 225_000_000 {
		t.Fatalf("share: floor %d ceiling %d", cfg.NativeFloor(), cfg.NativeCeil())
	}
	if cfg.MandatoryCap() != 150_000_000 {
		t.Fatalf("mandatory cap %d", cfg.MandatoryCap())
	}
}

// The fee market is a per-block input from Holocene, so changing it costs no
// execution rule — but it changes every later block's base fee, so it is gated
// like any other consensus change and must be inert before its height.
func TestFeeParamsFollowTheSchedule(t *testing.T) {
	cfg := &Config{
		GasLimit: 300_000_000,
		FeeMarkets: []FeeMarket{
			{Momentum: 100, Denominator: 25, Elasticity: 30},
			{Momentum: 200, Denominator: 8, Elasticity: 30},
		},
	}
	var zero [8]byte
	if got := cfg.FeeParams(99); got != zero {
		t.Fatalf("before the first entry the payload must say nothing, got %x", got)
	}
	if got := cfg.FeeTarget(99); got != 0 {
		t.Fatalf("before the first entry there is no target of ours: %d", got)
	}
	// Each period keeps its own parameters, which is what lets a node syncing
	// from genesis rebuild the blocks that were actually built.
	for _, c := range []struct {
		momentum uint64
		want     [8]byte
	}{
		{100, [8]byte{0, 0, 0, 25, 0, 0, 0, 30}},
		{199, [8]byte{0, 0, 0, 25, 0, 0, 0, 30}},
		{200, [8]byte{0, 0, 0, 8, 0, 0, 0, 30}},
		{10_000, [8]byte{0, 0, 0, 8, 0, 0, 0, 30}},
	} {
		if got := cfg.FeeParams(c.momentum); got != c.want {
			t.Fatalf("at momentum %d: got %x, want %x", c.momentum, got, c.want)
		}
	}
	if target := cfg.FeeTarget(200); target != 10_000_000 {
		t.Fatalf("target %d, want gasLimit/elasticity", target)
	}
	if !cfg.FeeMarketActive(100) || cfg.FeeMarketActive(99) {
		t.Fatal("FeeMarketActive should follow the first entry")
	}
	if cfg.FeeMarketFrom() != 100 {
		t.Fatalf("the schedule starts at %d", cfg.FeeMarketFrom())
	}
}

// A fee cap is sized from the market the chain is heading into, not from one it
// has left: a retired period that allowed a 4.6x rise per block must not keep
// inflating every cap after it.
func TestFeeCapFollowsTheOperativeMarket(t *testing.T) {
	tip := big.NewInt(1_000_000)
	base := big.NewInt(1_000_000_000)
	plain := &Config{GasLimit: 300_000_000}
	if got := plain.SuggestedFeeCap(base, tip); got.Cmp(big.NewInt(2_001_000_000)) != 0 {
		t.Fatalf("with no schedule the cap should be the conventional 2x: %s", got)
	}
	// A sharp period followed by a calm one: the calm one governs.
	cfg := &Config{
		GasLimit: 300_000_000,
		FeeMarkets: []FeeMarket{
			{Momentum: 100, Denominator: 8, Elasticity: 30}, // +362 %/block
			{Momentum: 200, Denominator: 6, Elasticity: 2},  // +16.7 %/block
		},
	}
	calm := cfg.SuggestedFeeCap(base, tip)
	if calm.Cmp(new(big.Int).Mul(base, big.NewInt(4))) > 0 {
		t.Fatalf("a retired sharp period should not inflate the cap: %s", calm)
	}
	// And a chain heading into the sharp market gets the headroom it needs.
	sharp := (&Config{
		GasLimit:   300_000_000,
		FeeMarkets: []FeeMarket{{Momentum: 100, Denominator: 8, Elasticity: 30}},
	}).SuggestedFeeCap(base, tip)
	if sharp.Cmp(new(big.Int).Mul(base, big.NewInt(10))) <= 0 {
		t.Fatalf("a sharp market needs real headroom: %s", sharp)
	}
}

func TestFeeMarketScheduleIsValidated(t *testing.T) {
	base := func() *Config {
		return &Config{GasLimit: 300_000_000, EVM: EVMKarst, MaxTxGas: EIP7825MaxTxGas}
	}
	for _, c := range []struct {
		name  string
		entry []FeeMarket
	}{
		{"no height", []FeeMarket{{Denominator: 25, Elasticity: 30}}},
		{"no parameters", []FeeMarket{{Momentum: 10}}},
		{"half a pair", []FeeMarket{{Momentum: 10, Denominator: 25}}},
		{"elasticity past the gas limit", []FeeMarket{{Momentum: 10, Denominator: 25, Elasticity: 300_000_001}}},
		{"out of order", []FeeMarket{
			{Momentum: 20, Denominator: 25, Elasticity: 30},
			{Momentum: 10, Denominator: 8, Elasticity: 30},
		}},
		{"two at the same height", []FeeMarket{
			{Momentum: 10, Denominator: 25, Elasticity: 30},
			{Momentum: 10, Denominator: 8, Elasticity: 30},
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			cfg.FeeMarkets = c.entry
			if err := cfg.CheckForks(); err == nil {
				t.Fatal("should have been refused")
			}
		})
	}
	cfg := base()
	cfg.FeeMarkets = []FeeMarket{
		{Momentum: 10, Denominator: 25, Elasticity: 30},
		{Momentum: 20, Denominator: 8, Elasticity: 30},
	}
	if err := cfg.CheckForks(); err != nil {
		t.Fatalf("an ascending, complete schedule should be accepted: %v", err)
	}
}
