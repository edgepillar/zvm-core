package derive

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// gasForkConfig is feeConfig with the gas and wire forks active from momentum
// 10 as well. GasPerPlasma is raised so that a short message can declare a
// large budget, which is what makes the lane arithmetic legible here.
func gasForkConfig(t *testing.T) *rollup.Config {
	t.Helper()
	cfg := feeConfig(t)
	cfg.GasPerPlasma = 1_000
	cfg.NativeFloorBP, cfg.NativeCeilBP = 2_500, 7_500
	cfg.MandatoryShareBP = 5_000
	cfg.FeeSplitter = rollup.FeeSplitterAddr
	cfg.Forks = &rollup.Forks{Gas: 10, Wire: 10}
	return cfg
}

// boostedCall is a call that declares gas and buys priority with part of its
// burn. The burn is gas + boost, because one raw unit is one gas in feeConfig.
func boostedCall(gas uint64, boost int64) ([]byte, int64) {
	c := Call{To: &common.Address{}, Value: new(big.Int), Gas: gas}
	if boost > 0 {
		c.Boost = big.NewInt(boost)
	}
	return EncodeCall(c), int64(gas) + boost
}

func signedGas(t *testing.T, key *ecdsa.PrivateKey, chainID, nonce, gas uint64) []byte {
	t.Helper()
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	tx := types.MustSignNewTx(key, types.LatestSignerForChainID(new(big.Int).SetUint64(chainID)), &types.DynamicFeeTx{
		ChainID: new(big.Int).SetUint64(chainID), Nonce: nonce, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2_000_000_000),
		Gas: gas, To: &to, Value: big.NewInt(1),
	})
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBoostNeedsTheGasFork(t *testing.T) {
	cfg := gasForkConfig(t)
	caller := znn.MustDevWallet().Key(3).Address
	msg, burn := boostedCall(100_000, 50_000)

	// One momentum before the fork the same bytes are not a call at all.
	before := gasForkConfig(t)
	before.Forks = &rollup.Forks{Gas: 11}
	mb := newMomentum(10)
	mb.send(caller, cfg.Inbox, znn.ZNN, burn, msg)
	plan, err := BuildPlan(before, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m := plan.Messages[0]; m.Status != StatusInvalid || !strings.Contains(m.Reason, "gas fork") {
		t.Fatalf("a five-item call before the fork must be invalid, got %+v", m)
	}

	mb = newMomentum(10)
	mb.send(caller, cfg.Inbox, znn.ZNN, burn, msg)
	plan, err = BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := plan.Messages[0]
	if m.Status != StatusIncluded || m.Boost != "50000" || m.BoostGas != 50_000 {
		t.Fatalf("the boost should be recorded and spent on priority, got %+v", m)
	}
	if got := plan.Txs[1].Tx.Gas(); got != 100_000 {
		t.Fatalf("the boost buys priority, not gas: %d", got)
	}
	// The boost is not available to pay for gas, so a call that boosts its
	// whole burn buys none.
	mb = newMomentum(10)
	only, _ := boostedCall(100_000, 100_000)
	mb.send(caller, cfg.Inbox, znn.ZNN, 100_000, only)
	plan, _ = BuildPlan(cfg, mb.dm, nil)
	if m := plan.Messages[0]; m.Status != StatusInvalid || !strings.Contains(m.Reason, "no fee") {
		t.Fatalf("boosting the whole burn leaves nothing for gas: %+v", m)
	}
}

func TestBoostOrdersAdmissionNotExecution(t *testing.T) {
	cfg := gasForkConfig(t)
	cfg.GasLimit = 12_000_000 // floor 3 M, ceiling 9 M
	w := znn.MustDevWallet()
	mb := newMomentum(10)

	// Three calls of 4 M gas each: the lane's 9 M ceiling admits two.
	for i, boost := range []int64{0, 100, 50} {
		msg, burn := boostedCall(4_000_000, boost)
		mb.send(w.Key(uint32(1000+i)).Address, cfg.Inbox, znn.ZNN, burn, msg)
	}
	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Txs) != 3 {
		t.Fatalf("want the L1 info deposit and two calls, got %d", len(plan.Txs))
	}
	if plan.Messages[0].Status != StatusDropped {
		t.Fatalf("the call that boosted nothing should be the one dropped, got %s", plan.Messages[0].Status)
	}
	// Admitted by boost, executed in content order: the 100-boost call is
	// second in the momentum and must still run before the 50-boost one.
	if plan.Txs[1].Tx.From() != common.Address(w.Key(1001).Address) ||
		plan.Txs[2].Tx.From() != common.Address(w.Key(1002).Address) {
		t.Fatalf("execution order changed: %s then %s", plan.Txs[1].Tx.From(), plan.Txs[2].Tx.From())
	}
}

func TestElasticShareHoldsTheNativeFloor(t *testing.T) {
	cfg := gasForkConfig(t)
	w := znn.MustDevWallet()
	key, _ := crypto.GenerateKey()
	mb := newMomentum(10)

	// Six relayed transactions of 5 M gas: more than the batch lane's ceiling
	// of 22.5 M, so admission has to stop, and one native call of 5 M, which
	// the floor keeps room for.
	var raws [][]byte
	for i := uint64(0); i < 6; i++ {
		raws = append(raws, signedGas(t, key, cfg.L2ChainID, i, 5_000_000))
	}
	batch, err := EncodeBatch(raws, BatchSpan)
	if err != nil {
		t.Fatal(err)
	}
	mb.send(w.Key(202).Address, cfg.Inbox, znn.ZeroTokenStandard, 0, batch)
	msg, burn := boostedCall(5_000_000, 0)
	mb.send(w.Key(1000).Address, cfg.Inbox, znn.ZNN, burn, msg)

	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	var batchGas, nativeGas uint64
	for _, tx := range plan.Txs {
		switch tx.Lane {
		case LaneBatch:
			batchGas += tx.Tx.Gas()
		case LaneNative:
			nativeGas += tx.Tx.Gas()
		}
	}
	if batchGas > cfg.GasLimit-cfg.NativeFloor() {
		t.Fatalf("the batch lane took %d, above its %d ceiling", batchGas, cfg.GasLimit-cfg.NativeFloor())
	}
	if nativeGas != 5_000_000 {
		t.Fatalf("the native call should have been kept room for, got %d", nativeGas)
	}
}

func TestElasticShareLetsNativeReachTheCeiling(t *testing.T) {
	cfg := gasForkConfig(t)
	w := znn.MustDevWallet()
	mb := newMomentum(10)
	for i := 0; i < 5; i++ {
		msg, burn := boostedCall(5_000_000, 0)
		mb.send(w.Key(uint32(1000+i)).Address, cfg.Inbox, znn.ZNN, burn, msg)
	}
	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	var nativeGas uint64
	for _, tx := range plan.Txs {
		if tx.Lane == LaneNative {
			nativeGas += tx.Tx.Gas()
		}
	}
	if nativeGas != 20_000_000 {
		t.Fatalf("with nothing relayed the lane should reach 4 calls (20 M) inside its 22.5 M ceiling, got %d", nativeGas)
	}
}

func TestChunkGasCountsTheWholePayload(t *testing.T) {
	cfg := feeConfig(t)
	author := znn.MustDevWallet().Key(1000).Address
	target := common.HexToAddress("0x0000000000000000000000000000000000001234")

	build := func(cfg *rollup.Config) *Plan {
		t.Helper()
		mb := newMomentum(10)
		payload := EncodeCall(Call{To: &target, Value: new(big.Int), Gas: 3_000_000, Data: make([]byte, 20_000)})
		var hashes []znn.Hash
		for _, c := range SplitChunks(payload) {
			hashes = append(hashes, mb.send(author, cfg.Inbox, znn.ZeroTokenStandard, 0, c).Hash)
		}
		mb.send(author, cfg.Inbox, znn.ZNN, 3_000_000, EncodeAssemble(hashes))
		plan, err := BuildPlan(cfg, mb.dm, nil)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}

	// Without the fork only the assemble's own plasma counts, and it is what
	// binds: 69 bytes of assemble is 25,692 plasma, which buys 411,072 gas.
	if got := build(cfg).Txs[1].Tx.Gas(); got != 411_072 {
		t.Fatalf("before the fork the assemble's plasma alone buys 411,072 gas, got %d", got)
	}
	// With it, every chunk's plasma counts too, and the call gets what it asked.
	fork := gasForkConfig(t)
	fork.GasPerPlasma = 16
	if got := build(fork).Txs[1].Tx.Gas(); got != 3_000_000 {
		t.Fatalf("the whole payload's plasma should buy the declared 3,000,000 gas, got %d", got)
	}
}

// fakeChunks is a ChunkSource that answers from a map, so a test can say a
// chunk was already spent by an earlier momentum.
type fakeChunks map[znn.Hash]*Chunk

func (f fakeChunks) Chunk(h znn.Hash) (*Chunk, bool) { c, ok := f[h]; return c, ok }

func TestChunkIsSpentOnce(t *testing.T) {
	cfg := gasForkConfig(t)
	cfg.GasPerPlasma = 16
	author := znn.MustDevWallet().Key(1000).Address
	target := common.HexToAddress("0x0000000000000000000000000000000000001234")
	payload := EncodeCall(Call{To: &target, Value: new(big.Int), Gas: 300_000, Data: make([]byte, 20_000)})

	// Two assembles in one momentum naming the same chunks: the second is
	// invalid, so the pair cannot buy the gas twice.
	mb := newMomentum(10)
	var hashes []znn.Hash
	for _, c := range SplitChunks(payload) {
		hashes = append(hashes, mb.send(author, cfg.Inbox, znn.ZeroTokenStandard, 0, c).Hash)
	}
	mb.send(author, cfg.Inbox, znn.ZNN, 300_000, EncodeAssemble(hashes))
	mb.send(author, cfg.Inbox, znn.ZNN, 300_000, EncodeAssemble(hashes))
	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	second := plan.Messages[len(plan.Messages)-1]
	if second.Status != StatusInvalid || !strings.Contains(second.Reason, "already been assembled") {
		t.Fatalf("the second assemble must be invalid, got %+v", second)
	}
	if len(plan.UsedChunks) != len(hashes) {
		t.Fatalf("the first assemble should spend %d chunks, recorded %d", len(hashes), len(plan.UsedChunks))
	}

	// And an assemble in a later momentum naming a chunk the store has marked.
	store := fakeChunks{}
	for i, c := range SplitChunks(payload) {
		h := hashes[i]
		store[h] = &Chunk{Hash: h, Author: author, Height: 10, Data: c[1:], Consumed: true}
	}
	mb = newMomentum(11)
	mb.send(author, cfg.Inbox, znn.ZNN, 300_000, EncodeAssemble(hashes))
	plan, err = BuildPlan(cfg, mb.dm, store)
	if err != nil {
		t.Fatal(err)
	}
	if m := plan.Messages[0]; m.Status != StatusInvalid || !strings.Contains(m.Reason, "already been assembled") {
		t.Fatalf("a chunk spent in an earlier momentum must not be spendable again, got %+v", m)
	}
}

func TestFeeSplitNamesEveryRelayer(t *testing.T) {
	cfg := gasForkConfig(t)
	w := znn.MustDevWallet()
	key, _ := crypto.GenerateKey()
	mb := newMomentum(10)

	// Two relayers, the second posting twice the gas of the first.
	one, err := EncodeBatch([][]byte{signedGas(t, key, cfg.L2ChainID, 0, 100_000)}, BatchZlib)
	if err != nil {
		t.Fatal(err)
	}
	two, err := EncodeBatch([][]byte{
		signedGas(t, key, cfg.L2ChainID, 1, 100_000),
		signedGas(t, key, cfg.L2ChainID, 2, 100_000),
	}, BatchZlib)
	if err != nil {
		t.Fatal(err)
	}
	a, b := w.Key(202).Address, w.Key(203).Address
	mb.send(a, cfg.Inbox, znn.ZeroTokenStandard, 0, one)
	mb.send(b, cfg.Inbox, znn.ZeroTokenStandard, 0, two)

	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	last := plan.Txs[len(plan.Txs)-1]
	if last.Lane != LaneFees || *last.Tx.To() != cfg.FeeSplitter || last.Tx.From() != rollup.SystemDepositor {
		t.Fatalf("the split should be the last transaction, to the splitter: %+v", last)
	}
	// Ordered by weight, so the heavier relayer is first.
	want := EncodeSettle(10, []common.Address{common.Address(b), common.Address(a)}, []uint64{200_000, 100_000})
	if string(last.Tx.Data()) != string(want) {
		t.Fatalf("settle calldata does not name the relayers by weight")
	}
	// Dropping one of the heavier relayer's transactions re-weights the split.
	if err := plan.Drop(plan.Txs[2].Tx.Hash(), "engine said no"); err != nil {
		t.Fatal(err)
	}
	last = plan.Txs[len(plan.Txs)-1]
	if last.Lane != LaneFees {
		t.Fatal("the split should still be last after a drop")
	}
	if string(last.Tx.Data()) == string(want) {
		t.Fatal("the split must be recomputed when the block changes")
	}
}

// The hand-rolled settle and markBurnedOnNoM encodings must match the
// compiled contract.
func TestFeesSelectorsMatchCompiledABI(t *testing.T) {
	var art struct {
		ABI json.RawMessage `json:"abi"`
	}
	if err := json.Unmarshal(rollupFeesArtifact(t), &art); err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(art.ABI)))
	if err != nil {
		t.Fatal(err)
	}
	addrs := []common.Address{common.HexToAddress("0x01"), common.HexToAddress("0x02")}
	want, err := parsed.Pack("settle", big.NewInt(1234), addrs, []*big.Int{big.NewInt(7), big.NewInt(8)})
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(EncodeSettle(1234, addrs, []uint64{7, 8})) {
		t.Fatal("settle encoding differs from the ABI package")
	}
	nomBlock := znn.Sha3([]byte("burn"))
	want, err = parsed.Pack("markBurnedOnNoM", [32]byte(nomBlock), big.NewInt(5_000_000))
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(EncodeMarkBurned(nomBlock, big.NewInt(5_000_000))) {
		t.Fatal("markBurnedOnNoM encoding differs from the ABI package")
	}
}

func TestBurnMirrorDerives(t *testing.T) {
	cfg := gasForkConfig(t)
	mb := newMomentum(10)
	// The committee destroying 2 ZNN on NoM by sending it where nobody can
	// spend it, tagged so derivation knows what it is.
	mb.send(cfg.Vault, cfg.Inbox, znn.ZNN, 200_000_000, rollup.BurnMagic)
	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Txs) != 2 {
		t.Fatalf("want the L1 info deposit and the mirror, got %d", len(plan.Txs))
	}
	tx := plan.Txs[1].Tx
	if *tx.To() != cfg.FeeSplitter || tx.From() != rollup.SystemDepositor {
		t.Fatalf("the mirror should be a system call to the splitter: to %s from %s", tx.To(), tx.From())
	}
	wei := new(big.Int).Mul(big.NewInt(200_000_000), rollup.ZNNScale)
	if string(tx.Data()) != string(EncodeMarkBurned(plan.Messages[0].NomHash, wei)) {
		t.Fatal("the mirror should record the amount in wei")
	}
	if plan.Messages[0].Kind != KindBurn {
		t.Fatalf("kind %s", plan.Messages[0].Kind)
	}
}

// The forks must change nothing below their height: the same momentum derived
// with the fork one block away and with no fork at all must be the same block.
func TestBeforeTheForkNothingMoves(t *testing.T) {
	w := znn.MustDevWallet()
	key, _ := crypto.GenerateKey()
	target := common.HexToAddress("0x0000000000000000000000000000000000001234")

	build := func(cfg *rollup.Config) *Plan {
		t.Helper()
		mb := newMomentum(10)
		mb.send(w.Key(1000).Address, cfg.Inbox, znn.ZNN, 120_000,
			EncodeCall(Call{To: &target, Value: new(big.Int), Gas: 120_000, Data: []byte{1, 2, 3}}))
		batch, err := EncodeBatch([][]byte{signedGas(t, key, cfg.L2ChainID, 0, 21_000)}, BatchZlib)
		if err != nil {
			t.Fatal(err)
		}
		mb.send(w.Key(202).Address, cfg.Inbox, znn.ZeroTokenStandard, 0, batch)
		mb.send(w.Key(1001).Address, cfg.Vault, znn.ZNN, 100_000_000, nil)
		plan, err := BuildPlan(cfg, mb.dm, nil)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}

	plain := build(feeConfig(t))
	scheduled := gasForkConfig(t)
	scheduled.GasPerPlasma = 16
	scheduled.Forks = &rollup.Forks{Gas: 11, Wire: 11}
	later := build(scheduled)

	if len(plain.Txs) != len(later.Txs) {
		t.Fatalf("%d transactions against %d", len(plain.Txs), len(later.Txs))
	}
	for i := range plain.Txs {
		if plain.Txs[i].Tx.Hash() != later.Txs[i].Tx.Hash() {
			t.Fatalf("transaction %d differs: %s against %s", i, plain.Txs[i].Tx.Hash(), later.Txs[i].Tx.Hash())
		}
	}
}

// rollupFeesArtifact reads the committed ZVMFees build.
func rollupFeesArtifact(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../rollup/artifacts/ZVMFees.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
