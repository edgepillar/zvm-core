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

	"github.com/Zenoglyphs-VM/zvm-core/l2"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func testConfig() *rollup.Config {
	return &rollup.Config{
		L1ChainID: 70, L2ChainID: 7340470,
		Inbox: rollup.Inbox, Vault: znn.MustDevWallet().Key(200).Address,
		L1StartHeight: 2, GasLimit: 30_000_000, GasPerPlasma: 16,
		MaxNativeGas: 16_777_216, MaxNativeGasPerBlock: 15_000_000, MaxTxGas: 30_000_000,
		ChunkTTL: 100, MaxAssembledBytes: 1 << 19, MaxBatchBytes: 1 << 22, FinalityDepth: 6,
	}
}

type momentumBuilder struct {
	dm     *znn.DetailedMomentum
	height map[znn.Address]uint64
}

func newMomentum(height uint64) *momentumBuilder {
	return &momentumBuilder{
		dm: &znn.DetailedMomentum{Momentum: &znn.Momentum{
			Version: 1, ChainIdentifier: 70, Height: height, Timestamp: 1_789_450_000 + height*10,
			Hash: znn.Sha3([]byte{byte(height)}),
		}},
		height: map[znn.Address]uint64{},
	}
}

func (mb *momentumBuilder) send(from, to znn.Address, zts znn.TokenStandard, amount int64, data []byte) *znn.AccountBlock {
	mb.height[from]++
	b := &znn.AccountBlock{
		Version: 1, ChainIdentifier: 70, BlockType: znn.BlockTypeUserSend, Height: mb.height[from],
		Address: from, ToAddress: to, TokenStandard: zts, Amount: znn.BigIntFromUint64(uint64(amount)),
		Data: data, BasePlasma: znn.BaseSendPlasma(len(data)), UsedPlasma: znn.BaseSendPlasma(len(data)),
	}
	b.FusedPlasma = b.BasePlasma
	b.Hash = b.ComputeHash()
	mb.dm.Blocks = append(mb.dm.Blocks, b)
	mb.dm.Momentum.Content = append(mb.dm.Momentum.Content, znn.AccountHeader{Address: from, Hash: b.Hash, Height: b.Height})
	return b
}

func signed(t *testing.T, key *ecdsa.PrivateKey, chainID uint64, nonce uint64) []byte {
	t.Helper()
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	tx := types.MustSignNewTx(key, types.LatestSignerForChainID(new(big.Int).SetUint64(chainID)), &types.DynamicFeeTx{
		ChainID: new(big.Int).SetUint64(chainID), Nonce: nonce, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2_000_000_000),
		Gas: 21_000, To: &to, Value: big.NewInt(1),
	})
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPlanOrderAndLanes(t *testing.T) {
	cfg := testConfig()
	w := znn.MustDevWallet()
	alice, bob, relayer := w.Key(1000).Address, w.Key(1001).Address, w.Key(202).Address
	mb := newMomentum(10)

	target := common.HexToAddress("0x0000000000000000000000000000000000001234")
	call := mb.send(alice, cfg.Inbox, znn.ZeroTokenStandard, 0, EncodeCall(Call{To: &target, Gas: 50_000, Data: []byte{1, 2, 3, 4}}))
	deposit := mb.send(bob, cfg.Vault, znn.ZNN, 5*100_000_000, nil)
	qsr := mb.send(bob, cfg.Vault, znn.QSR, 7*100_000_000, nil)

	key, _ := crypto.GenerateKey()
	batch, err := EncodeBatch([][]byte{signed(t, key, cfg.L2ChainID, 0), signed(t, key, 1, 0)}, BatchZlib)
	if err != nil {
		t.Fatal(err)
	}
	mb.send(relayer, cfg.Inbox, znn.ZeroTokenStandard, 0, batch)

	payoutData := append(append([]byte{}, rollup.PayoutMagic...), common.LeftPadBytes([]byte{9}, 32)...)
	payout := mb.send(cfg.Vault, alice, znn.ZNN, 100_000_000, payoutData)

	p, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Txs) != 6 {
		t.Fatalf("want 6 txs (L1 info, call, 2 deposits, 1 batch tx, payout), got %d", len(p.Txs))
	}
	if p.Txs[0].Tx.To() == nil || *p.Txs[0].Tx.To() != rollup.L1BlockAddr || p.Txs[0].Tx.From() != rollup.L1InfoDepositor {
		t.Fatal("first transaction is not the L1 info deposit")
	}
	if len(p.Txs[0].Tx.Data()) != 176 {
		t.Fatalf("L1 info data is %d bytes, op-geth expects 176", len(p.Txs[0].Tx.Data()))
	}

	native := p.Txs[1].Tx
	if native.From() != common.Address(call.Address) || native.Gas() != 50_000 || native.Mint() != nil {
		t.Fatalf("native call: from %s gas %d mint %v", native.From(), native.Gas(), native.Mint())
	}
	mint := p.Txs[2].Tx
	wantMint := new(big.Int).Mul(big.NewInt(5*100_000_000), rollup.ZNNScale)
	if mint.Mint() == nil || mint.Mint().Cmp(wantMint) != 0 || *mint.To() != common.Address(deposit.Address) {
		t.Fatalf("ZNN deposit mint %v to %v", mint.Mint(), mint.To())
	}
	if *p.Txs[3].Tx.To() != rollup.BridgeAddr || p.Txs[3].Tx.From() != rollup.SystemDepositor {
		t.Fatal("QSR deposit should be a system call to the bridge")
	}
	if p.Txs[4].Lane != LaneBatch {
		t.Fatalf("tx 4 lane %s", p.Txs[4].Lane)
	}
	if p.Txs[5].Tx.From() != rollup.SystemDepositor || p.Txs[5].Lane != LaneSystem {
		t.Fatal("payout should be a system call")
	}

	var batchMsg *Message
	for _, m := range p.Messages {
		if m.Kind == KindBatch {
			batchMsg = m
		}
	}
	if batchMsg == nil || len(batchMsg.Txs) != 1 || len(batchMsg.Dropped) != 1 || !strings.Contains(batchMsg.Dropped[0].Reason, "chain id") {
		t.Fatalf("batch message: %+v", batchMsg)
	}
	_ = qsr
	_ = payout

	// Source hashes must differ even for identical deposits.
	if p.Txs[2].Tx.Hash() == p.Txs[3].Tx.Hash() {
		t.Fatal("distinct deposits hashed the same")
	}
}

func TestPlanReservesDepositsAndDropsCalls(t *testing.T) {
	cfg := testConfig()
	cfg.GasLimit = rollup.L1InfoGas + rollup.SystemGas + 100_000
	w := znn.MustDevWallet()
	mb := newMomentum(11)
	target := common.HexToAddress("0x0000000000000000000000000000000000001234")
	// The call comes first in content order but must not take the deposit's gas.
	mb.send(w.Key(1000).Address, cfg.Inbox, znn.ZeroTokenStandard, 0, EncodeCall(Call{To: &target, Gas: 200_000}))
	mb.send(w.Key(1001).Address, cfg.Vault, znn.ZNN, 1, nil)
	p, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Txs) != 2 {
		t.Fatalf("want L1 info + deposit, got %d txs", len(p.Txs))
	}
	if p.Messages[0].Status != StatusDropped {
		t.Fatalf("call should be dropped, is %s", p.Messages[0].Status)
	}
}

func TestPlanAssemblesChunksWithinAMomentum(t *testing.T) {
	cfg := testConfig()
	author := znn.MustDevWallet().Key(1000).Address
	mb := newMomentum(12)
	target := common.HexToAddress("0x0000000000000000000000000000000000001234")
	payload := EncodeCall(Call{To: &target, Gas: 90_000, Data: make([]byte, 20_000)})
	var hashes []znn.Hash
	for _, c := range SplitChunks(payload) {
		hashes = append(hashes, mb.send(author, cfg.Inbox, znn.ZeroTokenStandard, 0, c).Hash)
	}
	mb.send(author, cfg.Inbox, znn.ZeroTokenStandard, 0, EncodeAssemble(hashes))
	p, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.NewChunks) != 2 || len(p.Txs) != 2 {
		t.Fatalf("chunks %d txs %d", len(p.NewChunks), len(p.Txs))
	}
	if got := len(p.Txs[1].Tx.Data()); got != 20_000 {
		t.Fatalf("assembled call data is %d bytes", got)
	}
}

// The hand-rolled selectors must match the compiled bridge. testdata holds
// ZVMBridge's ABI as solc wrote it; recompile and replace it when the
// contract changes.
func TestBridgeSelectorsMatchCompiledABI(t *testing.T) {
	raw, err := os.ReadFile("testdata/ZVMBridge.abi.json")
	if err != nil {
		t.Fatal(err)
	}
	var combined struct {
		Contracts map[string]struct {
			ABI json.RawMessage `json:"abi"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal(raw, &combined); err != nil {
		t.Fatal(err)
	}
	bridge, ok := combined.Contracts["src/ZVMBridge.sol:ZVMBridge"]
	if !ok {
		t.Fatal("ZVMBridge missing from testdata/ZVMBridge.abi.json")
	}
	parsed, err := abi.JSON(strings.NewReader(string(bridge.ABI)))
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Methods["markPaid"].ID) != string(selectorMarkPaid) {
		t.Fatal("markPaid selector mismatch")
	}
	if string(parsed.Methods["depositQSR"].ID) != string(selectorDepositQSR) {
		t.Fatal("depositQSR selector mismatch")
	}
	if string(parsed.Methods["markFused"].ID) != string(selectorMarkFused) {
		t.Fatal("markFused selector mismatch")
	}
	fused, err := parsed.Pack("markFused", [32]byte(znn.Sha3([]byte("f"))), common.HexToAddress("0x00bb"), big.NewInt(1_000_000_000))
	if err != nil {
		t.Fatal(err)
	}
	if string(fused) != string(EncodeMarkFused(znn.Sha3([]byte("f")), common.HexToAddress("0x00bb"), big.NewInt(1_000_000_000))) {
		t.Fatal("markFused encoding differs from the ABI package")
	}
	id, to, amount := big.NewInt(42), common.HexToAddress("0x00aa"), big.NewInt(12345)
	nomBlock := znn.Sha3([]byte("x"))
	want, err := parsed.Pack("markPaid", id, [32]byte(nomBlock), to, [10]byte(znn.QSR), amount)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(EncodeMarkPaid(id, nomBlock, to, znn.QSR, amount)) {
		t.Fatal("markPaid encoding differs from the ABI package")
	}
}

// feeConfig is testConfig with the burned-fee rule active from momentum 10,
// anchored so that the arithmetic is easy to state: a supply of 1e14 raw units
// against GasPerSupply 1e14 makes one unit of the token buy exactly one gas.
func feeConfig(t *testing.T) *rollup.Config {
	t.Helper()
	cfg := testConfig()
	cfg.MaxDepositCallGas = 1_000_000
	cfg.Fee = &rollup.Fee{
		FromHeight: 10, GasPerSupply: 100_000_000_000_000,
		GenesisTimestamp: 1_789_000_000, RefEpoch: 100_000,
		RefZNN: "100000000000000", RefQSR: "200000000000000",
	}
	if err := cfg.Fee.Check(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestFeeBoundsNativeGas(t *testing.T) {
	cfg := feeConfig(t)
	w := znn.MustDevWallet()
	caller := w.Key(3).Address
	// 200,000 gas asked for, well under the 367,552 this block's plasma buys,
	// so the burn is the only thing that can lower it.
	call := EncodeCall(Call{To: &common.Address{}, Value: new(big.Int), Gas: 200_000})

	// Before the activation height, plasma alone decides and no burn is needed.
	mb := newMomentum(9)
	mb.send(caller, cfg.Inbox, znn.ZeroTokenStandard, 0, call)
	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Txs[1].Tx.Gas(); got != 200_000 {
		t.Fatalf("before activation the call gets what it asked for, got %d", got)
	}

	// After it, the burn is the binding limit when it buys less than the plasma.
	mb = newMomentum(10)
	mb.send(caller, cfg.Inbox, znn.ZNN, 120_000, call)
	plan, err = BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Txs[1].Tx.Gas(); got != 120_000 {
		t.Fatalf("120,000 raw ZNN buys 120,000 gas here, got %d", got)
	}
	msg := plan.Messages[0]
	if msg.Burned != "120000" || msg.BurnToken != znn.ZNN.String() || msg.FeeGas != 120_000 || msg.FeePrice != 1000 {
		t.Fatalf("the message should record the burn: %+v", msg)
	}

	// A burn larger than the call needs leaves the declared limit standing.
	mb = newMomentum(10)
	mb.send(caller, cfg.Inbox, znn.ZNN, 900_000, call)
	plan, _ = BuildPlan(cfg, mb.dm, nil)
	if got := plan.Txs[1].Tx.Gas(); got != 200_000 {
		t.Fatalf("an overpaying call still gets only what it asked for, got %d", got)
	}

	// QSR's supply is twice ZNN's here, so the same gas costs twice as many units.
	mb = newMomentum(10)
	mb.send(caller, cfg.Inbox, znn.QSR, 120_000, call)
	plan, _ = BuildPlan(cfg, mb.dm, nil)
	if got := plan.Txs[1].Tx.Gas(); got != 60_000 {
		t.Fatalf("120,000 raw QSR buys 60,000 gas here, got %d", got)
	}
}

func TestCallWithNoFeeIsInvalidNotFree(t *testing.T) {
	cfg := feeConfig(t)
	caller := znn.MustDevWallet().Key(3).Address
	mb := newMomentum(10)
	mb.send(caller, cfg.Inbox, znn.ZeroTokenStandard, 0, EncodeCall(Call{To: &common.Address{}, Value: new(big.Int), Gas: 500_000}))
	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Txs) != 1 {
		t.Fatalf("a call that burned nothing must derive to no transaction, got %d", len(plan.Txs)-1)
	}
	if m := plan.Messages[0]; m.Status != StatusInvalid || !strings.Contains(m.Reason, "no fee") {
		t.Fatalf("want an invalid message naming the missing fee, got %+v", m)
	}
}

func TestDepositCarriedCallIsCappedNotBurned(t *testing.T) {
	cfg := feeConfig(t)
	caller := znn.MustDevWallet().Key(3).Address
	// A deposit's amount is bridged, not burned, so this call is priced by
	// plasma alone — and capped, or it would be free native gas.
	mb := newMomentum(10)
	// 1,500 bytes of calldata: 123,000 plasma, which buys 1,968,000 gas — more
	// than the cap, so the cap is what binds.
	big15 := EncodeCall(Call{To: &common.Address{}, Value: new(big.Int), Gas: 16_000_000, Data: make([]byte, 1_500)})
	mb.send(caller, cfg.Vault, znn.ZNN, 100_000_000, big15)
	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Txs[1].Tx.Gas(); got != cfg.MaxDepositCallGas {
		t.Fatalf("a deposit-carried call is capped at %d, got %d", cfg.MaxDepositCallGas, got)
	}
	if plan.Txs[1].Tx.Mint().Sign() <= 0 {
		t.Fatal("the deposit must still mint")
	}
}

func TestInboxValueIsRecordedEvenWhenItBuysNothing(t *testing.T) {
	cfg := feeConfig(t)
	caller := znn.MustDevWallet().Key(3).Address
	mb := newMomentum(10)
	// A batch carrying value: the value is burned by the inbox either way, and
	// the explorer should say so rather than lose it.
	mb.send(caller, cfg.Inbox, znn.ZNN, 5_000, []byte{MsgBatch, BatchRaw, 0xc0})
	plan, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m := plan.Messages[0]; m.Burned != "5000" || m.FeeGas != 0 {
		t.Fatalf("want the burn recorded and no gas bought, got %+v", m)
	}
}

func TestQSRDepositCanRedirect(t *testing.T) {
	cfg := testConfig()
	w := znn.MustDevWallet()
	bob := w.Key(1001).Address
	other := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	mb := newMomentum(10)

	plain := mb.send(bob, cfg.Vault, znn.QSR, 7*100_000_000, nil)
	redirected := mb.send(bob, cfg.Vault, znn.QSR, 3*100_000_000, EncodeCall(Call{To: &other}))
	badCall := mb.send(bob, cfg.Vault, znn.QSR, 1*100_000_000, EncodeCall(Call{To: &other, Value: big.NewInt(1)}))

	p, err := BuildPlan(cfg, mb.dm, nil)
	if err != nil {
		t.Fatal(err)
	}

	author := l2EthAddress(t, bob)
	wantPlain := EncodeDepositQSR(plain.Hash, author, plain.AmountBig())
	wantRedirected := EncodeDepositQSR(redirected.Hash, other, redirected.AmountBig())
	wantBad := EncodeDepositQSR(badCall.Hash, author, badCall.AmountBig())

	if got := findQSRDeposit(p, plain.Hash); string(got) != string(wantPlain) {
		t.Fatalf("a plain QSR deposit mints to the sender: got %x, want %x", got, wantPlain)
	}
	if got := findQSRDeposit(p, redirected.Hash); string(got) != string(wantRedirected) {
		t.Fatalf("a QSR deposit carrying a bare `to` call mints to it: got %x, want %x", got, wantRedirected)
	}
	if got := findQSRDeposit(p, badCall.Hash); string(got) != string(wantBad) {
		t.Fatalf("a QSR deposit carrying value in its call must fall back to the sender: got %x, want %x", got, wantBad)
	}
	if reason := messageFor(p, badCall.Hash); !strings.Contains(reason, "may only redirect the recipient") {
		t.Fatalf("want a reason explaining the rejected call, got %q", reason)
	}
}

func l2EthAddress(t *testing.T, addr znn.Address) common.Address {
	t.Helper()
	return l2.EthAddress(addr)
}

func findQSRDeposit(p *Plan, nomHash znn.Hash) []byte {
	for _, tx := range p.Txs {
		d := tx.Tx.Data()
		if len(d) >= 36 && string(d[4:36]) == string(nomHash[:]) {
			return d
		}
	}
	return nil
}

func messageFor(p *Plan, nomHash znn.Hash) string {
	for _, m := range p.Messages {
		if m.NomHash == nomHash {
			return m.Reason
		}
	}
	return ""
}
