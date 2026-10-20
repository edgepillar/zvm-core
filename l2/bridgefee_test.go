package l2

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
)

// The bridge's fee parameters are written into raw storage slots at genesis,
// which only works if the slots are where the compiled contract reads them.
// Rather than trust a layout written down by hand, run the predeployed code
// against the genesis storage and ask it.
func TestBridgeFeeSlots(t *testing.T) {
	cfg := &rollup.Config{L2ChainID: 7340470, GasLimit: 30_000_000,
		BridgeFee: &rollup.BridgeFee{BPS: 25, MinZNN: 1_000_000, MinQSR: 70_000_000}}
	g, err := BuildGenesis(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatal(err)
	}
	acct := g.Alloc[rollup.BridgeAddr]
	statedb.SetCode(rollup.BridgeAddr, acct.Code, tracing.CodeChangeUnspecified)
	for k, v := range acct.Storage {
		statedb.SetState(rollup.BridgeAddr, k, v)
	}

	call := func(sig string, args ...[]byte) *big.Int {
		t.Helper()
		data := crypto.Keccak256([]byte(sig))[:4]
		for _, a := range args {
			data = append(data, common.LeftPadBytes(a, 32)...)
		}
		out, _, err := runtime.Call(rollup.BridgeAddr, data, &runtime.Config{State: statedb, GasLimit: 1_000_000, Value: new(big.Int)})
		if err != nil {
			t.Fatalf("%s: %v", sig, err)
		}
		return new(big.Int).SetBytes(out)
	}
	for sig, want := range map[string]uint64{"feeBps()": 25, "minFeeZNN()": 1_000_000, "minFeeQSR()": 70_000_000} {
		if got := call(sig); got.Uint64() != want {
			t.Errorf("%s reads %s from genesis storage, want %d", sig, got, want)
		}
	}
	znnID := append(common.Hex2Bytes("14e66318c6318c6318c6"), make([]byte, 22)...)
	qsrID := append(common.Hex2Bytes("04066318c6318c6318c6"), make([]byte, 22)...)
	feeFor := func(id []byte, amount int64) uint64 {
		t.Helper()
		data := append(crypto.Keccak256([]byte("feeFor(bytes10,uint256)"))[:4], id...)
		data = append(data, common.LeftPadBytes(big.NewInt(amount).Bytes(), 32)...)
		out, _, err := runtime.Call(rollup.BridgeAddr, data, &runtime.Config{State: statedb, GasLimit: 1_000_000, Value: new(big.Int)})
		if err != nil {
			t.Fatal(err)
		}
		return new(big.Int).SetBytes(out).Uint64()
	}
	// 0.25 % of 10 ZNN is 0.025 ZNN, above the 0.01 floor.
	if got := feeFor(znnID, 1_000_000_000); got != 2_500_000 {
		t.Errorf("fee on 10 ZNN is %d, want 2,500,000", got)
	}
	// 0.25 % of 1 QSR is under the 0.7 QSR floor, so the floor applies.
	if got := feeFor(qsrID, 100_000_000); got != 70_000_000 {
		t.Errorf("fee on 1 QSR is %d, want the 70,000,000 floor", got)
	}
}

// A chain configured without a fee must build the same genesis it did before
// the fee existed, so an unchanged config does not become a new chain.
func TestNoBridgeFeeWritesNoStorage(t *testing.T) {
	g, err := BuildGenesis(&rollup.Config{L2ChainID: 7340470, GasLimit: 30_000_000}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Alloc[rollup.BridgeAddr].Storage) != 0 {
		t.Fatal("a fee-less genesis wrote bridge storage")
	}
	zero, err := BuildGenesis(&rollup.Config{L2ChainID: 7340470, GasLimit: 30_000_000, BridgeFee: &rollup.BridgeFee{}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if zero.ToBlock().Hash() != g.ToBlock().Hash() {
		t.Fatal("an all-zero fee should hash like no fee")
	}
}
