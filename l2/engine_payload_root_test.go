package l2

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// This fixture exercises the pinned encoder and real JSON-RPC client. It is a
// header/hash round trip; full EVM execution remains a separate integration test.
func emptyMessagePasserPayload(t *testing.T) *engine.ExecutionPayloadEnvelope {
	t.Helper()
	zero := uint64(0)
	root := types.EmptyRootHash
	beaconRoot := common.Hash{31: 17}
	requests := [][]byte{}
	requestsHash := types.CalcRequestsHash(requests)
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.Hash{31: 1}, UncleHash: types.EmptyUncleHash,
		Root: types.EmptyRootHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash,
		Difficulty: new(big.Int), Number: big.NewInt(1), GasLimit: 30_000_000,
		Time: 1_700_000_010, BaseFee: big.NewInt(1_000_000_000),
		WithdrawalsHash: &root, BlobGasUsed: &zero, ExcessBlobGas: &zero,
		ParentBeaconRoot: &beaconRoot, RequestsHash: &requestsHash,
	}).WithBody(types.Body{Withdrawals: types.Withdrawals{}})
	envelope := engine.BlockToExecutableData(block, new(big.Int), nil, requests)
	if envelope.ExecutionPayload.WithdrawalsRoot != nil {
		t.Fatal("the pinned encoder must omit the empty MessagePasser root")
	}
	return envelope
}

func readMessagePasserPayload(t *testing.T, envelope *engine.ExecutionPayloadEnvelope) (*engine.ExecutionPayloadEnvelope, error) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&call); err != nil || call.Method != "engine_getPayloadV4" {
			http.Error(w, "unexpected fixture request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": envelope})
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	client, err := DialEngine(ctx, server.URL, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client.GetPayload(ctx, engine.PayloadID{})
}

func TestGetPayloadBindsOmittedEmptyWithdrawalsRoot(t *testing.T) {
	envelope := emptyMessagePasserPayload(t)
	expectedHash := envelope.ExecutionPayload.BlockHash
	got, err := readMessagePasserPayload(t, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ExecutionPayload == nil || got.ExecutionPayload.WithdrawalsRoot == nil ||
		*got.ExecutionPayload.WithdrawalsRoot != types.EmptyRootHash || got.ExecutionPayload.BlockHash != expectedHash {
		t.Fatal("the omitted root was not bound to the original block hash")
	}
	block, err := engine.ExecutableDataToBlock(*got.ExecutionPayload, []common.Hash{},
		got.ParentBeaconBlockRoot, got.Requests, types.IsthmusBlockConfig)
	if err != nil || block.Hash() != expectedHash {
		t.Fatalf("restored payload cannot reproduce the original block: %v", err)
	}
	if envelope.ExecutionPayload.WithdrawalsRoot != nil {
		t.Fatal("the independent RPC fixture was changed")
	}
}

func TestGetPayloadRefusesUnboundEmptyWithdrawalsRoot(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		change func(*engine.ExecutionPayloadEnvelope)
	}{
		{"changed block hash", func(p *engine.ExecutionPayloadEnvelope) { p.ExecutionPayload.BlockHash[0] ^= 1 }},
		{"changed state root", func(p *engine.ExecutionPayloadEnvelope) { p.ExecutionPayload.StateRoot[0] ^= 1 }},
		{"changed beacon root", func(p *engine.ExecutionPayloadEnvelope) { p.ParentBeaconBlockRoot[0] ^= 1 }},
		{"missing beacon root", func(p *engine.ExecutionPayloadEnvelope) { p.ParentBeaconBlockRoot = nil }},
		{"missing request array", func(p *engine.ExecutionPayloadEnvelope) { p.Requests = nil }},
		{"nonempty requests", func(p *engine.ExecutionPayloadEnvelope) { p.Requests = [][]byte{{1, 2}} }},
		{"missing withdrawal array", func(p *engine.ExecutionPayloadEnvelope) { p.ExecutionPayload.Withdrawals = nil }},
		{"invalid transaction encoding", func(p *engine.ExecutionPayloadEnvelope) { p.ExecutionPayload.Transactions = [][]byte{{0xff}} }},
		{"missing execution payload", func(p *engine.ExecutionPayloadEnvelope) { p.ExecutionPayload = nil }},
		{"nonempty root omitted", func(p *engine.ExecutionPayloadEnvelope) {
			candidate := *p.ExecutionPayload
			root := common.Hash{31: 99}
			candidate.WithdrawalsRoot = &root
			block, err := engine.ExecutableDataToBlockNoHash(candidate, []common.Hash{},
				p.ParentBeaconBlockRoot, p.Requests, types.IsthmusBlockConfig)
			if err != nil {
				t.Fatal(err)
			}
			p.ExecutionPayload.BlockHash = block.Hash()
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			envelope := emptyMessagePasserPayload(t)
			fixture.change(envelope)
			got, err := readMessagePasserPayload(t, envelope)
			want := "withdrawals root"
			if fixture.name == "missing execution payload" {
				want = "executionPayload"
			}
			if got != nil || err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("unbound root must be refused, got %v, %v", got, err)
			}
		})
	}
}

func TestGetPayloadPreservesProvidedWithdrawalsRoot(t *testing.T) {
	for _, root := range []common.Hash{types.EmptyRootHash, {31: 99}} {
		envelope := emptyMessagePasserPayload(t)
		envelope.ExecutionPayload.WithdrawalsRoot = &root
		block, err := engine.ExecutableDataToBlockNoHash(*envelope.ExecutionPayload, []common.Hash{},
			envelope.ParentBeaconBlockRoot, envelope.Requests, types.IsthmusBlockConfig)
		if err != nil {
			t.Fatal(err)
		}
		envelope.ExecutionPayload.BlockHash = block.Hash()
		got, err := readMessagePasserPayload(t, envelope)
		if err != nil || got == nil || got.ExecutionPayload.WithdrawalsRoot == nil || *got.ExecutionPayload.WithdrawalsRoot != root {
			t.Fatalf("provided root must remain unchanged: %v", err)
		}
	}
}
