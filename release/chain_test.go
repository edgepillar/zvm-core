package release

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

const fixtureMomentum = "4242424242424242424242424242424242424242424242424242424242424242"

func observeFixture(t *testing.T, m Manifest, genesis, block *types.Header, change string) string {
	t.Helper()
	other := types.CopyHeader(block)
	other.Time++
	var l2Reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Version string            `json:"jsonrpc"`
			ID      json.RawMessage   `json:"id"`
			Method  string            `json:"method"`
			Params  []json.RawMessage `json:"params"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil || request.Version != "2.0" {
			t.Error("observer sent an invalid request")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var value any
		switch request.Method {
		case "ledger.getMomentumsByHeight":
			if len(request.Params) != 2 || string(request.Params[1]) != "1" {
				t.Error("observer must request one momentum")
				break
			}
			height, _ := strconv.ParseUint(string(request.Params[0]), 10, 64)
			hash := fixtureMomentum
			if height == 1 {
				hash = strings.TrimPrefix(m.Epoch.L1GenesisHash, "0x")
			} else if height != 5 {
				t.Error("observer requested an unexpected NoM height")
				break
			} else if change == "different-momentum" {
				hash = strings.Repeat("3", 64)
			}
			chain, _ := strconv.ParseUint(m.Epoch.L1ChainID, 10, 64)
			value = map[string]any{"list": []any{map[string]any{"hash": hash, "height": height, "chainIdentifier": chain}}}
		case "eth_chainId":
			chain, _ := new(big.Int).SetString(m.Epoch.L2ChainID, 10)
			value = hexutil.EncodeBig(chain)
		case "eth_getBlockByNumber":
			if len(request.Params) != 2 || string(request.Params[1]) != "false" {
				t.Error("observer must request a header without full transactions")
				break
			}
			switch string(request.Params[0]) {
			case `"0x0"`:
				value = genesis
			case `"0x3"`:
				value = block
				reads := l2Reads.Add(1)
				if change == "different-block" || (change == "changed-block" && reads > 1) {
					value = other
				}
			default:
				t.Error("observer requested an unexpected L2 height")
			}
		case "eth_getCode":
			var at rpc.BlockNumberOrHash
			if len(request.Params) != 2 || string(request.Params[0]) != strconv.Quote(m.Contracts[0].Address) ||
				json.Unmarshal(request.Params[1], &at) != nil || !at.RequireCanonical || at.BlockNumber != nil ||
				at.BlockHash == nil || *at.BlockHash != block.Hash() {
				t.Error("observer did not pin the code query to the agreed canonical block")
				break
			}
			value = "0x60006000"
			if change == "different-code" {
				value = "0x60016001"
			}
		default:
			t.Errorf("unexpected RPC method %q", request.Method)
		}
		if value == nil {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": value}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestReleaseChainObservationAtCommonHeights(t *testing.T) {
	f := newFixture(t)
	raw, err := os.ReadFile("../chains/l2/genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var configuration core.Genesis
	if err := json.Unmarshal(raw, &configuration); err != nil {
		t.Fatal(err)
	}
	genesis := configuration.ToBlock().Header()
	block := types.CopyHeader(genesis)
	block.Number.SetUint64(3)
	block.ParentHash = genesis.Hash()
	block.Time++
	for _, test := range []struct {
		name, change, errorText string
	}{
		{"agreement", "", ""},
		{"NoM witness disagrees", "different-momentum", "L1 endpoints disagree"},
		{"L2 witness disagrees", "different-block", "L2 endpoints disagree"},
		{"wrong contract code", "different-code", "did not establish the signed runtime code"},
		{"block changes during observation", "changed-block", "changed the observed block"},
	} {
		t.Run(test.name, func(t *testing.T) {
			primary := observeFixture(t, f.manifest, genesis, block, "")
			witness := observeFixture(t, f.manifest, genesis, block, test.change)
			targets := ChainTargets{
				L1: [2]string{primary, witness}, L2: [2]string{primary, witness}, L1Height: 5, L2Height: 3,
			}
			observation, err := f.manifest.ObserveChain(t.Context(), f.policy, f.signatures(t), f.keys, targets)
			if test.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorText) || observation != (ChainObservation{}) {
					t.Fatalf("inconsistent observation received a record: %+v, %v", observation, err)
				}
				return
			}
			wantManifest, _ := f.manifest.Fingerprint()
			wantEpoch, _ := f.manifest.EpochFingerprint()
			want := ChainObservation{
				ManifestSHA256: wantManifest, EpochSHA256: wantEpoch, TrustedSignatures: 2,
				L1: ObservedBlock{Height: 5, Hash: common.HexToHash(fixtureMomentum).Hex()},
				L2: ObservedBlock{Height: 3, Hash: block.Hash().Hex()}, VerifiedContracts: 1,
			}
			if err != nil || observation != want {
				t.Fatalf("unexpected chain observation: %+v, %v", observation, err)
			}
			inputs := writeReleaseTestInputs(t, f)
			result := runReleaseTestCLI(t, "release-observe-chain",
				"-manifest", filepath.Join(inputs, "manifest.json"),
				"-policy", filepath.Join(inputs, "policy.json"),
				"-signatures", filepath.Join(inputs, "signatures.json"),
				"-trusted-keys", filepath.Join(inputs, "keys.json"),
				"-l1-rpc", primary, "-l1-witness-rpc", witness, "-l1-height", "5",
				"-l2-rpc", primary, "-l2-witness-rpc", witness, "-l2-height", "3",
			)
			if json.Unmarshal(result, &observation) != nil || observation != want {
				t.Fatalf("unexpected CLI observation: %s", result)
			}
		})
	}
}

func TestReleaseChainObservationAuthenticatesBeforeReadingAnyRPC(t *testing.T) {
	f := newFixture(t)
	s := f.signatures(t)
	s.Signatures[0].KeySHA256 = strings.Repeat("4", 64)
	result, err := f.manifest.ObserveChain(t.Context(), f.policy, s, f.keys, ChainTargets{})
	if err == nil || !strings.Contains(err.Error(), "signature key") || result != (ChainObservation{}) {
		t.Fatalf("untrusted manifest reached the chain observer: %+v, %v", result, err)
	}
}
