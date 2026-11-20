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

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
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

func chainFixtureHeaders(t *testing.T, chain string) (*types.Header, *types.Header) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "chains", chain, "genesis.json"))
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
	return genesis, block
}

func TestReleaseChainObservationAtCommonHeights(t *testing.T) {
	f := newFixture(t)
	genesis, block := chainFixtureHeaders(t, "l2")
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

func serveFixtureNodeEpoch(t *testing.T, value nodeEpochObservation, mode string) string {
	t.Helper()
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/epoch" || r.Header.Get("Cache-Control") != "no-cache" {
			t.Error("observer did not request a fresh node epoch")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		response := value
		count := reads.Add(1)
		if mode == "different" || (mode == "changed" && count > 1) {
			response.LoadedRollupSHA256 = strings.Repeat("a", 64)
		}
		w.Header().Set("Content-Type", "application/json")
		if mode == "oversized" {
			_, _ = w.Write([]byte(strings.Repeat(" ", (4<<10)+1)))
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL + "/api/epoch"
}

func TestReleaseChainObservationBindsLoadedNodeEpoch(t *testing.T) {
	const chain = "l2-69"
	f := newFixtureForChain(t, chain)
	genesis, block := chainFixtureHeaders(t, chain)
	cfg, err := rollup.Load(filepath.Join("..", "chains", chain, "rollup.json"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := nodeEpochObservation{
		Schema: 1, L1ChainID: strconv.FormatUint(cfg.L1ChainID, 10), L2ChainID: strconv.FormatUint(cfg.L2ChainID, 10),
		L2GenesisHash: cfg.L2GenesisHash.Hex(), LoadedRollupSHA256: digest(loaded),
	}
	primaryRPC := observeFixture(t, f.manifest, genesis, block, "")
	witnessRPC := observeFixture(t, f.manifest, genesis, block, "")
	for _, test := range []struct {
		name, mode, errorText string
	}{
		{"two matching loaded configurations", "", ""},
		{"witness disagrees before chain observation", "different", "disagrees with the signed rollup"},
		{"witness changes after chain observation", "changed", "disagrees with the signed rollup"},
		{"oversized witness response", "oversized", "node epoch response was invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			primary := serveFixtureNodeEpoch(t, expected, "")
			witness := serveFixtureNodeEpoch(t, expected, test.mode)
			target := ChainTargets{
				L1: [2]string{primaryRPC, witnessRPC}, L2: [2]string{primaryRPC, witnessRPC}, L1Height: 5, L2Height: 3,
				NodeEpoch: [2]string{primary, witness}, FilesRoot: f.files,
			}
			got, err := f.manifest.ObserveChain(t.Context(), f.policy, f.signatures(t), f.keys, target)
			if test.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorText) || got != (ChainObservation{}) {
					t.Fatalf("inconsistent node epoch received a record: %+v, %v", got, err)
				}
				return
			}
			if err != nil || got.VerifiedNodeEpochs != 2 || got.LoadedRollupSHA256 != expected.LoadedRollupSHA256 ||
				got.L2.Hash != block.Hash().Hex() {
				t.Fatalf("the node epoch did not match the signed configuration at the agreed chain heads: %+v, %v", got, err)
			}
			inputs := writeReleaseTestInputs(t, f)
			raw := runReleaseTestCLI(t, "release-observe-chain", "-manifest", filepath.Join(inputs, "manifest.json"),
				"-policy", filepath.Join(inputs, "policy.json"), "-signatures", filepath.Join(inputs, "signatures.json"),
				"-trusted-keys", filepath.Join(inputs, "keys.json"), "-files-root", f.files,
				"-l1-rpc", primaryRPC, "-l1-witness-rpc", witnessRPC, "-l1-height", "5",
				"-l2-rpc", primaryRPC, "-l2-witness-rpc", witnessRPC, "-l2-height", "3",
				"-node-epoch-url", primary, "-node-witness-epoch-url", witness)
			var decoded ChainObservation
			if json.Unmarshal(raw, &decoded) != nil || decoded != got || strings.Contains(string(raw), "http://") {
				t.Fatal("the release CLI did not produce the scoped node epoch observation")
			}
			t.Logf("Verified chain-69 loaded rollup SHA-256 %s from %d endpoints", got.LoadedRollupSHA256, got.VerifiedNodeEpochs)
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
