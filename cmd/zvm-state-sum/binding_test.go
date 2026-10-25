package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/stateaudit"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

func boundCommandFixture(t *testing.T, root common.Hash, raw []byte) (stateaudit.SnapshotPolicy, stateaudit.Snapshot, stateaudit.BoundSummary) {
	t.Helper()
	input, err := os.ReadFile("../../stateaudit/testdata/release-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		SigningMessage string `json:"signingMessage"`
		Manifest       string `json:"manifestSha256"`
		Epoch          string `json:"epochSha256"`
	}
	if json.Unmarshal(input, &golden) != nil {
		t.Fatal("public source release vector unavailable")
	}
	message, err := base64.StdEncoding.Strict().DecodeString(golden.SigningMessage)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Epoch struct {
			Chain   string `json:"l2ChainId"`
			Genesis string `json:"l2GenesisHash"`
			Rollup  string `json:"rollupSha256"`
		} `json:"epoch"`
	}
	if json.Unmarshal(message[len("ZVM release manifest v1\n"):], &body) != nil {
		t.Fatal("public source epoch unavailable")
	}
	header := &types.Header{ParentHash: common.HexToHash("0x11"), UncleHash: types.EmptyUncleHash, Root: root, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Number: big.NewInt(40), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: uint64(time.Now().Unix() - 10)}
	policy := stateaudit.SnapshotPolicy{Schema: 1, Expected: stateaudit.ChainContext{ChainID: body.Epoch.Chain, GenesisHash: body.Epoch.Genesis, RollupSHA256: body.Epoch.Rollup, EpochSHA256: golden.Epoch}, ManifestSHA256: []string{golden.Manifest}, BlockNumber: 40, BlockHash: header.Hash().Hex(), MaxHeaderAgeSeconds: 3600, Bootstrap: true}
	limits := stateaudit.Limits{MaxEncodedBytes: 2 << 20, MaxNodes: 1000, MaxAccounts: 1000, MaxSteps: 10000}
	witness, err := stateaudit.Decode(context.Background(), bytes.NewReader(raw), limits)
	if err != nil {
		t.Fatal(err)
	}
	head, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, result, err := stateaudit.NewSnapshot(context.Background(), policy, golden.SigningMessage, []hexutil.Bytes{head}, witness, nil, time.Now().Unix(), limits, stateaudit.BindingLimits{MaxDocumentBytes: 8 << 20, MaxHeaders: 256, MaxHeaderBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	return policy, snapshot, result
}

func TestActualBoundCommandRequiresIndependentContextAndPinnedCheckpoint(t *testing.T) {
	binary := os.Getenv("ZVM_STATE_SUM_BINARY")
	if binary == "" {
		t.Skip("standalone binary required; dedicated workflow supplies it")
	}
	root, raw := commandFixture(t)
	basePolicy, baseSnapshot, initial := boundCommandFixture(t, root, raw)
	for _, kind := range []string{"bootstrap", "resume", "root-override", "missing-policy", "unknown-field", "wrong-epoch", "wrong-block", "wrong-witness", "missing-checkpoint", "changed-checkpoint", "unanchored-bootstrap", "stale-header", "context-limit", "header-limit"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			policy := basePolicy
			snapshot := baseSnapshot
			snapshot.Headers = append([]hexutil.Bytes(nil), snapshot.Headers...)
			checkpoint := initial.Checkpoint
			policyPath := filepath.Join(dir, "accepted-policy.json")
			snapshotPath := filepath.Join(dir, "snapshot.json")
			checkpointPath := filepath.Join(dir, "previous.json")
			args := []string{"-input", "-", "-snapshot", snapshotPath, "-snapshot-policy", policyPath}
			want := 1
			switch kind {
			case "bootstrap":
				want = 0
			case "resume":
				policy.Bootstrap = false
				policy.PreviousCheckpointSHA256 = initial.CheckpointSHA256
				args = append(args, "-checkpoint", checkpointPath)
				want = 0
			case "root-override":
				args = append(args, "-state-root", root.Hex())
				want = 2
			case "missing-policy":
				args = args[:4]
				want = 2
			case "wrong-epoch":
				policy.Expected.EpochSHA256 = strings.Repeat("3", 64)
			case "wrong-block":
				policy.BlockHash = "0x" + strings.Repeat("3", 64)
			case "wrong-witness":
				snapshot.WitnessSHA256 = strings.Repeat("3", 64)
			case "missing-checkpoint":
				policy.Bootstrap = false
				policy.PreviousCheckpointSHA256 = initial.CheckpointSHA256
			case "changed-checkpoint":
				policy.Bootstrap = false
				policy.PreviousCheckpointSHA256 = initial.CheckpointSHA256
				checkpoint.NativeBalanceWei = "0"
				args = append(args, "-checkpoint", checkpointPath)
			case "unanchored-bootstrap":
				policy.Bootstrap = false
			case "stale-header":
				policy.MaxHeaderAgeSeconds = 1
			case "context-limit":
				args = append(args, "-max-context-bytes", "100")
			case "header-limit":
				args = append(args, "-max-header-bytes", "1")
			}
			encoded, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unknown-field" {
				encoded = append([]byte("{\"unknown\":1,"), encoded[1:]...)
			}
			if err := os.WriteFile(policyPath, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			for path, value := range map[string]any{snapshotPath: snapshot, checkpointPath: checkpoint} {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, args...)
			cmd.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0 halt_on_error=1 exitcode=87")
			cmd.Stdin = bytes.NewReader(raw)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err = cmd.Run()
			actual := 0
			if ctx.Err() != nil {
				t.Fatal("owned bound verifier process did not terminate")
			}
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					actual = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if actual != want || strings.Contains(stderr.String(), "DATA RACE") {
				t.Fatalf("bound command exit %d want %d: %s", actual, want, stderr.String())
			}
			if want == 0 {
				var got stateaudit.BoundSummary
				if json.Unmarshal(stdout.Bytes(), &got) != nil || got.Summary.StateRoot != root || got.Summary.NativeBalanceWei != "2469" || got.CheckpointSHA256 == "" || got.Checkpoint.Context != basePolicy.Expected || got.Checkpoint.BlockHash != basePolicy.BlockHash || stderr.Len() != 0 {
					t.Fatal("bound process output did not preserve accepted identity")
				}
				if kind == "resume" && got.Checkpoint.FirstObservedAt != initial.Checkpoint.FirstObservedAt {
					t.Fatal("process restart refreshed source age")
				}
			} else if stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatal("refused bound input produced a successful summary")
			}
			if strings.Contains(stdout.String()+stderr.String(), dir) || strings.Contains(stdout.String(), baseSnapshot.SigningMessage) {
				t.Fatal("private input payload escaped into command output")
			}
		})
	}
}
