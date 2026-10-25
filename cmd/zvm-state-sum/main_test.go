package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/stateaudit"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

func commandFixture(t *testing.T) (common.Hash, []byte) {
	t.Helper()
	db := state.NewDatabaseForTesting()
	t.Cleanup(func() { db.TrieDB().Close() })
	s, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		a := common.BigToAddress(big.NewInt(int64(4096 + i)))
		s.SetBalance(a, uint256.NewInt(uint64(1234+i)), 0)
		s.SetNonce(a, 1, 0)
	}
	root, err := s.Commit(1, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TrieDB().Commit(root, false); err != nil {
		t.Fatal(err)
	}
	tree, err := db.OpenTrie(root)
	if err != nil {
		t.Fatal(err)
	}
	it, err := tree.NodeIterator(nil)
	if err != nil {
		t.Fatal(err)
	}
	limits := stateaudit.Limits{MaxEncodedBytes: 2 << 20, MaxNodes: 1000, MaxAccounts: 1000, MaxSteps: 10000}
	w, summary, err := stateaudit.Collect(context.Background(), root, it, limits)
	if err != nil || summary.NativeBalanceWei != "2469" || summary.Accounts != 2 {
		t.Fatalf("owned producer fixture: %+v %v", summary, err)
	}
	var out bytes.Buffer
	if err := stateaudit.Encode(context.Background(), &out, w, limits); err != nil {
		t.Fatal(err)
	}
	return root, out.Bytes()
}

func TestActualOfflineCommandHasNoSuccessOutputForRefusedEvidence(t *testing.T) {
	binary := os.Getenv("ZVM_STATE_SUM_BINARY")
	if binary == "" {
		t.Skip("standalone command binary required; the dedicated workflow builds it before this suite")
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("standalone command binary unavailable")
	}
	root, raw := commandFixture(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "owned.witness")
	if err := os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"stdin", "file", "wrong-root", "malformed", "truncated", "trailing", "byte-cap", "node-cap", "account-cap", "step-cap", "missing-root", "short-root", "zero-root", "long-root", "missing-input", "zero-limit", "positional", "missing-file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			args := []string{"-state-root", root.Hex(), "-input", "-"}
			data := raw
			want := 1
			switch kind {
			case "stdin":
				want = 0
			case "file":
				args[3] = input
				data = nil
				want = 0
			case "wrong-root":
				args[1] = common.HexToHash("0x01").Hex()
			case "malformed":
				data = []byte("invalid owned input")
			case "truncated":
				data = raw[:len(raw)-1]
			case "trailing":
				data = append(bytes.Clone(raw), 0)
			case "byte-cap":
				args = append(args, "-max-bytes", strconv.Itoa(len(raw)-1))
			case "node-cap":
				args = append(args, "-max-nodes", "1")
			case "account-cap":
				args = append(args, "-max-accounts", "1")
			case "step-cap":
				args = append(args, "-max-steps", "1")
			case "missing-root":
				args = []string{"-input", "-"}
				want = 2
			case "short-root":
				args[1] = "0x01"
				want = 2
			case "zero-root":
				args[1] = (common.Hash{}).Hex()
				want = 2
			case "long-root":
				args[1] = "0x" + strings.Repeat("01", 33)
				want = 2
			case "missing-input":
				args = []string{"-state-root", root.Hex()}
				want = 2
			case "zero-limit":
				args = append(args, "-max-steps", "0")
			case "positional":
				args = append(args, "unexpected")
				want = 2
			case "missing-file":
				args[3] = filepath.Join(dir, "missing")
				data = nil
			case "directory":
				args[3] = dir
				data = nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, args...)
			cmd.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0 halt_on_error=1 exitcode=87")
			cmd.Stdin = bytes.NewReader(data)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatal("owned standalone command did not terminate")
			}
			actual := 0
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					actual = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if actual != want || strings.Contains(stderr.String(), "DATA RACE") {
				t.Fatalf("command exit=%d want=%d: %s", actual, want, stderr.String())
			}
			if want == 0 {
				var summary stateaudit.Summary
				dec := json.NewDecoder(&stdout)
				if dec.Decode(&summary) != nil || summary.StateRoot != root || summary.Accounts != 2 || summary.NativeBalanceWei != "2469" || summary.WitnessBytes != uint64(len(raw)) || stderr.Len() != 0 {
					t.Fatalf("wrong verified command result: %+v %s", summary, stderr.String())
				}
				var tail any
				if dec.Decode(&tail) != io.EOF {
					t.Fatal("multiple command summaries")
				}
			} else if stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatal("refused command produced success output or lacked a diagnostic")
			}
			if strings.Contains(stdout.String()+stderr.String(), dir) {
				t.Fatal("input path escaped into command output")
			}
		})
	}
}

type brokenOutput struct{}

func (brokenOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCommandReportsOutputFailureAndRequiresExplicitRoot(t *testing.T) {
	root, raw := commandFixture(t)
	var stderr bytes.Buffer
	if code := run([]string{"-state-root", root.Hex(), "-input", "-"}, bytes.NewReader(raw), brokenOutput{}, &stderr); code != 1 || stderr.Len() == 0 {
		t.Fatal("output failure was successful")
	}
	var stdout bytes.Buffer
	if code := run([]string{"-input", "-"}, bytes.NewReader(raw), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatal("witness cannot select its own accepted root")
	}
}
