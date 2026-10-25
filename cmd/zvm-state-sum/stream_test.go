package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/stateaudit"
)

func TestActualCommandVerifiesOneStreamWithoutContextFiles(t *testing.T) {
	binary := os.Getenv("ZVM_STATE_SUM_BINARY")
	if binary == "" {
		t.Skip("dedicated workflow builds the standalone verifier")
	}
	root, raw := commandFixture(t)
	policy, snapshot, initial := boundCommandFixture(t, root, raw)
	limits := stateaudit.Limits{MaxEncodedBytes: 2 << 20, MaxNodes: 1000, MaxAccounts: 1000, MaxSteps: 10000}
	bounds := stateaudit.BindingLimits{MaxDocumentBytes: 8 << 20, MaxHeaders: 256, MaxHeaderBytes: 8192}
	witness, err := stateaudit.Decode(context.Background(), bytes.NewReader(raw), limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"bootstrap", "resume", "root-override", "file-override", "truncated", "trailing", "version"} {
		t.Run(kind, func(t *testing.T) {
			p := policy
			var previous *stateaudit.Checkpoint
			if kind == "resume" {
				p.Bootstrap = false
				p.PreviousCheckpointSHA256 = initial.CheckpointSHA256
				previous = &initial.Checkpoint
			}
			var stream bytes.Buffer
			if err := stateaudit.EncodeInput(context.Background(), &stream, p, snapshot, previous, witness, limits, bounds); err != nil {
				t.Fatal(err)
			}
			data := stream.Bytes()
			args := []string{"-bundle-stdin"}
			want := 1
			switch kind {
			case "bootstrap", "resume":
				want = 0
			case "root-override":
				args = append(args, "-state-root", root.Hex())
				want = 2
			case "file-override":
				args = append(args, "-input", "forbidden")
				want = 2
			case "truncated":
				data = data[:len(data)-1]
			case "trailing":
				data = append(bytes.Clone(data), 0)
			case "version":
				data[7]++
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
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if ctx.Err() != nil || code != want {
				t.Fatalf("stream process failed: %d %s", code, stderr.String())
			}
			if want == 0 {
				var result stateaudit.BoundSummary
				if json.Unmarshal(stdout.Bytes(), &result) != nil || result.Summary.NativeBalanceWei != "2469" || result.CheckpointSHA256 == "" {
					t.Fatal("stream did not retain the complete accepted snapshot")
				}
			} else if stdout.Len() != 0 {
				t.Fatal("refused stream emitted success")
			}
		})
	}
}
