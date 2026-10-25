package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/stateaudit"
)

func TestActualCommandPartitionsAllInputModesWithIndependentPolicy(t *testing.T) {
	binary := os.Getenv("ZVM_STATE_SUM_BINARY")
	if binary == "" {
		t.Skip("dedicated workflow builds the standalone verifier")
	}
	root, witnessRaw := commandFixture(t)
	snapshotPolicy, snapshot, _ := boundCommandFixture(t, root, witnessRaw)
	policy := stateaudit.PartitionPolicy{Schema: 1, Groups: []stateaudit.PartitionGroup{
		{ID: "a", Addresses: []string{"0x0000000000000000000000000000000000001000"}},
		{ID: "b", Addresses: []string{"0x0000000000000000000000000000000000001001", "0x0000000000000000000000000000000000009999"}},
	}}
	partitionLimits := stateaudit.PartitionLimits{MaxGroups: 64, MaxAddresses: 4096}
	pin, err := policy.Fingerprint(partitionLimits)
	if err != nil {
		t.Fatal(err)
	}
	limits := stateaudit.Limits{MaxEncodedBytes: 2 << 20, MaxNodes: 1000, MaxAccounts: 1000, MaxSteps: 10000}
	bounds := stateaudit.BindingLimits{MaxDocumentBytes: 8 << 20, MaxHeaders: 256, MaxHeaderBytes: 8192}
	witness, err := stateaudit.Decode(context.Background(), bytes.NewReader(witnessRaw), limits)
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	if err := stateaudit.EncodeInput(context.Background(), &frame, snapshotPolicy, snapshot, nil, witness, limits, bounds); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"root-stdin", "root-file", "bound-files", "framed-stdin", "wrong-pin", "missing-pin", "missing-policy", "overlap", "group-limit", "address-limit", "truncated", "trailing", "wrong-root", "framed-root-override"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			policyPath := filepath.Join(dir, "partition.json")
			selected := policy
			if kind == "overlap" {
				selected.Groups = append([]stateaudit.PartitionGroup(nil), policy.Groups...)
				selected.Groups[1].Addresses = []string{policy.Groups[0].Addresses[0]}
			}
			raw, _ := json.Marshal(selected)
			if err := os.WriteFile(policyPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-partition-policy", policyPath, "-partition-policy-sha256", pin, "-state-root", root.Hex(), "-input", "-"}
			data := bytes.Clone(witnessRaw)
			want := 1
			bound := false
			switch kind {
			case "root-stdin":
				want = 0
			case "root-file":
				path := filepath.Join(dir, "witness.bin")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				args[len(args)-1] = path
				data = nil
				want = 0
			case "bound-files":
				policyFile, snapshotFile := filepath.Join(dir, "snapshot-policy.json"), filepath.Join(dir, "snapshot.json")
				policyRaw, _ := json.Marshal(snapshotPolicy)
				snapshotRaw, _ := json.Marshal(snapshot)
				if os.WriteFile(policyFile, policyRaw, 0600) != nil || os.WriteFile(snapshotFile, snapshotRaw, 0600) != nil {
					t.Fatal("owned bound context fixture")
				}
				args = append(args[:4], "-snapshot-policy", policyFile, "-snapshot", snapshotFile, "-input", "-")
				want = 0
				bound = true
			case "framed-stdin":
				args = append(args[:4], "-bundle-stdin")
				data = bytes.Clone(frame.Bytes())
				want = 0
				bound = true
			case "wrong-pin":
				args[3] = strings.Repeat("a", 64)
			case "missing-pin":
				args = append(args[:2], args[4:]...)
				want = 2
			case "missing-policy":
				args = args[2:]
				want = 2
			case "overlap":
			case "group-limit":
				args = append(args, "-max-partition-groups", "1")
			case "address-limit":
				args = append(args, "-max-partition-addresses", "2")
			case "truncated":
				data = data[:len(data)-1]
			case "trailing":
				data = append(data, 0)
			case "wrong-root":
				args[5] = "0x" + strings.Repeat("1", 64)
			case "framed-root-override":
				args = append(args, "-bundle-stdin")
				data = bytes.Clone(frame.Bytes())
				want = 2
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
				t.Fatalf("actual partition command %s exited %d: %s", kind, code, stderr.String())
			}
			if want != 0 {
				if stdout.Len() != 0 || bytes.Contains(stderr.Bytes(), []byte(dir)) {
					t.Fatal("refused command exposed success or a local path")
				}
				return
			}
			var measured stateaudit.PartitionedSummary
			if bound {
				var result stateaudit.BoundPartitionedSummary
				if json.Unmarshal(stdout.Bytes(), &result) != nil || result.Bound.Checkpoint.StateRoot != root.Hex() {
					t.Fatal("partition lost accepted snapshot context")
				}
				measured = result.Partition
			} else if json.Unmarshal(stdout.Bytes(), &measured) != nil {
				t.Fatal("partition summary unavailable")
			}
			if measured.Summary.NativeBalanceWei != "2469" || measured.PartitionSHA256 != pin || len(measured.Groups) != 2 || measured.Groups[0].NativeBalanceWei != "1234" || measured.Groups[1].NativeBalanceWei != "1235" || measured.Groups[1].PresentAccounts != 1 || measured.Groups[1].SelectedAccounts != 2 || measured.RemainderAccounts != 0 || measured.RemainderBalanceWei != "0" {
				t.Fatalf("actual command did not preserve complete partition: %+v", measured)
			}
			for _, group := range policy.Groups {
				for _, address := range group.Addresses {
					if bytes.Contains(stdout.Bytes(), []byte(address)) {
						t.Fatal("aggregate command exposed selected addresses")
					}
				}
			}
		})
	}
}
