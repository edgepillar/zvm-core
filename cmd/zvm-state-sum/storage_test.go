package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/stateaudit"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

func storageCommandFixture(t *testing.T) (common.Hash, []byte, stateaudit.StoragePolicy, stateaudit.StorageWitness) {
	t.Helper()
	db := state.NewDatabaseForTesting()
	t.Cleanup(func() { db.TrieDB().Close() })
	s, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatal(err)
	}
	address := common.BigToAddress(big.NewInt(4096))
	origin := common.BigToAddress(big.NewInt(4097))
	code := []byte{0x60, 0x2a, 0x60, 0x00, 0x55, 0x60, 0x07, 0x60, 0x01, 0x55, 0x00}
	s.SetCode(address, code, 0)
	s.SetBalance(address, uint256.NewInt(1234), 0)
	s.SetBalance(origin, uint256.NewInt(1235), 0)
	s.SetNonce(address, 1, 0)
	s.SetNonce(origin, 1, 0)
	if _, _, err := runtime.Call(address, nil, &runtime.Config{State: s, Origin: origin, Value: new(big.Int), GasLimit: 100000}); err != nil {
		t.Fatal(err)
	}
	root, err := s.Commit(1, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TrieDB().Commit(root, false); err != nil {
		t.Fatal(err)
	}
	limits := stateaudit.Limits{MaxEncodedBytes: 2 << 20, MaxNodes: 1000, MaxAccounts: 1000, MaxSteps: 10000}
	tree, err := db.OpenTrie(root)
	if err != nil {
		t.Fatal(err)
	}
	iterator, err := tree.NodeIterator(nil)
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := stateaudit.Collect(context.Background(), root, iterator, limits)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := stateaudit.Encode(context.Background(), &encoded, w, limits); err != nil {
		t.Fatal(err)
	}
	policy := stateaudit.StoragePolicy{Schema: 1, Accounts: []stateaudit.StorageAccount{{ID: "selected", Address: hexutil.Encode(address[:]), CodeHash: crypto.Keccak256Hash(code).Hex(), Slots: []stateaudit.StorageSlot{{ID: "answer", Key: (common.Hash{}).Hex()}, {ID: "other", Key: common.BigToHash(big.NewInt(1)).Hex()}, {ID: "zero", Key: common.BigToHash(big.NewInt(9)).Hex()}}}}}
	sl := stateaudit.StorageLimits{MaxAccounts: 64, MaxSlots: 1024, MaxProofNodes: 8192, MaxProofBytes: 2 << 20, MaxProofSteps: 65536}
	collector, err := stateaudit.NewStorageProofCollector(context.Background(), sl)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := state.New(root, db)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := reader.OpenStorageTrie(address)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range policy.Accounts[0].Slots {
		key := common.HexToHash(slot.Key)
		if err := storage.Prove(crypto.Keccak256(key[:]), collector); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := collector.Witness()
	if err != nil {
		t.Fatal(err)
	}
	return root, encoded.Bytes(), policy, proof
}
func TestActualCommandVerifiesSameRootCodeAndStorageWithOptionalBalancePartitions(t *testing.T) {
	binary := os.Getenv("ZVM_STATE_SUM_BINARY")
	if binary == "" {
		t.Skip("dedicated workflow builds the real standalone verifier")
	}
	root, witnessRaw, storagePolicy, proof := storageCommandFixture(t)
	snapshotPolicy, snapshot, _ := boundCommandFixture(t, root, witnessRaw)
	limits := stateaudit.Limits{MaxEncodedBytes: 2 << 20, MaxNodes: 1000, MaxAccounts: 1000, MaxSteps: 10000}
	bounds := stateaudit.BindingLimits{MaxDocumentBytes: 8 << 20, MaxHeaders: 256, MaxHeaderBytes: 8192}
	storageLimits := stateaudit.StorageLimits{MaxAccounts: 64, MaxSlots: 1024, MaxProofNodes: 8192, MaxProofBytes: 2 << 20, MaxProofSteps: 65536}
	witness, err := stateaudit.Decode(context.Background(), bytes.NewReader(witnessRaw), limits)
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	if err := stateaudit.EncodeInput(context.Background(), &frame, snapshotPolicy, snapshot, nil, witness, limits, bounds); err != nil {
		t.Fatal(err)
	}
	partition := stateaudit.PartitionPolicy{Schema: 1, Groups: []stateaudit.PartitionGroup{{ID: "selected", Addresses: []string{storagePolicy.Accounts[0].Address}}}}
	partitionLimits := stateaudit.PartitionLimits{MaxGroups: 64, MaxAddresses: 4096}
	partitionPin, err := partition.Fingerprint(partitionLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"root-stdin", "root-file", "bound-files", "framed-stdin", "combined-root", "combined-framed", "wrong-pin", "changed-code", "missing-policy", "missing-pin", "missing-proof", "omitted-node", "extra-node", "duplicate-node", "reordered", "malformed-proof", "truncated-account", "trailing-account", "node-cap", "byte-cap", "step-cap", "slot-cap", "root-mismatch", "framed-root-override", "context-cap"} {
		t.Run(kind, func(t *testing.T) {
			var selected stateaudit.StoragePolicy
			raw, _ := json.Marshal(storagePolicy)
			json.Unmarshal(raw, &selected)
			var nodes stateaudit.StorageWitness
			raw, _ = json.Marshal(proof)
			json.Unmarshal(raw, &nodes)
			if kind == "changed-code" {
				selected.Accounts[0].CodeHash = "0x" + strings.Repeat("1", 64)
			}
			pin, err := selected.Fingerprint(storageLimits)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "omitted-node":
				nodes.Nodes = nodes.Nodes[1:]
			case "extra-node":
				path := append([]byte{0x20}, bytes.Repeat([]byte{0x11}, 32)...)
				node, _ := rlp.EncodeToBytes([]any{path, []byte{2}})
				nodes.Nodes = append(nodes.Nodes, node)
				sort.Slice(nodes.Nodes, func(i, j int) bool {
					a, b := crypto.Keccak256Hash(nodes.Nodes[i]), crypto.Keccak256Hash(nodes.Nodes[j])
					return bytes.Compare(a[:], b[:]) < 0
				})
			case "duplicate-node":
				nodes.Nodes = append(nodes.Nodes, nodes.Nodes[len(nodes.Nodes)-1])
			case "reordered":
				nodes.Nodes[0], nodes.Nodes[1] = nodes.Nodes[1], nodes.Nodes[0]
			case "malformed-proof":
				nodes.Nodes = []hexutil.Bytes{{0x80}}
			}
			dir := t.TempDir()
			policyPath, proofPath := filepath.Join(dir, "storage-policy.json"), filepath.Join(dir, "storage-proof.json")
			policyRaw, _ := json.Marshal(selected)
			proofRaw, _ := json.Marshal(nodes)
			if os.WriteFile(policyPath, policyRaw, 0600) != nil || os.WriteFile(proofPath, proofRaw, 0600) != nil {
				t.Fatal("owned storage sidecar fixture")
			}
			base := []string{"-storage-policy", policyPath, "-storage-policy-sha256", pin, "-storage-witness", proofPath}
			args := append(append([]string{}, base...), "-state-root", root.Hex(), "-input", "-")
			data := bytes.Clone(witnessRaw)
			want := 1
			bound, combined := false, false
			switch kind {
			case "root-stdin":
				want = 0
			case "root-file":
				path := filepath.Join(dir, "witness.bin")
				if os.WriteFile(path, data, 0600) != nil {
					t.Fatal("owned witness fixture")
				}
				args[len(args)-1] = path
				data = nil
				want = 0
			case "bound-files":
				policyFile, snapshotFile := filepath.Join(dir, "snapshot-policy.json"), filepath.Join(dir, "snapshot.json")
				p, _ := json.Marshal(snapshotPolicy)
				s, _ := json.Marshal(snapshot)
				if os.WriteFile(policyFile, p, 0600) != nil || os.WriteFile(snapshotFile, s, 0600) != nil {
					t.Fatal("owned bound fixture")
				}
				args = append(base, "-snapshot-policy", policyFile, "-snapshot", snapshotFile, "-input", "-")
				want = 0
				bound = true
			case "framed-stdin":
				args = append(base, "-bundle-stdin")
				data = bytes.Clone(frame.Bytes())
				want = 0
				bound = true
			case "combined-root":
				want = 0
				combined = true
			case "combined-framed":
				args = append(base, "-bundle-stdin")
				data = bytes.Clone(frame.Bytes())
				want = 0
				bound = true
				combined = true
			case "wrong-pin":
				args[3] = strings.Repeat("a", 64)
			case "changed-code", "omitted-node", "extra-node", "duplicate-node", "reordered", "malformed-proof":
			case "missing-policy":
				args = args[2:]
				want = 2
			case "missing-pin":
				args = append(args[:2], args[4:]...)
				want = 2
			case "missing-proof":
				args = append(args[:4], args[6:]...)
				want = 2
			case "truncated-account":
				data = data[:len(data)-1]
			case "trailing-account":
				data = append(data, 0)
			case "node-cap":
				args = append(args, "-max-storage-nodes", "1")
			case "byte-cap":
				args = append(args, "-max-storage-bytes", "1")
			case "step-cap":
				args = append(args, "-max-storage-steps", "1")
			case "slot-cap":
				args = append(args, "-max-storage-slots", "2")
			case "root-mismatch":
				args[7] = "0x" + strings.Repeat("1", 64)
			case "framed-root-override":
				args = append(args, "-bundle-stdin")
				data = bytes.Clone(frame.Bytes())
				want = 2
			case "context-cap":
				args = append(args, "-max-context-bytes", "16")
			}
			if combined {
				path := filepath.Join(dir, "partition.json")
				p, _ := json.Marshal(partition)
				if os.WriteFile(path, p, 0600) != nil {
					t.Fatal("owned partition fixture")
				}
				args = append(args, "-partition-policy", path, "-partition-policy-sha256", partitionPin)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, args...)
			command.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0 halt_on_error=1 exitcode=87")
			command.Stdin = bytes.NewReader(data)
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			err = command.Run()
			code := 0
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if ctx.Err() != nil || code != want {
				t.Fatalf("storage command %s: exit %d %s", kind, code, stderr.String())
			}
			if want != 0 {
				if stdout.Len() != 0 || bytes.Contains(stderr.Bytes(), []byte(dir)) {
					t.Fatal("refused command emitted success or a private path")
				}
				return
			}
			var result stateaudit.MeasurementsSummary
			if bound {
				var output stateaudit.BoundMeasurementsSummary
				if json.Unmarshal(stdout.Bytes(), &output) != nil || output.Bound.Checkpoint.StateRoot != root.Hex() {
					t.Fatal("storage command lost accepted snapshot binding")
				}
				result = output.Measurements
			} else if json.Unmarshal(stdout.Bytes(), &result) != nil {
				t.Fatal("storage summary unavailable")
			}
			if result.Summary.StateRoot != root || result.Summary.NativeBalanceWei != "2469" || result.Storage.StateRoot != root || result.Storage.PolicySHA256 != pin || len(result.Storage.Accounts) != 1 {
				t.Fatalf("same-root measurements incomplete: %+v", result)
			}
			values := result.Storage.Accounts[0].Slots
			if len(values) != 3 || values[0].ValueUint256 != "42" || !values[0].Present || values[1].ValueUint256 != "7" || !values[1].Present || values[2].ValueUint256 != "0" || values[2].Present {
				t.Fatal("actual command did not prove storage values and absence")
			}
			if combined {
				if result.Partition == nil || result.Partition.PartitionSHA256 != partitionPin || result.Partition.Groups[0].NativeBalanceWei != "1234" || result.Partition.RemainderBalanceWei != "1235" {
					t.Fatal("combined groups did not share complete state")
				}
			} else if result.Partition != nil {
				t.Fatal("command inferred an unconfigured balance partition")
			}
			if bytes.Contains(stdout.Bytes(), []byte(selected.Accounts[0].Address)) {
				t.Fatal("measurement output exposed the selected address")
			}
		})
	}
}
