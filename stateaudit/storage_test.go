package stateaudit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/l2"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

var storageLimits = StorageLimits{MaxAccounts: 64, MaxSlots: 1024, MaxProofNodes: 8192, MaxProofBytes: 2 << 20, MaxProofSteps: 65536}

type storageFixture struct {
	root    common.Hash
	db      *state.CachingDB
	witness Witness
	proof   StorageWitness
	policy  MeasurementPolicy
	bridge  *abi.ABI
	fees    *abi.ABI
}

func storageSlotKey(n uint64) string         { return common.BigToHash(new(big.Int).SetUint64(n)).Hex() }
func storageAddress(a common.Address) string { return hexutil.Encode(a[:]) }
func proofFromState(t *testing.T, s *state.StateDB, policy StoragePolicy) StorageWitness {
	t.Helper()
	collector, err := NewStorageProofCollector(context.Background(), storageLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range policy.Accounts {
		tree, err := s.OpenStorageTrie(common.HexToAddress(account.Address))
		if err != nil {
			t.Fatal(err)
		}
		for _, slot := range account.Slots {
			key := common.HexToHash(slot.Key)
			if err := tree.Prove(crypto.Keccak256(key[:]), collector); err != nil {
				t.Fatal(err)
			}
		}
	}
	proof, err := collector.Witness()
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
func storageContractFixture(t *testing.T, phase int) storageFixture {
	t.Helper()
	db := state.NewDatabaseForTesting()
	t.Cleanup(func() { db.TrieDB().Close() })
	s, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatal(err)
	}
	bridgeCode, err := l2.PredeployCode("ZVMBridge")
	if err != nil {
		t.Fatal(err)
	}
	feeCode := rollup.FeesArtifact.RuntimeCode()
	if len(feeCode) == 0 {
		t.Fatal("committed fee runtime unavailable")
	}
	bridgeABIBytes, err := os.ReadFile("../derive/testdata/ZVMBridge.abi.json")
	if err != nil {
		t.Fatal(err)
	}
	var bridgeArtifact struct {
		Contracts map[string]struct {
			ABI json.RawMessage `json:"abi"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal(bridgeABIBytes, &bridgeArtifact); err != nil {
		t.Fatal(err)
	}
	bridgeABIBytes = bridgeArtifact.Contracts["src/ZVMBridge.sol:ZVMBridge"].ABI
	if len(bridgeABIBytes) == 0 {
		t.Fatal("committed bridge ABI entry unavailable")
	}
	bridgeABI, err := abi.JSON(bytes.NewReader(bridgeABIBytes))
	if err != nil {
		t.Fatal(err)
	}
	feesABI, err := abi.JSON(bytes.NewReader(rollup.FeesArtifact.ABI))
	if err != nil {
		t.Fatal(err)
	}
	user := common.HexToAddress(partitionAddress(4096))
	relayer := common.HexToAddress(partitionAddress(4097))
	recipient := common.HexToAddress(partitionAddress(4098))
	s.SetBalance(user, uint256.MustFromBig(new(big.Int).Lsh(big.NewInt(1), 255)), 0)
	s.SetNonce(user, 1, 0)
	s.SetNonce(relayer, 1, 0)
	s.SetCode(rollup.BridgeAddr, bridgeCode, 0)
	s.SetCode(rollup.FeeSplitterAddr, feeCode, 0)
	s.SetBalance(rollup.FeeSplitterAddr, uint256.NewInt(100000000000), 0)
	s.SetState(rollup.BridgeAddr, common.BigToHash(big.NewInt(10)), common.BigToHash(big.NewInt(250)))
	s.SetState(rollup.BridgeAddr, common.BigToHash(big.NewInt(11)), common.BigToHash(big.NewInt(1)))
	call := func(contract, origin common.Address, parsed abi.ABI, method string, value *big.Int, args ...any) []byte {
		t.Helper()
		data, err := parsed.Pack(method, args...)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := runtime.Call(contract, data, &runtime.Config{State: s, Origin: origin, Value: value, GasLimit: 3000000})
		if err != nil {
			t.Fatalf("owned %s call: %v", method, err)
		}
		return out
	}
	if phase >= 1 {
		out := call(rollup.BridgeAddr, user, bridgeABI, "withdrawZNN", big.NewInt(1000000000000), recipient)
		if new(big.Int).SetBytes(out).Uint64() != 1 {
			t.Fatal("owned withdrawal id changed")
		}
	}
	if phase >= 2 {
		hash := crypto.Keccak256Hash([]byte("owned paid fixture"))
		var znn [10]byte
		copy(znn[:], common.FromHex("0x14e66318c6318c6318c6"))
		call(rollup.BridgeAddr, rollup.SystemDepositor, bridgeABI, "markPaid", new(big.Int), big.NewInt(1), [32]byte(hash), recipient, znn, big.NewInt(98))
	}
	if phase >= 3 {
		call(rollup.FeeSplitterAddr, rollup.SystemDepositor, feesABI, "settle", new(big.Int), big.NewInt(100), []common.Address{relayer}, []*big.Int{big.NewInt(1)})
	}
	if phase >= 4 {
		call(rollup.FeeSplitterAddr, relayer, feesABI, "withdraw", new(big.Int), recipient)
	}
	if phase >= 5 {
		hash := crypto.Keccak256Hash([]byte("owned burn mirror fixture"))
		call(rollup.FeeSplitterAddr, rollup.SystemDepositor, feesABI, "markBurnedOnNoM", new(big.Int), [32]byte(hash), big.NewInt(50000000000))
	}
	root, err := s.Commit(1, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TrieDB().Commit(root, false); err != nil {
		t.Fatal(err)
	}
	reader, err := state.New(root, db)
	if err != nil {
		t.Fatal(err)
	}
	policy := StoragePolicy{Schema: 1, Accounts: []StorageAccount{
		{ID: "bridge", Address: storageAddress(rollup.BridgeAddr), CodeHash: crypto.Keccak256Hash(bridgeCode).Hex(), Slots: []StorageSlot{{ID: "fees", Key: storageSlotKey(8)}, {ID: "paid", Key: storageSlotKey(3)}, {ID: "pending", Key: storageSlotKey(1)}, {ID: "zero", Key: storageSlotKey(255)}}},
		{ID: "fees", Address: storageAddress(rollup.FeeSplitterAddr), CodeHash: crypto.Keccak256Hash(feeCode).Hex(), Slots: []StorageSlot{{ID: "burned", Key: storageSlotKey(3)}, {ID: "collected", Key: storageSlotKey(0)}, {ID: "mirrored", Key: storageSlotKey(4)}, {ID: "owed", Key: storageSlotKey(1)}, {ID: "paid", Key: storageSlotKey(2)}, {ID: "zero", Key: storageSlotKey(255)}}},
	}}
	partition := PartitionPolicy{Schema: 1, Groups: []PartitionGroup{{ID: "selected-contracts", Addresses: []string{policy.Accounts[0].Address, policy.Accounts[1].Address}}}}
	sort.Strings(partition.Groups[0].Addresses)
	pin, err := policy.Fingerprint(storageLimits)
	if err != nil {
		t.Fatal(err)
	}
	partPin := partitionPin(t, partition)
	tree, err := db.OpenTrie(root)
	if err != nil {
		t.Fatal(err)
	}
	iterator, err := tree.NodeIterator(nil)
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := Collect(context.Background(), root, iterator, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	return storageFixture{root: root, db: db, witness: w, proof: proofFromState(t, reader, policy), policy: MeasurementPolicy{Storage: policy, StorageSHA256: pin, Partition: &PinnedPartition{Policy: partition, SHA256: partPin, Limits: partitionLimits}}, bridge: &bridgeABI, fees: &feesABI}
}
func storageVerify(f storageFixture) (MeasurementsSummary, error) {
	return VerifyMeasurements(context.Background(), f.root, f.policy, f.proof, f.witness, testLimits, storageLimits)
}
func assertStorageOracle(t *testing.T, f storageFixture, result MeasurementsSummary) {
	t.Helper()
	reader, err := state.New(f.root, f.db)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.StateRoot != f.root || result.Storage.StateRoot != f.root || result.Storage.PolicySHA256 != f.policy.StorageSHA256 || len(result.Storage.Accounts) != len(f.policy.Storage.Accounts) || result.Partition == nil || result.Partition.Summary != result.Summary {
		t.Fatal("code/storage and balance groups lost their common complete root")
	}
	for i, account := range f.policy.Storage.Accounts {
		got := result.Storage.Accounts[i]
		address := common.HexToAddress(account.Address)
		if got.ID != account.ID || got.CodeHash != reader.GetCodeHash(address).Hex() || got.StorageRoot != reader.GetStorageRoot(address).Hex() || got.NativeBalanceWei != reader.GetBalance(address).ToBig().String() {
			t.Fatal("account measurement differs from geth StateDB oracle")
		}
		for j, slot := range account.Slots {
			value := reader.GetState(address, common.HexToHash(slot.Key))
			if got.Slots[j].ID != slot.ID || got.Slots[j].ValueUint256 != new(big.Int).SetBytes(value[:]).String() || got.Slots[j].Present != (value != (common.Hash{})) {
				t.Fatalf("slot differs from committed geth state: %+v", got.Slots[j])
			}
		}
	}
	raw := encJSON(result)
	for _, account := range f.policy.Storage.Accounts {
		if bytes.Contains(raw, []byte(account.Address)) {
			t.Fatal("measurement output exposed address selection")
		}
	}
}
func TestStorageMeasurementsFollowCommittedBridgeAndFeeRuntimeTransitions(t *testing.T) {
	for phase, name := range []string{"initial", "pending", "paid", "settled", "withdrawn", "mirrored"} {
		t.Run(name, func(t *testing.T) {
			f := storageContractFixture(t, phase)
			before := encJSON(struct {
				Policy  MeasurementPolicy
				Proof   StorageWitness
				Witness Witness
			}{f.policy, f.proof, f.witness})
			result, err := storageVerify(f)
			if err != nil {
				t.Fatal(err)
			}
			assertStorageOracle(t, f, result)
			if !bytes.Equal(before, encJSON(struct {
				Policy  MeasurementPolicy
				Proof   StorageWitness
				Witness Witness
			}{f.policy, f.proof, f.witness})) {
				t.Fatal("measurement verification mutated retained inputs")
			}
			bridge, fees := result.Storage.Accounts[0], result.Storage.Accounts[1]
			wantPending, wantPaid, wantFees := "0", "0", "0"
			if phase >= 1 {
				wantPending, wantFees = "98", "2"
			}
			if phase >= 2 {
				wantPending, wantPaid = "0", "98"
			}
			if bridge.Slots[0].ValueUint256 != wantFees || bridge.Slots[1].ValueUint256 != wantPaid || bridge.Slots[2].ValueUint256 != wantPending || bridge.Slots[3].Present {
				t.Fatal("bridge raw counter transition differs from committed runtime")
			}
			if phase >= 1 && bridge.NativeBalanceWei != "1000000000000" {
				t.Fatal("payment marking changed the retained native bridge lock")
			}
			if phase >= 3 && (fees.Slots[0].ValueUint256 != "50000000000" || fees.Slots[1].ValueUint256 != "100000000000") {
				t.Fatal("settled fee counters differ from runtime")
			}
			if phase == 3 && fees.Slots[3].ValueUint256 != "50000000000" {
				t.Fatal("relayer owed disappeared from storage measurement")
			}
			if phase >= 4 && (fees.Slots[3].ValueUint256 != "0" || fees.Slots[4].ValueUint256 != "50000000000") {
				t.Fatal("withdrawal raw counters differ from runtime")
			}
			if phase == 5 && fees.Slots[2].ValueUint256 != "50000000000" {
				t.Fatal("burn mirror raw value was not measured")
			}
		})
	}
}
func TestStorageProofsRejectOmittedExtraMixedOrMalformedEvidenceWithoutPartialResults(t *testing.T) {
	f := storageContractFixture(t, 3)
	other := storageContractFixture(t, 4)
	for _, kind := range []string{"omitted-node", "extra-node", "duplicate-node", "unordered", "mixed-state", "wrong-code", "missing-account", "changed-policy", "changed-slot", "node-cap", "byte-cap", "step-cap", "account-cap", "slot-cap", "incomplete-account-state", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			policy := f.policy
			policy.Storage = StoragePolicy{}
			json.Unmarshal(encJSON(f.policy.Storage), &policy.Storage)
			proof := StorageWitness{}
			json.Unmarshal(encJSON(f.proof), &proof)
			w := f.witness
			limits := storageLimits
			ctx := context.Background()
			switch kind {
			case "omitted-node":
				proof.Nodes = proof.Nodes[1:]
			case "extra-node":
				for _, node := range other.proof.Nodes {
					hash := crypto.Keccak256Hash(node)
					found := false
					for _, old := range proof.Nodes {
						found = found || crypto.Keccak256Hash(old) == hash
					}
					if !found {
						proof.Nodes = append(proof.Nodes, node)
						break
					}
				}
				sort.Slice(proof.Nodes, func(i, j int) bool {
					a, b := crypto.Keccak256Hash(proof.Nodes[i]), crypto.Keccak256Hash(proof.Nodes[j])
					return bytes.Compare(a[:], b[:]) < 0
				})
			case "duplicate-node":
				proof.Nodes = append(proof.Nodes, proof.Nodes[len(proof.Nodes)-1])
			case "unordered":
				proof.Nodes[0], proof.Nodes[1] = proof.Nodes[1], proof.Nodes[0]
			case "mixed-state":
				proof = other.proof
			case "wrong-code":
				policy.Storage.Accounts[0].CodeHash = "0x" + strings.Repeat("1", 64)
				policy.StorageSHA256, _ = policy.Storage.Fingerprint(limits)
			case "missing-account":
				policy.Storage.Accounts[0].Address = partitionAddress(39321)
				policy.StorageSHA256, _ = policy.Storage.Fingerprint(limits)
			case "changed-policy":
				policy.StorageSHA256 = strings.Repeat("a", 64)
			case "changed-slot":
				policy.Storage.Accounts[0].Slots[0].Key = storageSlotKey(9)
			case "node-cap":
				limits.MaxProofNodes = 1
			case "byte-cap":
				limits.MaxProofBytes = 1
			case "step-cap":
				limits.MaxProofSteps = 1
			case "account-cap":
				limits.MaxAccounts = 1
			case "slot-cap":
				limits.MaxSlots = 1
			case "incomplete-account-state":
				w.Nodes = w.Nodes[1:]
			case "canceled":
				bounded, cancel := context.WithCancel(ctx)
				cancel()
				ctx = bounded
			}
			if result, err := VerifyMeasurements(ctx, f.root, policy, proof, w, testLimits, limits); err == nil || !reflect.DeepEqual(result, MeasurementsSummary{}) {
				t.Fatalf("refused %s produced a partial measurement: %v", kind, err)
			}
		})
	}
	for i := range f.proof.Nodes {
		proof := StorageWitness{Schema: 1, Nodes: append(append([]hexutil.Bytes{}, f.proof.Nodes[:i]...), f.proof.Nodes[i+1:]...)}
		if _, err := VerifyMeasurements(context.Background(), f.root, f.policy, proof, f.witness, testLimits, storageLimits); err == nil {
			t.Fatal("omitting a required union node did not fail closed")
		}
	}
}
func TestStoragePolicyAndWitnessJSONAreExactCanonicalBoundedAndPinned(t *testing.T) {
	f := storageContractFixture(t, 3)
	raw := encJSON(f.policy.Storage)
	for _, kind := range []string{"schema-alias", "duplicate", "missing", "null", "unknown", "account-order", "account-overlap", "slot-order", "slot-overlap", "address-case", "short-key", "code-zero", "empty-slots", "large-accounts", "large-slots", "large-nodes", "large-bytes", "large-steps", "zero-limit"} {
		t.Run(kind, func(t *testing.T) {
			var policy StoragePolicy
			json.Unmarshal(raw, &policy)
			limits := storageLimits
			bad := bytes.Clone(raw)
			jsonOnly := false
			switch kind {
			case "schema-alias":
				bad = bytes.Replace(bad, []byte(`"schema"`), []byte(`"Schema"`), 1)
				jsonOnly = true
			case "duplicate":
				bad = bytes.Replace(bad, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
				jsonOnly = true
			case "missing":
				bad = bytes.Replace(bad, []byte(`"schema":1,`), nil, 1)
				jsonOnly = true
			case "null":
				bad = bytes.Replace(bad, []byte(`"schema":1`), []byte(`"schema":null`), 1)
				jsonOnly = true
			case "unknown":
				bad = append([]byte(`{"extra":1,`), bad[1:]...)
				jsonOnly = true
			case "account-order":
				policy.Accounts[0], policy.Accounts[1] = policy.Accounts[1], policy.Accounts[0]
			case "account-overlap":
				policy.Accounts[1].Address = policy.Accounts[0].Address
			case "slot-order":
				policy.Accounts[0].Slots[0], policy.Accounts[0].Slots[1] = policy.Accounts[0].Slots[1], policy.Accounts[0].Slots[0]
			case "slot-overlap":
				policy.Accounts[0].Slots[1].Key = policy.Accounts[0].Slots[0].Key
			case "address-case":
				policy.Accounts[0].Address = "0x" + strings.Repeat("A", 40)
			case "short-key":
				policy.Accounts[0].Slots[0].Key = "0x00"
			case "code-zero":
				policy.Accounts[0].CodeHash = "0x" + strings.Repeat("0", 64)
			case "empty-slots":
				policy.Accounts[0].Slots = nil
			case "large-accounts":
				limits.MaxAccounts = 65
			case "large-slots":
				limits.MaxSlots = 1025
			case "large-nodes":
				limits.MaxProofNodes = 65537
			case "large-bytes":
				limits.MaxProofBytes = (16 << 20) + 1
			case "large-steps":
				limits.MaxProofSteps = 131073
			case "zero-limit":
				limits.MaxProofSteps = 0
			}
			if !jsonOnly {
				bad = encJSON(policy)
			}
			if got, err := DecodeStoragePolicy(bad, 1<<20, limits); err == nil || !reflect.DeepEqual(got, StoragePolicy{}) {
				t.Fatal("invalid storage policy acquired authority")
			}
		})
	}
	encoded := encJSON(f.proof)
	decoded, err := DecodeStorageWitness(context.Background(), encoded, 8<<20, storageLimits)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := decoded.Fingerprint(context.Background(), storageLimits)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := f.proof.Fingerprint(context.Background(), storageLimits)
	if pin != original {
		t.Fatal("storage proof codec changed its canonical digest")
	}
	for _, kind := range []string{"alias", "duplicate", "null", "uppercase-hex", "trailing", "document-cap"} {
		t.Run("proof-"+kind, func(t *testing.T) {
			bad := bytes.Clone(encoded)
			cap := uint64(8 << 20)
			switch kind {
			case "alias":
				bad = bytes.Replace(bad, []byte(`"nodes"`), []byte(`"Nodes"`), 1)
			case "duplicate":
				bad = bytes.Replace(bad, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
			case "null":
				bad = []byte(`{"schema":1,"nodes":null}`)
			case "uppercase-hex":
				bad = bytes.Replace(bad, []byte(hexutil.Encode(f.proof.Nodes[0])), []byte("0x"+strings.ToUpper(hex.EncodeToString(f.proof.Nodes[0]))), 1)
			case "trailing":
				bad = append(bad, []byte(` {}`)...)
			case "document-cap":
				cap = 1
			}
			if got, err := DecodeStorageWitness(context.Background(), bad, cap, storageLimits); err == nil || !reflect.DeepEqual(got, StorageWitness{}) {
				t.Fatal("ambiguous proof JSON became bounded evidence")
			}
		})
	}
}

func syntheticStorageMeasurement(t *testing.T, nodes []hexutil.Bytes, storageRoot common.Hash) (common.Hash, MeasurementPolicy, Witness, StorageWitness) {
	t.Helper()
	address := common.HexToAddress(partitionAddress(4096))
	code := crypto.Keccak256Hash([]byte{0x00})
	account := types.StateAccount{Nonce: 1, Balance: uint256.NewInt(7), Root: storageRoot, CodeHash: code[:]}
	accountRaw, err := rlp.EncodeToBytes(&account)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.Keccak256(address[:])
	path := append([]byte{0x20}, key...)
	leaf, err := rlp.EncodeToBytes([]any{path, accountRaw})
	if err != nil {
		t.Fatal(err)
	}
	root := crypto.Keccak256Hash(leaf)
	policy := StoragePolicy{Schema: 1, Accounts: []StorageAccount{{ID: "selected", Address: storageAddress(address), CodeHash: code.Hex(), Slots: []StorageSlot{{ID: "counter", Key: storageSlotKey(0)}}}}}
	pin, err := policy.Fingerprint(storageLimits)
	if err != nil {
		t.Fatal(err)
	}
	return root, MeasurementPolicy{Storage: policy, StorageSHA256: pin}, Witness{StateRoot: root, Nodes: [][]byte{leaf}}, StorageWitness{Schema: 1, Nodes: nodes}
}
func TestStorageCanonicalUint256MaximumAndExplicitEmptyRoot(t *testing.T) {
	for _, kind := range []string{"empty-root", "maximum"} {
		t.Run(kind, func(t *testing.T) {
			nodes := make([]hexutil.Bytes, 0)
			root := types.EmptyRootHash
			want := "0"
			present := false
			if kind == "maximum" {
				value := bytes.Repeat([]byte{0xff}, 32)
				encoded, _ := rlp.EncodeToBytes(value)
				slot := common.Hash{}
				path := append([]byte{0x20}, crypto.Keccak256(slot[:])...)
				node, _ := rlp.EncodeToBytes([]any{path, encoded})
				nodes = append(nodes, node)
				root = crypto.Keccak256Hash(node)
				want = new(big.Int).SetBytes(value).String()
				present = true
			}
			stateRoot, policy, w, proof := syntheticStorageMeasurement(t, nodes, root)
			result, err := VerifyMeasurements(context.Background(), stateRoot, policy, proof, w, testLimits, storageLimits)
			if err != nil || result.Partition != nil || result.Storage.Accounts[0].Slots[0].ValueUint256 != want || result.Storage.Accounts[0].Slots[0].Present != present {
				t.Fatalf("raw uint256 measurement changed: %+v %v", result, err)
			}
		})
	}
}
func TestStorageProofCanonicalShapeCannotTurnMalformedValuesIntoAbsence(t *testing.T) {
	slot := common.Hash{}
	path := append([]byte{0x20}, crypto.Keccak256(slot[:])...)
	for _, kind := range []string{"zero-leaf", "leading-zero", "too-large", "noncanonical-integer", "invalid-path", "unary-branch", "prefix-value", "empty-extension", "wrong-node-shape"} {
		t.Run(kind, func(t *testing.T) {
			value, _ := rlp.EncodeToBytes([]byte{1})
			compact := bytes.Clone(path)
			switch kind {
			case "zero-leaf":
				value = []byte{0x80}
			case "leading-zero":
				value, _ = rlp.EncodeToBytes([]byte{0, 1})
			case "too-large":
				value, _ = rlp.EncodeToBytes(bytes.Repeat([]byte{0xff}, 33))
			case "noncanonical-integer":
				value = []byte{0x81, 0x01}
			case "invalid-path":
				compact[0] = 0x40
			}
			node, _ := rlp.EncodeToBytes([]any{compact, value})
			if kind == "unary-branch" || kind == "prefix-value" {
				parts := make([]any, 17)
				for i := range parts {
					parts[i] = []byte{}
				}
				parts[0] = bytes.Repeat([]byte{1}, 32)
				if kind == "prefix-value" {
					parts[1] = bytes.Repeat([]byte{2}, 32)
					parts[16] = []byte{1}
				}
				node, _ = rlp.EncodeToBytes(parts)
			}
			if kind == "empty-extension" {
				node, _ = rlp.EncodeToBytes([]any{[]byte{0x00}, bytes.Repeat([]byte{1}, 32)})
			}
			if kind == "wrong-node-shape" {
				node, _ = rlp.EncodeToBytes([]any{[]byte{1}, []byte{2}, []byte{3}})
			}
			root, policy, w, proof := syntheticStorageMeasurement(t, []hexutil.Bytes{node}, crypto.Keccak256Hash(node))
			if result, err := VerifyMeasurements(context.Background(), root, policy, proof, w, testLimits, storageLimits); err == nil || !reflect.DeepEqual(result, MeasurementsSummary{}) {
				t.Fatal("malformed sparse proof became a zero or partial result")
			}
		})
	}
}
func TestStorageCollectorDeduplicatesCopiesAndRefusesPartialOutputAfterSourceErrors(t *testing.T) {
	path := append([]byte{0x20}, bytes.Repeat([]byte{1}, 32)...)
	value, _ := rlp.EncodeToBytes([]byte{1})
	node, _ := rlp.EncodeToBytes([]any{path, value})
	hash := crypto.Keccak256Hash(node)
	c, err := NewStorageProofCollector(context.Background(), storageLimits)
	if err != nil {
		t.Fatal(err)
	}
	source := bytes.Clone(node)
	if c.Put(hash[:], source) != nil || c.Put(hash[:], source) != nil {
		t.Fatal("repeated identical source blob was not deduplicated")
	}
	source[0] ^= 1
	proof, err := c.Witness()
	if err != nil || len(proof.Nodes) != 1 || !bytes.Equal(proof.Nodes[0], node) {
		t.Fatal("collector aliased source memory or repeated a blob")
	}
	if c.Put(hash[:], node) == nil {
		t.Fatal("finalized collector accepted another source mutation")
	}
	for _, kind := range []string{"hash", "node-bytes", "byte-budget", "node-budget", "delete", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			limits := storageLimits
			if kind == "byte-budget" {
				limits.MaxProofBytes = 1
			}
			if kind == "node-budget" {
				limits.MaxProofNodes = 1
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			collector, err := NewStorageProofCollector(ctx, limits)
			if err != nil {
				t.Fatal(err)
			}
			var problem error
			switch kind {
			case "hash":
				problem = collector.Put(make([]byte, 32), node)
			case "node-bytes":
				huge := bytes.Repeat([]byte{1}, maxNodeBytes+1)
				h := crypto.Keccak256Hash(huge)
				problem = collector.Put(h[:], huge)
			case "byte-budget":
				problem = collector.Put(hash[:], node)
			case "node-budget":
				if collector.Put(hash[:], node) != nil {
					t.Fatal("first bounded source blob")
				}
				other := bytes.Clone(node)
				other[len(other)-1] = 2
				h := crypto.Keccak256Hash(other)
				problem = collector.Put(h[:], other)
			case "delete":
				problem = collector.Delete(hash[:])
			case "canceled":
				cancel()
				problem = collector.Put(hash[:], node)
				if !errors.Is(problem, context.Canceled) {
					t.Fatal("collector did not preserve cancellation")
				}
			}
			if problem == nil {
				t.Fatal("source refusal was not reported")
			}
			if got, err := collector.Witness(); err == nil || !reflect.DeepEqual(got, StorageWitness{}) {
				t.Fatal("source refusal emitted partial proof")
			}
		})
	}
}
func TestBoundAndFramedStorageMeasurementsKeepOriginalCheckpointAndContext(t *testing.T) {
	f := storageContractFixture(t, 3)
	identity, manifest, message := releaseFixture("first")
	header := &types.Header{Root: f.root, Number: big.NewInt(40), Difficulty: new(big.Int), GasLimit: 30000000, Time: uint64(fixtureNow - 10)}
	headerRaw, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	policy := SnapshotPolicy{Schema: 1, Expected: identity, ManifestSHA256: []string{manifest}, BlockNumber: 40, BlockHash: header.Hash().Hex(), MaxHeaderAgeSeconds: 60, Bootstrap: true}
	snapshot, original, err := NewSnapshot(context.Background(), policy, message, []hexutil.Bytes{headerRaw}, f.witness, nil, fixtureNow, testLimits, bindingLimits)
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifySnapshotMeasurements(context.Background(), policy, snapshot, f.policy, f.proof, f.witness, nil, fixtureNow, testLimits, bindingLimits, storageLimits)
	if err != nil || result.Bound.CheckpointSHA256 != original.CheckpointSHA256 || result.Measurements.Summary != original.Summary {
		t.Fatalf("storage measurements changed accepted checkpoint: %v", err)
	}
	assertStorageOracle(t, f, result.Measurements)
	policy.Bootstrap = false
	policy.PreviousCheckpointSHA256 = original.CheckpointSHA256
	var stream bytes.Buffer
	if err := EncodeInput(context.Background(), &stream, policy, snapshot, &original.Checkpoint, f.witness, testLimits, bindingLimits); err != nil {
		t.Fatal(err)
	}
	resumed, err := VerifyInputMeasurements(context.Background(), bytes.NewReader(stream.Bytes()), f.policy, f.proof, fixtureNow+1, testLimits, bindingLimits, storageLimits)
	if err != nil || resumed.Bound.Checkpoint.FirstObservedAt != fixtureNow || resumed.Measurements.Storage.WitnessSHA256 != result.Measurements.Storage.WitnessSHA256 {
		t.Fatal("framed storage measurement lost checkpoint history or proof identity")
	}
	for _, kind := range []string{"stale", "context", "previous", "storage-pin", "partition-pin", "truncated", "trailing", "version"} {
		t.Run(kind, func(t *testing.T) {
			data := bytes.Clone(stream.Bytes())
			now := fixtureNow + 1
			p := policy
			cp := original.Checkpoint
			measure := f.policy
			switch kind {
			case "stale":
				now += 100
			case "context":
				p.Expected.ChainID = "1"
			case "previous":
				cp.NativeBalanceWei = "0"
			case "storage-pin":
				measure.StorageSHA256 = strings.Repeat("a", 64)
			case "partition-pin":
				part := *measure.Partition
				part.SHA256 = strings.Repeat("a", 64)
				measure.Partition = &part
			case "truncated":
				data = data[:len(data)-1]
			case "trailing":
				data = append(data, 0)
			case "version":
				data[7]++
			}
			if kind == "context" || kind == "previous" {
				var modified bytes.Buffer
				if err := EncodeInput(context.Background(), &modified, p, snapshot, &cp, f.witness, testLimits, bindingLimits); err != nil {
					t.Fatal(err)
				}
				data = modified.Bytes()
			}
			if got, err := VerifyInputMeasurements(context.Background(), bytes.NewReader(data), measure, f.proof, now, testLimits, bindingLimits, storageLimits); err == nil || !reflect.DeepEqual(got, BoundMeasurementsSummary{}) {
				t.Fatal("refused bound storage sample leaked a partial successful result")
			}
		})
	}
}
func TestStorageMeasurementPolicyDigestInteroperabilityFixture(t *testing.T) {
	policy := StoragePolicy{Schema: 1, Accounts: []StorageAccount{{ID: "a", Address: partitionAddress(4096), CodeHash: "0x" + strings.Repeat("1", 64), Slots: []StorageSlot{{ID: "counter", Key: storageSlotKey(0)}}}}}
	pin, err := policy.Fingerprint(storageLimits)
	if err != nil {
		t.Fatal(err)
	}
	if pin != "2f45c30f153e111d37c8b602c91b2000ecfe7e6a1bfcd1f85b2f1facff9d8a43" {
		t.Fatal("canonical storage policy domain or typed JSON changed")
	}
	empty := StorageWitness{Schema: 1, Nodes: make([]hexutil.Bytes, 0)}
	if got, err := empty.Fingerprint(context.Background(), storageLimits); err != nil || got != "11bf2ab9d32afbca42f2522b41b2a4bf68f2028b40426c40dc5965d459c705f1" {
		t.Fatal("empty storage proof digest recipe changed")
	}
	node := common.FromHex("0xe3a120111111111111111111111111111111111111111111111111111111111111111101")
	if got, err := (StorageWitness{Schema: 1, Nodes: []hexutil.Bytes{node}}).Fingerprint(context.Background(), storageLimits); err != nil || got != "f241d6895c2682d5cdb9bc860c7f17fdaf8555959c1b58a09f4b6550542b7d0f" {
		t.Fatal("streamed storage node digest recipe changed")
	}
}
