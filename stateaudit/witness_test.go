package stateaudit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

var testLimits = Limits{MaxEncodedBytes: 2 << 20, MaxNodes: 4096, MaxAccounts: 1024, MaxSteps: 16384}

type stateFixture struct {
	root common.Hash
	db   *state.CachingDB
	sum  string
	n    uint64
}

func fixture(t *testing.T, count int, execute bool) stateFixture {
	t.Helper()
	db := state.NewDatabaseForTesting()
	t.Cleanup(func() { db.TrieDB().Close() })
	s, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatal(err)
	}
	total := new(big.Int)
	for i := 0; i < count; i++ {
		address := common.BigToAddress(big.NewInt(int64(4096 + i)))
		amount := new(big.Int).SetUint64(uint64(i * 10000000001))
		if i < 3 {
			amount.Lsh(big.NewInt(1), 255) // Aggregate exceeds a single uint256.
		}
		if i == count-1 {
			amount.SetUint64(0) // A zero balance account with a nonce still counts.
		}
		s.SetBalance(address, uint256.MustFromBig(amount), 0)
		s.SetNonce(address, uint64(i+1), 0)
		total.Add(total, amount)
	}
	if execute {
		if count < 4 {
			t.Fatal("execution fixture needs funded accounts")
		}
		origin := common.BigToAddress(big.NewInt(4096))
		contract := common.BigToAddress(big.NewInt(4097))
		s.SetCode(contract, []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x00}, 0)
		_, _, err := runtime.Call(contract, nil, &runtime.Config{State: s, Origin: origin, Value: big.NewInt(777), GasLimit: 100000})
		if err != nil || s.GetState(contract, common.Hash{}) != common.BigToHash(big.NewInt(1)) {
			t.Fatalf("owned unsigned EVM fixture did not execute: %v", err)
		}
	}
	root, err := s.Commit(1, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TrieDB().Commit(root, false); err != nil {
		t.Fatal(err)
	}
	return stateFixture{root: root, db: db, sum: total.String(), n: uint64(count)}
}

func (f stateFixture) iterator(t *testing.T) NodeIterator {
	t.Helper()
	tree, err := f.db.OpenTrie(f.root)
	if err != nil {
		t.Fatal(err)
	}
	it, err := tree.NodeIterator(nil)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func collected(t *testing.T, f stateFixture) Witness {
	t.Helper()
	w, summary, err := Collect(context.Background(), f.root, f.iterator(t), testLimits)
	if err != nil || summary.NativeBalanceWei != f.sum || summary.Accounts != f.n {
		t.Fatalf("complete root sum: %+v %v", summary, err)
	}
	return w
}

func ordered(root common.Hash, blobs ...[]byte) Witness {
	w := Witness{StateRoot: root}
	for _, blob := range blobs {
		w.Nodes = append(w.Nodes, bytes.Clone(blob))
	}
	sort.Slice(w.Nodes, func(i, j int) bool {
		a, b := crypto.Keccak256Hash(w.Nodes[i]), crypto.Keccak256Hash(w.Nodes[j])
		return bytes.Compare(a[:], b[:]) < 0
	})
	return w
}

func enc(value any) []byte {
	raw, err := rlp.EncodeToBytes(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func accountRLP(balance uint64) []byte {
	a := types.NewEmptyStateAccount()
	a.Balance.SetUint64(balance)
	a.Nonce = 1
	return enc(a)
}

func TestCompleteStateRoundTripIncludesEveryAccountAfterUnsignedExecution(t *testing.T) {
	f := fixture(t, 64, true)
	w := collected(t, f)
	var output bytes.Buffer
	if err := Encode(context.Background(), &output, w, testLimits); err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(context.Background(), bytes.NewReader(output.Bytes()), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := Verify(context.Background(), f.root, decoded, testLimits)
	if err != nil || summary.Accounts != 64 || summary.NativeBalanceWei != f.sum || summary.WitnessBytes != uint64(output.Len()) {
		t.Fatalf("separate witness reconstruction: %+v %v", summary, err)
	}
	var repeat bytes.Buffer
	if err := Encode(context.Background(), &repeat, collected(t, f), testLimits); err != nil || !bytes.Equal(output.Bytes(), repeat.Bytes()) {
		t.Fatal("same root did not produce identical bounded binary witness")
	}
}

func TestEmptyRootRequiresNoNodesAndAnExplicitExpectedRoot(t *testing.T) {
	f := fixture(t, 0, false)
	w := collected(t, f)
	if f.root != types.EmptyRootHash || len(w.Nodes) != 0 {
		t.Fatal("unexpected empty state")
	}
	for _, expected := range []common.Hash{{}, common.HexToHash("0x01")} {
		if summary, err := Verify(context.Background(), expected, w, testLimits); err == nil || summary.NativeBalanceWei != "" {
			t.Fatal("unaccepted empty root became a zero balance claim")
		}
	}
	w.Nodes = [][]byte{enc([]any{[]byte{0x20}, accountRLP(1)})}
	if _, err := Verify(context.Background(), types.EmptyRootHash, w, testLimits); err == nil {
		t.Fatal("empty root accepted an extra node")
	}
}

func TestSharedSubtreeBlobIsRetainedOnceButBothAccountsAreCounted(t *testing.T) {
	leaf := enc([]any{append([]byte{0x30}, make([]byte, 31)...), accountRLP(7)})
	hash := crypto.Keccak256Hash(leaf)
	branch := make([]any, 17)
	for i := range branch {
		branch[i] = []byte{}
	}
	branch[0], branch[1] = hash[:], hash[:]
	rootBlob := enc(branch)
	root := crypto.Keccak256Hash(rootBlob)
	w := ordered(root, rootBlob, leaf)
	summary, err := Verify(context.Background(), root, w, testLimits)
	if err != nil || summary.Accounts != 2 || summary.NativeBalanceWei != "14" || summary.WitnessNodes != 2 {
		t.Fatalf("shared hash is not a shared account identity: %+v %v", summary, err)
	}
	db := &witnessDB{root: root, nodes: map[common.Hash][]byte{root: rootBlob, hash: leaf}, used: map[common.Hash]bool{}}
	tree, err := trie.New(trie.StateTrieID(root), db)
	if err != nil {
		t.Fatal(err)
	}
	it, err := tree.NodeIterator(nil)
	if err != nil {
		t.Fatal(err)
	}
	copy, got, err := Collect(context.Background(), root, it, testLimits)
	if err != nil || got.NativeBalanceWei != "14" || len(copy.Nodes) != 2 {
		t.Fatalf("collector must deduplicate blobs without deduplicating paths: %v", err)
	}
}

func TestPartialAlteredUnreachableOrWrongRootWitnessNeverReturnsASummary(t *testing.T) {
	f := fixture(t, 8, false)
	w := collected(t, f)
	for _, kind := range []string{"missing-root", "missing-node", "altered", "unreachable", "duplicate", "unordered", "wrong-root"} {
		t.Run(kind, func(t *testing.T) {
			bad := ordered(f.root, w.Nodes...)
			expected := f.root
			switch kind {
			case "missing-root":
				for i, blob := range bad.Nodes {
					if crypto.Keccak256Hash(blob) == f.root {
						bad.Nodes = append(bad.Nodes[:i], bad.Nodes[i+1:]...)
						break
					}
				}
			case "missing-node":
				bad.Nodes = bad.Nodes[1:]
			case "altered":
				bad.Nodes[0][len(bad.Nodes[0])-1] ^= 1
				bad = ordered(f.root, bad.Nodes...)
			case "unreachable":
				extra := enc([]any{append([]byte{0x20}, make([]byte, 32)...), accountRLP(99)})
				bad = ordered(f.root, append(bad.Nodes, extra)...)
			case "duplicate":
				bad = ordered(f.root, append(bad.Nodes, bad.Nodes[0])...)
			case "unordered":
				bad.Nodes[0], bad.Nodes[1] = bad.Nodes[1], bad.Nodes[0]
			case "wrong-root":
				expected = common.HexToHash("0x01")
			}
			if summary, err := Verify(context.Background(), expected, bad, testLimits); err == nil || summary.NativeBalanceWei != "" {
				t.Fatal("invalid coverage or root returned a numeric result")
			}
		})
	}
}

func TestNoncanonicalTrieAndAccountRepresentationsAreRejectedWithoutPanic(t *testing.T) {
	path := append([]byte{0x20}, make([]byte, 32)...)
	a := types.NewEmptyStateAccount()
	a.Balance.SetUint64(7)
	values := []struct {
		name string
		blob []byte
	}{
		{"not-list", enc([]byte{1})},
		{"arity", enc([]any{[]byte{1}, []byte{2}, []byte{3}})},
		{"short-key", enc([]any{[]byte{0x20, 0}, accountRLP(1)})},
		{"odd-key", enc([]any{[]byte{0x30}, accountRLP(1)})},
		{"overlong-key", enc([]any{append([]byte{0x20}, make([]byte, 33)...), accountRLP(1)})},
		{"compact-flags", enc([]any{append([]byte{0x40}, make([]byte, 32)...), accountRLP(1)})},
		{"compact-padding", enc([]any{append([]byte{0x21}, make([]byte, 32)...), accountRLP(1)})},
		{"empty-value", enc([]any{path, []byte{}})},
		{"account-fields", enc([]any{path, enc([]any{uint64(0), uint64(1), a.Root})})},
		{"nonce-overflow", enc([]any{path, enc([]any{append([]byte{1}, make([]byte, 8)...), []byte{1}, a.Root, a.CodeHash})})},
		{"balance-overflow", enc([]any{path, enc([]any{uint64(0), append([]byte{1}, make([]byte, 32)...), a.Root, a.CodeHash})})},
		{"leading-zero-balance", enc([]any{path, enc([]any{uint64(0), []byte{0, 1}, a.Root, a.CodeHash})})},
		{"short-code-hash", enc([]any{path, enc([]any{uint64(0), uint64(1), a.Root, make([]byte, 31)})})},
		{"slim-account", enc([]any{path, enc([]any{uint64(0), uint64(1), []byte{}, []byte{}})})},
		{"trailing-account", enc([]any{path, append(accountRLP(1), 0x80)})},
		{"storage-value", enc([]any{path, enc(uint64(1))})},
		{"nested-leaf-value", enc([]any{path, []any{uint64(0), uint64(1)}})},
		{"empty-extension", enc([]any{[]byte{0}, make([]byte, 32)})},
		{"missing-extension-child", enc([]any{[]byte{0x10}, make([]byte, 32)})},
	}
	leaf := enc([]any{path, accountRLP(1)})
	leafHash := crypto.Keccak256Hash(leaf)
	extension := enc([]any{[]byte{0x10}, leafHash[:]})
	values = append(values, struct {
		name string
		blob []byte
	}{"adjacent-short-nodes", extension})
	for _, phase := range []string{"one-child", "prefix-value", "short-child", "oversized-inline"} {
		branch := make([]any, 17)
		for i := range branch {
			branch[i] = []byte{}
		}
		branch[0] = leafHash[:]
		if phase != "one-child" {
			branch[1] = leafHash[:]
		}
		if phase == "prefix-value" {
			branch[16] = accountRLP(1)
		}
		if phase == "short-child" {
			branch[1] = []byte{1}
		}
		if phase == "oversized-inline" {
			branch[1] = rlp.RawValue(leaf)
		}
		values = append(values, struct {
			name string
			blob []byte
		}{phase, enc(branch)})
	}
	for _, value := range values {
		t.Run(value.name, func(t *testing.T) {
			root := crypto.Keccak256Hash(value.blob)
			w := ordered(root, value.blob)
			if value.name == "adjacent-short-nodes" || value.name == "one-child" || value.name == "prefix-value" || value.name == "short-child" || value.name == "oversized-inline" {
				w = ordered(root, value.blob, leaf)
			}
			if summary, err := Verify(context.Background(), root, w, testLimits); err == nil || summary.NativeBalanceWei != "" {
				t.Fatal("malformed account state became a verified numeric result")
			}
		})
	}
}

type sourceWrapper struct {
	NodeIterator
	remaining int
	badHash   bool
	broken    bool
}

func (s *sourceWrapper) Next(descend bool) bool {
	if s.remaining == 0 {
		return false
	}
	s.remaining--
	return s.NodeIterator.Next(descend)
}
func (s *sourceWrapper) Error() error {
	if s.broken {
		return errors.New("private source diagnostic")
	}
	return s.NodeIterator.Error()
}
func (s *sourceWrapper) Hash() common.Hash {
	if s.badHash {
		return common.Hash{}
	}
	return s.NodeIterator.Hash()
}

type repeatedNode struct {
	blob  []byte
	calls int
}

func (s *repeatedNode) Next(bool) bool    { s.calls++; return true }
func (s *repeatedNode) Error() error      { return nil }
func (s *repeatedNode) Hash() common.Hash { return crypto.Keccak256Hash(s.blob) }
func (s *repeatedNode) NodeBlob() []byte  { return s.blob }

func TestCollectorRefusesPartialErroredMismatchedAndUnboundedSources(t *testing.T) {
	f := fixture(t, 8, false)
	for _, kind := range []string{"partial", "source-error", "hash-mismatch", "nil-source", "repeated-forever"} {
		t.Run(kind, func(t *testing.T) {
			var source NodeIterator = &sourceWrapper{NodeIterator: f.iterator(t), remaining: 10000}
			limits := testLimits
			switch kind {
			case "partial":
				source.(*sourceWrapper).remaining = 1
			case "source-error":
				source.(*sourceWrapper).broken = true
			case "hash-mismatch":
				source.(*sourceWrapper).badHash = true
			case "nil-source":
				source = nil
			case "repeated-forever":
				source = &repeatedNode{blob: enc([]any{append([]byte{0x20}, make([]byte, 32)...), accountRLP(1)})}
				limits.MaxSteps = 3
			}
			w, summary, err := Collect(context.Background(), f.root, source, limits)
			if err == nil || len(w.Nodes) != 0 || summary.NativeBalanceWei != "" {
				t.Fatal("incomplete source returned a witness or summary")
			}
		})
	}
}

func TestEveryResourceLimitAndCancellationRemainExplicit(t *testing.T) {
	f := fixture(t, 8, false)
	w := collected(t, f)
	size, err := wireSize(context.Background(), w, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"bytes", "nodes", "accounts", "steps", "zero-bytes", "zero-nodes", "zero-accounts", "zero-steps", "overflow-bytes", "cancelled", "nil-context"} {
		t.Run(kind, func(t *testing.T) {
			limits := testLimits
			ctx := context.Background()
			switch kind {
			case "bytes":
				limits.MaxEncodedBytes = size - 1
			case "nodes":
				limits.MaxNodes = uint64(len(w.Nodes) - 1)
			case "accounts":
				limits.MaxAccounts = f.n - 1
			case "steps":
				limits.MaxSteps = 1
			case "zero-bytes":
				limits.MaxEncodedBytes = 0
			case "zero-nodes":
				limits.MaxNodes = 0
			case "zero-accounts":
				limits.MaxAccounts = 0
			case "zero-steps":
				limits.MaxSteps = 0
			case "overflow-bytes":
				limits.MaxEncodedBytes = math.MaxUint64
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			if summary, err := Verify(ctx, f.root, w, limits); err == nil || summary.NativeBalanceWei != "" {
				t.Fatal("limit refusal became an aggregate")
			}
		})
	}
}

func TestCollectorAlsoAppliesBudgetsAndCancellationBeforeReturningEvidence(t *testing.T) {
	f := fixture(t, 8, false)
	for _, kind := range []string{"bytes", "nodes", "accounts", "steps", "cancelled", "zero-root", "nil-context"} {
		t.Run(kind, func(t *testing.T) {
			limits := testLimits
			ctx := context.Background()
			root := f.root
			switch kind {
			case "bytes":
				limits.MaxEncodedBytes = headerBytes
			case "nodes":
				limits.MaxNodes = 1
			case "accounts":
				limits.MaxAccounts = 1
			case "steps":
				limits.MaxSteps = 1
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "zero-root":
				root = common.Hash{}
			case "nil-context":
				ctx = nil
			}
			w, summary, err := Collect(ctx, root, f.iterator(t), limits)
			if err == nil || len(w.Nodes) != 0 || summary.NativeBalanceWei != "" {
				t.Fatal("producer returned evidence after a limit or cancellation")
			}
		})
	}
}

func TestCodecRejectsEveryTruncatedPrefixAndExtraBytes(t *testing.T) {
	f := fixture(t, 2, false)
	w := collected(t, f)
	var buffer bytes.Buffer
	if err := Encode(context.Background(), &buffer, w, testLimits); err != nil {
		t.Fatal(err)
	}
	raw := buffer.Bytes()
	for i := 0; i < len(raw); i++ {
		if got, err := Decode(context.Background(), bytes.NewReader(raw[:i]), testLimits); err == nil || len(got.Nodes) != 0 {
			t.Fatalf("prefix %d accepted", i)
		}
	}
	for _, suffix := range [][]byte{{0}, []byte("unverified-total=0"), raw} {
		if _, err := Decode(context.Background(), bytes.NewReader(append(bytes.Clone(raw), suffix...)), testLimits); err == nil {
			t.Fatal("trailing bytes or another witness accepted")
		}
	}
	for _, kind := range []string{"version", "zero-root", "count", "zero-length", "oversized-length", "duplicate", "unordered", "byte-cap"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(raw)
			limits := testLimits
			switch kind {
			case "version":
				bad[7]++
			case "zero-root":
				clear(bad[8:40])
			case "count":
				binary.BigEndian.PutUint64(bad[40:48], math.MaxUint64)
			case "zero-length":
				clear(bad[48:52])
			case "oversized-length":
				binary.BigEndian.PutUint32(bad[48:52], math.MaxUint32)
			case "duplicate", "unordered":
				bad = rawWire(ordered(f.root, w.Nodes[0], w.Nodes[0]))
				if kind == "unordered" {
					copy := ordered(f.root, w.Nodes...)
					copy.Nodes[0], copy.Nodes[1] = copy.Nodes[1], copy.Nodes[0]
					bad = rawWire(copy)
				}
			case "byte-cap":
				limits.MaxEncodedBytes = uint64(len(raw) - 1)
			}
			if _, err := Decode(context.Background(), bytes.NewReader(bad), limits); err == nil {
				t.Fatal("bad wire accepted")
			}
		})
	}
}

func rawWire(w Witness) []byte {
	var out bytes.Buffer
	out.Write(magic[:])
	out.Write(w.StateRoot[:])
	binary.Write(&out, binary.BigEndian, uint64(len(w.Nodes)))
	for _, blob := range w.Nodes {
		binary.Write(&out, binary.BigEndian, uint32(len(blob)))
		out.Write(blob)
	}
	return out.Bytes()
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type cancelWriter struct{ cancel context.CancelFunc }

func (w cancelWriter) Write(p []byte) (int, error) { w.cancel(); return len(p), nil }

type readFailure struct{}

func (readFailure) Read([]byte) (int, error) { return 0, errors.New("private input detail") }

func TestCodecDoesNotPublishSuccessForIOFailureOrCancellation(t *testing.T) {
	w := Witness{StateRoot: types.EmptyRootHash}
	if err := Encode(context.Background(), shortWriter{}, w, testLimits); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := Encode(ctx, cancelWriter{cancel}, w, testLimits); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Decode(context.Background(), readFailure{}, testLimits); err == nil {
		t.Fatal("failed input accepted")
	}
	if _, err := Decode(ctx, bytes.NewReader(rawWire(w)), testLimits); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := Encode(context.Background(), nil, w, testLimits); err == nil {
		t.Fatal("nil output accepted")
	}
	if _, err := Decode(context.Background(), nil, testLimits); err == nil {
		t.Fatal("nil input accepted")
	}
}
