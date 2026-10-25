// Package stateaudit collects and verifies complete account-MPT witnesses.
// A verified sum is bound to the caller's expected state root. It does not
// establish that root's chain authority, circulating liability or peg backing.
package stateaudit

import (
	"bytes"
	"context"
	"errors"
	"math"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb/database"
)

const headerBytes = 48
const maxNodeBytes = 1024 // Consensus account leaves and 17-way MPT nodes fit.

// Limits are explicit resource bounds, not economic or chain acceptance policy.
// MaxSteps applies separately to collection and verification traversal.
type Limits struct {
	MaxEncodedBytes uint64
	MaxNodes        uint64
	MaxAccounts     uint64
	MaxSteps        uint64
}

// Witness contains unique RLP node blobs in ascending Keccak-256 hash order.
// Callers must keep it immutable during encoding or verification. Storage tries,
// bytecode and address preimages are not needed to sum native account balances.
type Witness struct {
	StateRoot common.Hash
	Nodes     [][]byte
}

type Summary struct {
	StateRoot        common.Hash `json:"stateRoot"`
	Accounts         uint64      `json:"accounts"`
	NativeBalanceWei string      `json:"nativeBalanceWei"`
	WitnessNodes     uint64      `json:"witnessNodes"`
	WitnessBytes     uint64      `json:"witnessBytes"`
}

// NodeIterator is the read-only subset of geth's account-trie node iterator.
// It must start before the first node and must not skip any children.
type NodeIterator interface {
	Next(bool) bool
	Error() error
	Hash() common.Hash
	NodeBlob() []byte
}

func check(ctx context.Context, limits Limits) error {
	if ctx == nil || limits.MaxEncodedBytes < headerBytes || limits.MaxEncodedBytes >= math.MaxInt64 || limits.MaxNodes == 0 || limits.MaxAccounts == 0 || limits.MaxSteps == 0 {
		return errors.New("invalid state witness limits or context")
	}
	return ctx.Err()
}

// Collect makes one complete source traversal and then reconstructs the trie
// from the resulting witness in a separate read-only database. Partial source
// output, iterator errors and resource refusals return no witness or summary.
// Cancellation is checked between synchronous source operations; the owner must
// bound a source that can block inside Next or NodeBlob.
func Collect(ctx context.Context, expectedRoot common.Hash, source NodeIterator, limits Limits) (Witness, Summary, error) {
	if err := check(ctx, limits); err != nil {
		return Witness{}, Summary{}, err
	}
	if source == nil || expectedRoot == (common.Hash{}) {
		return Witness{}, Summary{}, errors.New("state witness source or expected root unavailable")
	}
	nodes := make(map[common.Hash][]byte)
	var steps uint64
	size := uint64(headerBytes)
	for source.Next(true) {
		if err := ctx.Err(); err != nil {
			return Witness{}, Summary{}, err
		}
		if steps == limits.MaxSteps {
			return Witness{}, Summary{}, errors.New("state witness traversal limit")
		}
		steps++
		hash, blob := source.Hash(), source.NodeBlob()
		if source.Error() != nil {
			return Witness{}, Summary{}, errors.New("state witness source incomplete")
		}
		if hash == (common.Hash{}) && len(blob) == 0 {
			continue // Embedded/value nodes are already covered by their parent.
		}
		if len(blob) == 0 || len(blob) > maxNodeBytes || crypto.Keccak256Hash(blob) != hash {
			return Witness{}, Summary{}, errors.New("state witness source node mismatch")
		}
		if old, ok := nodes[hash]; ok {
			if !bytes.Equal(old, blob) {
				return Witness{}, Summary{}, errors.New("state witness source changed")
			}
			continue // A repeated subtree still has one content-addressed blob.
		}
		charge := uint64(4 + len(blob))
		if uint64(len(nodes)) >= limits.MaxNodes || charge > limits.MaxEncodedBytes-size {
			return Witness{}, Summary{}, errors.New("state witness size limit")
		}
		size += charge
		nodes[hash] = bytes.Clone(blob)
	}
	if source.Error() != nil {
		return Witness{}, Summary{}, errors.New("state witness source incomplete")
	}
	if err := ctx.Err(); err != nil {
		return Witness{}, Summary{}, err
	}
	hashes := make([]common.Hash, 0, len(nodes))
	for hash := range nodes {
		hashes = append(hashes, hash)
	}
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i][:], hashes[j][:]) < 0 })
	witness := Witness{StateRoot: expectedRoot}
	for _, hash := range hashes {
		witness.Nodes = append(witness.Nodes, nodes[hash])
	}
	summary, err := Verify(ctx, expectedRoot, witness, limits)
	if err != nil {
		return Witness{}, Summary{}, err
	}
	return witness, summary, nil
}

func wireSize(ctx context.Context, witness Witness, limits Limits) (uint64, error) {
	if err := check(ctx, limits); err != nil {
		return 0, err
	}
	if witness.StateRoot == (common.Hash{}) || uint64(len(witness.Nodes)) > limits.MaxNodes {
		return 0, errors.New("invalid state witness root or node count")
	}
	size := uint64(headerBytes)
	var previous common.Hash
	for i, blob := range witness.Nodes {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if len(blob) == 0 || len(blob) > maxNodeBytes || uint64(4+len(blob)) > limits.MaxEncodedBytes-size {
			return 0, errors.New("state witness size limit")
		}
		hash := crypto.Keccak256Hash(blob)
		if i > 0 && bytes.Compare(previous[:], hash[:]) >= 0 {
			return 0, errors.New("state witness nodes are duplicated or unordered")
		}
		previous = hash
		size += uint64(4 + len(blob))
	}
	return size, nil
}

// Verify reconstructs and traverses the entire account trie at expectedRoot.
// The root must come from the caller's independently accepted source, never
// merely from this witness. A successful result includes every account balance,
// including bridge locks, sinks and fee claims; it performs no exclusions.
func Verify(ctx context.Context, expectedRoot common.Hash, witness Witness, limits Limits) (Summary, error) {
	size, err := wireSize(ctx, witness, limits)
	if err != nil {
		return Summary{}, err
	}
	if expectedRoot == (common.Hash{}) || witness.StateRoot != expectedRoot {
		return Summary{}, errors.New("state witness does not match expected root")
	}
	if expectedRoot == types.EmptyRootHash {
		if len(witness.Nodes) != 0 {
			return Summary{}, errors.New("empty state witness has extra nodes")
		}
		return Summary{StateRoot: expectedRoot, NativeBalanceWei: "0", WitnessBytes: size}, nil
	}
	db := &witnessDB{root: expectedRoot, nodes: make(map[common.Hash][]byte), used: make(map[common.Hash]bool)}
	for _, blob := range witness.Nodes {
		db.nodes[crypto.Keccak256Hash(blob)] = blob
	}
	for _, blob := range witness.Nodes {
		if err := ctx.Err(); err != nil {
			return Summary{}, err
		}
		if err := validateNode(blob, db.nodes, 0); err != nil {
			return Summary{}, err
		}
	}
	tree, err := trie.New(trie.StateTrieID(expectedRoot), db)
	if err != nil {
		return Summary{}, errors.New("state witness root unavailable")
	}
	it, err := tree.NodeIterator(nil)
	if err != nil {
		return Summary{}, errors.New("state witness traversal unavailable")
	}
	total := new(big.Int)
	var accounts, steps uint64
	for it.Next(true) {
		if err := ctx.Err(); err != nil {
			return Summary{}, err
		}
		if steps == limits.MaxSteps || len(it.Path()) > 65 {
			return Summary{}, errors.New("state witness traversal limit or key depth")
		}
		steps++
		if !it.Leaf() {
			continue
		}
		if len(it.Path()) != 65 || it.Path()[64] != 16 || len(it.LeafKey()) != common.HashLength || accounts == limits.MaxAccounts {
			return Summary{}, errors.New("state witness account limit or key length")
		}
		var account types.StateAccount
		if err := rlp.DecodeBytes(it.LeafBlob(), &account); err != nil || account.Balance == nil || len(account.CodeHash) != common.HashLength {
			return Summary{}, errors.New("invalid consensus state account")
		}
		canonical, err := rlp.EncodeToBytes(&account)
		if err != nil || !bytes.Equal(canonical, it.LeafBlob()) {
			return Summary{}, errors.New("noncanonical state account")
		}
		total.Add(total, account.Balance.ToBig())
		accounts++
	}
	if it.Error() != nil {
		return Summary{}, errors.New("state witness traversal incomplete")
	}
	if err := ctx.Err(); err != nil {
		return Summary{}, err
	}
	if len(db.used) != len(db.nodes) {
		return Summary{}, errors.New("state witness has unreachable nodes")
	}
	return Summary{StateRoot: expectedRoot, Accounts: accounts, NativeBalanceWei: total.String(), WitnessNodes: uint64(len(db.nodes)), WitnessBytes: size}, nil
}

type witnessDB struct {
	root  common.Hash
	nodes map[common.Hash][]byte
	used  map[common.Hash]bool
}

func (db *witnessDB) NodeReader(root common.Hash) (database.NodeReader, error) {
	if root != db.root {
		return nil, errors.New("state witness database root mismatch")
	}
	return db, nil
}

func (db *witnessDB) Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error) {
	blob, exists := db.nodes[hash]
	if owner != (common.Hash{}) || len(path) > 64 || !exists || (len(path) != 0 && len(blob) < 32) {
		return nil, errors.New("state witness node unavailable")
	}
	db.used[hash] = true
	return blob, nil
}

func nodeList(blob []byte) ([]rlp.RawValue, error) {
	var elements []rlp.RawValue
	if len(blob) == 0 || len(blob) > maxNodeBytes || rlp.DecodeBytes(blob, &elements) != nil || (len(elements) != 2 && len(elements) != 17) {
		return nil, errors.New("invalid account trie node")
	}
	return elements, nil
}

func validateNode(blob []byte, nodes map[common.Hash][]byte, embeddedDepth int) error {
	if embeddedDepth > 64 {
		return errors.New("account trie embedded depth limit")
	}
	elements, err := nodeList(blob)
	if err != nil {
		return err
	}
	if len(elements) == 17 {
		var value []byte
		if rlp.DecodeBytes(elements[16], &value) != nil || len(value) != 0 {
			return errors.New("account trie branch has a prefix value")
		}
		children := 0
		for _, raw := range elements[:16] {
			child, err := nodeReference(raw, nodes, embeddedDepth)
			if err != nil {
				return err
			}
			if child != nil {
				children++
			}
		}
		if children < 2 {
			return errors.New("noncanonical account trie branch")
		}
		return nil
	}
	var path []byte
	if rlp.DecodeBytes(elements[0], &path) != nil || len(path) == 0 || len(path) > 33 || path[0]>>4 > 3 || (path[0]&0x10 == 0 && path[0]&15 != 0) {
		return errors.New("invalid account trie compact path")
	}
	if path[0]&0x20 != 0 {
		var value []byte
		if rlp.DecodeBytes(elements[1], &value) != nil || len(value) == 0 {
			return errors.New("invalid account trie leaf")
		}
		return nil // The full traversal checks key length and consensus account RLP.
	}
	if len(path) == 1 && path[0]&0x10 == 0 {
		return errors.New("empty account trie extension")
	}
	child, err := nodeReference(elements[1], nodes, embeddedDepth)
	if err != nil || child == nil {
		return errors.New("account trie extension child unavailable")
	}
	branch, err := nodeList(child)
	if err != nil || len(branch) != 17 {
		return errors.New("noncanonical adjacent account trie short nodes")
	}
	return nil
}

func nodeReference(raw rlp.RawValue, nodes map[common.Hash][]byte, depth int) ([]byte, error) {
	kind, content, rest, err := rlp.Split(raw)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid account trie reference")
	}
	if kind == rlp.List {
		if len(raw) >= 32 || validateNode(raw, nodes, depth+1) != nil {
			return nil, errors.New("invalid embedded account trie node")
		}
		return raw, nil
	}
	if len(content) == 0 {
		return nil, nil
	}
	if len(content) != common.HashLength {
		return nil, errors.New("invalid account trie child hash")
	}
	blob, ok := nodes[common.BytesToHash(content)]
	if !ok || len(blob) < 32 {
		return nil, errors.New("account trie child node unavailable")
	}
	return blob, nil
}
