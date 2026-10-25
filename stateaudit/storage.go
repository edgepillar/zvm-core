package stateaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// StoragePolicy selects raw uint256 storage measurements, not economic meaning.
// The owner independently accepts the address, runtime-code hash and slot map.
// A matching account code hash identifies bytes; it does not review those bytes
// or prove proxy implementation authority, layout semantics or upgrade safety.
type StoragePolicy struct {
	Schema   int              `json:"schema"`
	Accounts []StorageAccount `json:"accounts"`
}
type StorageAccount struct {
	ID       string        `json:"id"`
	Address  string        `json:"address"`
	CodeHash string        `json:"codeHash"`
	Slots    []StorageSlot `json:"slots"`
}
type StorageSlot struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}
type StorageLimits struct {
	MaxAccounts, MaxSlots, MaxProofNodes, MaxProofBytes, MaxProofSteps uint64
}

// StorageWitness contains the sorted unique union of nodes used by the selected
// storage paths. It omits address/slot labels: roots and keys come from accepted
// policy and complete account leaves, never from this untrusted proof document.
type StorageWitness struct {
	Schema int             `json:"schema"`
	Nodes  []hexutil.Bytes `json:"nodes"`
}

// Fingerprint hashes the domain, uint64 big-endian node count, then each uint32
// length and raw node. It avoids another whole JSON encoding of a large proof.
func (proof StorageWitness) Fingerprint(ctx context.Context, limits StorageLimits) (string, error) {
	if _, err := storageProofBudget(ctx, proof, limits); err != nil {
		return "", err
	}
	hash := sha256.New()
	hash.Write([]byte("ZVM storage witness v1\n"))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(proof.Nodes)))
	hash.Write(count[:])
	for _, node := range proof.Nodes {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(node)))
		hash.Write(size[:])
		hash.Write(node)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type StorageValue struct {
	ID           string `json:"id"`
	ValueUint256 string `json:"valueUint256"`
	Present      bool   `json:"present"`
}
type StorageAccountMeasurement struct {
	ID               string         `json:"id"`
	NativeBalanceWei string         `json:"nativeBalanceWei"`
	CodeHash         string         `json:"codeHash"`
	StorageRoot      string         `json:"storageRoot"`
	Slots            []StorageValue `json:"slots"`
}
type StorageSummary struct {
	StateRoot     common.Hash                 `json:"stateRoot"`
	PolicySHA256  string                      `json:"policySha256"`
	WitnessSHA256 string                      `json:"witnessSha256"`
	ProofNodes    uint64                      `json:"proofNodes"`
	NodeBytes     uint64                      `json:"nodeBytes"`
	ProofSteps    uint64                      `json:"proofSteps"`
	Accounts      []StorageAccountMeasurement `json:"accounts"`
}

func validStorageLimits(l StorageLimits) bool {
	return l.MaxAccounts > 0 && l.MaxAccounts <= 64 && l.MaxSlots > 0 && l.MaxSlots <= 1024 && l.MaxProofNodes > 0 && l.MaxProofNodes <= 65536 && l.MaxProofBytes > 0 && l.MaxProofBytes <= 16<<20 && l.MaxProofSteps > 0 && l.MaxProofSteps <= 131072
}
func storageHex(value string, size int) ([]byte, error) {
	if len(value) != 2+2*size || !strings.HasPrefix(value, "0x") || strings.ToLower(value) != value {
		return nil, errors.New("storage policy hexadecimal field is not canonical")
	}
	raw, err := hex.DecodeString(value[2:])
	if err != nil || len(raw) != size {
		return nil, errors.New("storage policy hexadecimal field unavailable")
	}
	return raw, nil
}

type storageSelection struct {
	policy  StorageAccount
	present bool
	root    common.Hash
	balance string
}
type storageAccumulator struct {
	pin      string
	selected []*storageSelection
	keys     map[common.Hash]*storageSelection
}

func prepareStorage(policy StoragePolicy, limits StorageLimits) (*storageAccumulator, error) {
	if !validStorageLimits(limits) || policy.Schema != 1 || len(policy.Accounts) == 0 || uint64(len(policy.Accounts)) > limits.MaxAccounts {
		return nil, errors.New("storage policy or limits unavailable")
	}
	a := &storageAccumulator{keys: make(map[common.Hash]*storageSelection)}
	previousID := ""
	var slotCount uint64
	for _, account := range policy.Accounts {
		address, err := storageHex(account.Address, common.AddressLength)
		if err != nil || !partitionID.MatchString(account.ID) || account.ID <= previousID || !contextHash(account.CodeHash) || len(account.Slots) == 0 || uint64(len(account.Slots)) > limits.MaxSlots-slotCount {
			return nil, errors.New("storage accounts must have exact unique identities and bounded slots")
		}
		key := crypto.Keccak256Hash(address)
		if a.keys[key] != nil {
			return nil, errors.New("storage account selections cannot overlap")
		}
		previousID = account.ID
		previousSlotID := ""
		seen := make(map[string]bool)
		for _, slot := range account.Slots {
			if _, err := storageHex(slot.Key, common.HashLength); err != nil || !partitionID.MatchString(slot.ID) || slot.ID <= previousSlotID || seen[slot.Key] {
				return nil, errors.New("storage slots must have exact unique keys and sorted identities")
			}
			seen[slot.Key] = true
			previousSlotID = slot.ID
			slotCount++
		}
		selection := &storageSelection{policy: account}
		a.keys[key] = selection
		a.selected = append(a.selected, selection)
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, errors.New("storage policy encoding unavailable")
	}
	a.pin = digestBytes(append([]byte("ZVM account storage measurement policy v1\n"), raw...))
	return a, nil
}
func (policy StoragePolicy) Fingerprint(limits StorageLimits) (string, error) {
	a, err := prepareStorage(policy, limits)
	if err != nil {
		return "", err
	}
	return a.pin, nil
}
func DecodeStoragePolicy(raw []byte, documentLimit uint64, limits StorageLimits) (StoragePolicy, error) {
	var policy StoragePolicy
	if err := decodeContextDocument(raw, &policy, documentLimit); err != nil {
		return StoragePolicy{}, err
	}
	if _, err := prepareStorage(policy, limits); err != nil {
		return StoragePolicy{}, err
	}
	return policy, nil
}
func (a *storageAccumulator) observe(key []byte, account *types.StateAccount) error {
	selection := a.keys[common.BytesToHash(key)]
	if selection == nil {
		return nil
	}
	if selection.present || account.Root == (common.Hash{}) || common.BytesToHash(account.CodeHash).Hex() != selection.policy.CodeHash {
		return errors.New("selected storage account code or identity disagrees with accepted policy")
	}
	selection.present = true
	selection.root = account.Root
	selection.balance = account.Balance.ToBig().String()
	return nil
}
func storageProofBudget(ctx context.Context, proof StorageWitness, limits StorageLimits) (uint64, error) {
	if ctx == nil || !validStorageLimits(limits) || proof.Schema != 1 || proof.Nodes == nil || uint64(len(proof.Nodes)) > limits.MaxProofNodes {
		return 0, errors.New("storage witness schema or bounds unavailable")
	}
	var count uint64
	var previous common.Hash
	for i, node := range proof.Nodes {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if len(node) == 0 || len(node) > maxNodeBytes || uint64(len(node)) > limits.MaxProofBytes-count {
			return 0, errors.New("storage witness node byte limit")
		}
		hash := crypto.Keccak256Hash(node)
		if i > 0 && bytes.Compare(previous[:], hash[:]) >= 0 {
			return 0, errors.New("storage witness nodes must be unique and hash-sorted")
		}
		previous = hash
		count += uint64(len(node))
	}
	return count, ctx.Err()
}
func DecodeStorageWitness(ctx context.Context, raw []byte, documentLimit uint64, limits StorageLimits) (StorageWitness, error) {
	var proof StorageWitness
	if err := decodeContextDocument(raw, &proof, documentLimit); err != nil {
		return StorageWitness{}, err
	}
	if _, err := storageProofBudget(ctx, proof, limits); err != nil {
		return StorageWitness{}, err
	}
	var fields struct {
		Nodes []string `json:"nodes"`
	}
	if json.Unmarshal(raw, &fields) != nil {
		return StorageWitness{}, errors.New("storage witness node encoding unavailable")
	}
	for i, node := range proof.Nodes {
		if fields.Nodes[i] != hexutil.Encode(node) {
			return StorageWitness{}, errors.New("storage witness nodes require canonical lowercase hex")
		}
	}
	return proof, nil
}

// StorageProofCollector is a bounded ethdb.KeyValueWriter for an owner's local
// trie.Prove calls. It retains one owned node per Keccak digest. Prove errors
// must be checked by the owner; collector output still requires full verification.
// The collector is single-use and is not safe for concurrent source writes.
type StorageProofCollector struct {
	ctx     context.Context
	limits  StorageLimits
	nodes   map[common.Hash][]byte
	bytes   uint64
	problem error
	sealed  bool
}

func NewStorageProofCollector(ctx context.Context, limits StorageLimits) (*StorageProofCollector, error) {
	if ctx == nil || !validStorageLimits(limits) {
		return nil, errors.New("storage proof collector limits unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &StorageProofCollector{ctx: ctx, limits: limits, nodes: make(map[common.Hash][]byte)}, nil
}
func (c *StorageProofCollector) Put(key, value []byte) error {
	if c.problem != nil {
		return c.problem
	}
	if c.sealed {
		return errors.New("storage proof collector already finalized")
	}
	if err := c.ctx.Err(); err != nil {
		c.problem = err
		return err
	}
	if len(key) != common.HashLength || len(value) == 0 || len(value) > maxNodeBytes || crypto.Keccak256Hash(value) != common.BytesToHash(key) {
		c.problem = errors.New("storage proof source node identity disagrees")
		return c.problem
	}
	hash := common.BytesToHash(key)
	if previous, exists := c.nodes[hash]; exists {
		if !bytes.Equal(previous, value) {
			c.problem = errors.New("storage proof source changed")
		}
		return c.problem
	}
	if uint64(len(c.nodes)) == c.limits.MaxProofNodes || uint64(len(value)) > c.limits.MaxProofBytes-c.bytes {
		c.problem = errors.New("storage proof collector resource limit")
		return c.problem
	}
	c.nodes[hash] = bytes.Clone(value)
	c.bytes += uint64(len(value))
	return nil
}
func (c *StorageProofCollector) Delete([]byte) error {
	c.problem = errors.New("storage proof collector cannot delete source evidence")
	return c.problem
}
func (c *StorageProofCollector) Witness() (StorageWitness, error) {
	if c.problem != nil {
		return StorageWitness{}, c.problem
	}
	if c.sealed {
		return StorageWitness{}, errors.New("storage proof collector already finalized")
	}
	if err := c.ctx.Err(); err != nil {
		return StorageWitness{}, err
	}
	c.sealed = true
	hashes := make([]common.Hash, 0, len(c.nodes))
	for hash := range c.nodes {
		hashes = append(hashes, hash)
	}
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i][:], hashes[j][:]) < 0 })
	proof := StorageWitness{Schema: 1, Nodes: make([]hexutil.Bytes, 0, len(hashes))}
	for _, hash := range hashes {
		proof.Nodes = append(proof.Nodes, c.nodes[hash])
	}
	return proof, nil
}

type storageProofDB struct {
	ctx             context.Context
	nodes           map[common.Hash][]byte
	used            map[common.Hash]bool
	steps, maxSteps uint64
	problem         error
}

func (db *storageProofDB) Get(key []byte) ([]byte, error) {
	if db.problem != nil {
		return nil, db.problem
	}
	if err := db.ctx.Err(); err != nil {
		db.problem = err
		return nil, err
	}
	if len(key) != common.HashLength || db.steps == db.maxSteps {
		db.problem = errors.New("storage proof traversal budget or key unavailable")
		return nil, db.problem
	}
	db.steps++
	hash := common.BytesToHash(key)
	node, exists := db.nodes[hash]
	if !exists {
		db.problem = errors.New("storage proof node missing")
		return nil, db.problem
	}
	db.used[hash] = true
	return node, nil
}
func (db *storageProofDB) Has(key []byte) (bool, error) {
	node, err := db.Get(key)
	return node != nil, err
}
func storageInteger(value []byte) (string, error) {
	raw, rest, err := rlp.SplitString(value)
	if err != nil || len(rest) != 0 || len(raw) == 0 || len(raw) > 32 || raw[0] == 0 {
		return "", errors.New("storage value is not canonical nonzero uint256")
	}
	canonical, err := rlp.EncodeToBytes(raw)
	if err != nil || !bytes.Equal(canonical, value) {
		return "", errors.New("storage value has noncanonical RLP")
	}
	return new(big.Int).SetBytes(raw).String(), nil
}

// Sparse proofs may omit off-path hash children. Every supplied node is checked
// structurally and every supplied hash blob must be consumed by a selected path.
func validateStorageNode(blob []byte, nodes map[common.Hash][]byte, depth int) error {
	if depth > 64 {
		return errors.New("storage proof embedded depth limit")
	}
	elements, err := nodeList(blob)
	if err != nil {
		return errors.New("invalid storage trie node")
	}
	if len(elements) == 17 {
		var value []byte
		if rlp.DecodeBytes(elements[16], &value) != nil || len(value) != 0 {
			return errors.New("storage trie branch has a prefix value")
		}
		children := 0
		for _, raw := range elements[:16] {
			exists, _, err := storageReference(raw, nodes, depth)
			if err != nil {
				return err
			}
			if exists {
				children++
			}
		}
		if children < 2 {
			return errors.New("storage trie branch is noncanonical")
		}
		return nil
	}
	var path []byte
	if rlp.DecodeBytes(elements[0], &path) != nil || len(path) == 0 || len(path) > 33 || path[0]>>4 > 3 || (path[0]&0x10 == 0 && path[0]&15 != 0) {
		return errors.New("invalid storage trie compact path")
	}
	if path[0]&0x20 != 0 {
		var value []byte
		if rlp.DecodeBytes(elements[1], &value) != nil {
			return errors.New("invalid storage leaf")
		}
		_, err := storageInteger(value)
		return err
	}
	if len(path) == 1 && path[0]&0x10 == 0 {
		return errors.New("empty storage trie extension")
	}
	exists, child, err := storageReference(elements[1], nodes, depth)
	if err != nil || !exists {
		return errors.New("storage extension child unavailable")
	}
	if child != nil {
		list, err := nodeList(child)
		if err != nil || len(list) != 17 {
			return errors.New("adjacent storage short nodes are noncanonical")
		}
	}
	return nil
}
func storageReference(raw rlp.RawValue, nodes map[common.Hash][]byte, depth int) (bool, []byte, error) {
	kind, content, rest, err := rlp.Split(raw)
	if err != nil || len(rest) != 0 {
		return false, nil, errors.New("invalid storage node reference")
	}
	if kind == rlp.List {
		if len(raw) >= 32 || validateStorageNode(raw, nodes, depth+1) != nil {
			return false, nil, errors.New("invalid embedded storage node")
		}
		return true, raw, nil
	}
	if len(content) == 0 {
		return false, nil, nil
	}
	if len(content) != common.HashLength {
		return false, nil, errors.New("invalid storage child hash")
	}
	child := nodes[common.BytesToHash(content)]
	if child != nil && len(child) < 32 {
		return false, nil, errors.New("short storage child must be embedded")
	}
	return true, child, nil
}
func (a *storageAccumulator) finish(ctx context.Context, proof StorageWitness, limits StorageLimits) (StorageSummary, error) {
	nodeBytes, err := storageProofBudget(ctx, proof, limits)
	if err != nil {
		return StorageSummary{}, err
	}
	db := &storageProofDB{ctx: ctx, nodes: make(map[common.Hash][]byte), used: make(map[common.Hash]bool), maxSteps: limits.MaxProofSteps}
	for _, node := range proof.Nodes {
		db.nodes[crypto.Keccak256Hash(node)] = node
	}
	for _, node := range proof.Nodes {
		if err := ctx.Err(); err != nil {
			return StorageSummary{}, err
		}
		if err := validateStorageNode(node, db.nodes, 0); err != nil {
			return StorageSummary{}, err
		}
	}
	accounts := make([]StorageAccountMeasurement, 0, len(a.selected))
	for _, selection := range a.selected {
		if !selection.present {
			return StorageSummary{}, errors.New("selected storage account is absent from complete state")
		}
		account := StorageAccountMeasurement{ID: selection.policy.ID, NativeBalanceWei: selection.balance, CodeHash: selection.policy.CodeHash, StorageRoot: selection.root.Hex()}
		for _, slot := range selection.policy.Slots {
			if err := ctx.Err(); err != nil {
				return StorageSummary{}, err
			}
			value, present := "0", false
			if selection.root != types.EmptyRootHash {
				key, _ := storageHex(slot.Key, common.HashLength)
				raw, err := trie.VerifyProof(selection.root, crypto.Keccak256(key), db)
				if db.problem != nil {
					return StorageSummary{}, db.problem
				}
				if err != nil {
					return StorageSummary{}, errors.New("storage proof incomplete or invalid")
				}
				if len(raw) != 0 {
					value, err = storageInteger(raw)
					if err != nil {
						return StorageSummary{}, err
					}
					present = true
				}
			}
			account.Slots = append(account.Slots, StorageValue{ID: slot.ID, ValueUint256: value, Present: present})
		}
		accounts = append(accounts, account)
	}
	if err := ctx.Err(); err != nil {
		return StorageSummary{}, err
	}
	if len(db.used) != len(db.nodes) {
		return StorageSummary{}, errors.New("storage witness includes unused nodes")
	}
	pin, err := proof.Fingerprint(ctx, limits)
	if err != nil {
		return StorageSummary{}, err
	}
	return StorageSummary{PolicySHA256: a.pin, WitnessSHA256: pin, ProofNodes: uint64(len(db.nodes)), NodeBytes: nodeBytes, ProofSteps: db.steps, Accounts: accounts}, nil
}
