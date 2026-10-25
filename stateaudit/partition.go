package stateaudit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// PartitionPolicy selects disjoint address sets for measurement only. Group
// membership does not establish code, storage, spendability, exclusion authority
// or economic liability. Keep address inventories outside public status output.
type PartitionPolicy struct {
	Schema int              `json:"schema"`
	Groups []PartitionGroup `json:"groups"`
}
type PartitionGroup struct {
	ID        string   `json:"id"`
	Addresses []string `json:"addresses"`
}
type PartitionLimits struct {
	MaxGroups    uint64
	MaxAddresses uint64
}
type PartitionBalance struct {
	ID               string `json:"id"`
	SelectedAccounts uint64 `json:"selectedAccounts"`
	PresentAccounts  uint64 `json:"presentAccounts"`
	NativeBalanceWei string `json:"nativeBalanceWei"`
}
type PartitionedSummary struct {
	Summary             Summary            `json:"summary"`
	PartitionSHA256     string             `json:"partitionSha256"`
	Groups              []PartitionBalance `json:"groups"`
	RemainderAccounts   uint64             `json:"remainderAccounts"`
	RemainderBalanceWei string             `json:"remainderBalanceWei"`
}
type BoundPartitionedSummary struct {
	Bound     BoundSummary       `json:"bound"`
	Partition PartitionedSummary `json:"partition"`
}

var partitionID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type partitionSelection struct {
	group   int
	present bool
}
type partitionAccumulator struct {
	sha256   string
	keys     map[common.Hash]*partitionSelection
	groups   []PartitionBalance
	balances []*big.Int
}

func preparePartition(policy PartitionPolicy, limits PartitionLimits) (*partitionAccumulator, error) {
	if limits.MaxGroups == 0 || limits.MaxGroups > 64 || limits.MaxAddresses == 0 || limits.MaxAddresses > 4096 || policy.Schema != 1 || len(policy.Groups) == 0 || uint64(len(policy.Groups)) > limits.MaxGroups {
		return nil, errors.New("partition policy or bounds unavailable")
	}
	a := &partitionAccumulator{keys: make(map[common.Hash]*partitionSelection)}
	previousID := ""
	var selected uint64
	for groupIndex, group := range policy.Groups {
		if !partitionID.MatchString(group.ID) || group.ID <= previousID || len(group.Addresses) == 0 || uint64(len(group.Addresses)) > limits.MaxAddresses-selected {
			return nil, errors.New("partition groups must be unique, sorted and bounded")
		}
		previousID = group.ID
		previousAddress := ""
		for _, address := range group.Addresses {
			if len(address) != 42 || !strings.HasPrefix(address, "0x") || strings.ToLower(address) != address || address <= previousAddress {
				return nil, errors.New("partition addresses must be canonical, unique and sorted")
			}
			raw, err := hex.DecodeString(address[2:])
			if err != nil || len(raw) != common.AddressLength {
				return nil, errors.New("partition address unavailable")
			}
			key := crypto.Keccak256Hash(raw)
			if _, exists := a.keys[key]; exists {
				return nil, errors.New("partition groups cannot overlap")
			}
			a.keys[key] = &partitionSelection{group: groupIndex}
			selected++
			previousAddress = address
		}
		a.groups = append(a.groups, PartitionBalance{ID: group.ID, SelectedAccounts: uint64(len(group.Addresses))})
		a.balances = append(a.balances, new(big.Int))
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, errors.New("partition policy encoding unavailable")
	}
	a.sha256 = digestBytes(append([]byte("ZVM native balance partition v1\n"), raw...))
	return a, nil
}

// Fingerprint commits to canonical typed JSON, including sorted group IDs and
// disjoint sorted lowercase addresses. It is a binding, not policy approval or
// a way to conceal a predictable address inventory.
func (policy PartitionPolicy) Fingerprint(limits PartitionLimits) (string, error) {
	a, err := preparePartition(policy, limits)
	if err != nil {
		return "", err
	}
	return a.sha256, nil
}
func DecodePartitionPolicy(raw []byte, documentLimit uint64, limits PartitionLimits) (PartitionPolicy, error) {
	var policy PartitionPolicy
	if err := decodeContextDocument(raw, &policy, documentLimit); err != nil {
		return PartitionPolicy{}, err
	}
	if _, err := preparePartition(policy, limits); err != nil {
		return PartitionPolicy{}, err
	}
	return policy, nil
}
func acceptedPartition(expectedSHA256 string, policy PartitionPolicy, limits PartitionLimits) (*partitionAccumulator, error) {
	a, err := preparePartition(policy, limits)
	if err != nil {
		return nil, err
	}
	if !contextDigest(expectedSHA256) || expectedSHA256 != a.sha256 {
		return nil, errors.New("partition policy disagrees with independent digest pin")
	}
	return a, nil
}
func (a *partitionAccumulator) observe(key []byte, balance *big.Int) error {
	selection, exists := a.keys[common.BytesToHash(key)]
	if !exists {
		return nil
	}
	if selection.present {
		return errors.New("partition account path repeated")
	}
	selection.present = true
	a.groups[selection.group].PresentAccounts++
	a.balances[selection.group].Add(a.balances[selection.group], balance)
	return nil
}
func (a *partitionAccumulator) finish(summary Summary) (PartitionedSummary, error) {
	total, ok := new(big.Int).SetString(summary.NativeBalanceWei, 10)
	if !ok {
		return PartitionedSummary{}, errors.New("complete partition total unavailable")
	}
	selected := new(big.Int)
	var present uint64
	groups := make([]PartitionBalance, len(a.groups))
	for i, group := range a.groups {
		group.NativeBalanceWei = a.balances[i].String()
		groups[i] = group
		selected.Add(selected, a.balances[i])
		present += group.PresentAccounts
	}
	if present > summary.Accounts || selected.Cmp(total) > 0 {
		return PartitionedSummary{}, errors.New("partition exceeds complete state")
	}
	return PartitionedSummary{Summary: summary, PartitionSHA256: a.sha256, Groups: groups, RemainderAccounts: summary.Accounts - present, RemainderBalanceWei: new(big.Int).Sub(total, selected).String()}, nil
}

// VerifyPartition validates the complete witness once and measures every group
// in that same account traversal. A selected absent account has a proved zero
// balance only after the entire trie has verified successfully. Partial or
// extra state, a wrong root or a bad policy returns no partial measurements.
func VerifyPartition(ctx context.Context, expectedRoot common.Hash, expectedPartitionSHA256 string, policy PartitionPolicy, witness Witness, limits Limits, partitionLimits PartitionLimits) (PartitionedSummary, error) {
	a, err := acceptedPartition(expectedPartitionSHA256, policy, partitionLimits)
	if err != nil {
		return PartitionedSummary{}, err
	}
	summary, err := verifyAccounts(ctx, expectedRoot, witness, limits, a.observe)
	if err != nil {
		return PartitionedSummary{}, err
	}
	return a.finish(summary)
}

// VerifySnapshotPartition retains the existing independently accepted context,
// checkpoint, continuity and freshness checks. The original checkpoint format
// stays unchanged; the group digest must be retained independently by its owner.
func VerifySnapshotPartition(ctx context.Context, policy SnapshotPolicy, snapshot Snapshot, expectedPartitionSHA256 string, partition PartitionPolicy, witness Witness, previous *Checkpoint, now int64, limits Limits, bounds BindingLimits, partitionLimits PartitionLimits) (BoundPartitionedSummary, error) {
	a, err := acceptedPartition(expectedPartitionSHA256, partition, partitionLimits)
	if err != nil {
		return BoundPartitionedSummary{}, err
	}
	bound, err := verifySnapshot(ctx, policy, snapshot, witness, previous, now, limits, bounds, a.observe)
	if err != nil {
		return BoundPartitionedSummary{}, err
	}
	result, err := a.finish(bound.Summary)
	if err != nil {
		return BoundPartitionedSummary{}, err
	}
	return BoundPartitionedSummary{Bound: bound, Partition: result}, nil
}

// VerifyInputPartition consumes the unchanged version-1 framed snapshot input.
// The address-group policy and its accepted pin come separately from the caller,
// so the producer cannot replace them inside its snapshot frame.
func VerifyInputPartition(ctx context.Context, reader io.Reader, expectedPartitionSHA256 string, partition PartitionPolicy, now int64, limits Limits, bounds BindingLimits, partitionLimits PartitionLimits) (BoundPartitionedSummary, error) {
	a, err := acceptedPartition(expectedPartitionSHA256, partition, partitionLimits)
	if err != nil {
		return BoundPartitionedSummary{}, err
	}
	input, err := decodeInput(ctx, reader, limits, bounds)
	if err != nil {
		return BoundPartitionedSummary{}, err
	}
	bound, err := verifySnapshot(ctx, input.policy, input.snapshot, input.witness, input.checkpoint, now, limits, bounds, a.observe)
	if err != nil {
		return BoundPartitionedSummary{}, err
	}
	result, err := a.finish(bound.Summary)
	if err != nil {
		return BoundPartitionedSummary{}, err
	}
	return BoundPartitionedSummary{Bound: bound, Partition: result}, nil
}
