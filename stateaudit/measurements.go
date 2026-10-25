package stateaudit

import (
	"context"
	"errors"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type PinnedPartition struct {
	Policy PartitionPolicy
	SHA256 string
	Limits PartitionLimits
}

// MeasurementPolicy combines independently provisioned measurement choices.
// Neither labels nor matching digests establish economic or upgrade authority.
type MeasurementPolicy struct {
	Storage       StoragePolicy
	StorageSHA256 string
	Partition     *PinnedPartition
}
type MeasurementsSummary struct {
	Summary   Summary             `json:"summary"`
	Partition *PartitionedSummary `json:"partition,omitempty"`
	Storage   StorageSummary      `json:"storage"`
}
type BoundMeasurementsSummary struct {
	Bound        BoundSummary        `json:"bound"`
	Measurements MeasurementsSummary `json:"measurements"`
}
type measurementAccumulator struct {
	storage   *storageAccumulator
	partition *partitionAccumulator
}

func prepareMeasurements(ctx context.Context, policy MeasurementPolicy, proof StorageWitness, limits StorageLimits) (*measurementAccumulator, error) {
	storage, err := prepareStorage(policy.Storage, limits)
	if err != nil {
		return nil, err
	}
	if !contextDigest(policy.StorageSHA256) || storage.pin != policy.StorageSHA256 {
		return nil, errors.New("storage policy disagrees with independent digest pin")
	}
	if _, err := storageProofBudget(ctx, proof, limits); err != nil {
		return nil, err
	}
	a := &measurementAccumulator{storage: storage}
	if policy.Partition != nil {
		p := policy.Partition
		a.partition, err = acceptedPartition(p.SHA256, p.Policy, p.Limits)
		if err != nil {
			return nil, err
		}
	}
	return a, nil
}
func (a *measurementAccumulator) balanceObserver() func([]byte, *big.Int) error {
	if a.partition == nil {
		return nil
	}
	return a.partition.observe
}
func (a *measurementAccumulator) finish(ctx context.Context, summary Summary, proof StorageWitness, limits StorageLimits) (MeasurementsSummary, error) {
	storage, err := a.storage.finish(ctx, proof, limits)
	if err != nil {
		return MeasurementsSummary{}, err
	}
	storage.StateRoot = summary.StateRoot
	result := MeasurementsSummary{Summary: summary, Storage: storage}
	if a.partition != nil {
		part, err := a.partition.finish(summary)
		if err != nil {
			return MeasurementsSummary{}, err
		}
		result.Partition = &part
	}
	return result, nil
}

// VerifyMeasurements verifies the entire account trie and collects selected
// account code/storage roots in that same traversal. It then proves every fixed
// storage key, including absence, against those roots. No partial result escapes.
func VerifyMeasurements(ctx context.Context, expectedRoot common.Hash, policy MeasurementPolicy, proof StorageWitness, witness Witness, limits Limits, storageLimits StorageLimits) (MeasurementsSummary, error) {
	if err := check(ctx, limits); err != nil {
		return MeasurementsSummary{}, err
	}
	a, err := prepareMeasurements(ctx, policy, proof, storageLimits)
	if err != nil {
		return MeasurementsSummary{}, err
	}
	summary, err := verifyAccountsDetailed(ctx, expectedRoot, witness, limits, a.balanceObserver(), a.storage.observe)
	if err != nil {
		return MeasurementsSummary{}, err
	}
	return a.finish(ctx, summary, proof, storageLimits)
}

// VerifySnapshotMeasurements preserves the existing accepted point/context and
// retained checkpoint rules. All balances and storage values share its state
// root; proof and measurement-policy pins remain separate retained evidence.
func VerifySnapshotMeasurements(ctx context.Context, policy SnapshotPolicy, snapshot Snapshot, measurements MeasurementPolicy, proof StorageWitness, witness Witness, previous *Checkpoint, now int64, limits Limits, bounds BindingLimits, storageLimits StorageLimits) (BoundMeasurementsSummary, error) {
	if err := check(ctx, limits); err != nil {
		return BoundMeasurementsSummary{}, err
	}
	a, err := prepareMeasurements(ctx, measurements, proof, storageLimits)
	if err != nil {
		return BoundMeasurementsSummary{}, err
	}
	bound, err := verifySnapshotDetailed(ctx, policy, snapshot, witness, previous, now, limits, bounds, a.balanceObserver(), a.storage.observe)
	if err != nil {
		return BoundMeasurementsSummary{}, err
	}
	result, err := a.finish(ctx, bound.Summary, proof, storageLimits)
	if err != nil {
		return BoundMeasurementsSummary{}, err
	}
	return BoundMeasurementsSummary{Bound: bound, Measurements: result}, nil
}

// VerifyInputMeasurements consumes the unchanged framed snapshot input. The
// storage policy, its accepted digest and bounded sparse proof are separate
// inputs; the frame cannot replace the measurement policy or pick another root.
func VerifyInputMeasurements(ctx context.Context, reader io.Reader, measurements MeasurementPolicy, proof StorageWitness, now int64, limits Limits, bounds BindingLimits, storageLimits StorageLimits) (BoundMeasurementsSummary, error) {
	if err := check(ctx, limits); err != nil {
		return BoundMeasurementsSummary{}, err
	}
	a, err := prepareMeasurements(ctx, measurements, proof, storageLimits)
	if err != nil {
		return BoundMeasurementsSummary{}, err
	}
	input, err := decodeInput(ctx, reader, limits, bounds)
	if err != nil {
		return BoundMeasurementsSummary{}, err
	}
	bound, err := verifySnapshotDetailed(ctx, input.policy, input.snapshot, input.witness, input.checkpoint, now, limits, bounds, a.balanceObserver(), a.storage.observe)
	if err != nil {
		return BoundMeasurementsSummary{}, err
	}
	result, err := a.finish(ctx, bound.Summary, proof, storageLimits)
	if err != nil {
		return BoundMeasurementsSummary{}, err
	}
	return BoundMeasurementsSummary{Bound: bound, Measurements: result}, nil
}
