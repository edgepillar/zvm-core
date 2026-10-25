package main

import (
	"errors"
	"io"
	"math"
	"os"

	"github.com/Zenoglyphs-VM/zvm-core/stateaudit"
)

type bindingInputs struct {
	policy     stateaudit.SnapshotPolicy
	snapshot   stateaudit.Snapshot
	checkpoint *stateaudit.Checkpoint
}

func bindingFile(path string, limit uint64) ([]byte, error) {
	if path == "" || path == "-" || limit == 0 || limit >= math.MaxInt64 {
		return nil, errors.New("bounded regular context file required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("context file unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || uint64(info.Size()) > limit {
		return nil, errors.New("context file exceeds bounds")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(raw) == 0 || uint64(len(raw)) > limit {
		return nil, errors.New("context file incomplete")
	}
	return raw, nil
}

func readBindingInputs(policyPath, snapshotPath, checkpointPath string, limit uint64) (bindingInputs, error) {
	var inputs bindingInputs
	raw, err := bindingFile(policyPath, limit)
	if err != nil {
		return inputs, err
	}
	inputs.policy, err = stateaudit.DecodeSnapshotPolicy(raw, limit)
	if err != nil {
		return bindingInputs{}, err
	}
	raw, err = bindingFile(snapshotPath, limit)
	if err != nil {
		return bindingInputs{}, err
	}
	inputs.snapshot, err = stateaudit.DecodeSnapshot(raw, limit)
	if err != nil {
		return bindingInputs{}, err
	}
	if checkpointPath != "" {
		raw, err = bindingFile(checkpointPath, limit)
		if err != nil {
			return bindingInputs{}, err
		}
		checkpoint, err := stateaudit.DecodeCheckpoint(raw, limit)
		if err != nil {
			return bindingInputs{}, err
		}
		inputs.checkpoint = &checkpoint
	}
	return inputs, nil
}
