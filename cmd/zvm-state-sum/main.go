// zvm-state-sum verifies an offline complete account-MPT witness. It does not
// fetch a root, contact RPC, open an engine database or establish peg backing.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/stateaudit"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("zvm-state-sum", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "binary witness file, or - for standard input")
	root := flags.String("state-root", "", "independently accepted 0x-prefixed 32-byte account-MPT root")
	snapshotPath := flags.String("snapshot", "", "bound snapshot context file")
	policyPath := flags.String("snapshot-policy", "", "independently accepted snapshot policy file")
	checkpointPath := flags.String("checkpoint", "", "previous checkpoint file, with its latest digest pinned in policy")
	partitionPath := flags.String("partition-policy", "", "independently provisioned disjoint address-group policy")
	partitionPin := flags.String("partition-policy-sha256", "", "independently accepted partition policy digest")
	partitionLimits := stateaudit.PartitionLimits{}
	flags.Uint64Var(&partitionLimits.MaxGroups, "max-partition-groups", 64, "maximum measured address groups, at most 64")
	flags.Uint64Var(&partitionLimits.MaxAddresses, "max-partition-addresses", 4096, "maximum selected addresses, at most 4096")
	storagePath := flags.String("storage-policy", "", "independently provisioned account code and fixed storage-slot policy")
	storagePin := flags.String("storage-policy-sha256", "", "independently accepted storage measurement policy digest")
	storageWitnessPath := flags.String("storage-witness", "", "bounded sorted union of selected storage proof nodes")
	storageLimits := stateaudit.StorageLimits{}
	flags.Uint64Var(&storageLimits.MaxAccounts, "max-storage-accounts", 64, "maximum selected storage accounts, at most 64")
	flags.Uint64Var(&storageLimits.MaxSlots, "max-storage-slots", 1024, "maximum selected storage slots, at most 1024")
	flags.Uint64Var(&storageLimits.MaxProofNodes, "max-storage-nodes", 8192, "maximum unique proof nodes, at most 65536")
	flags.Uint64Var(&storageLimits.MaxProofBytes, "max-storage-bytes", 2<<20, "maximum raw proof node bytes, at most 16 MiB")
	flags.Uint64Var(&storageLimits.MaxProofSteps, "max-storage-steps", 65536, "maximum proof node reads, at most 131072")
	stream := flags.Bool("bundle-stdin", false, "verify one framed policy/context/checkpoint and witness from standard input")
	bounds := stateaudit.BindingLimits{}
	flags.Uint64Var(&bounds.MaxDocumentBytes, "max-context-bytes", 8<<20, "maximum bytes per snapshot context file")
	flags.Uint64Var(&bounds.MaxHeaders, "max-headers", 256, "maximum linked headers in a snapshot")
	flags.Uint64Var(&bounds.MaxHeaderBytes, "max-header-bytes", 8192, "maximum bytes per canonical RLP header")
	limits := stateaudit.Limits{}
	flags.Uint64Var(&limits.MaxEncodedBytes, "max-bytes", 32<<20, "maximum encoded witness bytes")
	flags.Uint64Var(&limits.MaxNodes, "max-nodes", 250000, "maximum unique node blobs")
	flags.Uint64Var(&limits.MaxAccounts, "max-accounts", 250000, "maximum account leaves")
	flags.Uint64Var(&limits.MaxSteps, "max-steps", 1000000, "maximum verification traversal steps")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	var partition *stateaudit.PartitionPolicy
	if (*partitionPath == "") != (*partitionPin == "") {
		fmt.Fprintln(stderr, "partition policy and independent digest pin are both required")
		return 2
	}
	if *partitionPath != "" {
		raw, err := bindingFile(*partitionPath, bounds.MaxDocumentBytes)
		if err != nil {
			fmt.Fprintln(stderr, "partition policy input rejected")
			return 1
		}
		decoded, err := stateaudit.DecodePartitionPolicy(raw, bounds.MaxDocumentBytes, partitionLimits)
		if err != nil {
			fmt.Fprintln(stderr, "partition policy fields rejected")
			return 1
		}
		pin, err := decoded.Fingerprint(partitionLimits)
		if err != nil || pin != *partitionPin {
			fmt.Fprintln(stderr, "partition policy digest rejected")
			return 1
		}
		partition = &decoded
	}
	var measurements *stateaudit.MeasurementPolicy
	var storageProof stateaudit.StorageWitness
	storageConfigured := *storagePath != "" || *storagePin != "" || *storageWitnessPath != ""
	if storageConfigured {
		if *storagePath == "" || *storagePin == "" || *storageWitnessPath == "" {
			fmt.Fprintln(stderr, "storage policy, independent digest and proof are required together")
			return 2
		}
		raw, err := bindingFile(*storagePath, bounds.MaxDocumentBytes)
		if err != nil {
			fmt.Fprintln(stderr, "storage policy input rejected")
			return 1
		}
		policy, err := stateaudit.DecodeStoragePolicy(raw, bounds.MaxDocumentBytes, storageLimits)
		if err != nil {
			fmt.Fprintln(stderr, "storage policy fields rejected")
			return 1
		}
		pin, err := policy.Fingerprint(storageLimits)
		if err != nil || pin != *storagePin {
			fmt.Fprintln(stderr, "storage policy digest rejected")
			return 1
		}
		raw, err = bindingFile(*storageWitnessPath, bounds.MaxDocumentBytes)
		if err != nil {
			fmt.Fprintln(stderr, "storage witness input rejected")
			return 1
		}
		storageProof, err = stateaudit.DecodeStorageWitness(context.Background(), raw, bounds.MaxDocumentBytes, storageLimits)
		if err != nil {
			fmt.Fprintln(stderr, "storage witness encoding rejected")
			return 1
		}
		measurements = &stateaudit.MeasurementPolicy{Storage: policy, StorageSHA256: pin}
		if partition != nil {
			measurements.Partition = &stateaudit.PinnedPartition{Policy: *partition, SHA256: *partitionPin, Limits: partitionLimits}
		}
	}
	if *stream {
		if *root != "" || *snapshotPath != "" || *policyPath != "" || *checkpointPath != "" || (*input != "" && *input != "-") || flags.NArg() != 0 {
			fmt.Fprintln(stderr, "framed input cannot be combined with snapshot file or root overrides")
			return 2
		}
		var result any
		var err error
		if measurements != nil {
			result, err = stateaudit.VerifyInputMeasurements(context.Background(), stdin, *measurements, storageProof, time.Now().Unix(), limits, bounds, storageLimits)
		} else if partition != nil {
			result, err = stateaudit.VerifyInputPartition(context.Background(), stdin, *partitionPin, *partition, time.Now().Unix(), limits, bounds, partitionLimits)
		} else {
			result, err = stateaudit.VerifyInput(context.Background(), stdin, time.Now().Unix(), limits, bounds)
		}
		if err != nil {
			fmt.Fprintln(stderr, "framed snapshot verification rejected")
			return 1
		}
		if json.NewEncoder(stdout).Encode(result) != nil {
			fmt.Fprintln(stderr, "summary output incomplete")
			return 1
		}
		return 0
	}
	bound := *snapshotPath != "" || *policyPath != "" || *checkpointPath != ""
	var inputs bindingInputs
	var rawRoot []byte
	var err error
	if bound {
		if *root != "" || *snapshotPath == "" || *policyPath == "" {
			fmt.Fprintln(stderr, "bound mode requires snapshot and policy files without a separate root")
			return 2
		}
		inputs, err = readBindingInputs(*policyPath, *snapshotPath, *checkpointPath, bounds.MaxDocumentBytes)
		if err != nil {
			fmt.Fprintln(stderr, "snapshot context input rejected")
			return 1
		}
	} else {
		rawRoot, err = hexutil.Decode(*root)
		if err != nil || len(rawRoot) != common.HashLength || common.BytesToHash(rawRoot) == (common.Hash{}) {
			fmt.Fprintln(stderr, "an explicit complete state root is required")
			return 2
		}
	}
	if *input == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "input and an explicit complete state root are required")
		return 2
	}
	reader := stdin
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "unable to open witness input")
			return 1
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) > limits.MaxEncodedBytes {
			fmt.Fprintln(stderr, "witness input is not a regular file within the byte limit")
			return 1
		}
		reader = file
	}
	witness, err := stateaudit.Decode(context.Background(), reader, limits)
	if err != nil {
		fmt.Fprintln(stderr, "witness input rejected")
		return 1
	}
	var output any
	if measurements != nil {
		if bound {
			output, err = stateaudit.VerifySnapshotMeasurements(context.Background(), inputs.policy, inputs.snapshot, *measurements, storageProof, witness, inputs.checkpoint, time.Now().Unix(), limits, bounds, storageLimits)
		} else {
			output, err = stateaudit.VerifyMeasurements(context.Background(), common.BytesToHash(rawRoot), *measurements, storageProof, witness, limits, storageLimits)
		}
	} else if partition != nil {
		if bound {
			output, err = stateaudit.VerifySnapshotPartition(context.Background(), inputs.policy, inputs.snapshot, *partitionPin, *partition, witness, inputs.checkpoint, time.Now().Unix(), limits, bounds, partitionLimits)
		} else {
			output, err = stateaudit.VerifyPartition(context.Background(), common.BytesToHash(rawRoot), *partitionPin, *partition, witness, limits, partitionLimits)
		}
	} else if bound {
		output, err = stateaudit.VerifySnapshot(context.Background(), inputs.policy, inputs.snapshot, witness, inputs.checkpoint, time.Now().Unix(), limits, bounds)
	} else {
		output, err = stateaudit.Verify(context.Background(), common.BytesToHash(rawRoot), witness, limits)
	}
	if err != nil {
		fmt.Fprintln(stderr, "witness verification rejected")
		return 1
	}
	if json.NewEncoder(stdout).Encode(output) != nil {
		fmt.Fprintln(stderr, "summary output incomplete")
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
