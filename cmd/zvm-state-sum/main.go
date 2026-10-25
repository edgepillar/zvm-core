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
	if bound {
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
