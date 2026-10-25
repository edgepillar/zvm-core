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

	"github.com/Zenoglyphs-VM/zvm-core/stateaudit"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("zvm-state-sum", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "binary witness file, or - for standard input")
	root := flags.String("state-root", "", "independently accepted 0x-prefixed 32-byte account-MPT root")
	limits := stateaudit.Limits{}
	flags.Uint64Var(&limits.MaxEncodedBytes, "max-bytes", 32<<20, "maximum encoded witness bytes")
	flags.Uint64Var(&limits.MaxNodes, "max-nodes", 250000, "maximum unique node blobs")
	flags.Uint64Var(&limits.MaxAccounts, "max-accounts", 250000, "maximum account leaves")
	flags.Uint64Var(&limits.MaxSteps, "max-steps", 1000000, "maximum verification traversal steps")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	rawRoot, err := hexutil.Decode(*root)
	if err != nil || len(rawRoot) != common.HashLength || common.BytesToHash(rawRoot) == (common.Hash{}) || *input == "" || flags.NArg() != 0 {
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
	summary, err := stateaudit.Verify(context.Background(), common.BytesToHash(rawRoot), witness, limits)
	if err != nil {
		fmt.Fprintln(stderr, "witness verification rejected")
		return 1
	}
	if json.NewEncoder(stdout).Encode(summary) != nil {
		fmt.Fprintln(stderr, "summary output incomplete")
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
