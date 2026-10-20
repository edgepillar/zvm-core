// Command zvm is the ZVM's tool: the commands that are not a service.
//
// The L1 and L2 genesis generators, the dev-key transactions (call, deposit,
// balance, evm-send), the faucet, the fee splitter, the vector generator and
// the two repair commands live here and not in zvm-node, zvm-relayer or
// zvm-bridge because none of them is part of running one. They need what this
// module already is — the encodings, the dev mnemonic, the chain parameters —
// and nothing a service owns, so putting one in a service would make everyone
// who wants a genesis file build a node.
//
// The two exceptions are in zvm-node: `dex` and `verify-tokens` both need the
// compiled Solidity, and half a contract tree verifies nothing.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
)

type command struct {
	summary string
	run     func(args []string) error
}

var commands = map[string]command{}

func register(name, summary string, run func(args []string) error) {
	commands[name] = command{summary: summary, run: run}
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err := cmd.run(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "zvm %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: zvm <command> [flags]")
	fmt.Fprintln(os.Stderr)
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", n, commands[n].summary)
	}
}
