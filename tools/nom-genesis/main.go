//go:build ignore

// Build this command in a reviewed go-zenon checkout with that module's lock.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/zenon-network/go-zenon/chain/genesis"
)

const maxGenesisBytes = 16 << 20

type result struct {
	ChainID      uint64 `json:"chainId"`
	MomentumHash string `json:"momentumHash"`
}

func reconstruct(input io.Reader) (computed result, err error) {
	defer func() {
		if recover() != nil {
			computed = result{}
			err = errors.New("invalid NoM genesis configuration")
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(input, maxGenesisBytes+1))
	if err != nil || len(raw) > maxGenesisBytes || !utf8.Valid(raw) {
		return result{}, errors.New("NoM genesis input exceeds its byte or encoding limits")
	}
	var config genesis.GenesisConfig
	if json.Unmarshal(raw, &config) != nil {
		return result{}, errors.New("invalid NoM genesis configuration")
	}
	if genesis.CheckGenesis(&config) != nil {
		return result{}, errors.New("NoM genesis configuration failed ledger validation")
	}
	momentum := genesis.NewGenesis(&config).GetGenesisMomentum()
	if momentum.Height != 1 || momentum.ChainIdentifier != config.ChainIdentifier {
		return result{}, errors.New("invalid NoM genesis momentum")
	}
	return result{ChainID: momentum.ChainIdentifier, MomentumHash: "0x" + momentum.Hash.String()}, nil
}

func main() {
	value, err := reconstruct(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		os.Exit(1)
	}
}
