package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func init() {
	register("compare", "check that two ZVM nodes derived the same chain", runCompare)
}

// Block hashes chain, so agreement at a height implies agreement at every
// height below it. Disagreement is found by bisection rather than by walking.
func runCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	aURL := endpoint(fs, "a", envZVM, "first node's JSON-RPC")
	bURL := fs.String("b", "", "second node's JSON-RPC")
	fs.Parse(args)
	if err := needEndpoints(fs, "a", "b"); err != nil {
		return err
	}

	ctx := context.Background()
	a, err := ethclient.DialContext(ctx, *aURL)
	if err != nil {
		return err
	}
	b, err := ethclient.DialContext(ctx, *bURL)
	if err != nil {
		return err
	}
	headA, err := a.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("node a: %w", err)
	}
	headB, err := b.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("node b: %w", err)
	}
	common := min(headA, headB)
	fmt.Printf("a head %d · b head %d · comparing up to %d\n", headA, headB, common)

	header := func(c *ethclient.Client, n uint64) (*types.Header, error) {
		return c.HeaderByNumber(ctx, new(big.Int).SetUint64(n))
	}
	agree := func(n uint64) (bool, *types.Header, *types.Header, error) {
		ha, err := header(a, n)
		if err != nil {
			return false, nil, nil, err
		}
		hb, err := header(b, n)
		if err != nil {
			return false, nil, nil, err
		}
		return ha.Hash() == hb.Hash(), ha, hb, nil
	}

	ok, ha, hb, err := agree(common)
	if err != nil {
		return err
	}
	if ok {
		fmt.Printf("agreed: both nodes have the same block %d\n  hash       %s\n  state root %s\n",
			common, ha.Hash(), ha.Root)
		fmt.Println("Block hashes chain, so every block below this one matches too.")
		return nil
	}

	// Bisect for the first height they disagree on.
	lo, hi := uint64(0), common
	for lo+1 < hi {
		mid := (lo + hi) / 2
		ok, _, _, err := agree(mid)
		if err != nil {
			return err
		}
		if ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	ha, _ = header(a, hi)
	hb, _ = header(b, hi)
	fmt.Printf("DIVERGED at block %d (they agree at %d)\n", hi, lo)
	fmt.Printf("  a: hash %s  state %s  txs root %s  gas %d  time %d\n", ha.Hash(), ha.Root, ha.TxHash, ha.GasUsed, ha.Time)
	fmt.Printf("  b: hash %s  state %s  txs root %s  gas %d  time %d\n", hb.Hash(), hb.Root, hb.TxHash, hb.GasUsed, hb.Time)
	return fmt.Errorf("the two nodes derived different chains")
}
