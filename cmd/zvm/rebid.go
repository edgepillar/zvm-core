package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("rebid", "unwedge an account: re-publish its oldest unconfirmed block at the price the network asks now", runRebid)
}

// A wedged account is the dynamic-plasma failure mode: a block that committed
// to a price the network has since moved past is not rejected, it waits, and
// every later block on that account waits behind it. Services rebid on their
// own (znn.Account.AutoRebid); this is the same thing for an account no service
// is driving — a stuck wallet, or a benchmark run that ended mid-queue.
func runRebid(args []string) error {
	fs := flag.NewFlagSet("rebid", flag.ExitOnError)
	configPath := fs.String("config", "l2/rollup.json", "rollup config")
	l1URL := endpoint(fs, "l1", envNoM, "NoM node JSON-RPC")
	index := fs.Uint("index", devnet.DevOwner, "dev mnemonic index of the account to unwedge")
	rounds := fs.Int("rounds", 1, "how many blocks to rebid, oldest first")
	fs.Parse(args)
	if err := needEndpoints(fs, "l1"); err != nil {
		return err
	}

	cfg, err := rollup.Load(*configPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	l1 := znn.NewClient(*l1URL)
	acct := znn.NewAccount(devnet.Key(uint32(*index)), l1, cfg.L1ChainID)

	m, err := l1.FrontierMomentum(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("account     %s\n", acct.Address())
	fmt.Printf("network     momentum %d, version %d, fusion price %d\n", m.Height, m.Version, m.FusionPrice())
	for i := 0; i < *rounds; i++ {
		bid, err := acct.Rebid(ctx)
		if err != nil {
			return err
		}
		if bid == nil {
			fmt.Println("nothing to rebid: no unconfirmed block is underpaying")
			return nil
		}
		fmt.Printf("rebid       height %d as %s, paying %d plasma (was %d)\n",
			bid.Height, bid.Hash, bid.FusedPlasma, bid.BasePlasma)
	}
	return nil
}
