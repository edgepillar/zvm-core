package main

import (
	"encoding/hex"
	"fmt"

	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("constants", "print protocol addresses, chain ids and token bytes", runConstants)
}

func runConstants(args []string) error {
	inbox := znn.MustAddressFromBody("zvmxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	fmt.Printf("L1 chain id        %d\n", devnet.L1ChainID)
	fmt.Printf("L2 chain id        %d\n", devnet.L2ChainID)
	fmt.Printf("inbox              %s  %s  (type byte 0x%02x)\n", inbox, inbox.Hex(), inbox[0])
	for _, r := range []struct {
		name  string
		index uint32
	}{
		{"vault", devnet.Vault}, {"faucet", devnet.Faucet}, {"bench funder", devnet.BenchFunder},
		{"pillar producer", devnet.PillarProducer}, {"dev owner", devnet.DevOwner},
		// The funder on a chain nobody here genesised: `zvm fund` pays from a
		// dev index, and a script that has to name its address should not have
		// to hardcode the bech32.
		{"dev 3", devnet.Dev3}, {"dev 8", devnet.Dev8}, {"dev 9", devnet.Dev9},
	} {
		a := devnet.Key(r.index).Address
		fmt.Printf("%-18s %s  %s  (index %d)\n", r.name, a, a.Hex(), r.index)
	}
	for i := uint32(0); i < devnet.NumRelayers; i++ {
		a := devnet.RelayerKey(i).Address
		fmt.Printf("relayer %-10d %s  %s\n", i, a, a.Hex())
	}
	fmt.Printf("ZNN bytes10        0x%s\n", hex.EncodeToString(znn.ZNN[:]))
	fmt.Printf("QSR bytes10        0x%s\n", hex.EncodeToString(znn.QSR[:]))
	return nil
}
