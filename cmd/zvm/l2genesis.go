package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/l2"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("l2-genesis", "write op-geth's genesis, the rollup config and the Engine API secret", runL2Genesis)
}

func runL2Genesis(args []string) error {
	fs := flag.NewFlagSet("l2-genesis", flag.ExitOnError)
	out := fs.String("out", "l2", "output directory")
	l1URL := fs.String("l1", "", "NoM RPC to read the start momentum's parent from (unneeded for -start 2 on the ZVM L1)")
	l1Chain := fs.Uint64("l1-chain-id", devnet.L1ChainID, "NoM chain identifier")
	start := fs.Uint64("start", 2, "momentum derived into L2 block 1")
	gasLimit := fs.Uint64("gas-limit", 300_000_000, "gas limit of every L2 block")
	gasPerPlasma := fs.Uint64("gas-per-plasma", 16, "gas a native call gets per unit of plasma its NoM block paid")
	finality := fs.Uint64("finality", 6, "momentums before an L2 block is labelled finalized")
	vaultIndex := fs.Uint("vault-index", devnet.Vault, "dev mnemonic index of the bridge vault")
	vaultAddr := fs.String("vault", "", "bridge vault address (a committee's group address); overrides -vault-index")
	inboxTag := fs.String("inbox-tag", "", "a distinct inbox for a second rollup on the same NoM network, e.g. -inbox-tag rehearsal")
	timestamp := fs.String("timestamp", "", "the L1 genesis timestamp this chain starts from: unix seconds, or `now`; must match the L1's (default: the committed devnet constant, or read from -l1)")
	feeFrom := fs.Uint64("fee-from", 0, "momentum the burned-fee rule for native calls activates at (0: off)")
	feeSupply := fs.String("fee-anchor", "", "supply anchor for the fee rule: epoch,znnRaw,qsrRaw at this L1's genesis timestamp (default: read from -l1)")
	depositCallGas := fs.Uint64("max-deposit-call-gas", 1_000_000, "cap on a call carried by a deposit, once the fee rule is active")
	evm := fs.String("evm", rollup.EVMIsthmus, "execution rules: isthmus (Prague, op-geth or op-reth) or karst (Osaka and Jovian, op-reth only)")
	minBaseFee := fs.Uint64("min-base-fee", 0, "Jovian's floor under the EIP-1559 base fee, in wei (karst only; 0 leaves it to decay)")
	maxTxGas := fs.Uint64("max-tx-gas", 0, "cap on one relayed transaction (default: 30,000,000, or EIP-7825's 16,777,216 on karst)")
	gasFork := fs.Uint64("gas-fork", 0, "momentum the gas fork activates at: mine_boost, the elastic native share, chunk gas, the relayed fee split (0: off)")
	wireFork := fs.Uint64("wire-fork", 0, "momentum the wire fork activates at: brotli and span batches (0: off)")
	marketFork := fs.Uint64("market-fork", 0, "momentum this chain's own EIP-1559 parameters activate at (0: keep genesis'); later changes are added to feeMarket by hand")
	denominator := fs.Uint("eip1559-denominator", 0, "how hard the base fee is damped; smaller is faster. OP's 250 is for two-second blocks")
	elasticity := fs.Uint("eip1559-elasticity", 0, "gas limit divided by this is the target a block may use without moving the base fee")
	nativeFloor := fs.Uint64("native-floor-bp", 2_500, "the native lane's guaranteed share of a block, in basis points, from the gas fork")
	nativeCeil := fs.Uint64("native-ceiling-bp", 7_500, "the native lane's largest share of a block, in basis points, from the gas fork")
	bridgeFeeBps := fs.Uint64("bridge-fee-bps", 0, "withdrawal fee in basis points of 10,000, kept by the vault and fused to its plasma (D8); 0 with no floors means no fee")
	bridgeMinFee := fs.String("bridge-min-fee", "", "per-token floor under the withdrawal fee, in NoM base units, e.g. ZNN:1000000,QSR:10000000")
	mandatoryShare := fs.Uint64("mandatory-share-bp", 5_000, "the most of a block deposits, payouts and burn mirrors may claim, in basis points, from the gas fork; the rest waits for the next block")
	fs.Parse(args)
	if *evm != rollup.EVMIsthmus && *evm != rollup.EVMKarst {
		return fmt.Errorf("-evm %q: want %q or %q", *evm, rollup.EVMIsthmus, rollup.EVMKarst)
	}
	if *maxTxGas == 0 {
		// EIP-7825 caps a transaction at 2²⁴ gas from Osaka, which Karst
		// brings; a chain that declared more would admit transactions its own
		// client refuses.
		*maxTxGas = 30_000_000
		if *evm == rollup.EVMKarst {
			*maxTxGas = rollup.EIP7825MaxTxGas
		}
	}
	vault := devnet.Key(uint32(*vaultIndex)).Address
	if *vaultAddr != "" {
		v, err := znn.ParseAddress(*vaultAddr)
		if err != nil {
			return fmt.Errorf("-vault: %w", err)
		}
		if !v.IsUser() {
			return fmt.Errorf("-vault %s is not a user address", v)
		}
		vault = v
	}

	parsed, err := parseGenesisTimestamp(*timestamp)
	if err != nil {
		return err
	}
	ts := uint64(parsed)
	if *start < 2 {
		return fmt.Errorf("-start must be at least 2 (momentum 1 is the NoM genesis)")
	}
	if *l1URL != "" || *start != 2 {
		if *l1URL == "" {
			return fmt.Errorf("-l1 is required with -start %d", *start)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ms, err := znn.NewClient(*l1URL).DetailedMomentums(ctx, *start-1, 1)
		if err != nil {
			return err
		}
		if len(ms) != 1 {
			return fmt.Errorf("momentum %d not found", *start-1)
		}
		ts = ms[0].Momentum.Timestamp
		if ms[0].Momentum.ChainIdentifier != *l1Chain {
			return fmt.Errorf("the L1 node is chain %d, not %d", ms[0].Momentum.ChainIdentifier, *l1Chain)
		}
	}

	inbox, err := inboxFor(*inboxTag)
	if err != nil {
		return err
	}
	cfg := &rollup.Config{
		L1ChainID:            *l1Chain,
		L2ChainID:            7_340_400 + *l1Chain,
		Inbox:                inbox,
		Vault:                vault,
		L1StartHeight:        *start,
		GasLimit:             *gasLimit,
		GasPerPlasma:         *gasPerPlasma,
		MaxNativeGas:         16_777_216,
		MaxNativeGasPerBlock: *gasLimit / 2,
		MaxTxGas:             *maxTxGas,
		MaxDepositCallGas:    *depositCallGas,
		ChunkTTL:             8_640,
		MaxAssembledBytes:    512 * 1024,
		MaxBatchBytes:        4 * 1024 * 1024,
		FinalityDepth:        *finality,
		EVM:                  *evm,
		MinBaseFee:           *minBaseFee,
	}
	if *feeFrom != 0 {
		fee, err := buildFee(*feeFrom, *feeSupply, *l1URL, *depositCallGas)
		if err != nil {
			return err
		}
		cfg.Fee = fee
	}
	if *gasFork != 0 || *wireFork != 0 {
		cfg.Forks = &rollup.Forks{Gas: *gasFork, Wire: *wireFork}
	}
	if *marketFork != 0 || *denominator != 0 || *elasticity != 0 {
		cfg.FeeMarkets = []rollup.FeeMarket{{
			Momentum: *marketFork, Denominator: uint32(*denominator), Elasticity: uint32(*elasticity),
		}}
	}
	if *gasFork != 0 {
		cfg.NativeFloorBP, cfg.NativeCeilBP = *nativeFloor, *nativeCeil
		cfg.MandatoryShareBP = *mandatoryShare
		cfg.FeeSplitter = rollup.FeeSplitterAddr
	}
	if *bridgeFeeBps != 0 || *bridgeMinFee != "" {
		f := &rollup.BridgeFee{BPS: *bridgeFeeBps}
		for _, part := range strings.Split(*bridgeMinFee, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			sym, raw, ok := strings.Cut(part, ":")
			v, err := strconv.ParseUint(raw, 10, 64)
			if !ok || err != nil {
				return fmt.Errorf("-bridge-min-fee %q: want TOKEN:baseUnits", part)
			}
			switch strings.ToUpper(sym) {
			case "ZNN":
				f.MinZNN = v
			case "QSR":
				f.MinQSR = v
			default:
				return fmt.Errorf("-bridge-min-fee: only ZNN and QSR are bridged, not %q", sym)
			}
		}
		cfg.BridgeFee = f
	}
	if err := cfg.CheckForks(); err != nil {
		return err
	}

	g, err := l2.BuildGenesis(cfg, ts)
	if err != nil {
		return err
	}
	block := g.ToBlock()
	cfg.L2GenesisHash = block.Hash()
	cfg.L2GenesisTimestamp = ts

	if err := writeJSONFile(filepath.Join(*out, "genesis.json"), g); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(*out, "rollup.json"), cfg); err != nil {
		return err
	}
	jwtPath := filepath.Join(*out, "jwt.hex")
	if _, err := os.Stat(jwtPath); os.IsNotExist(err) {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		if err := os.WriteFile(jwtPath, []byte(hex.EncodeToString(secret)), 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %s: L2 chain %d, genesis %s at %d, gas limit %d, derives from momentum %d of chain %d, inbox %s\n",
		*out, cfg.L2ChainID, cfg.L2GenesisHash, ts, cfg.GasLimit, cfg.L1StartHeight, cfg.L1ChainID, cfg.Inbox)
	return nil
}

// buildFee anchors the burned-fee schedule to this L1's supply. The anchor is
// consensus: every node computes the same budget from it, so it is written into
// rollup.json rather than read from a node at runtime.
func buildFee(fromHeight uint64, anchor, l1URL string, depositCallGas uint64) (*rollup.Fee, error) {
	fee := &rollup.Fee{FromHeight: fromHeight, GasPerSupply: rollup.DefaultGasPerSupply}
	if anchor != "" {
		parts := strings.Split(anchor, ",")
		if len(parts) != 4 {
			return nil, fmt.Errorf("-fee-anchor wants genesisTimestamp,epoch,znnRaw,qsrRaw")
		}
		genesis, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("-fee-anchor genesisTimestamp: %w", err)
		}
		epoch, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("-fee-anchor epoch: %w", err)
		}
		fee.GenesisTimestamp, fee.RefEpoch, fee.RefZNN, fee.RefQSR = genesis, epoch, parts[2], parts[3]
	} else {
		if l1URL == "" {
			return nil, fmt.Errorf("-fee-from needs -l1 to read this network's supply, or -fee-anchor")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c := znn.NewClient(l1URL)
		genesis, err := c.MomentumByHeight(ctx, 1)
		if err != nil {
			return nil, fmt.Errorf("reading the L1 genesis momentum: %w", err)
		}
		frontier, err := c.FrontierMomentum(ctx)
		if err != nil {
			return nil, err
		}
		znnInfo, err := c.TokenInfo(ctx, znn.ZNN)
		if err != nil {
			return nil, err
		}
		qsrInfo, err := c.TokenInfo(ctx, znn.QSR)
		if err != nil {
			return nil, err
		}
		fee.GenesisTimestamp = int64(genesis.Timestamp)
		fee.RefZNN, fee.RefQSR = znnInfo.TotalSupply.Big().String(), qsrInfo.TotalSupply.Big().String()
		fee.RefEpoch = fee.EpochAt(int64(frontier.Timestamp))
	}
	if err := fee.Check(); err != nil {
		return nil, err
	}
	zPrice := fee.Cost(1_000_000, znn.ZNN, fee.RefEpoch, rollup.Price{})
	qPrice := fee.Cost(1_000_000, znn.QSR, fee.RefEpoch, rollup.Price{})
	fmt.Printf("fee rule from momentum %d: anchored at epoch %d (%s ZNN, %s QSR); 1,000,000 gas costs %s raw ZNN or %s raw QSR; deposit-carried calls capped at %d gas\n",
		fromHeight, fee.RefEpoch, fee.RefZNN, fee.RefQSR, zPrice, qPrice, depositCallGas)
	return fee, nil
}

// inboxFor builds this rollup's inbox address.
//
// Derivation reads every message sent to the inbox on its L1, so two rollups
// that share a NoM network *and* an inbox derive each other's calls — each
// against its own state, where the sender usually has no balance. Giving the
// second one a tag keeps them apart. One rollup per network needs no tag.
//
// The body is bech32 data characters, so a tag may only use those: the
// alphabet has no 1, b, i or o. It starts with "zvm" rather than "q", which is
// what makes the address unspendable: byte 0 is then 0x13, a type no keypair
// and no embedded contract can produce.
func inboxFor(tag string) (znn.Address, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return rollup.Inbox, nil
	}
	body := "zvm" + tag
	if len(body) > 32 {
		return znn.Address{}, fmt.Errorf("-inbox-tag is %d characters too long", len(body)-32)
	}
	addr, err := znn.AddressFromBody(body + strings.Repeat("x", 32-len(body)))
	if err != nil {
		return znn.Address{}, fmt.Errorf("-inbox-tag %q: %w (the bech32 alphabet has no 1, b, i or o)", tag, err)
	}
	return addr, nil
}
