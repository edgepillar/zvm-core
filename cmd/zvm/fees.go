package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("fees", "the relayed lane's fee splitter: where it lands, putting it there, and what it holds", runFees)
}

// The gas fork makes ZVMFees the block's coinbase, so it must exist before the
// fork's height or a block's priority fees accrue at an address with no code.
// Nothing is lost if that happens — CREATE2 can still deploy to an address
// holding a balance — but the split does not run until it does.
func runFees(args []string) error {
	subs := map[string]func([]string) error{
		"address": feesAddress,
		"deploy":  feesDeploy,
		"status":  feesStatus,
	}
	if len(args) == 0 || subs[args[0]] == nil {
		fmt.Fprintln(os.Stderr, `usage: zvm fees <address|deploy|status> [flags]

  address  where ZVMFees lands, and what that address is a function of
  deploy   put it there, through the deterministic deployer in genesis
  status   what it has collected, owes, burned, and had matched on NoM

It must be deployed before a chain sets forks.gas; see HANDOFF.md.`)
		return errors.New("missing or unknown step")
	}
	return subs[args[0]](args[1:])
}

func feesAddress(args []string) error {
	fs := flag.NewFlagSet("fees address", flag.ExitOnError)
	fs.Parse(args)
	init := rollup.FeesArtifact.InitCode()
	fmt.Printf("ZVMFees      %s\n", rollup.FeeSplitterAddr)
	fmt.Printf("deployer     %s (a genesis predeploy on every ZVM chain)\n", rollup.Create2Deployer)
	fmt.Printf("salt         %s  = keccak256(\"zvm/fees/v1\")\n", rollup.FeesSalt)
	fmt.Printf("init code    %d bytes, keccak %s\n", len(init), crypto.Keccak256Hash(init))
	fmt.Printf("compiler     %s\n", rollup.FeesArtifact.Compiler)
	fmt.Printf("burn address %s\n", rollup.BurnAddr)
	return nil
}

// feesDeploy publishes the deployment as a **native call**, which is the one
// lane that works on any chain: it needs no relayer, no EVM balance and no
// nonce, only a NoM account with plasma. The same message deploys at the same
// address on every chain that derives it.
func feesDeploy(args []string) error {
	fs := flag.NewFlagSet("fees deploy", flag.ExitOnError)
	configPath := fs.String("config", "l2/rollup.json", "rollup config")
	l1URL := endpoint(fs, "l1", envNoM, "NoM node JSON-RPC")
	ethURL := endpoint(fs, "eth", envZVM, "ZVM JSON-RPC, to confirm the code landed")
	index := fs.Uint("index", 1, "dev mnemonic index to publish from")
	gas := fs.Uint64("gas", 1_500_000, "gas to declare for the deployment")
	feeToken := fs.String("fee-token", "ZNN", "token burned for gas, where the chain prices native calls")
	wait := fs.Duration("wait", 90*time.Second, "how long to wait for the code to appear")
	fs.Parse(args)
	if err := needEndpoints(fs, "l1", "eth"); err != nil {
		return err
	}

	cfg, err := rollup.Load(*configPath)
	if err != nil {
		return err
	}
	token, err := parseFeeToken(*feeToken)
	if err != nil {
		return err
	}
	ctx := context.Background()
	eth, err := ethclient.DialContext(ctx, *ethURL)
	if err != nil {
		return err
	}
	if code, err := eth.CodeAt(ctx, rollup.FeeSplitterAddr, nil); err == nil && len(code) > 0 {
		fmt.Printf("already deployed: %s holds %d bytes\n", rollup.FeeSplitterAddr, len(code))
		return nil
	}

	to := rollup.Create2Deployer
	call := derive.Call{
		To:    &to,
		Value: new(big.Int),
		Gas:   *gas,
		Data:  rollup.DeployCalldata(rollup.FeesSalt, rollup.FeesArtifact.InitCode()),
	}
	acct := znn.NewAccount(devnet.Key(uint32(*index)), znn.NewClient(*l1URL), cfg.L1ChainID)
	carrier, tx, err := derive.PublishCall(ctx, cfg, acct, token, call)
	if err != nil {
		return err
	}
	fmt.Printf("NoM block    %s (%d bytes, %d plasma)\n", carrier.Hash, len(carrier.Data), carrier.UsedPlasma)
	if burn := carrier.AmountBig(); burn.Sign() > 0 {
		fmt.Printf("burned       %s %s for gas\n", burn, carrier.TokenStandard)
	}
	fmt.Printf("L2 tx        %s\n", tx.Hash())
	fmt.Printf("expecting    %s\n", rollup.FeeSplitterAddr)

	deadline := time.Now().Add(*wait)
	for time.Now().Before(deadline) {
		if code, err := eth.CodeAt(ctx, rollup.FeeSplitterAddr, nil); err == nil && len(code) > 0 {
			fmt.Printf("deployed     %d bytes of runtime code\n", len(code))
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("no code at %s after %s: the call may have been dropped, or this chain may not derive that inbox",
		rollup.FeeSplitterAddr, *wait)
}

func feesStatus(args []string) error {
	fs := flag.NewFlagSet("fees status", flag.ExitOnError)
	ethURL := endpoint(fs, "eth", envZVM, "ZVM JSON-RPC")
	fs.Parse(args)
	if err := needEndpoints(fs, "eth"); err != nil {
		return err
	}
	ctx := context.Background()
	eth, err := ethclient.DialContext(ctx, *ethURL)
	if err != nil {
		return err
	}
	code, err := eth.CodeAt(ctx, rollup.FeeSplitterAddr, nil)
	if err != nil {
		return err
	}
	if len(code) == 0 {
		fmt.Printf("%s holds no code on this chain: `zvm fees deploy` puts it there\n", rollup.FeeSplitterAddr)
		return nil
	}
	read := func(sig string) *big.Int {
		sel := crypto.Keccak256([]byte(sig))[:4]
		to := rollup.FeeSplitterAddr
		out, err := eth.CallContract(ctx, ethereum.CallMsg{To: &to, Data: sel}, nil)
		if err != nil || len(out) < 32 {
			return new(big.Int)
		}
		return new(big.Int).SetBytes(out[:32])
	}
	bal, _ := eth.BalanceAt(ctx, rollup.FeeSplitterAddr, nil)
	burned, _ := eth.BalanceAt(ctx, rollup.BurnAddr, nil)
	collected, owed := read("totalCollected()"), read("totalOwed()")
	paid, split := read("totalPaid()"), read("totalBurned()")
	onNoM, gap := read("burnedOnNoM()"), read("unmirrored()")

	fmt.Printf("splitter     %s\n", rollup.FeeSplitterAddr)
	fmt.Printf("  balance    %s wei (owed %s, the rest is this block's takings)\n", bal, owed)
	fmt.Printf("  collected  %s wei split so far\n", collected)
	fmt.Printf("  paid out   %s wei withdrawn by relayers\n", paid)
	fmt.Printf("burn         %s\n", rollup.BurnAddr)
	fmt.Printf("  burned     %s wei sent here by the splitter (balance %s)\n", split, burned)
	fmt.Printf("  on NoM     %s wei the committee has destroyed to match it\n", onNoM)
	if gap.Sign() > 0 {
		fmt.Printf("  unmirrored %s wei — %s NoM base units the committee still owes the burn\n",
			gap, new(big.Int).Div(gap, rollup.ZNNScale))
	} else {
		fmt.Printf("  unmirrored none: NoM's supply has lost everything this chain burned\n")
	}
	return nil
}

var _ = common.Address{}
