package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/l2"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("call", "send a native call (or a contract deploy) from a dev key through the inbox", runCall)
	register("deposit", "deposit ZNN or QSR from a dev key into the ZVM through the vault", runDeposit)
	register("balance", "show an address's balances on NoM and on the ZVM", runBalance)
}

func runCall(args []string) error {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	cf := addClientFlags(fs)
	to := fs.String("to", "", "target address (0x or z1); empty deploys -data as init code")
	data := fs.String("data", "", "calldata or init code as hex, or @file")
	value := fs.String("value", "0", "ZNN to send with the call")
	gas := fs.Uint64("gas", 0, "gas to ask for (0: what the block's plasma buys)")
	message := fs.String("message", "", "a complete call message as hex (0x01‖rlp…), published verbatim instead of -to/-data/-value/-gas")
	feeToken := fs.String("fee-token", "ZNN", "token burned for gas, where the chain prices native calls (ZNN or QSR)")
	boost := fs.String("boost", "0", "extra to burn for admission priority rather than gas, in whole units (needs the gas fork)")
	fs.Parse(args)
	if err := needEndpoints(fs, "l1", "eth"); err != nil {
		return err
	}

	cfg, err := rollup.Load(*cf.config)
	if err != nil {
		return err
	}
	payload, err := parseHexData(*data)
	if err != nil {
		return err
	}
	v, err := parseUnits(*value, 18)
	if err != nil {
		return err
	}
	call := derive.Call{Value: v, Gas: *gas, Data: payload}
	if *to != "" {
		a, err := parseEVMOrNoM(*to)
		if err != nil {
			return err
		}
		call.To = &a
	}
	// A boost is a fifth item, so it only exists on a chain whose gas fork has
	// a height. It rides on top of the fee rather than inside it: what the
	// block burns is the quote plus the boost.
	bo, err := parseUnits(*boost, 8)
	if err != nil {
		return fmt.Errorf("-boost: %w", err)
	}
	if bo.Sign() > 0 {
		if !cfg.Forks.GasScheduled() {
			return fmt.Errorf("-boost needs a chain whose gas fork has a height; this one has none")
		}
		call.Boost = bo
	}

	ctx := context.Background()
	l1 := znn.NewClient(*cf.l1)
	acct := znn.NewAccount(devnet.Key(uint32(*cf.index)), l1, cfg.L1ChainID)
	msg := derive.EncodeCall(call)
	if *message != "" {
		// Verbatim, so a test can publish exactly the bytes a page built
		// rather than this command's re-encoding of them.
		if msg, err = parseHexData(*message); err != nil {
			return err
		}
		if len(msg) == 0 {
			return fmt.Errorf("-message is empty")
		}
		switch msg[0] {
		case derive.MsgCall:
			if call, err = derive.DecodeCall(msg[1:], cfg.Forks.GasScheduled()); err != nil {
				return fmt.Errorf("-message: %w", err)
			}
		case derive.MsgBatch:
			// A batch buys no gas and burns nothing, so it is published as it
			// stands. This is the lane a relayer uses; here it is how an exact
			// batch — a span, say — can be put on a chain by hand.
			b, err := acct.Send(ctx, cfg.Inbox, znn.ZeroTokenStandard, new(big.Int), msg)
			if err != nil {
				return err
			}
			fmt.Printf("NoM block   %s (height %d, %d bytes, %d plasma)\n", b.Hash, b.Height, len(b.Data), b.UsedPlasma)
			fmt.Printf("batch       flag 0x%02x, published to the inbox %s\n", msg[1], cfg.Inbox)
			return nil
		default:
			return fmt.Errorf("-message must start with the call type 0x01 or the batch type 0x02")
		}
	}

	token, err := parseFeeToken(*feeToken)
	if err != nil {
		return err
	}
	carrier, tx, err := derive.PublishMessage(ctx, cfg, acct, token, msg, call)
	if err != nil {
		return err
	}
	fmt.Printf("NoM block   %s (height %d, %d bytes, %d plasma)\n", carrier.Hash, carrier.Height, len(carrier.Data), carrier.UsedPlasma)
	if burn := carrier.AmountBig(); burn.Sign() > 0 {
		fmt.Printf("burned      %s %s to the inbox, which nobody can spend\n", formatUnits(burn, 8), carrier.TokenStandard)
	}
	fmt.Printf("from        %s = %s\n", carrier.Address, common.Address(carrier.Address).Hex())
	fmt.Printf("L2 tx       %s (gas %d)\n", tx.Hash().Hex(), tx.Gas())
	if *cf.wait == 0 {
		return nil
	}
	eth, err := ethclient.Dial(*cf.eth)
	if err != nil {
		return err
	}
	r, err := waitReceipt(ctx, eth, tx.Hash(), *cf.wait)
	if err != nil {
		return err
	}
	fmt.Printf("receipt     block %d, status %d, gas used %d\n", r.BlockNumber, r.Status, r.GasUsed)
	if r.ContractAddress != (common.Address{}) {
		fmt.Printf("contract    %s = %s\n", r.ContractAddress.Hex(), znn.Address(r.ContractAddress))
	}
	return nil
}

func runDeposit(args []string) error {
	fs := flag.NewFlagSet("deposit", flag.ExitOnError)
	cf := addClientFlags(fs)
	amount := fs.String("amount", "10", "amount in whole units")
	token := fs.String("token", "ZNN", "ZNN or QSR")
	to := fs.String("to", "", "credit another ZVM address instead of the sender's own")
	message := fs.String("message", "", "a call message as hex to attach verbatim (ZNN only), instead of -to")
	fs.Parse(args)
	if err := needEndpoints(fs, "l1", "eth"); err != nil {
		return err
	}

	cfg, err := rollup.Load(*cf.config)
	if err != nil {
		return err
	}
	amt, err := parseUnits(*amount, 8)
	if err != nil {
		return err
	}
	var zts znn.TokenStandard
	switch strings.ToUpper(*token) {
	case "ZNN":
		zts = znn.ZNN
	case "QSR":
		zts = znn.QSR
	default:
		return fmt.Errorf("token must be ZNN or QSR")
	}
	var data []byte
	var call *derive.Call
	if *to != "" {
		a, err := parseEVMOrNoM(*to)
		if err != nil {
			return err
		}
		if zts == znn.ZNN {
			// ZNN mints to the sender then spends it: the carried call is a
			// plain value transfer to the real recipient.
			call = &derive.Call{To: &a, Value: new(big.Int).Mul(amt, rollup.ZNNScale), Gas: 30_000}
		} else {
			// QSR has no native value to spend; naming the recipient is the
			// whole call — WrappedQSR is minted to it directly.
			call = &derive.Call{To: &a}
		}
		data = derive.EncodeCall(*call)
	}
	if *message != "" {
		if zts != znn.ZNN {
			return fmt.Errorf("-message works for ZNN deposits only")
		}
		if data, err = parseHexData(*message); err != nil {
			return err
		}
		if len(data) == 0 || data[0] != derive.MsgCall {
			return fmt.Errorf("-message must start with the call type 0x01")
		}
		c, err := derive.DecodeCall(data[1:], cfg.Forks.GasScheduled())
		if err != nil {
			return fmt.Errorf("-message: %w", err)
		}
		call = &c
	}

	ctx := context.Background()
	acct := znn.NewAccount(devnet.Key(uint32(*cf.index)), znn.NewClient(*cf.l1), cfg.L1ChainID)
	b, err := acct.Send(ctx, cfg.Vault, zts, amt, data)
	if err != nil {
		return err
	}
	fmt.Printf("NoM block   %s: %s %s from %s to the vault %s\n", b.Hash, *amount, *token, b.Address, cfg.Vault)
	if zts != znn.ZNN {
		recipient := l2.EthAddress(b.Address)
		if call != nil && call.To != nil {
			recipient = *call.To
		}
		fmt.Printf("QSR is minted by the bridge contract; check the WrappedQSR balance of %s\n", recipient)
		return nil
	}
	var tx *types.Transaction
	if call != nil {
		tx = derive.DepositCallTx(cfg, b, *call)
	} else {
		tx = derive.DepositTx(b)
	}
	fmt.Printf("L2 tx       %s\n", tx.Hash().Hex())
	if *cf.wait == 0 {
		return nil
	}
	eth, err := ethclient.Dial(*cf.eth)
	if err != nil {
		return err
	}
	r, err := waitReceipt(ctx, eth, tx.Hash(), *cf.wait)
	if err != nil {
		return err
	}
	fmt.Printf("receipt     block %d, status %d\n", r.BlockNumber, r.Status)
	return nil
}

func runBalance(args []string) error {
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	cf := addClientFlags(fs)
	addr := fs.String("addr", "", "address (0x or z1); defaults to the -index dev key")
	fs.Parse(args)
	if err := needEndpoints(fs, "l1", "eth"); err != nil {
		return err
	}

	var a common.Address
	if *addr == "" {
		a = common.Address(devnet.Key(uint32(*cf.index)).Address)
	} else {
		var err error
		if a, err = parseEVMOrNoM(*addr); err != nil {
			return err
		}
	}
	ctx := context.Background()
	fmt.Printf("address     %s = %s\n", a.Hex(), znn.Address(a))
	if znn.Address(a).IsUser() {
		info, err := znn.NewClient(*cf.l1).AccountInfo(ctx, znn.Address(a))
		if err == nil {
			fmt.Printf("NoM         %s ZNN, %s QSR\n", formatUnits(info.Balance(znn.ZNN), 8), formatUnits(info.Balance(znn.QSR), 8))
		}
	}
	eth, err := ethclient.Dial(*cf.eth)
	if err != nil {
		return err
	}
	bal, err := eth.BalanceAt(ctx, a, nil)
	if err != nil {
		return err
	}
	nonce, _ := eth.NonceAt(ctx, a, nil)
	fmt.Printf("ZVM         %s ZNN (nonce %d)\n", formatUnits(bal, 18), nonce)
	return nil
}
