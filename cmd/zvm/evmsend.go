package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("evm-send", "sign and send EVM transactions with a secp256k1 key, as MetaMask would", runEVMSend)
	register("evm-key", "print a dev secp256k1 key and its addresses (for importing into MetaMask/Rabby)", runEVMKey)
}

func loadEVMKey(hexKey string, index uint) (*ecdsa.PrivateKey, error) {
	if hexKey != "" {
		return crypto.HexToECDSA(trim0x(hexKey))
	}
	return devnet.EVMKey(uint32(index)), nil
}

func trim0x(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

func runEVMKey(args []string) error {
	fs := flag.NewFlagSet("evm-key", flag.ExitOnError)
	index := fs.Uint("index", 0, "dev EVM key index")
	fs.Parse(args)
	key := devnet.EVMKey(uint32(*index))
	addr := crypto.PubkeyToAddress(key.PublicKey)
	fmt.Printf("private key  0x%x\n", crypto.FromECDSA(key))
	fmt.Printf("address      %s\n", addr.Hex())
	fmt.Printf("as NoM       %s\n", znn.Address(addr))
	return nil
}

func runEVMSend(args []string) error {
	fs := flag.NewFlagSet("evm-send", flag.ExitOnError)
	configPath := fs.String("config", "l2/rollup.json", "rollup config")
	ethURL := endpoint(fs, "eth", envZVM, "ZVM JSON-RPC to read state from")
	l1URL := endpoint(fs, "l1", envNoM, "NoM node JSON-RPC, for the height -batch encodes at")
	submitURL := fs.String("submit", "", "where to send the raw transaction (default: -eth, which forwards to the relayer)")
	keyHex := fs.String("key", "", "private key hex (default: the dev EVM key at -key-index)")
	keyIndex := fs.Uint("key-index", 0, "dev EVM key index")
	to := fs.String("to", "", "recipient (0x or z1); empty deploys -data")
	value := fs.String("value", "0", "ZNN to send")
	data := fs.String("data", "", "calldata as hex, or @file")
	gas := fs.Uint64("gas", 0, "gas limit (0: estimate + 20%)")
	count := fs.Int("count", 1, "send this many transactions with consecutive nonces")
	wait := fs.Duration("wait", 90*time.Second, "how long to wait for the last receipt (0 to not wait)")
	batch := fs.Bool("batch", false, "do not send: print the signed transactions as one 0x02 inbox message, for `zvm call -message`")
	nonceFlag := fs.Int64("nonce", -1, "first nonce to sign with (default: the account's next)")
	fs.Parse(args)
	if err := needEndpoints(fs, "eth"); err != nil {
		return err
	}

	cfg, err := rollup.Load(*configPath)
	if err != nil {
		return err
	}
	key, err := loadEVMKey(*keyHex, *keyIndex)
	if err != nil {
		return err
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	payload, err := parseHexData(*data)
	if err != nil {
		return err
	}
	v, err := parseUnits(*value, 18)
	if err != nil {
		return err
	}
	var target *common.Address
	if *to != "" {
		a, err := parseEVMOrNoM(*to)
		if err != nil {
			return err
		}
		target = &a
	}

	ctx := context.Background()
	eth, err := ethclient.Dial(*ethURL)
	if err != nil {
		return err
	}
	submit := eth
	if *submitURL != "" {
		if submit, err = ethclient.Dial(*submitURL); err != nil {
			return err
		}
	}
	nonce, err := eth.NonceAt(ctx, from, nil)
	if err != nil {
		return err
	}
	if *nonceFlag >= 0 {
		nonce = uint64(*nonceFlag)
	}
	head, err := eth.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	// The tip is the only part of a relayed fee that reaches the relayer, so it
	// is not decorative: see rollup.DefaultTipWei.
	tip := rollup.DefaultTip()
	// Headroom sized to this chain's fee market rather than a flat 2×: past the
	// market fork the base fee can more than double in a block, and a cap is a
	// ceiling rather than a price.
	feeCap := cfg.SuggestedFeeCap(head.BaseFee, tip)
	gasLimit := *gas
	if gasLimit == 0 {
		est, err := eth.EstimateGas(ctx, ethereum.CallMsg{From: from, To: target, Value: v, Data: payload})
		if err != nil {
			return fmt.Errorf("estimating gas: %w", err)
		}
		gasLimit = est * 12 / 10
	}
	signer := types.LatestSignerForChainID(cfg.L2ChainIDBig())
	var last *types.Transaction
	var raws [][]byte
	var signed []*types.Transaction
	started := time.Now()
	for i := 0; i < *count; i++ {
		tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
			ChainID: cfg.L2ChainIDBig(), Nonce: nonce + uint64(i), GasTipCap: tip, GasFeeCap: feeCap,
			Gas: gasLimit, To: target, Value: v, Data: payload,
		})
		if err != nil {
			return err
		}
		if *batch {
			encoded, err := tx.MarshalBinary()
			if err != nil {
				return err
			}
			raws, last, signed = append(raws, encoded), tx, append(signed, tx)
			continue
		}
		if err := submit.SendTransaction(ctx, tx); err != nil {
			return fmt.Errorf("tx %d (nonce %d): %w", i, tx.Nonce(), err)
		}
		last = tx
	}
	// -batch prints the message a relayer would post instead of posting it, so
	// an exact batch — including one the engine will refuse (D12) — can be put
	// on a chain by hand with `zvm call -message`.
	if *batch {
		if err := needEndpoints(fs, "l1"); err != nil {
			return err
		}
		// The codec is chosen by height, so it has to be *this* chain's height:
		// encoding at zero always picks the pre-fork one, which on a forked
		// chain is not what a relayer would post.
		frontier, err := znn.NewClient(*l1URL).FrontierMomentum(ctx)
		if err != nil {
			return fmt.Errorf("reading the frontier momentum for the codec: %w", err)
		}
		msg, err := derive.EncodeBatch(raws, derive.BestCodec(cfg.Forks, frontier.Height))
		if err != nil {
			return err
		}
		fmt.Printf("from        %s (%s)\n", from.Hex(), znn.Address(from))
		for i, tx := range signed {
			fmt.Printf("tx %d        %s (nonce %d, %d bytes)\n", i, tx.Hash(), tx.Nonce(), len(raws[i]))
		}
		fmt.Printf("message     0x%x\n", msg)
		fmt.Printf("publish it  zvm call -index 1 -message 0x%x\n", msg)
		return nil
	}
	raw, _ := last.MarshalBinary()
	fmt.Printf("from        %s (%s)\n", from.Hex(), znn.Address(from))
	fmt.Printf("sent        %d tx, nonces %d..%d, gas %d, %d bytes each, fee cap %s wei\n",
		*count, nonce, nonce+uint64(*count)-1, gasLimit, len(raw), feeCap)
	fmt.Printf("last tx     %s\n", last.Hash().Hex())
	if *wait == 0 {
		return nil
	}
	r, err := waitReceipt(ctx, eth, last.Hash(), *wait)
	if err != nil {
		return err
	}
	fmt.Printf("receipt     block %d, status %d, gas used %d, %.1fs after submit\n",
		r.BlockNumber, r.Status, r.GasUsed, time.Since(started).Seconds())
	if r.ContractAddress != (common.Address{}) {
		fmt.Printf("contract    %s = %s\n", r.ContractAddress.Hex(), znn.Address(r.ContractAddress))
	}
	_ = hexutil.Encode
	return nil
}
