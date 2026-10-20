// Package cli holds the argument parsing, amount formatting and JSON replies
// that every ZVM command line and status endpoint does identically.
//
// These began as unexported helpers in cmd/zvm. Once the node, the relayer and
// the bridge became separate modules they had to be shared rather than copied:
// a -index flag that means a different dev key in two binaries, or a parseUnits
// that rounds in one and errors in the other, is the kind of difference nobody
// notices until a transfer is off by a factor of ten.
package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// The nodes a command talks to come from the environment, never from the
// binary: a built-in address is a node every user of the tool leans on without
// choosing it. NOM_NODE is a NoM node's JSON-RPC, ZVM_RPC the ZVM's, ZVM_NODE a
// ZVM node's read API (the base that /api and /rpc hang off) and ZVM_RELAYER a
// relayer. Each repository's .env.example names a local zvm-devnet's.
const (
	EnvNoM     = "NOM_NODE"
	EnvZVM     = "ZVM_RPC"
	EnvAPI     = "ZVM_NODE"
	EnvRelayer = "ZVM_RELAYER"
)

type endpointKey struct {
	fs   *flag.FlagSet
	name string
}

var endpointEnv = map[endpointKey]string{}

// Endpoint registers a URL flag that defaults to the environment variable env.
func Endpoint(fs *flag.FlagSet, name, env, usage string) *string {
	endpointEnv[endpointKey{fs, name}] = env
	return fs.String(name, os.Getenv(env), usage+" (default $"+env+")")
}

// NeedEndpoints fails, naming what to set, when any of the named endpoint
// flags on a parsed fs is empty.
func NeedEndpoints(fs *flag.FlagSet, names ...string) error {
	for _, name := range names {
		f := fs.Lookup(name)
		if f == nil || f.Value.String() != "" {
			continue
		}
		if env, ok := endpointEnv[endpointKey{fs, name}]; ok {
			return fmt.Errorf("-%s is not set: pass it, or set %s", name, env)
		}
		return fmt.Errorf("-%s is not set", name)
	}
	return nil
}

// ClientFlags are the four endpoints and one key index a command needs to talk
// to both layers.
type ClientFlags struct {
	Config *string
	L1     *string
	Eth    *string
	Index  *uint
	Wait   *time.Duration
}

func AddClientFlags(fs *flag.FlagSet) ClientFlags {
	return ClientFlags{
		Config: fs.String("config", "l2/rollup.json", "rollup config"),
		L1:     Endpoint(fs, "l1", EnvNoM, "NoM node JSON-RPC"),
		Eth:    Endpoint(fs, "eth", EnvZVM, "ZVM JSON-RPC"),
		Index:  fs.Uint("index", devnet.DevOwner, "dev mnemonic index to sign with"),
		Wait:   fs.Duration("wait", 90*time.Second, "how long to wait for the L2 receipt (0 to not wait)"),
	}
}

// ParseEVMOrNoM accepts either of the two spellings an address has on this
// chain: a 0x EVM address, or the z1 Zenon address whose 20 bytes it is.
func ParseEVMOrNoM(s string) (common.Address, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "z1") {
		a, err := znn.ParseAddress(s)
		return common.Address(a), err
	}
	if !common.IsHexAddress(s) {
		return common.Address{}, fmt.Errorf("%q is neither a 0x nor a z1 address", s)
	}
	return common.HexToAddress(s), nil
}

// ParseHexData reads calldata as hex, or from a file when prefixed with @.
func ParseHexData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "@") {
		raw, err := os.ReadFile(s[1:])
		if err != nil {
			return nil, err
		}
		s = strings.TrimSpace(string(raw))
	}
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

// ParseUnits parses a decimal amount with the given number of decimals. An
// amount with more precision than the token has is an error rather than a
// rounding, so that a typo cannot quietly become a different transfer.
func ParseUnits(s string, decimals int) (*big.Int, error) {
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("bad amount %q", s)
	}
	r.Mul(r, new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)))
	if !r.IsInt() {
		return nil, fmt.Errorf("amount %q has more than %d decimals", s, decimals)
	}
	return r.Num(), nil
}

// FormatUnits is ParseUnits backwards, without trailing zeros.
func FormatUnits(x *big.Int, decimals int) string {
	r := new(big.Rat).SetFrac(x, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
	return strings.TrimRight(strings.TrimRight(r.FloatString(decimals), "0"), ".")
}

// ParseFeeToken picks the token a native call burns for its gas.
func ParseFeeToken(s string) (znn.TokenStandard, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ZNN", "":
		return znn.ZNN, nil
	case "QSR":
		return znn.QSR, nil
	}
	return znn.ZeroTokenStandard, fmt.Errorf("-fee-token must be ZNN or QSR, not %q", s)
}

func WaitReceipt(ctx context.Context, eth *ethclient.Client, hash common.Hash, timeout time.Duration) (*types.Receipt, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r, err := eth.TransactionReceipt(ctx, hash)
		if err == nil {
			return r, nil
		}
		time.Sleep(time.Second)
	}
	return nil, errors.New("no receipt yet (the block may still be on its way, or the message was dropped)")
}

// WriteJSON is how every status endpoint in this tree replies.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
