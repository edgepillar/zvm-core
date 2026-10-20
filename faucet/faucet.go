// Package faucet hands out devnet funds, on the layer the address can use.
//
// A Zenon address (first byte 0x00) gets ZNN, QSR and a plasma fusion on
// Zenon, and nothing on the ZVM. The fusion is there because a fresh Syrius
// wallet with no plasma computes proof of work for every block — tens of
// seconds each — and would read as a broken integration rather than an
// unfunded one. Any other address gets ZNN on the ZVM only: no Zenon key can
// sign for it, so Zenon funds sent there would be lost.
//
// A Zenon address's own 20 bytes are an account on the ZVM too, but only a
// native call can spend from it, and wallets act on the ZVM through an EVM
// key. ZVM ZNN paid there sat unused, so the faucet no longer pays it.
package faucet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

var plasmaContract = znn.MustParseAddress("z1qxemdeddedxplasmaxxxxxxxxxxxxxxxxsctrp")

// fuseData is plasma.Fuse(beneficiary). Embedded-contract selectors are the
// first four bytes of SHA3-256 of the signature — SHA3, not Keccak.
func fuseData(beneficiary znn.Address) []byte {
	sel := znn.Sha3([]byte("Fuse(address)"))
	return append(append([]byte{}, sel[:4]...), common.LeftPadBytes(beneficiary[:], 32)...)
}

type Config struct {
	Rollup  *rollup.Config
	L1      *znn.Client
	Eth     *ethclient.Client
	Account *znn.Account

	// Amounts: L1 in NoM base units, L2 in wei.
	L1ZNN   *big.Int
	L1QSR   *big.Int
	FuseQSR *big.Int
	L2ZNN   *big.Int

	// L2Floor and L2TopUp keep the faucet's own ZVM balance funded by
	// depositing through the vault, so faucet ZNN is backed like any other.
	L2Floor *big.Int
	L2TopUp *big.Int

	Cooldown time.Duration
	Log      *slog.Logger
}

type Faucet struct {
	cfg Config

	mu     sync.Mutex
	lastBy map[string]time.Time

	served atomic.Uint64
}

func New(cfg Config) *Faucet {
	return &Faucet{cfg: cfg, lastBy: map[string]time.Time{}}
}

// Result lists what a drip sent.
type Result struct {
	Address   string `json:"address"`
	EVM       string `json:"evmAddress"`
	L1ZNN     string `json:"l1ZnnBlock,omitempty"`
	L1QSR     string `json:"l1QsrBlock,omitempty"`
	L1Fuse    string `json:"l1FuseBlock,omitempty"`
	L2Carrier string `json:"l2NomBlock,omitempty"`
	L2Tx      string `json:"l2Tx,omitempty"`
	L1Skipped string `json:"l1Skipped,omitempty"`
	L2Skipped string `json:"l2Skipped,omitempty"`
}

// Why each half of a drip is skipped for an address, or "" for the half it
// gets. Exactly one is empty.
func skipped(nom znn.Address) (l1, l2 string) {
	if nom.IsUser() {
		return "", "a Zenon address: Zenon funds only. ZVM ZNN goes to an EVM (0x…) address"
	}
	return "not a Zenon address: ZVM funds only", ""
}

// CooldownError reports a request inside the cooldown window. Client is set
// when it was the requester, not the recipient, that was paid recently: a new
// address from a client already served used to be told "already paid that
// recipient", which is false and sent people looking for a payment that never
// happened.
type CooldownError struct {
	Wait   time.Duration
	Client bool
}

func (e *CooldownError) Error() string {
	if e.Client {
		return fmt.Sprintf("this faucet already paid a request from your connection; try again in %s", e.Wait.Round(time.Second))
	}
	return fmt.Sprintf("this faucet already paid that recipient; try again in %s", e.Wait.Round(time.Second))
}

func ParseAnyAddress(s string) (common.Address, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "z1") {
		a, err := znn.ParseAddress(strings.ToLower(s))
		return common.Address(a), err
	}
	if !common.IsHexAddress(s) {
		return common.Address{}, errors.New("not a z1… or 0x… address")
	}
	return common.HexToAddress(s), nil
}

func (f *Faucet) claim(keys ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		if last, ok := f.lastBy[k]; ok && now.Sub(last) < f.cfg.Cooldown {
			return &CooldownError{Wait: f.cfg.Cooldown - now.Sub(last), Client: strings.HasPrefix(k, "client:")}
		}
	}
	for _, k := range keys {
		f.lastBy[k] = now
	}
	return nil
}

// Drip pays one recipient.
func (f *Faucet) Drip(ctx context.Context, addr common.Address, client string) (*Result, error) {
	if err := f.claim("addr:"+addr.Hex(), "client:"+client); err != nil {
		return nil, err
	}
	nom := znn.Address(addr)
	res := &Result{Address: nom.String(), EVM: addr.Hex()}
	res.L1Skipped, res.L2Skipped = skipped(nom)
	acct := f.cfg.Account
	if res.L1Skipped == "" {
		steps := []struct {
			out *string
			fn  func() (*znn.AccountBlock, error)
		}{
			{&res.L1ZNN, func() (*znn.AccountBlock, error) { return acct.Send(ctx, nom, znn.ZNN, f.cfg.L1ZNN, nil) }},
			{&res.L1QSR, func() (*znn.AccountBlock, error) { return acct.Send(ctx, nom, znn.QSR, f.cfg.L1QSR, nil) }},
			{&res.L1Fuse, func() (*znn.AccountBlock, error) {
				return acct.Send(ctx, plasmaContract, znn.QSR, f.cfg.FuseQSR, fuseData(nom))
			}},
		}
		for _, s := range steps {
			b, err := s.fn()
			if err != nil {
				acct.Reset()
				return nil, fmt.Errorf("paying on NoM: %w", err)
			}
			*s.out = b.Hash.String()
		}
	}
	if res.L2Skipped == "" {
		call := derive.Call{To: &addr, Value: f.cfg.L2ZNN, Gas: 30_000}
		b, tx, err := derive.PublishCall(ctx, f.cfg.Rollup, acct, znn.ZNN, call)
		if err != nil {
			acct.Reset()
			return nil, fmt.Errorf("paying on the ZVM: %w", err)
		}
		res.L2Carrier = b.Hash.String()
		res.L2Tx = tx.Hash().Hex()
	}
	f.served.Add(1)
	f.cfg.Log.Info("drip", "to", nom, "l1Znn", res.L1ZNN, "l2Tx", res.L2Tx)
	return res, nil
}

// KeepFunded tops the faucet's ZVM balance up through the vault.
func (f *Faucet) KeepFunded(ctx context.Context) {
	addr := common.Address(f.cfg.Account.Address())
	var pendingUntil time.Time
	for {
		bal, err := f.cfg.Eth.BalanceAt(ctx, addr, nil)
		switch {
		case err != nil:
			f.cfg.Log.Warn("reading faucet balance", "err", err)
		case bal.Cmp(f.cfg.L2Floor) < 0 && time.Now().After(pendingUntil):
			units := new(big.Int).Div(f.cfg.L2TopUp, rollup.ZNNScale)
			b, err := f.cfg.Account.Send(ctx, f.cfg.Rollup.Vault, znn.ZNN, units, nil)
			if err != nil {
				f.cfg.Account.Reset()
				f.cfg.Log.Warn("topping up the faucet", "err", err)
			} else {
				f.cfg.Log.Info("topped up the faucet through the vault", "znn", new(big.Int).Div(units, znn.OneZNN), "nomBlock", b.Hash)
				pendingUntil = time.Now().Add(2 * time.Minute)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}

type Status struct {
	Address    string            `json:"address"`
	L1Balances map[string]string `json:"l1Balances"`
	L2Balance  string            `json:"l2Balance"`
	Served     uint64            `json:"served"`
	Drip       map[string]string `json:"drip"`
	Cooldown   string            `json:"cooldown"`
}

func (f *Faucet) Status(ctx context.Context) *Status {
	s := &Status{
		Address: f.cfg.Account.Address().String(), L1Balances: map[string]string{}, Served: f.served.Load(),
		Cooldown: f.cfg.Cooldown.String(),
		Drip: map[string]string{
			"l1Znn": f.cfg.L1ZNN.String(), "l1Qsr": f.cfg.L1QSR.String(), "fuseQsr": f.cfg.FuseQSR.String(), "l2ZnnWei": f.cfg.L2ZNN.String(),
		},
	}
	if info, err := f.cfg.L1.AccountInfo(ctx, f.cfg.Account.Address()); err == nil {
		s.L1Balances["ZNN"] = info.Balance(znn.ZNN).String()
		s.L1Balances["QSR"] = info.Balance(znn.QSR).String()
	}
	if bal, err := f.cfg.Eth.BalanceAt(ctx, common.Address(f.cfg.Account.Address()), nil); err == nil {
		s.L2Balance = bal.String()
	}
	return s
}
