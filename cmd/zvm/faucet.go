package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/ethrpc"
	"github.com/Zenoglyphs-VM/zvm-core/faucet"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("faucet", "hand out devnet ZNN/QSR on NoM (with plasma) and ZNN on the ZVM", runFaucet)
}

func runFaucet(args []string) error {
	fs := flag.NewFlagSet("faucet", flag.ExitOnError)
	configPath := fs.String("config", "/config/rollup.json", "rollup config")
	l1URL := fs.String("l1", "http://l1-rpc:35997", "NoM node JSON-RPC")
	ethURL := fs.String("eth", "http://op-geth:8545", "ZVM JSON-RPC")
	listen := fs.String("listen", ":8549", "HTTP listen address")
	index := fs.Uint("index", devnet.Faucet, "dev mnemonic index of the faucet account")
	cooldown := fs.Duration("cooldown", 10*time.Second, "per-recipient and per-client cooldown")
	// The drip and the float, in whole units. These were constants sized for
	// the allocation `zvm l1-genesis` writes — 10 M ZNN to the faucet — which
	// is the wrong scale on a chain this faucet was funded on by hand: a
	// top-up larger than the whole budget fails, resets the account and logs,
	// every fifteen seconds, forever.
	dripZNN := fs.Int64("drip-znn", 100, "ZNN each NoM recipient is paid")
	dripQSR := fs.Int64("drip-qsr", 1_000, "QSR each NoM recipient is paid")
	dripFuse := fs.Int64("drip-fuse-qsr", 200, "QSR fused for each NoM recipient, so a fresh wallet is not computing PoW per block")
	dripL2 := fs.Int64("drip-l2-znn", 50, "ZNN each recipient is paid on the ZVM")
	l2Floor := fs.Int64("l2-floor", 1_000, "ZVM balance below which the faucet refills its own float through the vault")
	l2TopUp := fs.Int64("l2-top-up", 100_000, "ZNN the faucet deposits through the vault when it refills")
	trustProxies := fs.String("trust-proxies", "", "comma-separated addresses or CIDRs whose X-Forwarded-For may be believed (default: none, so the cooldown keys on the peer)")
	fs.Parse(args)

	trusted, err := parseTrustedProxies(*trustProxies)
	if err != nil {
		return err
	}

	cfg, err := rollup.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	eth, err := waitFor(ctx, "ZVM rpc", func() (*ethclient.Client, error) {
		c, err := ethrpc.Dial(ctx, *ethURL)
		if err != nil {
			return nil, err
		}
		_, err = c.BlockNumber(ctx)
		return c, err
	})
	if err != nil {
		return err
	}
	l1 := znn.NewClient(*l1URL)
	acct := znn.NewAccount(devnet.Key(uint32(*index)), l1, cfg.L1ChainID)
	acct.AssumeFused = true
	wei := func(whole int64) *big.Int { return new(big.Int).Mul(devnet.Units(whole), rollup.ZNNScale) }
	f := faucet.New(faucet.Config{
		Rollup: cfg, L1: l1, Eth: eth, Account: acct,
		L1ZNN: devnet.Units(*dripZNN), L1QSR: devnet.Units(*dripQSR), FuseQSR: devnet.Units(*dripFuse), L2ZNN: wei(*dripL2),
		L2Floor: wei(*l2Floor), L2TopUp: wei(*l2TopUp),
		Cooldown: *cooldown, Log: slog.Default().With("svc", "faucet"),
	})
	go f.KeepFunded(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, f.Status(r.Context()))
	})
	mux.HandleFunc("/drip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST {\"address\": \"z1… or 0x…\"}", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected {\"address\": \"…\"}"})
			return
		}
		addr, err := faucet.ParseAnyAddress(body.Address)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		res, err := f.Drip(r.Context(), addr, clientKey(r, trusted))
		if err != nil {
			status := http.StatusBadGateway
			var cd *faucet.CooldownError
			if errors.As(err, &cd) {
				status = http.StatusTooManyRequests
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		srv.Shutdown(c)
	}()
	slog.Info("faucet listening", "addr", *listen, "account", acct.Address())
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// clientKey identifies the requester for the cooldown.
//
// **Not the first X-Forwarded-For hop**, which is what this used to take and
// what the fleet benchmark found (defect 3): a client sets that header itself,
// a proxy only *appends* to it, so the first hop is the caller's own claim and
// a different value in each request walks straight around the cooldown.
//
// So the peer's address is the default, and the header is read only for a peer
// that is a configured trusted proxy — and then only the last hop, the one
// that proxy appended, because it is the only one it saw for itself. Each
// further trusted proxy in the chain lets one more hop be believed.
func clientKey(r *http.Request, trusted []netip.Prefix) string {
	peer := peerIP(r.RemoteAddr)
	if len(trusted) == 0 || !trustedIP(peer, trusted) {
		return peer
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		if trustedIP(hop, trusted) {
			continue // another of ours; keep walking left
		}
		return hop
	}
	return peer
}

func peerIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

func trustedIP(ip string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseTrustedProxies reads the -trust-proxies list: CIDRs, or bare addresses.
func parseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p)
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("-trust-proxies %q: not an address or a CIDR", part)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}
