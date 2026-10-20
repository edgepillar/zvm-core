package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("fund", "put ZNN, QSR and plasma on an L1 account, for a chain that is already running", runFund)
}

// runFund bootstraps a service account on an L1 nobody here genesised.
//
// `zvm l1-genesis` writes balances and fusions straight into a genesis, which
// is the only funding path this tree had. It is unavailable the moment the
// target is a network that is already producing momentums — someone else's
// devnet, a testnet, mainnet — and then the vault, the faucet and the relayers
// start at zero with no way to get off it.
//
// Two NoM properties shape what this does:
//
//   - **A transfer is not a credit until the recipient receives it.** A send
//     sits in the recipient's unreceived list until they publish a receive, so
//     funding an account we hold the key for means publishing that receive too.
//     The vault under a committee is the exception: nobody here can sign for
//     it, and it does not need us to — the bridge receives its own deposits.
//   - **Fusing for a beneficiary needs no signature from the beneficiary.**
//     Plasma is credited by the embedded contract, so a FROST vault can be
//     given plasma by anyone. That is what makes a committee-held vault
//     fundable at all, and it is why the fusion goes first here: an account
//     with plasma receives cheaply, one without computes proof of work per
//     block.
func runFund(args []string) error {
	fs := flag.NewFlagSet("fund", flag.ExitOnError)
	l1URL := endpoint(fs, "l1", envNoM, "NoM node JSON-RPC")
	chainID := fs.Uint64("l1-chain-id", devnet.L1ChainID, "NoM chain identifier the node must report")
	fromIndex := fs.Uint("from-index", devnet.DevOwner, "dev mnemonic index to pay from")
	to := fs.String("to", "", "recipient: a z1… address, or a dev mnemonic index")
	znnAmount := fs.String("znn", "0", "ZNN to transfer, in whole units")
	qsrAmount := fs.String("qsr", "0", "QSR to transfer, in whole units")
	fuseAmount := fs.String("fuse", "0", "QSR to fuse for the recipient's plasma, in whole units")
	wait := fs.Duration("wait", 3*time.Minute, "how long to wait for each block to confirm (0 to publish and not wait)")
	noReceive := fs.Bool("no-receive", false, "leave transfers unreceived even when the recipient's key is a dev index")
	fs.Parse(args)
	if err := needEndpoints(fs, "l1"); err != nil {
		return err
	}

	if strings.TrimSpace(*to) == "" {
		return errors.New("-to is required: a z1… address, or a dev mnemonic index")
	}
	amounts := map[string]*big.Int{}
	for name, raw := range map[string]string{"znn": *znnAmount, "qsr": *qsrAmount, "fuse": *fuseAmount} {
		v, err := parseUnits(raw, 8)
		if err != nil {
			return fmt.Errorf("-%s: %w", name, err)
		}
		if v.Sign() < 0 {
			return fmt.Errorf("-%s is negative", name)
		}
		amounts[name] = v
	}
	if amounts["znn"].Sign() == 0 && amounts["qsr"].Sign() == 0 && amounts["fuse"].Sign() == 0 {
		return errors.New("nothing to do: set -znn, -qsr or -fuse")
	}
	// NoM fuses at least ten QSR, in whole QSR. Refusing here names the rule;
	// the node would otherwise refuse the block with less to go on.
	if f := amounts["fuse"]; f.Sign() > 0 {
		if f.Cmp(new(big.Int).Mul(big.NewInt(10), znn.OneQSR)) < 0 {
			return fmt.Errorf("-fuse %s: NoM fuses at least 10 QSR", formatUnits(f, 8))
		}
		if new(big.Int).Mod(f, znn.OneQSR).Sign() != 0 {
			return fmt.Errorf("-fuse %s: NoM fuses whole QSR only", formatUnits(f, 8))
		}
	}

	recipient, recipientKey, err := resolveFundTarget(*to)
	if err != nil {
		return err
	}
	if !recipient.IsUser() {
		return fmt.Errorf("-to %s is not a user address", recipient)
	}

	ctx := context.Background()
	l1 := znn.NewClient(*l1URL)
	// Check the node is the chain the caller thinks it is before signing
	// anything: a block carries its chain id, so the alternative to this error
	// is a silent refusal at publish time.
	m, err := l1.FrontierMomentum(ctx)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *l1URL, err)
	}
	if m.ChainIdentifier != *chainID {
		return fmt.Errorf("the L1 node is chain %d, not %d", m.ChainIdentifier, *chainID)
	}

	funder := devnet.Key(uint32(*fromIndex))
	if funder.Address == recipient {
		return fmt.Errorf("-to is the funding account itself (%s)", recipient)
	}
	info, err := l1.AccountInfo(ctx, funder.Address)
	if err != nil {
		return err
	}
	needZNN := amounts["znn"]
	needQSR := new(big.Int).Add(amounts["qsr"], amounts["fuse"])
	if have := info.Balance(znn.ZNN); have.Cmp(needZNN) < 0 {
		return fmt.Errorf("index %d holds %s ZNN and this needs %s", *fromIndex, formatUnits(have, 8), formatUnits(needZNN, 8))
	}
	if have := info.Balance(znn.QSR); have.Cmp(needQSR) < 0 {
		return fmt.Errorf("index %d holds %s QSR and this needs %s (%s transferred plus %s fused)",
			*fromIndex, formatUnits(have, 8), formatUnits(needQSR, 8), formatUnits(amounts["qsr"], 8), formatUnits(amounts["fuse"], 8))
	}

	fmt.Printf("chain       %d at %s (momentum %d, version %d)\n", m.ChainIdentifier, *l1URL, m.Height, m.Version)
	fmt.Printf("from        index %d  %s\n", *fromIndex, funder.Address)
	fmt.Printf("to          %s\n", recipient)

	acct := znn.NewAccount(funder, l1, *chainID)
	var published []*znn.AccountBlock

	// The fusion goes first so that the receives below are cheap.
	if amounts["fuse"].Sign() > 0 {
		plasma, err := l1.PlasmaInfo(ctx, recipient)
		if err != nil {
			return err
		}
		fused := plasma.QsrAmount.Big()
		ceiling := znn.MaxFusedAmountForAccount(m)
		if after := new(big.Int).Add(fused, amounts["fuse"]); after.Cmp(ceiling) > 0 {
			// Not an error: NoM accepts the fusion, it just stops buying
			// plasma. Saying so is more useful than refusing.
			fmt.Printf("note        %s QSR already fused; this chain stops crediting plasma past %s QSR per account\n",
				formatUnits(fused, 8), formatUnits(ceiling, 8))
		}
		b, err := acct.Send(ctx, derive.PlasmaContract, znn.QSR, amounts["fuse"], derive.EncodePlasmaFuse(recipient))
		if err != nil {
			acct.Reset()
			return fmt.Errorf("fusing: %w", err)
		}
		fmt.Printf("fuse        %s QSR for %s  (block %s)\n", formatUnits(amounts["fuse"], 8), recipient, b.Hash)
		published = append(published, b)
	}

	transfers := []struct {
		name   string
		zts    znn.TokenStandard
		amount *big.Int
	}{
		{"ZNN", znn.ZNN, amounts["znn"]},
		{"QSR", znn.QSR, amounts["qsr"]},
	}
	var sent []*znn.AccountBlock
	for _, t := range transfers {
		if t.amount.Sign() == 0 {
			continue
		}
		b, err := acct.Send(ctx, recipient, t.zts, t.amount, nil)
		if err != nil {
			acct.Reset()
			return fmt.Errorf("sending %s: %w", t.name, err)
		}
		fmt.Printf("send        %s %s  (block %s)\n", formatUnits(t.amount, 8), t.name, b.Hash)
		published = append(published, b)
		sent = append(sent, b)
	}

	if *wait == 0 {
		fmt.Printf("published   %d blocks, not waiting for confirmation\n", len(published))
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, *wait)
	defer cancel()
	for _, b := range published {
		if err := waitForConfirmation(waitCtx, l1, b.Hash); err != nil {
			return fmt.Errorf("waiting for %s: %w", b.Hash, err)
		}
	}
	fmt.Printf("confirmed   %d blocks\n", len(published))

	switch {
	case len(sent) == 0:
	case *noReceive:
		fmt.Printf("unreceived  %d transfer(s) wait for %s to receive them\n", len(sent), recipient)
	case recipientKey == nil:
		// The committee-held vault lands here, and it is the normal case for
		// it: the bridge receives what the vault is sent.
		fmt.Printf("unreceived  %d transfer(s) wait for %s to receive them; no dev key here signs for it\n", len(sent), recipient)
	default:
		in := znn.NewAccount(recipientKey, l1, *chainID)
		for _, b := range sent {
			r, err := in.Receive(waitCtx, b.Hash)
			if err != nil {
				in.Reset()
				return fmt.Errorf("receiving %s: %w", b.Hash, err)
			}
			fmt.Printf("received    %s  (block %s)\n", b.Hash, r.Hash)
		}
	}

	if info, err := l1.AccountInfo(ctx, recipient); err == nil {
		fmt.Printf("balance     %s ZNN, %s QSR\n", formatUnits(info.Balance(znn.ZNN), 8), formatUnits(info.Balance(znn.QSR), 8))
	}
	if p, err := l1.PlasmaInfo(ctx, recipient); err == nil {
		fmt.Printf("plasma      %d of %d, from %s QSR fused\n", p.CurrentPlasma, p.MaxPlasma, formatUnits(p.QsrAmount.Big(), 8))
	}
	return nil
}

// resolveFundTarget reads -to as an address or as a dev mnemonic index. The key
// comes back only for an index, and only then can this command receive on the
// recipient's behalf.
func resolveFundTarget(s string) (znn.Address, *znn.KeyPair, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "z1") {
		addr, err := znn.ParseAddress(strings.ToLower(s))
		return addr, nil, err
	}
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return znn.Address{}, nil, fmt.Errorf("-to %q: want a z1… address or a dev mnemonic index", s)
	}
	key := devnet.Key(uint32(i))
	return key.Address, key, nil
}

// waitForConfirmation polls until the block is in a momentum. A funding run
// that does not wait looks identical to one that worked and then had every
// block refused, which on a chain that cannot be re-genesised is the wrong
// thing to be unsure about.
func waitForConfirmation(ctx context.Context, l1 *znn.Client, hash znn.Hash) error {
	for {
		b, err := l1.AccountBlockByHash(ctx, hash)
		if err != nil {
			return err
		}
		if b != nil && b.ConfirmationDetail != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("not confirmed yet; it may still be on its way")
		case <-time.After(2 * time.Second):
		}
	}
}
