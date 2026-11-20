package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/Zenoglyphs-VM/zvm-core/release"
)

func init() {
	register("release-message", "emit the canonical release signing message without signing", func(args []string) error { return releaseMessage(args, os.Stdout) })
	register("release-verify", "verify a signed release against independent policy and local inputs", func(args []string) error { return releaseVerify(args, os.Stdout) })
	register("release-observe-chain", "compare chain and contract observations with a signed release", func(args []string) error { return releaseObserveChain(args, os.Stdout) })
}

func releaseDocument(name string) ([]byte, error) {
	return release.ReadDocument(name)
}

func releaseMessage(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-message", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *policy == "" || fs.NArg() != 0 {
		return errors.New("manifest and independent policy are required")
	}
	m, p, err := releaseInputs(*manifest, *policy)
	if err != nil {
		return err
	}
	if err := m.ValidateAgainst(p); err != nil {
		return err
	}
	message, err := m.SigningMessage()
	if err != nil {
		return err
	}
	_, err = w.Write(message)
	return err
}

func releaseInputs(manifest, policy string) (release.Manifest, release.Policy, error) {
	var m release.Manifest
	var p release.Policy
	raw, err := releaseDocument(manifest)
	if err != nil {
		return m, p, err
	}
	m, err = release.DecodeManifest(raw)
	if err != nil {
		return m, p, err
	}
	raw, err = releaseDocument(policy)
	if err != nil {
		return m, p, err
	}
	p, err = release.DecodePolicy(raw)
	return m, p, err
}

func signedReleaseInputs(manifest, policy, signatures, keys string) (release.Manifest, release.Policy, release.Signatures, release.TrustedKeys, error) {
	var s release.Signatures
	var k release.TrustedKeys
	m, p, err := releaseInputs(manifest, policy)
	if err != nil {
		return m, p, s, k, err
	}
	raw, err := releaseDocument(signatures)
	if err != nil {
		return m, p, s, k, err
	}
	s, err = release.DecodeSignatures(raw)
	if err != nil {
		return m, p, s, k, err
	}
	raw, err = releaseDocument(keys)
	if err != nil {
		return m, p, s, k, err
	}
	k, err = release.DecodeTrustedKeys(raw)
	return m, p, s, k, err
}

func releaseVerify(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	signatures := fs.String("signatures", "", "detached signature envelope")
	keys := fs.String("trusted-keys", "", "independently provisioned public-key inventory")
	files := fs.String("files-root", "", "root of repository-relative pinned files")
	sources := fs.String("sources-root", "", "root of clean repository worktrees")
	l1Verifier := fs.String("l1-genesis-verifier", "", "absolute path to an independently provisioned NoM genesis verifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *policy == "" || *signatures == "" || *keys == "" || *files == "" || *sources == "" || fs.NArg() != 0 {
		return errors.New("manifest, policy, signatures, trusted keys, files root and sources root are required")
	}
	m, p, s, k, err := signedReleaseInputs(*manifest, *policy, *signatures, *keys)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var receipt release.Receipt
	if *l1Verifier == "" {
		receipt, err = m.Verify(ctx, p, s, k, *files, *sources)
	} else {
		receipt, err = m.VerifyWithL1Genesis(ctx, p, s, k, *files, *sources, *l1Verifier)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(receipt)
}

func bindChainTargets(fs *flag.FlagSet, targets *release.ChainTargets) {
	fs.StringVar(&targets.L1[0], "l1-rpc", "", "primary NoM RPC URL")
	fs.StringVar(&targets.L1[1], "l1-witness-rpc", "", "independently selected NoM RPC URL")
	fs.StringVar(&targets.L2[0], "l2-rpc", "", "primary execution RPC URL")
	fs.StringVar(&targets.L2[1], "l2-witness-rpc", "", "independently selected execution RPC URL")
	fs.Uint64Var(&targets.L1Height, "l1-height", 0, "NoM momentum height to compare")
	fs.Uint64Var(&targets.L2Height, "l2-height", 0, "execution block number to compare")
	fs.StringVar(&targets.NodeEpoch[0], "node-epoch-url", "", "primary node's loaded epoch endpoint")
	fs.StringVar(&targets.NodeEpoch[1], "node-witness-epoch-url", "", "independently selected node's loaded epoch endpoint")
}

func releaseObserveChain(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-observe-chain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	signatures := fs.String("signatures", "", "detached signature envelope")
	keys := fs.String("trusted-keys", "", "independently provisioned public-key inventory")
	var targets release.ChainTargets
	bindChainTargets(fs, &targets)
	fs.StringVar(&targets.FilesRoot, "files-root", "", "signed files root for node epoch verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *policy == "" || *signatures == "" || *keys == "" || fs.NArg() != 0 {
		return errors.New("manifest, policy, signatures and trusted keys are required")
	}
	m, p, s, k, err := signedReleaseInputs(*manifest, *policy, *signatures, *keys)
	if err != nil {
		return err
	}
	observation, err := m.ObserveChain(context.Background(), p, s, k, targets)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(observation)
}
