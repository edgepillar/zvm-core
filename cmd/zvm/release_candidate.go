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
	register("release-verify-candidate", "verify signed inputs, running services and chain observations together", func(args []string) error {
		return releaseVerifyCandidate(args, os.Stdout)
	})
}

func releaseVerifyCandidate(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-verify-candidate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	signatures := fs.String("signatures", "", "detached signature envelope")
	keys := fs.String("trusted-keys", "", "independently provisioned public-key inventory")
	var targets release.CandidateTargets
	fs.StringVar(&targets.SourcesRoot, "sources-root", "", "root of clean repository worktrees")
	fs.StringVar(&targets.L1GenesisVerifier, "l1-genesis-verifier", "", "absolute path to an independently provisioned NoM genesis verifier")
	bindServicesTarget(fs, &targets.Services)
	bindChainTargets(fs, &targets.Chain)
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
	observation, err := m.VerifyCandidate(context.Background(), p, s, k, targets)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(observation)
}
