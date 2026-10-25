// zvm-artifact-check verifies an explicitly selected release file set offline.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Zenoglyphs-VM/zvm-core/release/artifacts"
)

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("zvm-artifact-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifest := flags.String("manifest", "", "Exact manifest JSON")
	policy := flags.String("policy", "", "Independently selected policy JSON")
	directory := flags.String("directory", "", "Dedicated selected artifact directory")
	provenancePolicy := flags.String("provenance-policy", "", "Independent exact GitHub provenance policy JSON")
	verifier := flags.String("verifier", "", "Absolute independently pinned GitHub CLI executable")
	trustedRoot := flags.String("trusted-root", "", "Independently pinned local trusted-root JSONL")
	temporary := flags.String("temporary-directory", "", "Explicit owned directory for bounded verifier scratch")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: zvm-artifact-check -manifest FILE -policy FILE -directory DIR\nSignatures require all of: -provenance-policy FILE -verifier FILE -trusted-root FILE -temporary-directory DIR\nByte selection alone verifies no signatures. SBOM contents, build reproduction and release acceptance remain unverified.")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.Usage()
			return nil
		}
		return errors.New("invalid command arguments; use -h for usage")
	}
	if flags.NArg() != 0 || *manifest == "" || *policy == "" || *directory == "" {
		return errors.New("manifest, independent policy and dedicated directory are required")
	}
	m, err := artifacts.ReadDocument(*manifest)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	p, err := artifacts.ReadDocument(*policy)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	provided := 0
	for _, value := range []string{*provenancePolicy, *verifier, *trustedRoot, *temporary} {
		if value != "" {
			provided++
		}
	}
	if provided != 0 && provided != 4 {
		return errors.New("all four provenance options are required together")
	}
	var result any
	if provided == 4 {
		v, readErr := artifacts.ReadDocument(*provenancePolicy)
		if readErr != nil {
			return fmt.Errorf("provenance policy: %w", readErr)
		}
		result, err = artifacts.CheckProvenance(context.Background(), m, p, v, *directory, artifacts.ProvenanceOptions{
			VerifierPath: *verifier, TrustedRootPath: *trustedRoot, TemporaryDirectory: *temporary})
	} else {
		result, err = artifacts.Check(m, p, *directory)
	}
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return errors.New("result could not be written")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "artifact check:", err)
		os.Exit(1)
	}
}
