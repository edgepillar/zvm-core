// zvm-artifact-pack streams or independently verifies a canonical ZIP package.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Zenoglyphs-VM/zvm-core/release/artifacts"
)

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("zvm-artifact-pack", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifest := flags.String("manifest", "", "Independent exact manifest JSON")
	policy := flags.String("policy", "", "Independent selection policy JSON")
	archivePolicy := flags.String("archive-policy", "", "Independent ZIP32 profile/epoch policy JSON")
	directory := flags.String("directory", "", "Dedicated selected file directory for production")
	check := flags.String("check", "", "Existing archive to verify without extraction")
	pin := flags.String("archive-pin", "", "Independent expected archive file pin JSON")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "Usage: zvm-artifact-pack -manifest FILE -policy FILE -archive-policy FILE -directory DIR > candidate.zip\nVerify: zvm-artifact-pack -manifest FILE -policy FILE -archive-policy FILE -check FILE -archive-pin FILE\nZIP output is streamed; failed/partial output remains unverified. Signatures, SBOM contents and release acceptance are not established by packaging.")
			return nil
		}
		return errors.New("invalid command arguments; use -h for usage")
	}
	if flags.NArg() != 0 || *manifest == "" || *policy == "" || *archivePolicy == "" {
		return errors.New("independent manifest, selection policy and archive policy are required")
	}
	if (*check == "") != (*pin == "") || (*check == "" && *directory == "") || (*check != "" && *directory != "") {
		return errors.New("choose selected-directory production or archive verification with an independent pin")
	}
	m, err := artifacts.ReadDocument(*manifest)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	p, err := artifacts.ReadDocument(*policy)
	if err != nil {
		return fmt.Errorf("selection policy: %w", err)
	}
	a, err := artifacts.ReadDocument(*archivePolicy)
	if err != nil {
		return fmt.Errorf("archive policy: %w", err)
	}
	if *check != "" {
		raw, err := artifacts.ReadDocument(*pin)
		if err != nil {
			return fmt.Errorf("archive pin: %w", err)
		}
		expected, err := artifacts.ParseArchivePin(raw)
		if err != nil {
			return err
		}
		result, err := artifacts.CheckArchiveFile(*check, expected, m, p, a)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			return errors.New("archive result could not be written")
		}
		return nil
	}
	_, err = artifacts.WriteArchive(stdout, m, p, a, *directory)
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "artifact package:", err)
		os.Exit(1)
	}
}
