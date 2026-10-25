// zvm-sbom generates or checks a selected SPDX 2.3 Go build-info inventory.
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
	flags := flag.NewFlagSet("zvm-sbom", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policy := flags.String("policy", "", "Independent Go SBOM policy JSON")
	goMod := flags.String("go-mod", "", "Selected source go.mod")
	goSum := flags.String("go-sum", "", "Selected source go.sum")
	subject := flags.String("subject", "", "Qualified Go executable; read only, never executed")
	check := flags.String("check", "", "Existing SPDX document to check instead of generating")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "Usage: zvm-sbom -policy FILE -go-mod FILE -go-sum FILE -subject FILE [-check FILE]\nGenerates SPDX JSON or checks the exact selected Go build-info profile. Runtime/license coverage, source authority and release acceptance remain unqualified.")
			return nil
		}
		return errors.New("invalid command arguments; use -h for usage")
	}
	if flags.NArg() != 0 || *policy == "" || *goMod == "" || *goSum == "" || *subject == "" {
		return errors.New("independent policy, module/checksum inputs and subject are required")
	}
	read := func(name string) ([]byte, error) { return artifacts.ReadDocument(name) }
	p, err := read(*policy)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	m, err := read(*goMod)
	if err != nil {
		return fmt.Errorf("module input: %w", err)
	}
	s, err := read(*goSum)
	if err != nil {
		return fmt.Errorf("checksum input: %w", err)
	}
	if *check != "" {
		doc, err := read(*check)
		if err != nil {
			return fmt.Errorf("SPDX document: %w", err)
		}
		result, err := artifacts.CheckGoSBOM(doc, p, m, s, *subject)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			return errors.New("verification result could not be written")
		}
		return nil
	}
	doc, _, err := artifacts.GenerateGoSBOM(p, m, s, *subject)
	if err != nil {
		return err
	}
	if n, err := stdout.Write(doc); err != nil || n != len(doc) {
		return errors.New("SPDX document could not be written completely")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "SBOM check:", err)
		os.Exit(1)
	}
}
