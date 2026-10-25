// zvm-source-check verifies an independently selected complete Go source export.
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
	flags := flag.NewFlagSet("zvm-source-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policy := flags.String("policy", "", "Independently selected complete source policy")
	policySHA := flags.String("policy-sha256", "", "Policy SHA-256 from the independent input selection")
	directory := flags.String("directory", "", "Complete regular-file source export, excluding Gitlink directories")
	controls := flags.String("controls", "", "Dedicated pinned raw commit-object directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "Usage: zvm-source-check -policy FILE -policy-sha256 SHA256 -directory DIR -controls DIR\nVerifies source content and Gitlink object bindings. Child trees, compiler use, source authority and release acceptance remain unqualified.")
			return nil
		}
		return errors.New("invalid command arguments; use -h for usage")
	}
	if flags.NArg() != 0 || *policy == "" || *policySHA == "" || *directory == "" || *controls == "" {
		return errors.New("independent policy/hash, source export and commit controls are required")
	}
	raw, err := artifacts.ReadDocument(*policy)
	if err != nil {
		return errors.New("independent source policy could not be read")
	}
	result, err := artifacts.CheckGoSourceTree(raw, *policySHA, artifacts.GoSourceTreeOptions{Directory: *directory, ControlDirectory: *controls})
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return errors.New("source verification result could not be encoded")
	}
	encoded = append(encoded, '\n')
	if n, err := stdout.Write(encoded); err != nil || n != len(encoded) {
		return errors.New("source verification result could not be written completely")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Source check:", err)
		os.Exit(1)
	}
}
