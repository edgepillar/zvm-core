package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/Zenoglyphs-VM/zvm-core/vectors"
)

func init() {
	register("vectors", "write or check the golden encodings in vectors/vectors.json", runVectors)
}

func runVectors(args []string) error {
	fs := flag.NewFlagSet("vectors", flag.ExitOnError)
	// The vectors sit beside the code that computes them; SPEC.md in zvm-docs
	// is pinned by this file.
	path := fs.String("file", filepath.Join("vectors", "vectors.json"), "vectors file")
	write := fs.Bool("write", false, "regenerate the file from the current code")
	check := fs.Bool("check", false, "fail if the file and the code disagree")
	fs.Parse(args)

	switch {
	case *write:
		if err := vectors.Write(*path); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", *path)
	case *check:
		if err := vectors.Check(*path); err != nil {
			return err
		}
		fmt.Printf("%s matches the current encodings\n", *path)
	default:
		return fmt.Errorf("pass -write or -check")
	}
	return nil
}
