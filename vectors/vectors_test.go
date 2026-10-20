package vectors

import (
	"os"
	"path/filepath"
	"testing"
)

// vectorsPath locates the committed vectors, which sit beside the code that
// computes them. They are what SPEC.md in zvm-docs is pinned by. ZVM_SPEC
// points the test at another copy, and a missing file fails rather than skips:
// an encoding test that quietly does not run pins nothing.
func vectorsPath(t *testing.T) string {
	t.Helper()
	root := os.Getenv("ZVM_SPEC")
	if root == "" {
		root = "."
	}
	path := filepath.Join(root, "vectors.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no vectors at %s: set ZVM_SPEC to a checkout that has vectors.json", path)
	}
	return path
}

// The committed vectors are the consensus test: if this fails, a change moved
// an encoding, and every node that does not have that change disagrees.
func TestCommittedVectorsMatch(t *testing.T) {
	if err := Check(vectorsPath(t)); err != nil {
		t.Fatal(err)
	}
}

func TestGasRule(t *testing.T) {
	f, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Gas {
		switch {
		case c.Requested != 0 && c.Gas > c.Requested:
			t.Errorf("gas %d exceeds the %d asked for", c.Gas, c.Requested)
		case c.Gas > 16_777_216:
			t.Errorf("gas %d above the per-call cap", c.Gas)
		case c.Requested == 0 && c.Gas != min(c.UsedPlasma*16, 16_777_216):
			t.Errorf("plasma %d bought %d gas", c.UsedPlasma, c.Gas)
		}
	}
}
