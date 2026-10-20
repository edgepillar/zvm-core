package l2

import (
	"os"
	"path/filepath"
	"testing"
)

// chainDir locates a committed chain definition (rollup.json, genesis.json)
// under chains/. Every node of a chain must start from exactly these files,
// and the invariants they are checked against are this package's, so they are
// kept here. ZVM_CHAINS points the tests at another set; a missing directory
// fails rather than skips, because a silently skipped genesis check is how the
// op-geth/op-reth split (D2) comes back.
func chainDir(t *testing.T, name string) string {
	t.Helper()
	root := os.Getenv("ZVM_CHAINS")
	if root == "" {
		root = filepath.Join("..", "chains")
	}
	dir := filepath.Join(root, name)
	if _, err := os.Stat(filepath.Join(dir, "rollup.json")); err != nil {
		t.Fatalf("no chain definition at %s: set ZVM_CHAINS to a checkout that has %s/rollup.json", dir, name)
	}
	return dir
}
