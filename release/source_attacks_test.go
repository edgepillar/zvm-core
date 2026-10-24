package release

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReplacementObjectsCannotDisguiseChangedSourcesAsTheSignedCommit(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(f.sources, "zvm-core")
	original := f.manifest.Repositories[0].Commit
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("Changed fixture code.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "commit", "-am", "Changed fixture source")
	replacement := runGit(t, dir, "rev-parse", "HEAD")
	runGit(t, dir, "reset", "--soft", original)
	runGit(t, dir, "replace", original, replacement)
	// With replacement refs enabled, HEAD keeps its old SHA while status
	// compares against the replacement tree and reports these sources clean.
	if got := runGit(t, dir, "status", "--porcelain"); got != "" {
		t.Fatalf("replacement fixture is not deceptive: %s", got)
	}
	if _, err := f.manifest.VerifySources(context.Background(), f.sources); err == nil {
		t.Fatal("replacement objects authenticated changed sources under the original commit")
	}
}

func TestMissingPromisorObjectsNeverTriggerAnImplicitNetworkFetch(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(f.sources, "zvm-core")
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()
	runGit(t, dir, "config", "remote.origin.url", srv.URL+"/fixture.git")
	runGit(t, dir, "config", "remote.origin.promisor", "true")
	runGit(t, dir, "config", "remote.origin.partialclonefilter", "blob:none")
	tree := runGit(t, dir, "rev-parse", "HEAD^{tree}")
	if len(tree) != 40 {
		t.Fatal("fixture requires a loose SHA-1 Git tree")
	}
	object := filepath.Join(dir, ".git", "objects", tree[:2], tree[2:])
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manifest.VerifySources(context.Background(), f.sources); err == nil {
		t.Fatal("missing committed tree was accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("an offline source read contacted the configured remote")
	}
}

func TestEmptyArtifactsAndOversizedDeclarationsAreRefusedBeforeReading(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"empty-artifact", "file-set-budget"} {
		t.Run(name, func(t *testing.T) {
			m := copyManifest(t, f.manifest)
			if name == "empty-artifact" {
				for i := range m.Files {
					if m.Files[i].ID == "tool-archive" {
						m.Files[i].Bytes = 0
						m.Files[i].SHA256 = digest(nil)
					}
				}
				m.Toolchains[0].SHA256 = digest(nil)
				m.Compilers[0].SHA256 = digest(nil)
			} else {
				for i := 0; i < 4; i++ {
					m.Files[i].Bytes = 1 << 30
				}
			}
			if _, err := m.SigningMessage(); err == nil {
				t.Fatal("invalid release input declaration was signable")
			}
		})
	}
}

func TestPolicyRejectsDuplicateFileIDsAndUnknownFileRoles(t *testing.T) {
	f := newFixture(t)
	p := f.policy
	p.Files = append(p.Files, p.Files[0])
	if _, err := p.Fingerprint(); err == nil {
		t.Fatal("duplicate policy file identifier was accepted")
	}
	p = f.policy
	p.Files = append([]FileRequirement{}, p.Files...)
	p.Files[0].Kind = "unknown"
	if _, err := p.Fingerprint(); err == nil {
		t.Fatal("unknown policy file role was accepted")
	}
	if strings.Contains(p.Files[0].Path, "..") {
		t.Fatal("fixture path unexpectedly escapes its input root")
	}
}
