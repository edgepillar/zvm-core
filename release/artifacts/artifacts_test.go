package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func independentSHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func fixturePolicy() Policy {
	return Policy{Schema: 1,
		Release: Release{ID: "candidate-1", EpochSHA256: strings.Repeat("a", 64), QualificationSHA256: strings.Repeat("b", 64), Tag: "v0.1.0", TagCommit: strings.Repeat("1", 40),
			Source: Source{Repository: "Example/project", Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40), Gitlinks: []Gitlink{}}},
		Build: Build{WorkflowPath: ".github/workflows/release.yml", WorkflowCommit: strings.Repeat("3", 40), RecipeSHA256: strings.Repeat("c", 64), EnvironmentPolicySHA256: strings.Repeat("d", 64), Flags: []string{"-trimpath"},
			Toolchains: []Input{{"go", strings.Repeat("e", 64)}}, Images: []Input{{"builder", strings.Repeat("f", 64)}}, Materials: []Input{{"source", strings.Repeat("9", 64)}}},
		Artifacts: []Artifact{{"linux-amd64", "binary", "linux/amd64", "bin/zvm-linux-amd64", "sbom/zvm.spdx.json", "provenance/zvm.jsonl"}}, ChecksumsPath: "SHA256SUMS", NotesPath: "notes.md"}
}

func fixtureHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native file verification supports Linux and macOS only")
	}
}
func marshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func bind(t *testing.T, m *Manifest, p Policy) {
	t.Helper()
	m.Schema = p.Schema
	m.Release = p.Release
	m.Build = p.Build
	m.Artifacts = p.Artifacts
	m.ChecksumsPath = p.ChecksumsPath
	m.NotesPath = p.NotesPath
	m.PolicySHA256 = independentSHA(marshal(t, p))
}

type fixture struct {
	p        Policy
	m        Manifest
	root     string
	payloads map[string][]byte
}

func prepare(t *testing.T, p Policy) *fixture {
	t.Helper()
	fixtureHost(t)
	f := &fixture{p: p, root: t.TempDir(), payloads: map[string][]byte{p.NotesPath: []byte("Synthetic release notes. No release is accepted.\n")}}
	for _, a := range p.Artifacts {
		f.payloads[a.SubjectPath] = []byte("Synthetic binary subject: " + a.ID + "\n")
		f.payloads[a.SBOMPath] = []byte("{\"fixture\":true,\"notACompleteSBOM\":true}\n")
		f.payloads[a.ProvenancePath] = []byte("{\"synthetic\":true,\"signed\":false}\n")
	}
	bind(t, &f.m, p)
	f.repin(t)
	for name, raw := range f.payloads {
		file := filepath.Join(f.root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func (f *fixture) repin(t *testing.T) {
	t.Helper()
	names := make([]string, 0, len(f.payloads))
	for name := range f.payloads {
		if name != f.p.ChecksumsPath {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var checks strings.Builder
	for _, name := range names {
		checks.WriteString(independentSHA(f.payloads[name]) + "  " + name + "\n")
	}
	f.payloads[f.p.ChecksumsPath] = []byte(checks.String())
	names = append(names, f.p.ChecksumsPath)
	sort.Strings(names)
	f.m.Files = nil
	for _, name := range names {
		raw := f.payloads[name]
		f.m.Files = append(f.m.Files, File{name, int64(len(raw)), independentSHA(raw)})
	}
}
func (f *fixture) check(t *testing.T) (Result, error) {
	t.Helper()
	return Check(marshal(t, f.m), marshal(t, f.p), f.root)
}
func refused(t *testing.T, result Result, err error) {
	t.Helper()
	if err == nil || result != (Result{}) {
		t.Fatalf("expected refusal and no success receipt, got %+v / %v", result, err)
	}
}

func TestKnownPolicyAndSelection(t *testing.T) {
	f := prepare(t, fixturePolicy())
	canonical, err := CanonicalPolicy(f.p)
	if err != nil {
		t.Fatal(err)
	}
	// This digest is independently generated from the fixed schema vector.
	const expectedPolicySHA = "f117574336d1f4528423645d39c26c41cf1fc6b5f35426598cd8ef3bec4c36c8"
	if independentSHA(canonical) != expectedPolicySHA {
		t.Fatalf("policy vector digest changed: %s", independentSHA(canonical))
	}
	result, err := f.check(t)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, raw := range f.payloads {
		total += int64(len(raw))
	}
	if !result.SelectionVerified || result.FilesVerified != 5 || result.BytesVerified != total || result.PolicySHA256 != expectedPolicySHA || result.ManifestSHA256 != independentSHA(marshal(t, f.m)) {
		t.Fatalf("incomplete selection receipt: %+v", result)
	}
	if result.ReleaseAccepted || result.ProvenanceSignaturesVerified || result.SBOMContentsVerified {
		t.Fatalf("byte selection invented release acceptance: %+v", result)
	}
	names, err := ExpectedPaths(f.p)
	if err != nil || strings.Join(names, "\n") != "SHA256SUMS\nbin/zvm-linux-amd64\nnotes.md\nprovenance/zvm.jsonl\nsbom/zvm.spdx.json" {
		t.Fatalf("unexpected selected paths: %v %v", names, err)
	}
}

func TestIndependentPolicyBindings(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Manifest)
	}{
		{"schema", func(m *Manifest) { m.Schema = 2 }},
		{"policy", func(m *Manifest) { m.PolicySHA256 = strings.Repeat("4", 64) }},
		{"release", func(m *Manifest) { m.Release.ID = "another" }},
		{"epoch", func(m *Manifest) { m.Release.EpochSHA256 = strings.Repeat("4", 64) }},
		{"qualification", func(m *Manifest) { m.Release.QualificationSHA256 = strings.Repeat("4", 64) }},
		{"tag", func(m *Manifest) { m.Release.Tag = "v0.2.0" }},
		{"tag-commit", func(m *Manifest) { m.Release.TagCommit = strings.Repeat("4", 40) }},
		{"repository", func(m *Manifest) { m.Release.Source.Repository = "Example/other" }},
		{"source-commit", func(m *Manifest) {
			m.Release.Source.Commit = strings.Repeat("4", 40)
			m.Release.TagCommit = m.Release.Source.Commit
		}},
		{"source-tree", func(m *Manifest) { m.Release.Source.Tree = strings.Repeat("4", 40) }},
		{"gitlink", func(m *Manifest) {
			m.Release.Source.Gitlinks = append(m.Release.Source.Gitlinks, Gitlink{"core", "Example/core", strings.Repeat("4", 40)})
		}},
		{"workflow", func(m *Manifest) { m.Build.WorkflowPath = ".github/workflows/other.yml" }},
		{"workflow-commit", func(m *Manifest) { m.Build.WorkflowCommit = strings.Repeat("4", 40) }},
		{"recipe", func(m *Manifest) { m.Build.RecipeSHA256 = strings.Repeat("4", 64) }},
		{"environment", func(m *Manifest) { m.Build.EnvironmentPolicySHA256 = strings.Repeat("4", 64) }},
		{"flags", func(m *Manifest) { m.Build.Flags = append([]string{}, "-race") }},
		{"toolchain", func(m *Manifest) { m.Build.Toolchains = append([]Input{}, Input{"go", strings.Repeat("4", 64)}) }},
		{"image", func(m *Manifest) { m.Build.Images = append([]Input{}, Input{"builder", strings.Repeat("4", 64)}) }},
		{"materials", func(m *Manifest) { m.Build.Materials = append([]Input{}, Input{"source", strings.Repeat("4", 64)}) }},
		{"platform", func(m *Manifest) {
			m.Artifacts = append([]Artifact{}, m.Artifacts...)
			m.Artifacts[0].Platform = "linux/arm64"
		}},
		{"kind", func(m *Manifest) { m.Artifacts = append([]Artifact{}, m.Artifacts...); m.Artifacts[0].Kind = "archive" }},
		{"sidecar", func(m *Manifest) {
			m.Artifacts = append([]Artifact{}, m.Artifacts...)
			m.Artifacts[0].SBOMPath = "sbom/other.json"
		}},
		{"notes", func(m *Manifest) { m.NotesPath = "other.md" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := prepare(t, fixturePolicy())
			tc.change(&f.m)
			r, err := f.check(t)
			refused(t, r, err)
		})
	}
}

func TestInvalidPolicyAndPortableNames(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Policy)
	}{
		{"schema", func(p *Policy) { p.Schema = 0 }},
		{"zero-digest", func(p *Policy) { p.Release.EpochSHA256 = strings.Repeat("0", 64) }},
		{"uppercase-digest", func(p *Policy) { p.Release.QualificationSHA256 = strings.Repeat("A", 64) }},
		{"source-url", func(p *Policy) { p.Release.Source.Repository = "https://example.invalid/project" }},
		{"tree-algorithm", func(p *Policy) { p.Release.Source.Tree = strings.Repeat("1", 64) }},
		{"tag-ref", func(p *Policy) { p.Release.Tag = "refs/tags/v1.0.0" }},
		{"wrong-tag-commit", func(p *Policy) { p.Release.TagCommit = strings.Repeat("4", 40) }},
		{"null-gitlinks", func(p *Policy) { p.Release.Source.Gitlinks = nil }},
		{"duplicate-gitlink", func(p *Policy) {
			g := Gitlink{"core", "Example/core", strings.Repeat("4", 40)}
			p.Release.Source.Gitlinks = []Gitlink{g, g}
		}},
		{"gitlink-traversal", func(p *Policy) {
			p.Release.Source.Gitlinks = []Gitlink{{"../core", "Example/core", strings.Repeat("4", 40)}}
		}},
		{"unsafe-workflow", func(p *Policy) { p.Build.WorkflowPath = "release.yml" }},
		{"control-flag", func(p *Policy) { p.Build.Flags = []string{"-trimpath\nsecret"} }},
		{"null-flags", func(p *Policy) { p.Build.Flags = nil }},
		{"missing-toolchain", func(p *Policy) { p.Build.Toolchains = []Input{} }},
		{"duplicate-input", func(p *Policy) { p.Build.Materials = append(p.Build.Materials, p.Build.Materials[0]) }},
		{"unsorted-inputs", func(p *Policy) {
			p.Build.Materials = []Input{{"z", strings.Repeat("4", 64)}, {"a", strings.Repeat("5", 64)}}
		}},
		{"too-many-inputs", func(p *Policy) { p.Build.Images = make([]Input, 65) }},
		{"no-artifacts", func(p *Policy) { p.Artifacts = []Artifact{} }},
		{"too-many-artifacts", func(p *Policy) { p.Artifacts = make([]Artifact, 65) }},
		{"unsupported-kind", func(p *Policy) { p.Artifacts[0].Kind = "unknown" }},
		{"invalid-platform", func(p *Policy) { p.Artifacts[0].Platform = "linux/amd64/variant/extra" }},
		{"duplicate-artifact", func(p *Policy) { p.Artifacts = append(p.Artifacts, p.Artifacts[0]) }},
		{"role-collision", func(p *Policy) { p.Artifacts[0].ProvenancePath = p.Artifacts[0].SBOMPath }},
		{"notes-collision", func(p *Policy) { p.NotesPath = p.ChecksumsPath }},
		{"case-alias", func(p *Policy) { p.NotesPath = "sha256sums" }},
		{"directory-case-alias", func(p *Policy) {
			p.Artifacts[0].SBOMPath = "Data/sbom.json"
			p.Artifacts[0].ProvenancePath = "data/provenance.json"
		}},
		{"file-as-directory", func(p *Policy) { p.NotesPath = "bin" }},
	}
	for _, bad := range []string{"../x", "/absolute", "x//y", "x/./y", "x/../y", "x\\y", "x:y", "x y", "x.", "CON", "nul.txt", "LPT1.bin", ".git/config", ".GIT/config", "unicode-\u00e9", "a/b/c/d/e/f/g/h/i", strings.Repeat("x", 65)} {
		value := bad
		cases = append(cases, struct {
			name   string
			change func(*Policy)
		}{"path-" + value, func(p *Policy) { p.NotesPath = value }})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePolicy()
			tc.change(&p)
			var m Manifest
			bind(t, &m, p)
			r, err := Check(marshal(t, m), marshal(t, p), "not-opened")
			refused(t, r, err)
		})
	}
}

func TestStrictDocuments(t *testing.T) {
	f := prepare(t, fixturePolicy())
	m := string(marshal(t, f.m))
	p := marshal(t, f.p)
	cases := map[string][]byte{
		"duplicate":         []byte(strings.Replace(m, `"schema":1`, `"schema":1,"schema":1`, 1)),
		"escaped-duplicate": []byte(strings.Replace(m, `"schema":1`, `"schema":1,"\u0073chema":1`, 1)),
		"case-alias":        []byte(strings.Replace(m, `"schema":1`, `"Schema":1`, 1)),
		"unknown":           []byte(strings.Replace(m, `"schema":1`, `"schema":1,"ignored":true`, 1)),
		"missing":           []byte(strings.Replace(m, `"schema":1,`, "", 1)),
		"nested-unknown":    []byte(strings.Replace(m, `"repository":"Example/project"`, `"repository":"Example/project","ignored":0`, 1)),
		"nested-missing":    []byte(strings.Replace(m, `"gitlinks":[]`, `"gitlinks":null`, 1)),
		"null-object":       []byte(strings.Replace(m, `"source":{`, `"source":null,"other":{`, 1)),
		"fractional-schema": []byte(strings.Replace(m, `"schema":1`, `"schema":1.0`, 1)),
		"string-integer":    []byte(strings.Replace(m, `"schema":1`, `"schema":"1"`, 1)),
		"trailing":          []byte(m + " {}"), "truncated": []byte(m[:len(m)-1]),
		"invalid-utf8": append([]byte{0xff}, []byte(m)...), "bom": append([]byte{0xef, 0xbb, 0xbf}, []byte(m)...),
		"oversize": []byte(strings.Repeat(" ", MaxDocumentBytes+1)), "empty": {},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) { r, err := Check(raw, p, f.root); refused(t, r, err) })
	}
	badPolicy := []byte(strings.Replace(string(p), `"schema":1`, `"schema":1,"schema":1`, 1))
	r, err := Check([]byte(m), badPolicy, f.root)
	refused(t, r, err)
}

func TestFileInventoryAndBudgets(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Manifest)
	}{
		{"missing", func(m *Manifest) { m.Files = m.Files[:len(m.Files)-1] }},
		{"extra", func(m *Manifest) { m.Files = append(m.Files, File{"z-extra", 1, strings.Repeat("4", 64)}) }},
		{"duplicate", func(m *Manifest) { m.Files[1] = m.Files[0] }},
		{"unsorted", func(m *Manifest) { m.Files[0], m.Files[1] = m.Files[1], m.Files[0] }},
		{"negative-size", func(m *Manifest) { m.Files[1].Bytes = -1 }},
		{"zero-size", func(m *Manifest) { m.Files[1].Bytes = 0 }},
		{"per-file-budget", func(m *Manifest) { m.Files[1].Bytes = MaxFileBytes + 1 }},
		{"total-budget", func(m *Manifest) {
			for i := range m.Files {
				m.Files[i].Bytes = MaxFileBytes
			}
		}},
		{"malformed-hash", func(m *Manifest) { m.Files[1].SHA256 = "0x" + strings.Repeat("4", 64) }},
		{"wrong-hash", func(m *Manifest) { m.Files[1].SHA256 = strings.Repeat("4", 64) }},
		{"length-mismatch", func(m *Manifest) { m.Files[1].Bytes++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := prepare(t, fixturePolicy())
			tc.change(&f.m)
			r, err := f.check(t)
			refused(t, r, err)
		})
	}
}

func TestSharedSidecarsAndExactRequiredPlatforms(t *testing.T) {
	p := fixturePolicy()
	second := p.Artifacts[0]
	second.ID = "linux-arm64"
	second.Platform = "linux/arm64"
	second.SubjectPath = "bin/zvm-linux-arm64"
	p.Artifacts = append(p.Artifacts, second)
	f := prepare(t, p)
	r, err := f.check(t)
	if err != nil || r.FilesVerified != 6 || !r.SelectionVerified {
		t.Fatalf("explicit shared sidecars refused: %+v %v", r, err)
	}
	f.m.Artifacts = f.m.Artifacts[:1]
	r, err = f.check(t)
	refused(t, r, err)
}

func TestChecksumsAreContentBound(t *testing.T) {
	for _, mutation := range []string{"omit", "extra", "crlf", "wrong-hash"} {
		t.Run(mutation, func(t *testing.T) {
			f := prepare(t, fixturePolicy())
			raw := string(f.payloads[f.p.ChecksumsPath])
			switch mutation {
			case "omit":
				raw = strings.Join(strings.Split(raw, "\n")[1:], "\n")
			case "extra":
				raw += strings.Repeat("4", 64) + "  extra\n"
			case "crlf":
				raw = strings.ReplaceAll(raw, "\n", "\r\n")
			case "wrong-hash":
				raw = "0" + raw[1:]
			}
			if err := os.WriteFile(filepath.Join(f.root, f.p.ChecksumsPath), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			for i := range f.m.Files {
				if f.m.Files[i].Path == f.p.ChecksumsPath {
					f.m.Files[i].Bytes = int64(len(raw))
					f.m.Files[i].SHA256 = independentSHA([]byte(raw))
				}
			}
			r, err := f.check(t)
			refused(t, r, err)
		})
	}
}

func TestFilesystemRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *fixture)
	}{
		{"missing", func(t *testing.T, f *fixture) {
			if err := os.Remove(filepath.Join(f.root, "notes.md")); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra-file", func(t *testing.T, f *fixture) {
			if err := os.WriteFile(filepath.Join(f.root, "extra"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra-empty-directory", func(t *testing.T, f *fixture) {
			if err := os.Mkdir(filepath.Join(f.root, "extra"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory-for-file", func(t *testing.T, f *fixture) {
			name := filepath.Join(f.root, "notes.md")
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(name, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-file", func(t *testing.T, f *fixture) {
			name := filepath.Join(f.root, "notes.md")
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("SHA256SUMS", name); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink-file", func(t *testing.T, f *fixture) {
			if err := os.Link(filepath.Join(f.root, "notes.md"), filepath.Join(t.TempDir(), "linked")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-directory", func(t *testing.T, f *fixture) {
			target := filepath.Join(t.TempDir(), "old-bin")
			if err := os.Rename(filepath.Join(f.root, "bin"), target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(f.root, "bin")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-root", func(t *testing.T, f *fixture) {
			link := filepath.Join(t.TempDir(), "linked")
			if err := os.Symlink(f.root, link); err != nil {
				t.Fatal(err)
			}
			f.root = link
		}},
		{"symlink-ancestor", func(t *testing.T, f *fixture) {
			parent := filepath.Join(t.TempDir(), "linked")
			if err := os.Symlink(filepath.Dir(f.root), parent); err != nil {
				t.Fatal(err)
			}
			f.root = filepath.Join(parent, filepath.Base(f.root))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := prepare(t, fixturePolicy())
			tc.mutate(t, f)
			r, err := f.check(t)
			refused(t, r, err)
		})
	}
}

func TestSubstitutionDuringActualRead(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *fixture, string)
	}{
		{"replace-inode", func(t *testing.T, f *fixture, name string) {
			file := filepath.Join(f.root, name)
			if err := os.Rename(file, filepath.Join(t.TempDir(), "original")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, f.payloads[name], 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"grow", func(t *testing.T, f *fixture, name string) {
			file, err := os.OpenFile(filepath.Join(f.root, name), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write([]byte("extra")); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncate", func(t *testing.T, f *fixture, name string) {
			if err := os.Truncate(filepath.Join(f.root, name), 1); err != nil {
				t.Fatal(err)
			}
		}},
		{"same-size-same-mtime", func(t *testing.T, f *fixture, name string) {
			file := filepath.Join(f.root, name)
			info, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			raw := append([]byte{}, f.payloads[name]...)
			raw[0] ^= 1
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.Chtimes(file, time.Now(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode", func(t *testing.T, f *fixture, name string) {
			if err := os.Chmod(filepath.Join(f.root, name), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"new-hardlink", func(t *testing.T, f *fixture, name string) {
			if err := os.Link(filepath.Join(f.root, name), filepath.Join(t.TempDir(), "linked")); err != nil {
				t.Fatal(err)
			}
		}},
		{"late-extra-file", func(t *testing.T, f *fixture, name string) {
			if err := os.WriteFile(filepath.Join(f.root, "extra"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"replace-root", func(t *testing.T, f *fixture, name string) {
			if err := os.Rename(f.root, filepath.Join(t.TempDir(), "original-root")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.root, 0700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := prepare(t, fixturePolicy())
			called := false
			r, err := check(marshal(t, f.m), marshal(t, f.p), f.root, func(name string) {
				if !called && name == "notes.md" {
					called = true
					tc.mutate(t, f, name)
				}
			})
			if !called {
				t.Fatal("actual open/read boundary was not reached")
			}
			refused(t, r, err)
		})
	}
}

func TestBoundedDocumentInputs(t *testing.T) {
	fixtureHost(t)
	root := t.TempDir()
	name := filepath.Join(root, "manifest.json")
	raw := []byte("{\"fixture\":true}\n")
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDocument(name)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("regular document: %q %v", got, err)
	}
	link := filepath.Join(root, "linked")
	if err = os.Symlink("manifest.json", link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadDocument(link); err == nil {
		t.Fatal("linked document accepted")
	}
	if _, err = ReadDocument(root); err == nil {
		t.Fatal("directory document accepted")
	}
	if err = os.WriteFile(name, make([]byte, MaxDocumentBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadDocument(name); err == nil {
		t.Fatal("oversized document accepted")
	}
}
