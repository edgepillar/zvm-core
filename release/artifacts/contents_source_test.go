package artifacts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceContentsPolicy(t *testing.T, p Policy) SourceContentsPolicy {
	t.Helper()
	base := contentsPolicyFixture(t, p)
	c := SourceContentsPolicy{Schema: 2, SelectionPolicySHA256: base.SelectionPolicySHA256, Artifacts: []SourceSBOMRequirement{}}
	for _, a := range base.Artifacts {
		c.Artifacts = append(c.Artifacts, SourceSBOMRequirement{a.ID, GoSourceSBOMProfile, a.Policy, a.GoMod, a.GoSum, []File{{"core.commit", 100, strings.Repeat("1", 64)}}})
	}
	return c
}

func TestSourceContentsPolicyClosureAndVersion(t *testing.T) {
	p := fixturePolicy()
	c := sourceContentsPolicy(t, p)
	if _, err := CanonicalSourceContentsPolicy(c, p); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*SourceContentsPolicy)
	}{
		{"version", func(c *SourceContentsPolicy) { c.Schema = 1 }},
		{"selection", func(c *SourceContentsPolicy) { c.SelectionPolicySHA256 = strings.Repeat("9", 64) }},
		{"no-commits", func(c *SourceContentsPolicy) { c.Artifacts[0].CommitObjects = []File{} }},
		{"null-commits", func(c *SourceContentsPolicy) { c.Artifacts[0].CommitObjects = nil }},
		{"duplicate-commit", func(c *SourceContentsPolicy) {
			c.Artifacts[0].CommitObjects = append(c.Artifacts[0].CommitObjects, c.Artifacts[0].CommitObjects[0])
		}},
		{"case-commit", func(c *SourceContentsPolicy) {
			c.Artifacts[0].CommitObjects = append([]File{{"CORE.commit", 100, strings.Repeat("1", 64)}}, c.Artifacts[0].CommitObjects...)
		}},
		{"role-collision", func(c *SourceContentsPolicy) { c.Artifacts[0].CommitObjects[0] = c.Artifacts[0].Policy }},
		{"parent-collision", func(c *SourceContentsPolicy) { c.Artifacts[0].CommitObjects[0].Path = "source" }},
		{"empty-commit", func(c *SourceContentsPolicy) { c.Artifacts[0].CommitObjects[0].Bytes = 0 }},
		{"oversize-commit", func(c *SourceContentsPolicy) { c.Artifacts[0].CommitObjects[0].Bytes = MaxDocumentBytes + 1 }},
		{"traversal-commit", func(c *SourceContentsPolicy) { c.Artifacts[0].CommitObjects[0].Path = "../outside" }},
		{"unknown-profile", func(c *SourceContentsPolicy) { c.Artifacts[0].Profile = "other" }},
		{"remote-with-commits", func(c *SourceContentsPolicy) { c.Artifacts[0].Profile = GoSBOMProfile }},
		{"empty-lock-bad-pin", func(c *SourceContentsPolicy) { c.Artifacts[0].GoSum.Bytes = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := sourceContentsPolicy(t, p)
			tc.change(&c)
			if _, err := c.validate(p); err == nil {
				t.Fatal("ambiguous source contents policy accepted")
			}
		})
	}
	c.Artifacts[0].GoSum.Bytes = 0
	c.Artifacts[0].GoSum.SHA256 = independentSHA(nil)
	if _, err := c.validate(p); err != nil {
		t.Fatal("explicit empty local checksum refused", err)
	}
	legacy := contentsPolicyFixture(t, p)
	legacy.Artifacts[0].Profile = GoSourceSBOMProfile
	if _, err := legacy.validate(p); err == nil {
		t.Fatal("schema 1 silently accepted local-source scope")
	}
	valid := string(marshal(t, sourceContentsPolicy(t, p)))
	for _, raw := range []string{strings.Replace(valid, `"schema":2`, `"schema":2,"schema":2`, 1), strings.Replace(valid, `"schema":2`, `"Schema":2`, 1), strings.Replace(valid, `"commitObjects"`, `"unknown"`, 1), strings.Replace(valid, `"schema":2`, `"schema":3`, 1), valid + `{}`} {
		if _, _, _, err := parseContentsPolicy([]byte(raw), p); err == nil {
			t.Fatal("ambiguous schema dispatched")
		}
	}
}

func TestPrivateContentsSourceMapping(t *testing.T) {
	fixtureHost(t)
	valid := `{"schema":1,"artifacts":[{"id":"darwin-arm64","sources":[{"path":"core","directory":"/private/runtime-only"}]}]}`
	dirs, err := ParseContentsSourceDirectories([]byte(valid))
	if err != nil || dirs["darwin-arm64"]["core"] != "/private/runtime-only" {
		t.Fatal("valid private mapping refused")
	}
	for _, raw := range []string{`{}`, `null`, strings.Replace(valid, `"schema":1`, `"schema":2`, 1), strings.Replace(valid, `"schema":1`, `"schema":1,"schema":1`, 1), strings.Replace(valid, `"directory"`, `"Directory"`, 1), strings.Replace(valid, `/private/runtime-only`, `relative`, 1), strings.Replace(valid, `"core"`, `"../core"`, 1), strings.Replace(valid, `"darwin-arm64"`, `"../outside"`, 1), `{"schema":1,"artifacts":[]}`, `{"schema":1,"artifacts":[{"id":"a","sources":[]}]}`} {
		if _, err := ParseContentsSourceDirectories([]byte(raw)); err == nil {
			t.Fatal("ambiguous private source mapping accepted")
		}
	}
	base := contentsPolicyFixture(t, fixturePolicy())
	if _, _, err := contentsDirectories(base.Artifacts, ContentsOptions{SourceDirectories: dirs}); err == nil {
		t.Fatal("legacy profile accepted unrelated runtime mapping")
	}
}

type actualSourceContentsFixture struct {
	f            *fixture
	policy       SourceContentsPolicy
	sourcePolicy GoSourceSBOMPolicy
	root         string
	directories  map[string]map[string]string
	sourceRoot   string
}

func actualSourceContents(t *testing.T) *actualSourceContentsFixture {
	t.Helper()
	dir := os.Getenv("ZVM_GO_SOURCE_FIXTURE_DIRECTORY")
	if dir == "" {
		t.Skip("qualified actual local-Core source fixture was not provisioned")
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var sp GoSourceSBOMPolicy
	if err := decode(read("policy.json"), &sp); err != nil {
		t.Fatal(err)
	}
	var mapping map[string]string
	mapping, err := ParseGoSourceDirectories(read("directories.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Independent temporary aliases allow late-mutation tests without touching any retained input.
	sourceRoot := t.TempDir()
	for _, local := range sp.LocalSources {
		for _, file := range local.Files {
			raw, err := os.ReadFile(filepath.Join(mapping[local.Path], filepath.FromSlash(file.Path)))
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(sourceRoot, local.Path, filepath.FromSlash(file.Path))
			if os.MkdirAll(filepath.Dir(name), 0700) != nil || os.WriteFile(name, raw, os.FileMode(0600)|os.FileMode(mustExecutable(file.Mode))) != nil {
				t.Fatal("source fixture copy failed")
			}
		}
		mapping[local.Path] = filepath.Join(sourceRoot, local.Path)
	}
	p := fixturePolicy()
	p.Release.Source = sp.Go.Source
	p.Release.TagCommit = sp.Go.Source.Commit
	p.Release.QualificationSHA256 = sp.Go.QualifiedInputsSHA256
	settings := map[string]string{}
	for _, s := range sp.Go.BuildSettings {
		settings[s.Key] = s.Value
	}
	p.Artifacts[0].SubjectPath = sp.Go.Subject.Path
	p.Artifacts[0].Platform = settings["GOOS"] + "/" + settings["GOARCH"]
	f := prepare(t, p)
	f.payloads[p.Artifacts[0].SubjectPath] = read("subject")
	doc, _, err := GenerateGoSourceSBOM(read("policy.json"), read("go.mod"), read("go.sum"), filepath.Join(dir, "subject"), GoSourceOptions{mapping, filepath.Join(dir, "controls")})
	if err != nil {
		t.Fatal(err)
	}
	f.payloads[p.Artifacts[0].SBOMPath] = doc
	f.payloads[p.Artifacts[0].ProvenancePath] = []byte(`{"dsseEnvelope":{"syntheticProtocolControl":true}}`)
	f.sync(t)
	root := t.TempDir()
	canonical, err := CanonicalPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	pin := func(name string, raw []byte) File {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("control fixture write failed")
		}
		return File{name, int64(len(raw)), independentSHA(raw)}
	}
	commits := []File{}
	for _, local := range sp.LocalSources {
		commits = append(commits, pin(local.CommitObject.Path, read(filepath.Join("controls", local.CommitObject.Path))))
	}
	c := SourceContentsPolicy{2, independentSHA(canonical), []SourceSBOMRequirement{{p.Artifacts[0].ID, GoSourceSBOMProfile, pin("go-policy.json", read("policy.json")), pin("parent/go.mod", read("go.mod")), pin("parent/go.sum", read("go.sum")), commits}}}
	return &actualSourceContentsFixture{f, c, sp, root, map[string]map[string]string{p.Artifacts[0].ID: mapping}, sourceRoot}
}

func mustExecutable(mode string) uint32 {
	if mode == "100755" {
		return 0100
	}
	return 0
}

func TestActualLocalSourceCompleteContents(t *testing.T) {
	c := actualSourceContents(t)
	f := c.f
	result, err := CheckContentsWithOptions(marshal(t, f.m), marshal(t, f.p), marshal(t, c.policy), f.root, c.root, ContentsOptions{c.directories})
	if err != nil || !result.SelectionVerified || !result.SBOMContentsVerified || result.LocalSourceTreesVerified != 1 || result.LocalSourceFilesVerified != 112 || result.LocalCommitObjectsVerified != 1 || result.GoModuleRecordsVerified != 24 || result.ControlFilesVerified != 4 || result.SBOMProfileScope != GoSourceSBOMProfile || result.ProvenanceSignaturesVerified || result.CompilerUseOfTreesProven || result.ParentSourceTreeVerified || result.ReleaseAccepted {
		t.Fatalf("actual source contents failed: %+v %v", result, err)
	}
	for _, root := range []string{c.root, c.sourceRoot} {
		if bytes.Contains(marshal(t, result), []byte(root)) {
			t.Fatal("receipt disclosed runtime path")
		}
	}
	for _, dirs := range []map[string]map[string]string{nil, {"unselected": c.directories[f.p.Artifacts[0].ID]}, {f.p.Artifacts[0].ID: {"other": c.sourceRoot}}} {
		got, err := CheckContentsWithOptions(marshal(t, f.m), marshal(t, f.p), marshal(t, c.policy), f.root, c.root, ContentsOptions{dirs})
		if err == nil || got != (SourceContentsResult{}) {
			t.Fatal("incomplete runtime source mapping accepted")
		}
	}
	if got, err := CheckContents(marshal(t, f.m), marshal(t, f.p), marshal(t, c.policy), f.root, c.root); err == nil || got != (ContentsResult{}) {
		t.Fatal("source profile inferred runtime directories")
	}
	for _, change := range []func(){
		func() { c.policy.Artifacts[0].CommitObjects[0].SHA256 = strings.Repeat("2", 64) },
		func() {
			c.policy.Artifacts[0].CommitObjects = append(c.policy.Artifacts[0].CommitObjects, File{"other.commit", 1, strings.Repeat("1", 64)})
		},
	} {
		old := marshal(t, c.policy)
		change()
		if got, err := CheckContentsWithOptions(marshal(t, f.m), marshal(t, f.p), marshal(t, c.policy), f.root, c.root, ContentsOptions{c.directories}); err == nil || got != (SourceContentsResult{}) {
			t.Fatal("independent commit inventory mismatch accepted")
		}
		if json.Unmarshal(old, &c.policy) != nil {
			t.Fatal("policy reset failed")
		}
	}
}

func TestActualLocalSourceBundleProtocolAndLateMutation(t *testing.T) {
	for _, name := range []string{"protocol-success", "signature-refusal", "late-source-bytes", "late-source-extra", "late-commit", "late-parent-lock", "late-source-identity"} {
		t.Run(name, func(t *testing.T) {
			c := actualSourceContents(t)
			f := c.f
			_, v, options := provenanceFixture(t)
			v.Artifacts[0].ID = f.p.Artifacts[0].ID
			calls := 0
			runner := func(context.Context, string, string, []string) ([]byte, error) {
				calls++
				if name == "signature-refusal" {
					return nil, errors.New("synthetic protocol refusal")
				}
				local := c.sourcePolicy.LocalSources[0]
				source := c.directories[f.p.Artifacts[0].ID][local.Path]
				write := func(path string, raw []byte) {
					t.Helper()
					if os.WriteFile(path, raw, 0600) != nil {
						t.Fatal("late mutation failed")
					}
				}
				switch name {
				case "late-source-bytes":
					write(filepath.Join(source, "go.mod"), []byte("changed\n"))
				case "late-source-extra":
					write(filepath.Join(source, "unselected"), []byte("extra\n"))
				case "late-commit":
					write(filepath.Join(c.root, local.CommitObject.Path), []byte("changed\n"))
				case "late-parent-lock":
					write(filepath.Join(c.root, "parent/go.mod"), []byte("changed\n"))
				case "late-source-identity":
					path := filepath.Join(source, "go.mod")
					raw, err := os.ReadFile(path)
					if err != nil || os.Remove(path) != nil {
						t.Fatal("replacement setup failed")
					}
					write(path, raw)
				}
				return marshal(t, []any{protocolResult(t, f.p, v, c.sourcePolicy.Go.Subject.SHA256)}), nil
			}
			got, err := checkSourceBundle(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), marshal(t, c.policy), f.root, c.root, ContentsOptions{c.directories}, options, runner)
			if calls != 1 {
				t.Fatal("composition did not reach the declared signature protocol stage", err)
			}
			if name == "protocol-success" {
				if err != nil || !got.ProvenanceSignaturesVerified || !got.SBOMContentsVerified || got.LocalSourceFilesVerified != 112 || got.ReleaseAccepted || got.CompilerUseOfTreesProven {
					t.Fatalf("synthetic protocol composition failed: %+v %v", got, err)
				}
			} else if err == nil || got != (SourceBundleResult{}) {
				t.Fatal("late refusal retained partial source or signature acceptance")
			}
		})
	}
}

func TestSchemaTwoRemoteProfileRetainsItsScope(t *testing.T) {
	c := actualContents(t)
	f := c.f
	a := c.policy.Artifacts[0]
	p := SourceContentsPolicy{2, c.policy.SelectionPolicySHA256, []SourceSBOMRequirement{{a.ID, a.Profile, a.Policy, a.GoMod, a.GoSum, []File{}}}}
	got, err := CheckContents(marshal(t, f.m), marshal(t, f.p), marshal(t, p), f.root, c.root)
	if err != nil || !got.SBOMContentsVerified || got.SBOMProfileScope != GoSBOMProfile || got.GoModuleRecordsVerified != 1 {
		t.Fatal("explicit schema 2 remote profile changed scope", err)
	}
}
