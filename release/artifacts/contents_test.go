package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func contentsPolicyFixture(t *testing.T, p Policy) ContentsPolicy {
	t.Helper()
	canonical, err := CanonicalPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	pin := func(name string) File { return File{name, 1, strings.Repeat("1", 64)} }
	c := ContentsPolicy{Schema: 1, SelectionPolicySHA256: independentSHA(canonical), Artifacts: []SBOMRequirement{}}
	for _, a := range p.Artifacts {
		c.Artifacts = append(c.Artifacts, SBOMRequirement{a.ID, GoSBOMProfile, pin(a.ID + ".json"), pin("source/go.mod"), pin("source/go.sum")})
	}
	return c
}

func TestCompleteContentsPolicyBindings(t *testing.T) {
	p := fixturePolicy()
	c := contentsPolicyFixture(t, p)
	if _, err := c.validate(p); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*ContentsPolicy)
	}{
		{"schema", func(c *ContentsPolicy) { c.Schema = 2 }}, {"selection-binding", func(c *ContentsPolicy) { c.SelectionPolicySHA256 = strings.Repeat("2", 64) }},
		{"missing-profile", func(c *ContentsPolicy) { c.Artifacts = []SBOMRequirement{} }}, {"extra-profile", func(c *ContentsPolicy) { c.Artifacts = append(c.Artifacts, c.Artifacts[0]) }},
		{"artifact-id", func(c *ContentsPolicy) { c.Artifacts[0].ID = "other" }}, {"profile", func(c *ContentsPolicy) { c.Artifacts[0].Profile = "unknown" }},
		{"control-hash", func(c *ContentsPolicy) { c.Artifacts[0].Policy.SHA256 = strings.Repeat("0", 64) }}, {"control-size", func(c *ContentsPolicy) { c.Artifacts[0].Policy.Bytes = MaxDocumentBytes + 1 }},
		{"control-path", func(c *ContentsPolicy) { c.Artifacts[0].Policy.Path = "../outside" }},
		{"control-case-alias", func(c *ContentsPolicy) { c.Artifacts[0].GoSum.Path = "SOURCE/GO.MOD" }},
		{"control-directory-case-alias", func(c *ContentsPolicy) { c.Artifacts[0].GoSum.Path = "SOURCE/go.sum" }},
		{"control-role-alias", func(c *ContentsPolicy) { c.Artifacts[0].GoSum = c.Artifacts[0].GoMod }},
		{"control-directory-alias", func(c *ContentsPolicy) { c.Artifacts[0].Policy.Path = "source" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := contentsPolicyFixture(t, p)
			tc.change(&c)
			if _, err := c.validate(p); err == nil {
				t.Fatal("incomplete or ambiguous contents policy accepted")
			}
		})
	}
	for _, raw := range [][]byte{[]byte(`{"schema":1,"schema":1}`), []byte(`null`), []byte(`{} {}`)} {
		if _, err := prepareContents(marshal(t, p), raw, t.TempDir()); err == nil {
			t.Fatal("ambiguous contents document accepted")
		}
	}
}

type actualContentsFixture struct {
	f        *fixture
	policy   ContentsPolicy
	root     string
	goPolicy GoSBOMPolicy
	controls map[string][]byte
}

func actualContents(t *testing.T) *actualContentsFixture {
	t.Helper()
	dir := os.Getenv("ZVM_GO_SBOM_FIXTURE_DIRECTORY")
	if dir == "" {
		t.Skip("qualified Go subject and source controls were not provisioned")
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var goPolicy GoSBOMPolicy
	if err := decode(read("policy.json"), &goPolicy); err != nil {
		t.Fatal(err)
	}
	p := fixturePolicy()
	p.Release.Source = goPolicy.Source
	p.Release.TagCommit = goPolicy.Source.Commit
	p.Release.QualificationSHA256 = goPolicy.QualifiedInputsSHA256
	settings := map[string]string{}
	for _, s := range goPolicy.BuildSettings {
		settings[s.Key] = s.Value
	}
	p.Artifacts[0].SubjectPath = goPolicy.Subject.Path
	p.Artifacts[0].Platform = settings["GOOS"] + "/" + settings["GOARCH"]
	f := prepare(t, p)
	f.payloads[p.Artifacts[0].SubjectPath] = read("subject")
	doc, _, err := GenerateGoSBOM(read("policy.json"), read("go.mod"), read("go.sum"), filepath.Join(dir, "subject"))
	if err != nil {
		t.Fatal(err)
	}
	f.payloads[p.Artifacts[0].SBOMPath] = doc
	f.payloads[p.Artifacts[0].ProvenancePath] = []byte(`{"dsseEnvelope":{"syntheticProtocolControl":true}}`)
	f.sync(t)
	c := &actualContentsFixture{f: f, root: t.TempDir(), goPolicy: goPolicy, controls: map[string][]byte{"go-policy.json": read("policy.json"), "source/go.mod": read("go.mod"), "source/go.sum": read("go.sum")}}
	c.repin(t)
	return c
}

func (c *actualContentsFixture) repin(t *testing.T) {
	t.Helper()
	canonical, err := CanonicalPolicy(c.f.p)
	if err != nil {
		t.Fatal(err)
	}
	pin := func(name string) File {
		raw := c.controls[name]
		return File{name, int64(len(raw)), independentSHA(raw)}
	}
	c.policy = ContentsPolicy{Schema: 1, SelectionPolicySHA256: independentSHA(canonical), Artifacts: []SBOMRequirement{{c.f.p.Artifacts[0].ID, GoSBOMProfile, pin("go-policy.json"), pin("source/go.mod"), pin("source/go.sum")}}}
	for name, raw := range c.controls {
		path := filepath.Join(c.root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestActualCompleteContentsAndBundleProtocol(t *testing.T) {
	t.Run("actual-contents", func(t *testing.T) {
		c := actualContents(t)
		f := c.f
		r, err := CheckContents(marshal(t, f.m), marshal(t, f.p), marshal(t, c.policy), f.root, c.root)
		if err != nil || !r.SelectionVerified || !r.SBOMContentsVerified || r.ProvenanceSignaturesVerified || r.SBOMProfilesVerified != 1 || r.GoModuleRecordsVerified != 1 || r.ControlFilesVerified != 3 || r.CompleteRuntimeInventoryEstablished || r.LicenseCoverageEstablished || r.ReleaseAccepted {
			t.Fatalf("actual contents binding failed: %+v %v", r, err)
		}
		legacy, err := f.check(t)
		if err != nil || legacy.SBOMContentsVerified {
			t.Fatal("default selection invented content acceptance")
		}
	})
	cases := []struct {
		name   string
		change func(*actualContentsFixture)
	}{
		{"source", func(c *actualContentsFixture) {
			c.f.p.Release.Source.Commit = strings.Repeat("1", 40)
			c.f.p.Release.TagCommit = c.f.p.Release.Source.Commit
		}},
		{"tree", func(c *actualContentsFixture) { c.f.p.Release.Source.Tree = strings.Repeat("1", 40) }},
		{"qualification", func(c *actualContentsFixture) { c.f.p.Release.QualificationSHA256 = strings.Repeat("1", 64) }},
		{"platform", func(c *actualContentsFixture) { c.f.p.Artifacts[0].Platform = "linux/amd64" }},
		{"declared-subject", func(c *actualContentsFixture) {
			c.goPolicy.Subject.Path = "bin/other"
			c.controls["go-policy.json"] = marshal(t, c.goPolicy)
		}},
		{"module-omission", func(c *actualContentsFixture) {
			c.goPolicy.Modules = []GoSBOMModule{}
			c.controls["go-policy.json"] = marshal(t, c.goPolicy)
		}},
		{"changed-document", func(c *actualContentsFixture) { c.f.payloads[c.f.p.Artifacts[0].SBOMPath] = []byte(`{}`) }},
		{"changed-lock", func(c *actualContentsFixture) {
			c.controls["source/go.sum"] = append(c.controls["source/go.sum"], []byte("changed\n")...)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := actualContents(t)
			tc.change(c)
			bind(t, &c.f.m, c.f.p)
			c.f.sync(t)
			c.repin(t)
			r, err := CheckContents(marshal(t, c.f.m), marshal(t, c.f.p), marshal(t, c.policy), c.f.root, c.root)
			if err == nil || r != (ContentsResult{}) {
				t.Fatal("cross-policy mismatch produced acceptance")
			}
		})
	}
	t.Run("extra-control", func(t *testing.T) {
		c := actualContents(t)
		if err := os.WriteFile(filepath.Join(c.root, "extra"), []byte("extra"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckContents(marshal(t, c.f.m), marshal(t, c.f.p), marshal(t, c.policy), c.f.root, c.root); err == nil {
			t.Fatal("extra control accepted")
		}
	})
	t.Run("linked-control", func(t *testing.T) {
		c := actualContents(t)
		path := filepath.Join(c.root, "go-policy.json")
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path+".original", path); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckContents(marshal(t, c.f.m), marshal(t, c.f.p), marshal(t, c.policy), c.f.root, c.root); err == nil {
			t.Fatal("linked control accepted")
		}
	})
	t.Run("composition-protocol-only", func(t *testing.T) {
		c := actualContents(t)
		f := c.f
		_, v, options := provenanceFixture(t)
		v.Artifacts[0].ID = f.p.Artifacts[0].ID
		runner := func(context.Context, string, string, []string) ([]byte, error) {
			return marshal(t, []any{protocolResult(t, f.p, v, c.goPolicy.Subject.SHA256)}), nil
		}
		r, err := checkBundle(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), marshal(t, c.policy), f.root, c.root, options, runner)
		if err != nil || !r.SBOMContentsVerified || !r.ProvenanceSignaturesVerified || r.ReleaseAccepted || r.CompleteRuntimeInventoryEstablished {
			t.Fatal("bundle protocol composition failed")
		}
		encoded := marshal(t, r)
		var fields map[string]any
		if json.Unmarshal(encoded, &fields) != nil || fields["selectionVerified"] != true || fields["sbomContentsVerified"] != true || fields["releaseAccepted"] != false {
			t.Fatal("embedded result fields were lost or ambiguous")
		}
		refused := func(context.Context, string, string, []string) ([]byte, error) {
			return nil, errors.New("declared protocol verifier refusal")
		}
		r, err = checkBundle(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), marshal(t, c.policy), f.root, c.root, options, refused)
		if err == nil || r != (BundleResult{}) {
			t.Fatal("later signature refusal retained partial SBOM success")
		}
		changed := func(ctx context.Context, tool, work string, args []string) ([]byte, error) {
			raw, err := runner(ctx, tool, work, args)
			if writeErr := os.WriteFile(filepath.Join(c.root, "source/go.mod"), []byte("changed"), 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
			return raw, err
		}
		r, err = checkBundle(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), marshal(t, c.policy), f.root, c.root, options, changed)
		if err == nil || r != (BundleResult{}) {
			t.Fatal("changed control after signature verification produced acceptance")
		}
	})
}
