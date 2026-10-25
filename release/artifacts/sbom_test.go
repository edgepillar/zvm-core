package artifacts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

func sbomPolicyFixture(t *testing.T) (GoSBOMPolicy, []byte, []byte, *debug.BuildInfo) {
	t.Helper()
	mod := []byte("module example.invalid/project\n\ngo 1.25.0\n")
	h1 := "h1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	lock := []byte("example.invalid/dependency v1.2.3 " + h1 + "\nexample.invalid/dependency v1.2.3/go.mod " + h1 + "\n")
	p := GoSBOMPolicy{Schema: 1, Profile: GoSBOMProfile, Subject: File{"bin/tool", 10, strings.Repeat("1", 64)},
		Source:                Source{Repository: "Example/project", Commit: strings.Repeat("2", 40), Tree: strings.Repeat("3", 40), Gitlinks: []Gitlink{}},
		QualifiedInputsSHA256: strings.Repeat("4", 64), GoModSHA256: independentSHA(mod), GoSumSHA256: independentSHA(lock),
		MainPackage: "example.invalid/project/cmd/tool", MainModule: "example.invalid/project", MainVersion: "(devel)", GoVersion: "go1.25.14",
		BuildSettings: []GoSetting{{"-buildmode", "exe"}, {"-compiler", "gc"}, {"-trimpath", "true"}, {"CGO_ENABLED", "0"}, {"GOARCH", "arm64"}, {"GOOS", "darwin"}},
		Modules:       []GoSBOMModule{{"example.invalid/dependency", "v1.2.3", "none", "example.invalid/dependency", "v1.2.3", h1}},
		DocumentName:  "selected-tool", DocumentNamespace: "https://example.invalid/spdx/selected-tool-1", Created: "2026-01-01T00:00:00Z"}
	info := &debug.BuildInfo{GoVersion: p.GoVersion, Path: p.MainPackage, Main: debug.Module{Path: p.MainModule, Version: p.MainVersion},
		Deps: []*debug.Module{{Path: p.Modules[0].Path, Version: p.Modules[0].Version, Sum: h1}}}
	for _, s := range p.BuildSettings {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: s.Key, Value: s.Value})
	}
	return p, mod, lock, info
}

func TestGoSBOMPolicyAndIndependentMetadata(t *testing.T) {
	p, _, lock, info := sbomPolicyFixture(t)
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if err := matchGoInventory(info, p); err != nil {
		t.Fatal(err)
	}
	locks, err := lockModules(lock)
	if err != nil || locks[p.Modules[0].EffectivePath+" "+p.Modules[0].EffectiveVersion] != p.Modules[0].Sum {
		t.Fatal("expected Go tree sum is not bound")
	}
	slices.Reverse(info.Settings)
	if err := matchGoInventory(info, p); err != nil {
		t.Fatal("metadata order changed semantic inventory")
	}
	cases := []struct {
		name   string
		change func(*GoSBOMPolicy)
	}{
		{"schema", func(p *GoSBOMPolicy) { p.Schema = 2 }}, {"profile", func(p *GoSBOMPolicy) { p.Profile = "SPDX-3.0" }},
		{"subject", func(p *GoSBOMPolicy) { p.Subject.SHA256 = strings.Repeat("0", 64) }}, {"path", func(p *GoSBOMPolicy) { p.Subject.Path = "../outside" }},
		{"source", func(p *GoSBOMPolicy) { p.Source.Commit = "main" }}, {"qualification", func(p *GoSBOMPolicy) { p.QualifiedInputsSHA256 = "" }},
		{"namespace", func(p *GoSBOMPolicy) { p.DocumentNamespace = "https://user@example.invalid/path" }},
		{"namespace-space", func(p *GoSBOMPolicy) { p.DocumentNamespace = "https://example.invalid/a b" }},
		{"created", func(p *GoSBOMPolicy) { p.Created = "2026-01-01T01:00:00+01:00" }},
		{"toolchain", func(p *GoSBOMPolicy) { p.GoVersion = "devel" }}, {"main", func(p *GoSBOMPolicy) { p.MainModule = "/private/local/module" }},
		{"CGO", func(p *GoSBOMPolicy) { p.BuildSettings[3].Value = "1" }}, {"trimpath", func(p *GoSBOMPolicy) { p.BuildSettings[2].Value = "false" }},
		{"settings-duplicate", func(p *GoSBOMPolicy) { p.BuildSettings = append(p.BuildSettings, p.BuildSettings[0]) }},
		{"module-duplicate", func(p *GoSBOMPolicy) { p.Modules = append(p.Modules, p.Modules[0]) }},
		{"local-replacement", func(p *GoSBOMPolicy) { p.Modules[0].Replacement = "local" }},
		{"inconsistent-effective", func(p *GoSBOMPolicy) { p.Modules[0].EffectivePath = "example.invalid/other" }},
		{"checksum-algorithm", func(p *GoSBOMPolicy) { p.Modules[0].Sum = "sha256:" + strings.Repeat("1", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _, _ := sbomPolicyFixture(t)
			tc.change(&p)
			if p.validate() == nil {
				t.Fatal("invalid independent policy accepted")
			}
		})
	}
}

func TestGoSBOMVersionedReplacementAndRefusals(t *testing.T) {
	p, _, _, info := sbomPolicyFixture(t)
	p.Modules[0].Replacement = "versioned"
	p.Modules[0].EffectivePath = "example.invalid/replacement"
	p.Modules[0].EffectiveVersion = "v2.0.1+incompatible"
	info.Deps[0].Sum = ""
	info.Deps[0].Replace = &debug.Module{Path: p.Modules[0].EffectivePath, Version: p.Modules[0].EffectiveVersion, Sum: p.Modules[0].Sum}
	if p.validate() != nil || matchGoInventory(info, p) != nil {
		t.Fatal("effective versioned replacement was not preserved")
	}
	cases := []struct {
		name   string
		change func(*debug.BuildInfo)
	}{
		{"main-package", func(i *debug.BuildInfo) { i.Path = "example.invalid/other" }}, {"main-module", func(i *debug.BuildInfo) { i.Main.Path = "example.invalid/other" }},
		{"toolchain", func(i *debug.BuildInfo) { i.GoVersion = "go1.26.0" }}, {"missing-module", func(i *debug.BuildInfo) { i.Deps = nil }},
		{"duplicate-module", func(i *debug.BuildInfo) { i.Deps = append(i.Deps, i.Deps[0]) }}, {"nil-module", func(i *debug.BuildInfo) { i.Deps[0] = nil }},
		{"sum", func(i *debug.BuildInfo) { i.Deps[0].Replace.Sum = "h1:changed" }},
		{"local", func(i *debug.BuildInfo) {
			i.Deps[0].Replace.Path = "/private/not-for-output"
			i.Deps[0].Replace.Version = ""
		}},
		{"nested", func(i *debug.BuildInfo) { i.Deps[0].Replace.Replace = &debug.Module{Path: "example.invalid/nested"} }},
		{"settings", func(i *debug.BuildInfo) { i.Settings[0].Value = "plugin" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, i := sbomPolicyFixture(t)
			i.Deps[0].Sum = ""
			i.Deps[0].Replace = &debug.Module{Path: p.Modules[0].EffectivePath, Version: p.Modules[0].EffectiveVersion, Sum: p.Modules[0].Sum}
			tc.change(i)
			err := matchGoInventory(i, p)
			if err == nil || strings.Contains(err.Error(), "not-for-output") {
				t.Fatal("metadata mismatch was accepted or disclosed a local path")
			}
		})
	}
}

func TestGoSBOMLockAndReadBudgets(t *testing.T) {
	_, _, valid, _ := sbomPolicyFixture(t)
	for _, raw := range [][]byte{nil, append(append([]byte{}, valid...), valid...), []byte("example.invalid/module v1.2.3 h1:invalid\n"), []byte("/private/local v1.2.3 h1:invalid\n"), bytes.Repeat([]byte{'a'}, MaxDocumentBytes+1)} {
		if _, err := lockModules(raw); err == nil {
			t.Fatal("invalid checksum lock accepted")
		}
	}
	r := &metadataReader{reader: bytes.NewReader([]byte("abcdef")), size: 6, remaining: 3}
	if n, err := r.ReadAt(make([]byte, 3), 0); n != 3 || err != nil {
		t.Fatal("bounded metadata read failed")
	}
	if _, err := r.ReadAt(make([]byte, 1), 3); err == nil {
		t.Fatal("cumulative metadata read budget was ignored")
	}
	for _, offset := range []int64{-1, 7} {
		if _, err := r.ReadAt(nil, offset); err == nil {
			t.Fatal("invalid metadata offset accepted")
		}
	}
	f := filepath.Join(t.TempDir(), "subject")
	if err := os.WriteFile(f, []byte("not an executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readGoSubject(f, File{"subject", 17, independentSHA([]byte("not an executable"))}); err == nil {
		t.Fatal("non-Go subject accepted")
	}
}

func TestSPDXGoProfileKnownUnknownsAndTreeSums(t *testing.T) {
	p, _, _, _ := sbomPolicyFixture(t)
	canonical := marshal(t, p)
	doc := goSPDX(p, independentSHA(canonical))
	raw := marshal(t, doc)
	if _, err := objectDocument(raw); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || len(doc.Packages) != 4 || len(doc.Relationships) != 4 {
		t.Fatal("incomplete deterministic SPDX inventory")
	}
	for _, pkg := range doc.Packages {
		if pkg.FilesAnalyzed || pkg.LicenseConcluded != "NOASSERTION" || pkg.LicenseDeclared != "NOASSERTION" || pkg.Copyright != "NOASSERTION" {
			t.Fatal("unqualified license/file coverage asserted")
		}
		if strings.HasPrefix(pkg.ID, "SPDXRef-Module-") && (len(pkg.Checksums) != 0 || len(pkg.References) != 1 || pkg.References[0].Locator != p.Modules[0].Sum) {
			t.Fatal("Go file-tree sum was mislabeled as an artifact checksum")
		}
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("invalid generated JSON")
	}
}

func TestActualQualifiedGoSBOMSubject(t *testing.T) {
	dir := os.Getenv("ZVM_GO_SBOM_FIXTURE_DIRECTORY")
	if dir == "" {
		t.Skip("independently qualified Go subject/source inputs were not provisioned")
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := ReadDocument(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	policy, mod, lock := read("policy.json"), read("go.mod"), read("go.sum")
	subject := filepath.Join(dir, "subject")
	doc, result, err := GenerateGoSBOM(policy, mod, lock, subject)
	if err != nil || !result.SPDXProfileVerified || !result.LockedModulesMatched || result.ModulesVerified != 1 || result.SourceCommitAuthenticated || result.ToolchainIdentityAuthenticated || result.CompleteRuntimeInventoryEstablished || result.LicenseCoverageEstablished || result.ReleaseAccepted {
		t.Fatalf("actual subject inventory failed: %+v %v", result, err)
	}
	second, _, err := GenerateGoSBOM(policy, mod, lock, subject)
	if err != nil || !bytes.Equal(doc, second) {
		t.Fatal("same pinned inputs did not generate identical SPDX bytes")
	}
	if _, err := CheckGoSBOM(doc, policy, mod, lock, subject); err != nil {
		t.Fatal(err)
	}
	var original map[string]any
	if json.Unmarshal(doc, &original) != nil {
		t.Fatal("invalid generated JSON")
	}
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"unsupported-schema", func(d map[string]any) { d["spdxVersion"] = "SPDX-3.0" }}, {"unknown", func(d map[string]any) { d["extra"] = true }},
		{"missing-package", func(d map[string]any) { d["packages"] = d["packages"].([]any)[1:] }},
		{"duplicate-package", func(d map[string]any) { d["packages"] = append(d["packages"].([]any), d["packages"].([]any)[0]) }},
		{"wrong-subject", func(d map[string]any) {
			for _, v := range d["packages"].([]any) {
				p := v.(map[string]any)
				if p["SPDXID"] == "SPDXRef-Artifact" {
					p["checksums"].([]any)[0].(map[string]any)["checksumValue"] = strings.Repeat("9", 64)
				}
			}
		}},
		{"missing-relationship", func(d map[string]any) { d["relationships"] = d["relationships"].([]any)[1:] }},
		{"dangling-relationship", func(d map[string]any) {
			d["relationships"].([]any)[0].(map[string]any)["relatedSpdxElement"] = "SPDXRef-absent"
		}},
		{"coverage-claim", func(d map[string]any) { d["comment"] = "complete runtime and license inventory" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d map[string]any
			json.Unmarshal(doc, &d)
			tc.change(d)
			r, err := CheckGoSBOM(marshal(t, d), policy, mod, lock, subject)
			if err == nil || r != (GoSBOMResult{}) {
				t.Fatal("changed SPDX contents produced acceptance")
			}
		})
	}
	for _, raw := range [][]byte{[]byte(`{"SPDXID":"SPDXRef-DOCUMENT","SPDXID":"other"}`), []byte(`{} {}`), bytes.Repeat([]byte{'x'}, MaxDocumentBytes+1)} {
		if _, err := CheckGoSBOM(raw, policy, mod, lock, subject); err == nil {
			t.Fatal("ambiguous or oversized document accepted")
		}
	}
	t.Run("independent-module-omission", func(t *testing.T) {
		var p GoSBOMPolicy
		if decode(policy, &p) != nil {
			t.Fatal("invalid fixture policy")
		}
		p.Modules = []GoSBOMModule{}
		if _, _, err := GenerateGoSBOM(marshal(t, p), mod, lock, subject); err == nil {
			t.Fatal("binary module omitted from policy was accepted")
		}
	})
}
