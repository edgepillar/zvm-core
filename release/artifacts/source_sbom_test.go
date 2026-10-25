package artifacts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func sourcePolicyFixture(t *testing.T) (GoSourceSBOMPolicy, GoSourceOptions, *debug.BuildInfo) {
	t.Helper()
	fixtureHost(t)
	base, _, _, info := sbomPolicyFixture(t)
	data := map[string]string{"a.b": "file before directory\n", "a/x.go": "package local\nconst Value=7\n", "go.mod": "module example.invalid/local\n\ngo 1.25.0\n", "run.sh": "#!/bin/sh\nexit 0\n"}
	root, controls := t.TempDir(), t.TempDir()
	tree := "eed75c2d85ee440dbc9337aa6e7ee7ed578c58a7"
	commit := []byte("tree " + tree + "\nauthor Anonymous Contributor <anonymous@contributors.invalid> 0 +0000\ncommitter Anonymous Contributor <anonymous@contributors.invalid> 0 +0000\n\nQualification fixture.\n")
	local := GoLocalSource{Module: "example.invalid/local", Version: "v0.0.0", Path: "core", Source: Source{Repository: "Example/core", Commit: "b22de470f5dda1e7309a60a99b015a487fb13b1d", Tree: tree, Gitlinks: []Gitlink{}}, GoModSHA256: independentSHA([]byte(data["go.mod"])), CommitObject: File{"core.commit", int64(len(commit)), independentSHA(commit)}, Files: []SourceFile{}}
	for _, name := range []string{"a.b", "a/x.go", "go.mod", "run.sh"} {
		mode, perm := "100644", os.FileMode(0600)
		if name == "run.sh" {
			mode, perm = "100755", 0700
		}
		f := filepath.Join(root, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(f), 0700) != nil || os.WriteFile(f, []byte(data[name]), perm) != nil {
			t.Fatal("fixture write failed")
		}
		local.Files = append(local.Files, SourceFile{name, int64(len(data[name])), independentSHA([]byte(data[name])), mode})
	}
	if os.WriteFile(filepath.Join(controls, "core.commit"), commit, 0600) != nil {
		t.Fatal("control write failed")
	}
	base.Source.Gitlinks = []Gitlink{{local.Path, local.Source.Repository, local.Source.Commit}}
	info.Deps = append(info.Deps, &debug.Module{Path: local.Module, Version: local.Version, Replace: &debug.Module{Path: "./core", Version: "(devel)"}})
	return GoSourceSBOMPolicy{1, GoSourceSBOMProfile, base, []GoLocalSource{local}}, GoSourceOptions{map[string]string{"core": root}, controls}, info
}

func TestGitSourceObjectIdentityAndDirectoryOrdering(t *testing.T) {
	if got := hex.EncodeToString(gitObject("blob", nil, 40)); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatal("empty Git blob differs from the published object format")
	}
	if got := hex.EncodeToString((&gitNode{children: map[string]*gitNode{}}).digest(40)); got != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" {
		t.Fatal("empty Git tree differs")
	}
	p, options, _ := sourcePolicyFixture(t)
	controls, err := p.validate()
	if err != nil {
		t.Fatal(err)
	}
	observed, err := observeGoSources(p, controls, options)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.close()
	if len(observed.trees) != 1 || observed.files != 4 || observed.bytes <= 0 {
		t.Fatal("source byte coverage is wrong")
	}
	if err := observed.unchanged(); err != nil {
		t.Fatal(err)
	}
}

func TestGoSourcePolicyAndMetadataBindings(t *testing.T) {
	p, _, info := sourcePolicyFixture(t)
	if _, err := p.validate(); err != nil || matchGoSourceInventory(info, p) != nil {
		t.Fatal("valid selected local and remote records refused")
	}
	if matchGoInventory(info, p.Go) == nil {
		t.Fatal("legacy profile silently accepted a local replacement")
	}
	cases := []struct {
		name   string
		change func(*GoSourceSBOMPolicy)
	}{
		{"schema", func(p *GoSourceSBOMPolicy) { p.Schema = 2 }},
		{"profile", func(p *GoSourceSBOMPolicy) { p.Profile = GoSBOMProfile }},
		{"remote-profile", func(p *GoSourceSBOMPolicy) { p.Go.Profile = GoSourceSBOMProfile }},
		{"no-source", func(p *GoSourceSBOMPolicy) { p.LocalSources = []GoLocalSource{} }},
		{"duplicate-module", func(p *GoSourceSBOMPolicy) { p.LocalSources = append(p.LocalSources, p.LocalSources[0]) }},
		{"remote-module-alias", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].Module = p.Go.Modules[0].Path }},
		{"missing-parent-link", func(p *GoSourceSBOMPolicy) { p.Go.Source.Gitlinks = []Gitlink{} }},
		{"parent-commit", func(p *GoSourceSBOMPolicy) { p.Go.Source.Gitlinks[0].Commit = strings.Repeat("3", 40) }},
		{"parent-repository", func(p *GoSourceSBOMPolicy) { p.Go.Source.Gitlinks[0].Repository = "Other/core" }},
		{"absolute-binding", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].Path = "/private/no-export" }},
		{"nested-tree", func(p *GoSourceSBOMPolicy) {
			p.LocalSources[0].Source.Gitlinks = []Gitlink{{"child", "Example/child", strings.Repeat("5", 40)}}
		}},
		{"control-size", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].CommitObject.Bytes = MaxDocumentBytes + 1 }},
		{"control-path", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].CommitObject.Path = "../outside" }},
		{"file-oversize", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].Files[0].Bytes = MaxLocalSourceFileBytes + 1 }},
		{"file-mode", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].Files[0].Mode = "120000" }},
		{"file-case-alias", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].Files[1].Path = "A.B" }},
		{"file-directory-alias", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].Files[0].Path = "a" }},
		{"file-Git-metadata", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].Files[0].Path = ".git" }},
		{"module-digest", func(p *GoSourceSBOMPolicy) { p.LocalSources[0].GoModSHA256 = strings.Repeat("6", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _ := sourcePolicyFixture(t)
			tc.change(&p)
			if _, err := p.validate(); err == nil {
				t.Fatal("invalid source policy accepted")
			}
		})
	}
	metadata := []struct {
		name   string
		change func(*debug.Module)
	}{
		{"requested-version", func(m *debug.Module) { m.Version = "v1.0.0" }},
		{"invented-sum", func(m *debug.Module) { m.Sum = "h1:invented" }},
		{"missing-local", func(m *debug.Module) { m.Replace = nil }},
		{"local-version", func(m *debug.Module) { m.Replace.Version = "v1.0.0" }},
		{"local-sum", func(m *debug.Module) { m.Replace.Sum = "h1:invented" }},
		{"absolute-private", func(m *debug.Module) { m.Replace.Path = "/private/no-export" }},
		{"other-relative-root", func(m *debug.Module) { m.Replace.Path = "../core" }},
		{"nested-replacement", func(m *debug.Module) { m.Replace.Replace = &debug.Module{Path: "./other"} }},
	}
	for _, tc := range metadata {
		t.Run(tc.name, func(t *testing.T) {
			p, _, info := sourcePolicyFixture(t)
			tc.change(info.Deps[len(info.Deps)-1])
			err := matchGoSourceInventory(info, p)
			if err == nil || strings.Contains(err.Error(), "no-export") {
				t.Fatal("changed metadata accepted or exposed a runtime path")
			}
		})
	}
}

func TestGoSourceTreesRejectChangedFilesControlsAndSelfConsistentRebinding(t *testing.T) {
	cases := []struct {
		name   string
		change func(*GoSourceSBOMPolicy, GoSourceOptions)
	}{
		{"source-byte", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			os.WriteFile(filepath.Join(o.Directories["core"], "a.b"), []byte("changed bytes\n"), 0600)
		}},
		{"missing-file", func(p *GoSourceSBOMPolicy, o GoSourceOptions) { os.Remove(filepath.Join(o.Directories["core"], "a.b")) }},
		{"extra-file", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			os.WriteFile(filepath.Join(o.Directories["core"], "extra"), []byte("x"), 0600)
		}},
		{"extra-directory", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			os.Mkdir(filepath.Join(o.Directories["core"], "extra"), 0700)
		}},
		{"mode", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			os.Chmod(filepath.Join(o.Directories["core"], "run.sh"), 0600)
		}},
		{"extra-control", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			os.WriteFile(filepath.Join(o.ControlDirectory, "extra"), []byte("x"), 0600)
		}},
		{"commit-bytes", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			os.WriteFile(filepath.Join(o.ControlDirectory, "core.commit"), []byte("changed\n"), 0600)
		}},
		{"updated-file-pin", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			raw := []byte("changed bytes\n")
			os.WriteFile(filepath.Join(o.Directories["core"], "a.b"), raw, 0600)
			p.LocalSources[0].Files[0].Bytes = int64(len(raw))
			p.LocalSources[0].Files[0].SHA256 = independentSHA(raw)
		}},
		{"changed-tree", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			p.LocalSources[0].Source.Tree = strings.Repeat("7", 40)
		}},
		{"changed-commit-control-without-parent-link", func(p *GoSourceSBOMPolicy, o GoSourceOptions) {
			raw := []byte("tree " + strings.Repeat("7", 40) + "\n\nchanged\n")
			s := &p.LocalSources[0]
			s.Source.Tree = strings.Repeat("7", 40)
			s.Source.Commit = hex.EncodeToString(gitObject("commit", raw, 40))
			s.CommitObject.Bytes = int64(len(raw))
			s.CommitObject.SHA256 = independentSHA(raw)
			os.WriteFile(filepath.Join(o.ControlDirectory, "core.commit"), raw, 0600)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, o, _ := sourcePolicyFixture(t)
			tc.change(&p, o)
			controls, err := p.validate()
			if err == nil {
				var observed *sourceObservation
				observed, err = observeGoSources(p, controls, o)
				if observed != nil {
					observed.close()
				}
			}
			if err == nil {
				t.Fatal("changed source binding accepted")
			}
		})
	}
	t.Run("late-extra-file", func(t *testing.T) {
		p, o, _ := sourcePolicyFixture(t)
		controls, _ := p.validate()
		s, err := observeGoSources(p, controls, o)
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		os.WriteFile(filepath.Join(o.Directories["core"], "late"), []byte("x"), 0600)
		if s.unchanged() == nil {
			t.Fatal("late source inventory mutation accepted")
		}
	})
	t.Run("late-control", func(t *testing.T) {
		p, o, _ := sourcePolicyFixture(t)
		controls, _ := p.validate()
		s, err := observeGoSources(p, controls, o)
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		os.WriteFile(filepath.Join(o.ControlDirectory, "core.commit"), []byte("x"), 0600)
		if s.unchanged() == nil {
			t.Fatal("late commit identity change accepted")
		}
	})
}

func TestGoSourceStrictJSONMappingsAndPrivacy(t *testing.T) {
	p, o, _ := sourcePolicyFixture(t)
	raw := marshal(t, p)
	if profile, err := GoSBOMPolicyProfile(raw); err != nil || profile != GoSourceSBOMProfile {
		t.Fatal("selected profile failed dispatch")
	}
	for _, bad := range [][]byte{[]byte(`{"profile":"x","profile":"y"}`), []byte(`{"schema":1,"profile":"spdx-2.3-go-local-source-v1"}`), append(append([]byte{}, raw...), []byte(" {}")...)} {
		if _, err := GoSBOMPolicyProfile(bad); err == nil {
			t.Fatal("ambiguous policy dispatched")
		}
	}
	mapping := []byte(`{"schema":1,"sources":[{"path":"core","directory":"/private/no-export"}]}`)
	roots, err := ParseGoSourceDirectories(mapping)
	if err != nil || roots["core"] != "/private/no-export" {
		t.Fatal("runtime mapping failed")
	}
	for _, text := range []string{`{"schema":1,"sources":[]}`, `{"schema":1,"sources":[{"path":"../core","directory":"/private/no-export"}]}`, `{"schema":1,"sources":[{"path":"core","directory":"relative"}]}`, `{"schema":1,"sources":[{"path":"core","directory":"/one"},{"path":"core","directory":"/two"}]}`} {
		if _, err := ParseGoSourceDirectories([]byte(text)); err == nil || strings.Contains(err.Error(), "no-export") {
			t.Fatal("unsafe mapping accepted or disclosed")
		}
	}
	doc := marshal(t, goSourceSPDX(p, independentSHA(raw)))
	if bytes.Contains(doc, []byte(o.Directories["core"])) || bytes.Contains(doc, []byte(o.ControlDirectory)) || bytes.Contains(doc, []byte("./core")) {
		t.Fatal("SPDX disclosed source runtime locations")
	}
	if !bytes.Contains(doc, []byte("No Go h1 sum is invented")) {
		t.Fatal("source checksum scope is ambiguous")
	}
}

func TestActualLocalCoreSourceSPDX(t *testing.T) {
	dir := os.Getenv("ZVM_GO_SOURCE_FIXTURE_DIRECTORY")
	if dir == "" {
		t.Skip("qualified local replacement subject and independent source controls were not provisioned")
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
	roots, err := ParseGoSourceDirectories(read("directories.json"))
	if err != nil {
		t.Fatal(err)
	}
	options := GoSourceOptions{Directories: roots, ControlDirectory: filepath.Join(dir, "controls")}
	var p GoSourceSBOMPolicy
	if decode(policy, &p) != nil || len(p.LocalSources) != 1 || p.LocalSources[0].Module != "github.com/Zenoglyphs-VM/zvm-core" {
		t.Fatal("actual Core source fixture required")
	}
	subject := filepath.Join(dir, "subject")
	doc, r, err := GenerateGoSourceSBOM(policy, mod, lock, subject, options)
	if err != nil || r.LocalSourceTreesVerified != 1 || r.LocalCommitObjectsVerified != 1 || r.LocalSourceFilesVerified != len(p.LocalSources[0].Files) || r.ModulesVerified != len(p.Go.Modules)+1 || !r.SPDXProfileVerified || r.SourceCommitAuthenticated || r.CompilerUseOfTreesProven || r.ParentSourceTreeVerified || r.ReleaseAccepted {
		t.Fatalf("actual source binding failed: %+v %v", r, err)
	}
	if _, err := CheckGoSourceSBOM(doc, policy, mod, lock, subject, options); err != nil {
		t.Fatal(err)
	}
	second, _, err := GenerateGoSourceSBOM(policy, mod, lock, subject, options)
	if err != nil || !bytes.Equal(doc, second) {
		t.Fatal("source profile generation changed bytes")
	}
	var changed map[string]any
	json.Unmarshal(doc, &changed)
	changed["comment"] = "complete authenticated source and runtime inventory"
	if result, err := CheckGoSourceSBOM(marshal(t, changed), policy, mod, lock, subject, options); err == nil || result != (GoSourceSBOMResult{}) {
		t.Fatal("unsupported coverage claim accepted")
	}
	p.Go.Source.Gitlinks[0].Commit = strings.Repeat("8", 40)
	if _, result, err := GenerateGoSourceSBOM(marshal(t, p), mod, lock, subject, options); err == nil || result != (GoSourceSBOMResult{}) {
		t.Fatal("changed parent/source binding accepted")
	}
	for _, root := range roots {
		if bytes.Contains(doc, []byte(root)) {
			t.Fatal("actual SPDX disclosed a private source location")
		}
	}
}
