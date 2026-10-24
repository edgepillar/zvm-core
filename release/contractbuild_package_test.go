package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type packageMemberFixture struct {
	name   string
	data   []byte
	kind   byte
	format tar.Format
}

func packageArchiveFixture(t *testing.T, members []packageMemberFixture) []byte {
	t.Helper()
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	for _, member := range members {
		kind := member.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		format := member.format
		if format == 0 {
			format = tar.FormatUSTAR
		}
		header := &tar.Header{Name: member.name, Mode: 0644, Size: int64(len(member.data)), Typeflag: kind, Format: format}
		if kind == tar.TypeSymlink || kind == tar.TypeLink {
			header.Linkname = "../outside"
			header.Size = 0
		}
		if format == tar.FormatPAX {
			header.PAXRecords = map[string]string{"comment": "synthetic fixture"}
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tw.Write(member.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return gzipPackageFixture(t, plain.Bytes())
}

func gzipPackageFixture(t *testing.T, plain []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	if _, err := z.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func npmLockFixture(t *testing.T, archive []byte) map[string]any {
	digest := sha512.Sum512(archive)
	return map[string]any{"lockfileVersion": 3, "packages": map[string]any{"node_modules/@fixture/pkg": map[string]any{"version": "1.2.3", "integrity": "sha512-" + base64.StdEncoding.EncodeToString(digest[:]), "resolved": "https://packages.fixture.invalid/pkg-1.2.3.tgz"}}}
}

type packageBuildFixture struct {
	*contractBuildFixture
	archive []byte
	lock    map[string]any
	source  []byte
}

func (f *packageBuildFixture) savePackage(t *testing.T, commit bool) {
	t.Helper()
	f.pin(t, "fixture-package", "artifact", "rebuild/fixture-package.tgz", f.archive)
	raw := buildRaw(t, f.lock)
	f.pin(t, "fixture-package-lock", "lock", "contracts/package-lock.json", raw)
	name := filepath.Join(f.sources, "zvm-core/contracts/package-lock.json")
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if commit {
		dir := filepath.Join(f.sources, "zvm-core")
		runGit(t, dir, "add", "contracts/package-lock.json")
		runGit(t, dir, "commit", "-m", "Pin synthetic external source archive")
		f.manifest.Repositories[0].Commit = runGit(t, dir, "rev-parse", "HEAD")
	}
	f.save(t)
}

func newPackageBuildFixture(t *testing.T) *packageBuildFixture {
	t.Helper()
	base := newContractBuildFixture(t)
	oldUnit := "Fixture.sol"
	unit := "@fixture/pkg/Fixture.sol"
	input := base.bundle["input"].(map[string]any)
	oldSources := input["sources"].(map[string]any)
	source := []byte(oldSources[oldUnit].(map[string]any)["content"].(string))
	input["sources"] = map[string]any{unit: oldSources[oldUnit]}
	output := base.bundle["output"].(map[string]any)
	contracts := output["contracts"].(map[string]any)
	output["contracts"] = map[string]any{unit: contracts[oldUnit]}
	output["sources"] = map[string]any{unit: map[string]any{"id": 0}}
	for name, raw := range contracts[oldUnit].(map[string]any) {
		artifact := raw.(map[string]any)
		var metadata map[string]any
		if err := json.Unmarshal([]byte(artifact["metadata"].(string)), &metadata); err != nil {
			t.Fatal(err)
		}
		metadata["settings"].(map[string]any)["compilationTarget"] = map[string]any{unit: name}
		metadata["sources"] = map[string]any{unit: metadata["sources"].(map[string]any)[oldUnit]}
		encoded := buildRaw(t, metadata)
		artifact["metadata"] = string(encoded)
		for i := range base.buildPolicy.Builds[0].Contracts {
			target := &base.buildPolicy.Builds[0].Contracts[i]
			if target.Name == name {
				target.Unit = unit
				target.MetadataSHA256 = digest(encoded)
			}
		}
	}
	base.buildPolicy.Builds[0].Sources = []ContractBuildSource{{Unit: unit, File: "fixture-package", Member: "package/Fixture.sol", LockFile: "fixture-package-lock", PackageKey: "node_modules/@fixture/pkg", PackageName: "@fixture/pkg", PackageVersion: "1.2.3"}}
	archive := packageArchiveFixture(t, []packageMemberFixture{{name: "package/Fixture.sol", data: source}, {name: "package/package.json", data: []byte(`{"name":"@fixture/pkg","version":"1.2.3"}`)}})
	f := &packageBuildFixture{contractBuildFixture: base, archive: archive, source: source, lock: npmLockFixture(t, archive)}
	f.savePackage(t, true)
	return f
}

func (f *packageBuildFixture) entry() map[string]any {
	return f.lock["packages"].(map[string]any)["node_modules/@fixture/pkg"].(map[string]any)
}

func TestSavedPackageSourcesBindSignedArchiveToCleanCommittedLockWithoutInventingGitFiles(t *testing.T) {
	f := newPackageBuildFixture(t)
	if _, err := os.Stat(filepath.Join(f.sources, "zvm-core/rebuild/fixture-package.tgz")); !os.IsNotExist(err) {
		t.Fatal("archive unexpectedly installed in source Git tree")
	}
	r, err := f.manifest.Verify(context.Background(), f.policy, f.signatures(t), f.keys, f.files, f.sources)
	if err != nil {
		t.Fatal(err)
	}
	if r.VerifiedContractBuilds != 13 || r.CompilerExecuted || r.RuntimeObserved {
		t.Fatal("saved package material mistaken for execution", r)
	}
}

func TestPackageSourceBindingRejectsUpdatedOuterPinsForInvalidSupplierMaterial(t *testing.T) {
	cases := map[string]func(*packageBuildFixture){
		"wrong integrity": func(f *packageBuildFixture) {
			f.entry()["integrity"] = "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))
		},
		"weak integrity":       func(f *packageBuildFixture) { f.entry()["integrity"] = "sha1-" + strings.Repeat("a", 40) },
		"wrong locked version": func(f *packageBuildFixture) { f.entry()["version"] = "1.2.4" },
		"wrong package identity": func(f *packageBuildFixture) {
			f.archive = packageArchiveFixture(t, []packageMemberFixture{{name: "package/Fixture.sol", data: f.source}, {name: "package/package.json", data: []byte(`{"name":"@fixture/other","version":"1.2.3"}`)}})
			f.lock = npmLockFixture(t, f.archive)
		},
		"missing source member": func(f *packageBuildFixture) {
			f.archive = packageArchiveFixture(t, []packageMemberFixture{{name: "package/package.json", data: []byte(`{"name":"@fixture/pkg","version":"1.2.3"}`)}})
			f.lock = npmLockFixture(t, f.archive)
		},
		"symlink source": func(f *packageBuildFixture) {
			f.archive = packageArchiveFixture(t, []packageMemberFixture{{name: "package/Fixture.sol", kind: tar.TypeSymlink}, {name: "package/package.json", data: []byte(`{"name":"@fixture/pkg","version":"1.2.3"}`)}})
			f.lock = npmLockFixture(t, f.archive)
		},
		"case duplicate": func(f *packageBuildFixture) {
			f.archive = packageArchiveFixture(t, []packageMemberFixture{{name: "package/Fixture.sol", data: f.source}, {name: "package/fixture.sol", data: f.source}, {name: "package/package.json", data: []byte(`{"name":"@fixture/pkg","version":"1.2.3"}`)}})
			f.lock = npmLockFixture(t, f.archive)
		},
		"traversal member": func(f *packageBuildFixture) {
			f.archive = packageArchiveFixture(t, []packageMemberFixture{{name: "package/../Fixture.sol", data: f.source}, {name: "package/package.json", data: []byte(`{"name":"@fixture/pkg","version":"1.2.3"}`)}})
			f.lock = npmLockFixture(t, f.archive)
		},
		"PAX extension": func(f *packageBuildFixture) {
			f.archive = packageArchiveFixture(t, []packageMemberFixture{{name: "package/Fixture.sol", data: f.source, format: tar.FormatPAX}, {name: "package/package.json", data: []byte(`{"name":"@fixture/pkg","version":"1.2.3"}`)}})
			f.lock = npmLockFixture(t, f.archive)
		},
		"linked lock entry": func(f *packageBuildFixture) { f.entry()["link"] = true },
		"null link":         func(f *packageBuildFixture) { f.entry()["link"] = nil },
		"credential label": func(f *packageBuildFixture) {
			f.entry()["resolved"] = "https://fixture:fixture@packages.fixture.invalid/pkg.tgz"
		},
		"insecure label":             func(f *packageBuildFixture) { f.entry()["resolved"] = "http://packages.fixture.invalid/pkg.tgz" },
		"member alias":               func(f *packageBuildFixture) { f.buildPolicy.Builds[0].Sources[0].Member = "package/Other.sol" },
		"partial source declaration": func(f *packageBuildFixture) { f.buildPolicy.Builds[0].Sources[0].LockFile = "" },
		"missing lock entry":         func(f *packageBuildFixture) { f.lock["packages"] = map[string]any{} },
		"legacy lock":                func(f *packageBuildFixture) { f.lock["lockfileVersion"] = 1 },
		"lock field alias": func(f *packageBuildFixture) {
			f.lock["LockfileVersion"] = f.lock["lockfileVersion"]
			delete(f.lock, "lockfileVersion")
		},
		"entry field alias": func(f *packageBuildFixture) {
			f.entry()["Integrity"] = f.entry()["integrity"]
			delete(f.entry(), "integrity")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPackageBuildFixture(t)
			mutate(f)
			f.savePackage(t, false)
			if _, err := f.manifest.VerifyContractBuilds(f.files, f.sources); err == nil {
				t.Fatal("invalid package supplier material accepted after outer file pins changed")
			}
		})
	}
}

func TestPackageLockMustMatchActualSourceBytesAndArchiveCacheCannotChangeAuthority(t *testing.T) {
	f := newPackageBuildFixture(t)
	if err := os.WriteFile(filepath.Join(f.sources, "zvm-core/contracts/package-lock.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manifest.VerifyContractBuilds(f.files, f.sources); err == nil {
		t.Fatal("different source checkout lock accepted")
	}
	f.savePackage(t, false)
	files, err := openDirectory(f.files)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	sources, err := openDirectory(f.sources)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	pins := map[string]File{}
	for _, pin := range f.manifest.Files {
		pins[pin.ID] = pin
	}
	reader := newBuildPackageReader(files, sources, pins)
	source := f.buildPolicy.Builds[0].Sources[0]
	for i := 0; i < 3; i++ {
		raw, err := reader.source(source, pins[source.File])
		if err != nil || !bytes.Equal(raw, f.source) {
			t.Fatal("cached source changed", err)
		}
	}
	if len(reader.archives) != 1 || reader.compressed != len(f.archive) || reader.members != 2 {
		t.Fatal("package budget renewed per source", reader.compressed, reader.members)
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(reader.locks[source.LockFile][source.PackageKey], &entry); err != nil {
		t.Fatal(err)
	}
	entry["integrity"] = buildRaw(t, "sha512-"+base64.StdEncoding.EncodeToString(make([]byte, 64)))
	reader.locks[source.LockFile][source.PackageKey] = buildRaw(t, entry)
	if _, err := reader.source(source, pins[source.File]); err == nil {
		t.Fatal("cached archive accepted a different lock authority")
	}
}

func TestPackageParsingBoundsAndIgnoredTrailingBytesAreEnforced(t *testing.T) {
	raw := packageArchiveFixture(t, []packageMemberFixture{{name: "package/A.sol", data: []byte("contract A {}")}, {name: "package/package.json", data: []byte(`{"name":"@fixture/pkg","version":"1.2.3"}`)}})
	if _, _, _, err := readBuildPackage(raw, 512, 4096); err == nil {
		t.Fatal("expanded byte bound ignored")
	}
	if _, _, _, err := readBuildPackage(raw, maxBuildPackageExpanded, 1); err == nil {
		t.Fatal("member bound ignored")
	}
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	_ = z.Close()
	extra := make([]byte, 512)
	extra[0] = 1
	plain = append(plain, extra...)
	if _, _, _, err := readBuildPackage(gzipPackageFixture(t, plain), maxBuildPackageExpanded, 4096); err == nil {
		t.Fatal("trailing tar data ignored")
	}
}

func TestPackagePayloadZerosCannotReplaceArchiveEndMarkers(t *testing.T) {
	raw := packageArchiveFixture(t, []packageMemberFixture{
		{name: "package/A.sol", data: []byte("contract A {}")},
		{name: "package/package.json", data: []byte(`{"name":"@fixture/pkg","version":"1.2.3"}`)},
		{name: "package/padding.bin", data: make([]byte, 1024)},
	})
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	_ = z.Close()
	if len(plain) < 2048 {
		t.Fatal("invalid zero-tail fixture")
	}
	// Keep the last member's zero payload but remove the actual two end blocks.
	unterminated := gzipPackageFixture(t, plain[:len(plain)-1024])
	if _, _, _, err := readBuildPackage(unterminated, maxBuildPackageExpanded, maxBuildPackageMembers); err == nil {
		t.Fatal("file payload zeros were accepted as missing archive end markers")
	}
}
