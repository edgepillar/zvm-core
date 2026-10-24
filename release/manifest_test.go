package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

type fixture struct {
	manifest       Manifest
	policy         Policy
	keys           TrustedKeys
	private        []ed25519.PrivateKey
	files, sources string
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	argv := append([]string{"-c", "user.name=Fixture Contributor", "-c", "user.email=fixture@contributors.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.DevNull, "-C", dir}, args...)
	cmd := exec.Command("git", argv...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull}
	if v := os.Getenv("SystemRoot"); v != "" {
		cmd.Env = append(cmd.Env, "SystemRoot="+v)
	}
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture Git command failed: %v: %s", err, raw)
	}
	return strings.TrimSpace(string(raw))
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{files: filepath.Join(root, "files"), sources: filepath.Join(root, "sources"), keys: TrustedKeys{Schema: Schema}}
	for _, name := range []string{".github", "zvm-core"} {
		dir := filepath.Join(f.sources, name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		runGit(t, dir, "init", "--initial-branch=main")
	}
	dir := filepath.Join(f.sources, "zvm-core")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("Fixture-only repository.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "README.md")
	runGit(t, dir, "commit", "-m", "Fixture source")
	sha := runGit(t, dir, "rev-parse", "HEAD")
	f.policy = Policy{Schema: Schema, MinSignatures: 2, Repositories: []string{"zvm-core", ".github"}, Toolchains: []string{"fixture-go"}, Images: []string{"fixture-engine"}, Compilers: []string{"fixture-solc"}, Contracts: []string{"fixture-contract"}}
	rollupRaw, err := os.ReadFile("../chains/l2/rollup.json")
	if err != nil {
		t.Fatal(err)
	}
	genesisRaw, err := os.ReadFile("../chains/l2/genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		L1ChainID, L2ChainID uint64
		L2GenesisHash        string
		EVM                  string
	}
	if err := json.Unmarshal(rollupRaw, &cfg); err != nil {
		t.Fatal(err)
	}
	// These public synthetic bytes are not compiler binaries or live code.
	code := []byte{0x60, 0x00, 0x60, 0x00}
	contract := Contract{ID: "fixture-contract", RuntimeFile: "runtime", Address: "0x" + strings.Repeat("7", 40), RuntimeCodeHash: crypto.Keccak256Hash(code).Hex()}
	deploymentRaw, err := json.Marshal(DeploymentBindings{Schema: Schema, Contracts: []Contract{contract}})
	if err != nil {
		t.Fatal(err)
	}
	evm := cfg.EVM
	if evm == "" {
		evm = "isthmus"
	}
	f.manifest = Manifest{Schema: Schema, Epoch: Epoch{ID: strings.Repeat("5", 64), L1ChainID: "70", L2ChainID: "7340470", L1GenesisHash: "0x" + strings.Repeat("1", 64), L2GenesisHash: cfg.L2GenesisHash, RollupSHA256: digest(rollupRaw), DeploymentsSHA256: digest(deploymentRaw), EVM: evm}, Repositories: []Repository{{Name: "zvm-core", Commit: sha}, {Name: ".github", Empty: true}}, Toolchains: []Artifact{{ID: "fixture-go", FileID: "tool-archive", Version: "fixture-v1", Platform: "darwin/arm64", SHA256: digest([]byte("fixture-only-archive"))}}, Compilers: []Artifact{{ID: "fixture-solc", FileID: "tool-archive", Version: "fixture-v1", Platform: "darwin/arm64", SHA256: digest([]byte("fixture-only-archive"))}}, Images: []Image{{ID: "fixture-engine", Platform: "linux/amd64", Reference: "registry.invalid/fixture/engine@sha256:" + digest([]byte("fixture-only-image"))}}, Contracts: []Contract{contract}}
	for _, item := range []struct {
		id, kind string
		raw      []byte
	}{{"rollup", "rollup", rollupRaw}, {"l1-genesis", "l1-genesis", []byte(`{"fixtureOnly":true}`)}, {"l2-genesis", "l2-genesis", genesisRaw}, {"deployments", "deployments", deploymentRaw}, {"lock", "lock", []byte("fixture-only-lock")}, {"tool-archive", "artifact", []byte("fixture-only-archive")}, {"runtime", "runtime-code", []byte("0x60006000")}} {
		pin := File{ID: item.id, Kind: item.kind, Repository: "zvm-core", Path: item.id + ".fixture", Bytes: int64(len(item.raw)), SHA256: digest(item.raw)}
		f.manifest.Files = append(f.manifest.Files, pin)
		f.policy.Files = append(f.policy.Files, FileRequirement{ID: pin.ID, Kind: pin.Kind, Repository: pin.Repository, Path: pin.Path})
		file := filepath.Join(f.files, pin.Repository, pin.Path)
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, item.raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.manifest.PolicySHA256, err = f.policy.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.keys.Keys = append(f.keys.Keys, base64.StdEncoding.EncodeToString(public))
		f.private = append(f.private, private)
	}
	return f
}

func (f *fixture) signatures(t *testing.T) Signatures {
	t.Helper()
	message, err := f.manifest.SigningMessage()
	if err != nil {
		t.Fatal(err)
	}
	s := Signatures{Schema: Schema}
	for _, key := range f.private {
		s.Signatures = append(s.Signatures, Signature{Algorithm: "ed25519", KeySHA256: digest(key.Public().(ed25519.PublicKey)), Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))})
	}
	return s
}

func copyManifest(t *testing.T, m Manifest) Manifest {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var c Manifest
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSignedOfflineReleaseBindsFilesSourcesAndEpochWithoutClaimingRuntime(t *testing.T) {
	f := newFixture(t)
	r, err := f.manifest.Verify(context.Background(), f.policy, f.signatures(t), f.keys, f.files, f.sources)
	if err != nil {
		t.Fatal(err)
	}
	if r.RuntimeObserved || r.TrustedSignatures != 2 || r.VerifiedFiles != 7 || r.VerifiedRepositories != 2 || r.ManifestSHA256 == "" || r.EpochSHA256 == "" {
		t.Fatalf("wrong verification scope: %+v", r)
	}
	raw, err := json.Marshal(r)
	if err != nil || bytes.Contains(raw, []byte(f.files)) || bytes.Contains(raw, []byte(f.sources)) {
		t.Fatal("receipt contains a private input path")
	}
}

func TestIndependentPolicyRejectsMissingAndUnexpectedInventory(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"repositories", "toolchains", "images", "compilers", "files", "contracts"} {
		t.Run(name, func(t *testing.T) {
			m := copyManifest(t, f.manifest)
			switch name {
			case "repositories":
				m.Repositories = m.Repositories[:1]
			case "toolchains":
				m.Toolchains = nil
			case "images":
				m.Images = nil
			case "compilers":
				m.Compilers = nil
			case "files":
				m.Files = m.Files[:len(m.Files)-1]
			case "contracts":
				m.Contracts = nil
			}
			if err := m.ValidateAgainst(f.policy); err == nil {
				t.Fatal("manifest accepted an omitted inventory category")
			}
		})
	}
	policy := f.policy
	policy.Repositories = append(slices.Clone(policy.Repositories), "unreviewed-repo")
	if err := f.manifest.ValidateAgainst(policy); err == nil {
		t.Fatal("manifest accepted a changed independent policy")
	}
}

func TestManifestDecodingRejectsAmbiguousAndUnsupportedDocuments(t *testing.T) {
	f := newFixture(t)
	raw, err := json.Marshal(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate root":  bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"case alias":      bytes.Replace(raw, []byte(`"schema":1`), []byte(`"Schema":1`), 1),
		"future schema":   bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":2`), 1),
		"unknown root":    bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"unknown":true`), 1),
		"duplicate epoch": bytes.Replace(raw, []byte(`"l1ChainId":"70"`), []byte(`"l1ChainId":"70","l1ChainId":"70"`), 1),
		"unknown nested":  bytes.Replace(raw, []byte(`"l1ChainId":"70"`), []byte(`"l1ChainId":"70","hidden":0`), 1),
		"null scalar":     bytes.Replace(raw, []byte(`"empty":false`), []byte(`"empty":null`), 1),
		"trailing value":  append(slices.Clone(raw), []byte(` {}`)...),
		"oversized":       bytes.Repeat([]byte(" "), MaxDocumentBytes+1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeManifest(body); err == nil {
				t.Fatal("ambiguous manifest accepted")
			}
		})
	}
	if _, err := DecodeManifest(raw); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalOrderingIsStableAndDoesNotMutateCallerSlices(t *testing.T) {
	f := newFixture(t)
	before := copyManifest(t, f.manifest)
	first, err := f.manifest.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(f.manifest.Repositories)
	slices.Reverse(f.manifest.Files)
	second, err := f.manifest.Canonical()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("record order changed the release identity")
	}
	if f.manifest.Repositories[0].Name != before.Repositories[1].Name {
		t.Fatal("canonicalization reordered caller state")
	}
	policy := f.policy
	policy.Repositories = slices.Clone(policy.Repositories)
	slices.Reverse(policy.Repositories)
	a, _ := policy.Fingerprint()
	b, _ := f.policy.Fingerprint()
	if a != b {
		t.Fatal("policy order changed its identity")
	}
}

func TestResetAndContractChangesInvalidateTheEpochEvenWhenChainIDIsReused(t *testing.T) {
	f := newFixture(t)
	initial, err := f.manifest.EpochFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"identical-genesis-reset", "l1-genesis", "l2-genesis", "rollup", "deployment", "contract-address", "contract-code"} {
		t.Run(field, func(t *testing.T) {
			m := copyManifest(t, f.manifest)
			switch field {
			case "identical-genesis-reset":
				m.Epoch.ID = strings.Repeat("6", 64)
			case "l1-genesis":
				m.Epoch.L1GenesisHash = "0x" + strings.Repeat("2", 64)
			case "l2-genesis":
				m.Epoch.L2GenesisHash = "0x" + strings.Repeat("2", 64)
			case "rollup":
				m.Epoch.RollupSHA256 = strings.Repeat("2", 64)
				for i := range m.Files {
					if m.Files[i].Kind == "rollup" {
						m.Files[i].SHA256 = m.Epoch.RollupSHA256
					}
				}
			case "deployment":
				m.Epoch.DeploymentsSHA256 = strings.Repeat("2", 64)
				for i := range m.Files {
					if m.Files[i].Kind == "deployments" {
						m.Files[i].SHA256 = m.Epoch.DeploymentsSHA256
					}
				}
			case "contract-address":
				m.Contracts[0].Address = "0x" + strings.Repeat("8", 40)
			case "contract-code":
				m.Contracts[0].RuntimeCodeHash = "0x" + strings.Repeat("2", 64)
			}
			changed, err := m.EpochFingerprint()
			if err != nil || changed == initial || m.Epoch.L2ChainID != f.manifest.Epoch.L2ChainID {
				t.Fatal("changed chain epoch was treated as the old one")
			}
		})
	}
}

func TestSignaturesRejectTamperingUntrustedKeysDuplicatesAndMissingQuorum(t *testing.T) {
	f := newFixture(t)
	signed := f.signatures(t)
	for _, name := range []string{"tampered", "unknown-key", "duplicate", "missing-quorum", "wrong-algorithm", "malformed", "untrusted"} {
		t.Run(name, func(t *testing.T) {
			m := copyManifest(t, f.manifest)
			s := signed
			s.Signatures = slices.Clone(s.Signatures)
			keys := f.keys
			keys.Keys = slices.Clone(keys.Keys)
			switch name {
			case "tampered":
				m.Images[0].Reference = "registry.invalid/fixture/engine@sha256:" + strings.Repeat("3", 64)
			case "unknown-key":
				s.Signatures[0].KeySHA256 = strings.Repeat("3", 64)
			case "duplicate":
				s.Signatures[1] = s.Signatures[0]
			case "missing-quorum":
				s.Signatures = s.Signatures[:1]
			case "wrong-algorithm":
				s.Signatures[0].Algorithm = "unknown"
			case "malformed":
				s.Signatures[0].Value = "broken"
			case "untrusted":
				keys.Keys = keys.Keys[:1]
			}
			if _, err := m.VerifySignatures(f.policy, s, keys); err == nil {
				t.Fatal("invalid signature set satisfied policy")
			}
		})
	}
}

func TestFilesRejectChangedBytesLinksAndSizeMismatch(t *testing.T) {
	for _, name := range []string{"content", "symlink", "ancestor", "size", "missing"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			pin := f.manifest.Files[4]
			file := filepath.Join(f.files, pin.Repository, pin.Path)
			switch name {
			case "content":
				raw, _ := os.ReadFile(file)
				raw[0] ^= 1
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "size":
				if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(file, file+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(file+".target", file); err != nil {
					t.Fatal(err)
				}
			case "ancestor":
				dir := filepath.Join(f.files, "zvm-core")
				if err := os.Rename(dir, dir+"-target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-target", dir); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.manifest.VerifyFiles(f.files); err == nil {
				t.Fatal("invalid file set was verified")
			}
		})
	}
}

func TestSourceVerificationRejectsDirtyWrongAndNonemptyRepositories(t *testing.T) {
	for _, name := range []string{"dirty", "wrong-head", "empty-has-content", "missing", "uninitialized-gitlink"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			dir := filepath.Join(f.sources, "zvm-core")
			switch name {
			case "dirty":
				if err := os.WriteFile(filepath.Join(dir, "untracked.fixture"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-head":
				f.manifest.Repositories[0].Commit = strings.Repeat("3", 40)
			case "empty-has-content":
				if err := os.WriteFile(filepath.Join(f.sources, ".github", "unexpected"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Rename(dir, dir+"-moved"); err != nil {
					t.Fatal(err)
				}
			case "uninitialized-gitlink":
				sha := f.manifest.Repositories[0].Commit
				runGit(t, dir, "update-index", "--add", "--cacheinfo", "160000,"+sha+",dependency")
				runGit(t, dir, "commit", "-m", "Fixture gitlink")
				f.manifest.Repositories[0].Commit = runGit(t, dir, "rev-parse", "HEAD")
				f.manifest.Repositories[0].Gitlinks = []Gitlink{{Path: "dependency", Commit: sha}}
			}
			if _, err := f.manifest.VerifySources(context.Background(), f.sources); err == nil {
				t.Fatal("invalid source snapshot was verified")
			}
		})
	}
}

func TestToolAndImagePinsRejectFloatingOrUnboundInputs(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"image-tag", "image-zero-digest", "compiler-file", "tool-version", "file-traversal", "zero-hash"} {
		t.Run(name, func(t *testing.T) {
			m := copyManifest(t, f.manifest)
			switch name {
			case "image-tag":
				m.Images[0].Reference = "registry.invalid/fixture/engine:latest"
			case "image-zero-digest":
				m.Images[0].Reference = "registry.invalid/fixture/engine@sha256:" + strings.Repeat("0", 64)
			case "compiler-file":
				m.Compilers[0].FileID = "missing"
			case "tool-version":
				m.Toolchains[0].Version = "https://credential@fixture.invalid"
			case "file-traversal":
				m.Files[0].Path = "../outside"
			case "zero-hash":
				m.Epoch.L1GenesisHash = "0x" + strings.Repeat("0", 64)
			}
			if err := m.ValidateAgainst(f.policy); err == nil {
				t.Fatal("unbound or invalid release input accepted")
			}
		})
	}
}

func TestEpochSemanticChecksRejectResignedInconsistentFiles(t *testing.T) {
	for _, name := range []string{"rollup-chain", "rollup-unknown", "genesis-header", "genesis-rules", "deployment", "runtime"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			var kind string
			switch name {
			case "rollup-chain", "rollup-unknown":
				kind = "rollup"
			case "genesis-header", "genesis-rules":
				kind = "l2-genesis"
			case "deployment":
				kind = "deployments"
			case "runtime":
				kind = "runtime-code"
			}
			for i, pin := range f.manifest.Files {
				if pin.Kind != kind {
					continue
				}
				file := filepath.Join(f.files, pin.Repository, pin.Path)
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "rollup-chain":
					raw = bytes.Replace(raw, []byte(`"l2ChainId": 7340470`), []byte(`"l2ChainId": 7340471`), 1)
				case "rollup-unknown":
					raw = bytes.Replace(raw, []byte(`"l1ChainId": 70`), []byte(`"l1ChainId": 70, "unknown": true`), 1)
				case "genesis-header":
					var g map[string]any
					if json.Unmarshal(raw, &g) != nil {
						t.Fatal("invalid fixture")
					}
					g["timestamp"] = "0x1"
					raw, _ = json.Marshal(g)
				case "genesis-rules":
					var g map[string]any
					if json.Unmarshal(raw, &g) != nil {
						t.Fatal("invalid fixture")
					}
					g["config"].(map[string]any)["chainId"] = 1
					raw, _ = json.Marshal(g)
				case "deployment":
					raw = []byte(`{"schema":1,"contracts":[]}`)
				case "runtime":
					raw = []byte("0x60016001")
				}
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				f.manifest.Files[i].Bytes = int64(len(raw))
				f.manifest.Files[i].SHA256 = digest(raw)
				if kind == "rollup" {
					f.manifest.Epoch.RollupSHA256 = digest(raw)
				}
				if kind == "deployments" {
					f.manifest.Epoch.DeploymentsSHA256 = digest(raw)
				}
			}
			if err := f.manifest.VerifyEpochFiles(f.files); err == nil {
				t.Fatal("internally inconsistent epoch was verified")
			}
		})
	}
}

func TestReleaseCLIEmitsTheSigningMessageAndVerifiesTheActualInputSet(t *testing.T) {
	f := newFixture(t)
	inputs := t.TempDir()
	for name, value := range map[string]any{"manifest": f.manifest, "policy": f.policy, "signatures": f.signatures(t), "keys": f.keys} {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(inputs, name+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	tool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		tool += ".exe"
	}
	run := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, tool, append([]string{"run", "-mod=readonly", "../cmd/zvm"}, args...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		raw, err := cmd.Output()
		if err != nil {
			t.Fatalf("release CLI failed: %v: %s", err, stderr.Bytes())
		}
		return raw
	}
	common := []string{"-manifest", filepath.Join(inputs, "manifest.json"), "-policy", filepath.Join(inputs, "policy.json")}
	message := run(append([]string{"release-message"}, common...)...)
	want, err := f.manifest.SigningMessage()
	if err != nil || !bytes.Equal(message, want) {
		t.Fatal("CLI changed the signing message")
	}
	args := append([]string{"release-verify"}, common...)
	args = append(args, "-signatures", filepath.Join(inputs, "signatures.json"), "-trusted-keys", filepath.Join(inputs, "keys.json"), "-files-root", f.files, "-sources-root", f.sources)
	var receipt Receipt
	if err := json.Unmarshal(run(args...), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.RuntimeObserved || receipt.TrustedSignatures != 2 || receipt.VerifiedFiles != 7 || receipt.VerifiedRepositories != 2 {
		t.Fatalf("CLI scope is wrong: %+v", receipt)
	}
}

func TestUntrustedSignaturesFailBeforeAnyFileOrSourceAccess(t *testing.T) {
	f := newFixture(t)
	s := f.signatures(t)
	s.Signatures[0].KeySHA256 = strings.Repeat("4", 64)
	if _, err := f.manifest.Verify(context.Background(), f.policy, s, f.keys, "unavailable-fixture-files", "unavailable-fixture-sources"); err == nil || !strings.Contains(err.Error(), "signature key") {
		t.Fatalf("untrusted document reached the file verifier: %v", err)
	}
}

func TestInitializedGitlinksAreVerifiedAndDirtyDependenciesAreRefused(t *testing.T) {
	f := newFixture(t)
	dependency := filepath.Join(t.TempDir(), "dependency-source")
	if err := os.MkdirAll(dependency, 0700); err != nil {
		t.Fatal(err)
	}
	runGit(t, dependency, "init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(dependency, "content"), []byte("fixture dependency\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dependency, "add", "content")
	runGit(t, dependency, "commit", "-m", "Fixture dependency")
	commit := runGit(t, dependency, "rev-parse", "HEAD")
	dir := filepath.Join(f.sources, "zvm-core")
	// file:// uses transport rather than Git's hard-linked local clone path.
	runGit(t, dir, "-c", "protocol.file.allow=always", "submodule", "add", "file://"+filepath.ToSlash(dependency), "dependency")
	runGit(t, dir, "commit", "-am", "Bind fixture dependency")
	f.manifest.Repositories[0].Commit = runGit(t, dir, "rev-parse", "HEAD")
	f.manifest.Repositories[0].Gitlinks = []Gitlink{{Path: "dependency", Commit: commit}}
	f.policy.Gitlinks = []string{"zvm-core:dependency"}
	var err error
	f.manifest.PolicySHA256, err = f.policy.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manifest.VerifySources(context.Background(), f.sources); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dependency", "content"), []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manifest.VerifySources(context.Background(), f.sources); err == nil {
		t.Fatal("dirty initialized dependency was verified")
	}
}

func TestIndependentFileRolesCannotBeSubstitutedWhileKeepingTheirIDs(t *testing.T) {
	f := newFixture(t)
	m := copyManifest(t, f.manifest)
	m.Files[4].Path = "different.fixture"
	if err := m.ValidateAgainst(f.policy); err == nil {
		t.Fatal("file ID hid a substituted lock path")
	}
}

func TestCommandOutputCannotBypassItsWriteLimitThroughIOCopy(t *testing.T) {
	var out commandOutput
	_, err := io.Copy(&out, bytes.NewReader(bytes.Repeat([]byte{'x'}, (2<<20)+1)))
	if err == nil || !out.overflow || out.data.Len() > 2<<20 {
		t.Fatal("command output bypassed its bounded writer")
	}
}
