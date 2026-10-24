package release

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/l2"
)

// These wrappers are synthetic saved-document fixtures, not compiler runs or
// authoritative upstream Git documents. The embedded VM programs are compared
// independently with the supported genesis code. Real-source execution belongs
// to separately pinned compiler and constructor qualification.
const beaconAssemblyFixture = `caller
push20 0xfffffffffffffffffffffffffffffffffffffffe
eq
push1 0x4d
jumpi
push1 0x20
calldatasize
eq
push1 0x24
jumpi
push0
push0
revert
jumpdest
push0
calldataload
dup1
iszero
push1 0x49
jumpi
push3 0x001fff
dup2
mod
swap1
dup2
sload
eq
push1 0x3c
jumpi
push0
push0
revert
jumpdest
push3 0x001fff
add
sload
push0
mstore
push1 0x20
push0
return
jumpdest
push0
push0
revert
jumpdest
push3 0x001fff
timestamp
mod
timestamp
dup2
sstore
push0
calldataload
swap1
push3 0x001fff
add
sstore
stop
`

const historyAssemblyFixture = `caller
push20 0xfffffffffffffffffffffffffffffffffffffffe
eq
push1 0x46
jumpi
push1 0x20
calldatasize
sub
push1 0x42
jumpi
push0
calldataload
push1 0x01
number
sub
dup2
gt
push1 0x42
jumpi
push2 0x1fff
dup2
number
sub
gt
push1 0x42
jumpi
push2 0x1fff
swap1
mod
sload
push0
mstore
push1 0x20
push0
return
jumpdest
push0
push0
revert
jumpdest
push0
calldataload
push2 0x1fff
push1 0x01
number
sub
mod
sstore
stop
`

type typedBuildFixture struct {
	*contractBuildFixture
	typed ContractBuildPolicyV2
}

func (f *typedBuildFixture) save(t *testing.T) {
	t.Helper()
	f.contractBuildFixture.save(t)
	f.pin(t, ContractBuildPolicyID, "config", "contract-build-policy.json", buildRaw(t, f.typed))
	f.manifest.PolicySHA256, _ = f.policy.Fingerprint()
}

func (f *typedBuildFixture) verify(t *testing.T) (Receipt, error) {
	t.Helper()
	return f.manifest.Verify(context.Background(), f.policy, f.signatures(t), f.keys, f.files, f.sources)
}

func newTypedBuildFixture(t *testing.T) *typedBuildFixture {
	t.Helper()
	f := &typedBuildFixture{contractBuildFixture: newContractBuildFixture(t)}
	f.typed = ContractBuildPolicyV2{Schema: 2, EpochID: f.manifest.Epoch.ID, RollupSHA256: f.manifest.Epoch.RollupSHA256, L2GenesisHash: f.manifest.Epoch.L2GenesisHash}
	build := f.buildPolicy.Builds[0]
	build.Contracts = nil
	contexts := map[string]json.RawMessage{}
	artifacts := f.bundle["output"].(map[string]any)["contracts"].(map[string]any)["Fixture.sol"].(map[string]any)
	for _, target := range f.buildPolicy.Builds[0].Contracts {
		if target.Contract == "beaconroots_4788" || target.Contract == "historystorage_2935" || target.Contract == "create2deployer_arachnid" || target.Contract == "safesingletonfactory" {
			continue
		}
		artifact := artifacts[target.Name].(map[string]any)
		deployed := artifact["evm"].(map[string]any)["deployedBytecode"].(map[string]any)
		runtime, _ := hex.DecodeString(deployed["object"].(string))
		context := map[string]any{"kind": "exact"}
		if target.Contract == "permit2" || target.Contract == "entrypoint_v07" {
			oldName := target.Name
			if target.Contract == "permit2" {
				target.Name = "Permit2"
				clear(runtime[6945:6977])
				clear(runtime[6983:7015])
				deployed["immutableReferences"] = map[string]any{"1032": []any{map[string]any{"start": 6945, "length": 32}}, "1030": []any{map[string]any{"start": 6983, "length": 32}}}
				context = map[string]any{"kind": "permit2-domain-cache", "chainId": "10", "chainIdImmutable": "1032", "domainImmutable": "1030"}
			} else {
				target.Name = "EntryPoint"
				clear(runtime[3362:3394])
				clear(runtime[12875:12907])
				deployed["immutableReferences"] = map[string]any{"140": []any{map[string]any{"start": 3362, "length": 32}, map[string]any{"start": 12875, "length": 32}}}
				context = map[string]any{"kind": "entrypoint-sender-creator", "immutable": "140", "childContract": "sendercreator_v07", "childNonce": "1"}
			}
			deployed["object"] = hex.EncodeToString(runtime)
			delete(artifacts, oldName)
			artifacts[target.Name] = artifact
			var metadata map[string]any
			if err := json.Unmarshal([]byte(artifact["metadata"].(string)), &metadata); err != nil {
				t.Fatal(err)
			}
			metadata["settings"].(map[string]any)["compilationTarget"] = map[string]any{"Fixture.sol": target.Name}
			artifact["metadata"] = string(buildRaw(t, metadata))
			target.MetadataSHA256 = digest([]byte(artifact["metadata"].(string)))
		}
		context["runtimeTemplateSha256"] = digest(runtime)
		contexts[target.Contract] = buildRaw(t, context)
		build.Contracts = append(build.Contracts, target)
	}
	f.typed.Builds = append(f.typed.Builds, TypedContractBuild{ID: build.ID, Kind: "solidity", Definition: buildRaw(t, SolidityBuildV2{Build: build, RuntimeContexts: contexts})})
	source := []byte("// Synthetic Yul source fixture; not compiled.\nobject \"Proxy\" { code { stop() } }\n")
	f.pin(t, "yul-source", "artifact", "contracts/Proxy.yul", source)
	yulPath := filepath.Join(f.sources, "zvm-core", "contracts/Proxy.yul")
	if err := os.WriteFile(yulPath, source, 0600); err != nil {
		t.Fatal(err)
	}
	f.pin(t, "yul-compiler", "artifact", "fixture-solc-yul.wasm", []byte("Synthetic pinned compiler fixture; never executed."))
	compiler := Artifact{ID: "fixture-solc-yul", FileID: "yul-compiler", Version: "0.5.8+commit.23d335f2", Platform: "emscripten/wasm32", SHA256: digest([]byte("Synthetic pinned compiler fixture; never executed."))}
	f.manifest.Compilers = append(f.manifest.Compilers, compiler)
	f.policy.Compilers = append(f.policy.Compilers, compiler.ID)
	runtime, err := l2.PredeployCode("SafeSingletonFactory")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _ := hex.DecodeString("604580600e600039806000f350fe")
	creation := append(prefix, runtime...)
	yulInput := map[string]any{"language": "Yul", "sources": map[string]any{"Proxy.yul": map[string]any{"content": string(source)}}, "settings": map[string]any{"optimizer": map[string]any{"enabled": true}}}
	yulBundle := map[string]any{"schema": 1, "compilerVersion": compiler.Version + ".Emscripten.clang", "input": yulInput, "output": map[string]any{"contracts": map[string]any{"Proxy.yul": map[string]any{"Proxy": map[string]any{"evm": map[string]any{"bytecode": map[string]any{"object": hex.EncodeToString(creation), "linkReferences": map[string]any{}}}}}}}}
	f.pin(t, "yul-bundle", "artifact", "fixture-yul-build.json", buildRaw(t, yulBundle))
	yul := YulBuildV2{Compiler: compiler.ID, BundleFile: "yul-bundle", InputSHA256: digest(buildRaw(t, yulInput)), Sources: []ContractBuildSource{{Unit: "Proxy.yul", File: "yul-source"}}}
	for _, id := range []string{"create2deployer_arachnid", "safesingletonfactory"} {
		yul.Contracts = append(yul.Contracts, YulBuildTarget{Contract: id, Unit: "Proxy.yul", Name: "Proxy", CreationSHA256: digest(creation), RuntimeSHA256: digest(runtime)})
	}
	f.typed.Builds = append(f.typed.Builds, TypedContractBuild{ID: "factory-build", Kind: "solc-yul-fixed-return-v1", Definition: buildRaw(t, yul)})
	for _, item := range []struct {
		eip                int
		name, id, assembly string
	}{{4788, "BeaconRoots_4788", "beaconroots_4788", beaconAssemblyFixture}, {2935, "HistoryStorage_2935", "historystorage_2935", historyAssemblyFixture}} {
		runtime, err := l2.PredeployCode(item.name)
		if err != nil {
			t.Fatal(err)
		}
		creation := append([]byte{0x60, byte(len(runtime)), 0x80, 0x60, 9, 0x5f, 0x39, 0x5f, 0xf3}, runtime...)
		document := []byte(fmt.Sprintf("---\neip: %d\nstatus: Final\n---\nSynthetic parser fixture.\n```\n%s```\n```json\n{\"input\":\"0x%x\"}\n```\n", item.eip, item.assembly, creation))
		path := fmt.Sprintf("EIPS/eip-%d.md", item.eip)
		id := fmt.Sprintf("eip-%d-source", item.eip)
		f.pin(t, id, "artifact", path, document)
		if err := os.MkdirAll(filepath.Dir(filepath.Join(f.sources, "zvm-core", path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.sources, "zvm-core", path), document, 0600); err != nil {
			t.Fatal(err)
		}
		definition := EIPAssemblyBuildV2{Source: ContractBuildSource{Unit: path, File: id}, Contracts: []EIPAssemblyTarget{{Contract: item.id, EIP: item.eip, AssemblySHA256: digest([]byte(item.assembly)), CreationSHA256: digest(creation), RuntimeSHA256: digest(runtime)}}}
		f.typed.Builds = append(f.typed.Builds, TypedContractBuild{ID: fmt.Sprintf("eip-%d-build", item.eip), Kind: "eip-evm-assembly-v1", Definition: buildRaw(t, definition)})
	}
	runGit(t, filepath.Join(f.sources, "zvm-core"), "add", "contracts/Proxy.yul", "EIPS")
	runGit(t, filepath.Join(f.sources, "zvm-core"), "commit", "-m", "Synthetic typed source wrappers")
	f.manifest.Repositories[0].Commit = runGit(t, filepath.Join(f.sources, "zvm-core"), "rev-parse", "HEAD")
	f.save(t)
	return f
}

func TestTypedBuildsPreserveCompleteSignedCoverageAndDistinctMaterialKinds(t *testing.T) {
	f := newTypedBuildFixture(t)
	r, err := f.verify(t)
	if err != nil {
		t.Fatal(err)
	}
	if r.VerifiedContractBuilds != len(l2.Predeploys())+1 || r.CompilerExecuted || r.RuntimeObserved {
		t.Fatalf("typed source consistency was mistaken for execution: %+v", r)
	}
	raw := buildRaw(t, r)
	if bytes.Contains(raw, []byte(f.files)) || bytes.Contains(raw, []byte(f.sources)) {
		t.Fatal("typed receipt exposes a private input path")
	}
}

func TestTypedBuildsRefuseOmissionsUnknownKindsAndCrossKindFields(t *testing.T) {
	for name, change := range map[string]func(*typedBuildFixture){
		"only two EIP targets":         func(f *typedBuildFixture) { f.typed.Builds = f.typed.Builds[2:] },
		"missing factory":              func(f *typedBuildFixture) { f.typed.Builds = append(f.typed.Builds[:1], f.typed.Builds[2:]...) },
		"duplicate build":              func(f *typedBuildFixture) { f.typed.Builds = append(f.typed.Builds, f.typed.Builds[1]) },
		"unknown kind":                 func(f *typedBuildFixture) { f.typed.Builds[0].Kind = "assembly-or-solidity" },
		"wrong epoch":                  func(f *typedBuildFixture) { f.typed.EpochID += "-other" },
		"new fields on schema one":     func(f *typedBuildFixture) { f.typed.Schema = 1 },
		"Yul masquerading as Solidity": func(f *typedBuildFixture) { f.typed.Builds[1].Kind = "solidity" },
		"duplicate definition key": func(f *typedBuildFixture) {
			f.typed.Builds[1].Definition = []byte(`{"compiler":"first","compiler":"second"}`)
		},
		"case alias definition": func(f *typedBuildFixture) { f.typed.Builds[2].Definition = []byte(`{"Source":{},"contracts":[]}`) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newTypedBuildFixture(t)
			change(f)
			f.save(t)
			if _, err := f.verify(t); err == nil {
				t.Fatal("invalid typed scope accepted")
			}
		})
	}
}

func TestHistoricalContextsRequireExactDeclaredDerivationsAndImmutableRanges(t *testing.T) {
	f := newTypedBuildFixture(t)
	var definition SolidityBuildV2
	if err := json.Unmarshal(f.typed.Builds[0].Definition, &definition); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"permit2", "entrypoint_v07"} {
		var target ContractBuildTarget
		for _, item := range definition.Build.Contracts {
			if item.Contract == id {
				target = item
			}
		}
		contract, _ := f.manifest.releaseContract(id)
		artifact := f.bundle["output"].(map[string]any)["contracts"].(map[string]any)[target.Unit].(map[string]any)[target.Name].(map[string]any)
		deployed := artifact["evm"].(map[string]any)["deployedBytecode"].(map[string]any)
		runtime, _ := hex.DecodeString(deployed["object"].(string))
		raw := definition.RuntimeContexts[id]
		var bytecode buildBytecode
		if err := json.Unmarshal(buildRaw(t, deployed), &bytecode); err != nil {
			t.Fatal(err)
		}
		actual, err := f.manifest.resolveBuildRuntime(raw, target, contract, bytecode, runtime)
		if err != nil {
			t.Fatal(err)
		}
		name := "Permit2"
		if id == "entrypoint_v07" {
			name = "EntryPoint_v07"
		}
		expected, _ := l2.PredeployCode(name)
		if !bytes.Equal(actual, expected) {
			t.Fatal("historical derivation disagrees with the full supported runtime")
		}
		if bytes.Equal(runtime, actual) {
			t.Fatal("immutable template was reported as a complete deployed runtime")
		}
		for caseName, change := range map[string]func(map[string]any, *buildBytecode, []byte){
			"unknown context": func(c map[string]any, b *buildBytecode, r []byte) { c["kind"] = "observed-chain-words" },
			"changed template pin": func(c map[string]any, b *buildBytecode, r []byte) {
				c["runtimeTemplateSha256"] = strings.Repeat("1", 64)
			},
			"null immutable map":    func(c map[string]any, b *buildBytecode, r []byte) { b.ImmutableReferences = []byte("null") },
			"missing immutable map": func(c map[string]any, b *buildBytecode, r []byte) { b.ImmutableReferences = []byte("{}") },
			"case-aliased range": func(c map[string]any, b *buildBytecode, r []byte) {
				b.ImmutableReferences = []byte(`{"140":[{"Start":3362,"length":32}]}`)
			},
			"overlapping ranges": func(c map[string]any, b *buildBytecode, r []byte) {
				b.ImmutableReferences = []byte(`{"140":[{"start":3362,"length":32},{"start":3363,"length":32}]}`)
			},
			"prefilled template": func(c map[string]any, b *buildBytecode, r []byte) {
				at := 3362
				if id == "permit2" {
					at = 6945
				}
				r[at] = 1
				c["runtimeTemplateSha256"] = digest(r)
			},
		} {
			t.Run(id+"/"+caseName, func(t *testing.T) {
				var context map[string]any
				_ = json.Unmarshal(raw, &context)
				b := bytecode
				r := bytes.Clone(runtime)
				change(context, &b, r)
				if _, err := f.manifest.resolveBuildRuntime(buildRaw(t, context), target, contract, b, r); err == nil {
					t.Fatal("invalid immutable context accepted")
				}
			})
		}
	}
}

func TestFixedReturnYulRefusesSelfConsistentInventedOrAmbiguousMaterial(t *testing.T) {
	for name, change := range map[string]func(map[string]any, *YulBuildV2){
		"invented empty metadata": func(b map[string]any, d *YulBuildV2) { yulFixtureArtifact(b)["metadata"] = "" },
		"invented layout": func(b map[string]any, d *YulBuildV2) {
			yulFixtureArtifact(b)["storageLayout"] = map[string]any{"storage": []any{}, "types": nil}
		},
		"invented ABI": func(b map[string]any, d *YulBuildV2) { yulFixtureArtifact(b)["abi"] = []any{} },
		"invented deployed output": func(b map[string]any, d *YulBuildV2) {
			yulFixtureArtifact(b)["evm"].(map[string]any)["deployedBytecode"] = map[string]any{}
		},
		"compiler error": func(b map[string]any, d *YulBuildV2) {
			b["output"].(map[string]any)["errors"] = []any{map[string]any{"severity": "error"}}
		},
		"source URL": func(b map[string]any, d *YulBuildV2) {
			b["input"].(map[string]any)["sources"] = map[string]any{"Proxy.yul": map[string]any{"urls": []any{"https://source.fixture.invalid/Proxy.yul"}}}
		},
		"extra compiler target": func(b map[string]any, d *YulBuildV2) {
			b["output"].(map[string]any)["contracts"].(map[string]any)["Proxy.yul"].(map[string]any)["Other"] = yulFixtureArtifact(b)
		},
		"library reference": func(b map[string]any, d *YulBuildV2) {
			yulFixtureArtifact(b)["evm"].(map[string]any)["bytecode"].(map[string]any)["linkReferences"] = map[string]any{"Lib.yul": map[string]any{}}
		},
		"case alias bytecode": func(b map[string]any, d *YulBuildV2) {
			code := yulFixtureArtifact(b)["evm"].(map[string]any)["bytecode"].(map[string]any)
			code["Object"] = code["object"]
			delete(code, "object")
		},
		"self-consistent changed copy prefix": func(b map[string]any, d *YulBuildV2) {
			code := yulFixtureArtifact(b)["evm"].(map[string]any)["bytecode"].(map[string]any)
			old := code["object"].(string)
			code["object"] = "61" + old[2:]
			raw, _ := hex.DecodeString(code["object"].(string))
			for i := range d.Contracts {
				d.Contracts[i].CreationSHA256 = digest(raw)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newTypedBuildFixture(t)
			var def YulBuildV2
			_ = json.Unmarshal(f.typed.Builds[1].Definition, &def)
			raw, err := os.ReadFile(filepath.Join(f.files, "zvm-core", "fixture-yul-build.json"))
			if err != nil {
				t.Fatal(err)
			}
			var bundle map[string]any
			if err := json.Unmarshal(raw, &bundle); err != nil {
				t.Fatal(err)
			}
			change(bundle, &def)
			def.InputSHA256 = digest(buildRaw(t, bundle["input"]))
			f.pin(t, "yul-bundle", "artifact", "fixture-yul-build.json", buildRaw(t, bundle))
			f.typed.Builds[1].Definition = buildRaw(t, def)
			f.save(t)
			if _, err := f.verify(t); err == nil {
				t.Fatal("invalid self-consistent Yul material accepted")
			}
		})
	}
}

func yulFixtureArtifact(bundle map[string]any) map[string]any {
	return bundle["output"].(map[string]any)["contracts"].(map[string]any)["Proxy.yul"].(map[string]any)["Proxy"].(map[string]any)
}

func TestHistoricalContextCannotBeSilentlyReboundToCurrentChainOrAnotherChild(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"wrong cache chain":    func(c map[string]any) { c["chainId"] = "7340470" },
		"noncanonical chain":   func(c map[string]any) { c["chainId"] = "010" },
		"overwide chain":       func(c map[string]any) { c["chainId"] = strings.Repeat("9", 79) },
		"observed domain word": func(c map[string]any) { c["domainWord"] = strings.Repeat("1", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newTypedBuildFixture(t)
			var def SolidityBuildV2
			_ = json.Unmarshal(f.typed.Builds[0].Definition, &def)
			var context map[string]any
			_ = json.Unmarshal(def.RuntimeContexts["permit2"], &context)
			mutate(context)
			def.RuntimeContexts["permit2"] = buildRaw(t, context)
			f.typed.Builds[0].Definition = buildRaw(t, def)
			f.save(t)
			if _, err := f.verify(t); err == nil {
				t.Fatal("incorrect historical context accepted")
			}
		})
	}
	f := newTypedBuildFixture(t)
	var def SolidityBuildV2
	_ = json.Unmarshal(f.typed.Builds[0].Definition, &def)
	var context map[string]any
	_ = json.Unmarshal(def.RuntimeContexts["entrypoint_v07"], &context)
	context["childContract"] = "permit2"
	def.RuntimeContexts["entrypoint_v07"] = buildRaw(t, context)
	f.typed.Builds[0].Definition = buildRaw(t, def)
	f.save(t)
	if _, err := f.verify(t); err == nil {
		t.Fatal("EntryPoint rebound to another release contract")
	}
}

func TestLiteralAssemblerAndEIPDocumentRefuseAmbiguityAndUnsupportedPrograms(t *testing.T) {
	for _, source := range []string{"", "label:", "push1 0x1", "push1 0xFF", "push0 0x00", "PUSH1 0x00", "push33 0x00", "stop extra", strings.Repeat("\n", 256)} {
		if _, _, err := assembleBuildLiteral(source); err == nil {
			t.Fatalf("invalid literal program accepted: %q", source)
		}
	}
	f := newTypedBuildFixture(t)
	path := filepath.Join(f.files, "zvm-core", "EIPS/eip-4788.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string][]byte{
		"draft":               bytes.Replace(raw, []byte("status: Final"), []byte("status: Draft"), 1),
		"duplicate identity":  append(bytes.Clone(raw), []byte("eip: 4788\n")...),
		"duplicate assembly":  append(bytes.Clone(raw), []byte("```\ncaller\nstop\n```\n")...),
		"changed copy prefix": bytes.Replace(raw, []byte(`"input":"0x606180`), []byte(`"input":"0x606280`), 1),
		"unsupported macro":   bytes.Replace(raw, []byte("caller\n"), []byte("caller\nmacro()\n"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(changed, raw) {
				t.Fatal("negative fixture did not change its input")
			}
			if _, _, _, err := buildEIPMaterial(changed, 4788); err == nil {
				t.Fatal("ambiguous EIP document accepted")
			}
		})
	}
}
