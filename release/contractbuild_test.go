package release

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/l2"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/ethereum/go-ethereum/crypto"
)

// These are intentionally synthetic compiler documents. This suite exercises
// saved-input validation and must never be counted as compiler execution.
type contractBuildFixture struct {
	*fixture
	buildPolicy ContractBuildPolicy
	bundle      map[string]any
}

func (f *contractBuildFixture) pin(t *testing.T, id, kind, path string, raw []byte) {
	t.Helper()
	pin := File{ID: id, Kind: kind, Repository: "zvm-core", Path: path, Bytes: int64(len(raw)), SHA256: digest(raw)}
	found := false
	for i := range f.manifest.Files {
		if f.manifest.Files[i].ID == id {
			f.manifest.Files[i] = pin
			found = true
		}
	}
	if !found {
		f.manifest.Files = append(f.manifest.Files, pin)
		f.policy.Files = append(f.policy.Files, FileRequirement{ID: id, Kind: kind, Repository: pin.Repository, Path: pin.Path})
	}
	name := filepath.Join(f.files, pin.Repository, pin.Path)
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func buildRaw(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *contractBuildFixture) save(t *testing.T) {
	t.Helper()
	f.buildPolicy.Builds[0].InputSHA256 = digest(buildRaw(t, f.bundle["input"]))
	f.pin(t, "fixture-build-bundle", "artifact", "fixture-build.json", buildRaw(t, f.bundle))
	f.pin(t, ContractBuildPolicyID, "config", "contract-build-policy.json", buildRaw(t, f.buildPolicy))
	deployment := buildRaw(t, DeploymentBindings{Schema: 1, Contracts: f.manifest.Contracts})
	f.manifest.Epoch.DeploymentsSHA256 = digest(deployment)
	f.pin(t, "deployments", "deployments", "deployments.fixture", deployment)
	f.manifest.PolicySHA256, _ = f.policy.Fingerprint()
}

func newContractBuildFixture(t *testing.T) *contractBuildFixture {
	t.Helper()
	f := &contractBuildFixture{fixture: newFixture(t)}
	source := []byte("// Synthetic document fixture, not compiled.\ncontract Fixture {}\n")
	f.pin(t, "fixture-build-source", "artifact", "contracts/Fixture.sol", source)
	dir := filepath.Join(f.sources, "zvm-core")
	if err := os.MkdirAll(filepath.Join(dir, "contracts"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contracts/Fixture.sol"), source, 0600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "contracts/Fixture.sol")
	runGit(t, dir, "commit", "-m", "Synthetic compiler input")
	f.manifest.Repositories[0].Commit = runGit(t, dir, "rev-parse", "HEAD")
	f.manifest.Compilers[0].Version = "0.8.30+commit.73712a01"
	f.manifest.Compilers[0].Platform = "emscripten/wasm32"
	build := ContractBuild{ID: "fixture-build", Compiler: "fixture-solc", BundleFile: "fixture-build-bundle", Sources: []ContractBuildSource{{Unit: "Fixture.sol", File: "fixture-build-source"}}}
	names := make([]string, 0, len(l2.Predeploys()))
	for name := range l2.Predeploys() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		id := strings.ToLower(name)
		code, err := l2.PredeployCode(name)
		if err != nil {
			t.Fatal(err)
		}
		f.pin(t, "runtime-"+id, "runtime-code", "predeploys/"+name+".hex", []byte(hex.EncodeToString(code)))
		address := l2.Predeploys()[name]
		contract := Contract{ID: id, RuntimeFile: "runtime-" + id, Address: strings.ToLower(address.Hex()), RuntimeCodeHash: crypto.Keccak256Hash(code).Hex()}
		f.manifest.Contracts = append(f.manifest.Contracts, contract)
		f.policy.Contracts = append(f.policy.Contracts, id)
	}
	artifacts := map[string]any{}
	for i, contract := range f.manifest.Contracts {
		name := "Fixture" + strings.Repeat("x", i)
		metadata := string(buildRaw(t, map[string]any{"compiler": map[string]any{"version": f.manifest.Compilers[0].Version}, "settings": map[string]any{"compilationTarget": map[string]any{"Fixture.sol": name}}, "sources": map[string]any{"Fixture.sol": map[string]any{"keccak256": crypto.Keccak256Hash(source).Hex()}}}))
		layout := map[string]any{"storage": []any{}, "types": nil}
		creation := "6000"
		var runtime string
		for _, pin := range f.manifest.Files {
			if pin.ID == contract.RuntimeFile {
				raw, err := os.ReadFile(filepath.Join(f.files, pin.Repository, pin.Path))
				if err != nil {
					t.Fatal(err)
				}
				runtime = strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x")
			}
		}
		artifacts[name] = map[string]any{"metadata": metadata, "storageLayout": layout, "evm": map[string]any{"bytecode": map[string]any{"object": creation, "linkReferences": map[string]any{}}, "deployedBytecode": map[string]any{"object": runtime, "linkReferences": map[string]any{}, "immutableReferences": map[string]any{}}}}
		build.Contracts = append(build.Contracts, ContractBuildTarget{Contract: contract.ID, Unit: "Fixture.sol", Name: name, CreationSHA256: digest([]byte{0x60, 0}), StorageLayoutSHA256: digest(buildRaw(t, layout)), MetadataSHA256: digest([]byte(metadata))})
	}
	f.bundle = map[string]any{"schema": 1, "compilerVersion": "0.8.30+commit.73712a01.Emscripten.clang", "input": map[string]any{"language": "Solidity", "sources": map[string]any{"Fixture.sol": map[string]any{"content": string(source)}}, "settings": map[string]any{"optimizer": map[string]any{"enabled": true, "runs": 200}}}, "output": map[string]any{"contracts": map[string]any{"Fixture.sol": artifacts}, "sources": map[string]any{"Fixture.sol": map[string]any{"id": 0}}}}
	f.buildPolicy = ContractBuildPolicy{Schema: 1, EpochID: f.manifest.Epoch.ID, RollupSHA256: f.manifest.Epoch.RollupSHA256, L2GenesisHash: f.manifest.Epoch.L2GenesisHash, Builds: []ContractBuild{build}}
	f.save(t)
	return f
}

func (f *contractBuildFixture) artifact() map[string]any {
	return f.bundle["output"].(map[string]any)["contracts"].(map[string]any)["Fixture.sol"].(map[string]any)[f.buildPolicy.Builds[0].Contracts[0].Name].(map[string]any)
}

func TestSavedContractBuildsBindReleaseGenesisSourceCreationLayoutAndMetadata(t *testing.T) {
	f := newContractBuildFixture(t)
	r, err := f.manifest.Verify(context.Background(), f.policy, f.signatures(t), f.keys, f.files, f.sources)
	if err != nil {
		t.Fatal(err)
	}
	if r.VerifiedContractBuilds != len(l2.Predeploys())+1 || r.CompilerExecuted || r.RuntimeObserved {
		t.Fatalf("saved compiler documents were mistaken for execution: %+v", r)
	}
	raw := buildRaw(t, r)
	if bytes.Contains(raw, []byte(f.files)) || bytes.Contains(raw, []byte(f.sources)) {
		t.Fatal("receipt contains an input path")
	}
}

func TestSavedContractBuildRejectsSelfConsistentPinsForInvalidBuildMaterial(t *testing.T) {
	cases := map[string]func(*contractBuildFixture){
		"compiler version": func(f *contractBuildFixture) { f.bundle["compilerVersion"] = "0.8.29+commit.invalid.Emscripten.clang" },
		"successful process with compiler error": func(f *contractBuildFixture) {
			f.bundle["output"].(map[string]any)["errors"] = []any{map[string]any{"severity": "error"}}
		},
		"unknown diagnostic": func(f *contractBuildFixture) {
			f.bundle["output"].(map[string]any)["errors"] = []any{map[string]any{"severity": "fatal"}}
		},
		"source URL": func(f *contractBuildFixture) {
			f.bundle["input"].(map[string]any)["sources"].(map[string]any)["Fixture.sol"] = map[string]any{"urls": []any{"https://source.fixture.invalid/Fixture.sol"}}
		},
		"source content": func(f *contractBuildFixture) {
			f.bundle["input"].(map[string]any)["sources"].(map[string]any)["Fixture.sol"] = map[string]any{"content": "contract Changed {}"}
		},
		"missing source": func(f *contractBuildFixture) { f.bundle["input"].(map[string]any)["sources"] = map[string]any{} },
		"unexpected source": func(f *contractBuildFixture) {
			f.bundle["input"].(map[string]any)["sources"].(map[string]any)["Extra.sol"] = map[string]any{"content": "contract Extra {}"}
		},
		"missing source identity": func(f *contractBuildFixture) {
			f.bundle["output"].(map[string]any)["sources"].(map[string]any)["Fixture.sol"] = map[string]any{}
		},
		"changed source identity": func(f *contractBuildFixture) {
			f.bundle["output"].(map[string]any)["sources"] = map[string]any{"Other.sol": map[string]any{"id": 0}}
		},
		"changed creation": func(f *contractBuildFixture) {
			f.artifact()["evm"].(map[string]any)["bytecode"].(map[string]any)["object"] = "6001"
		},
		"changed runtime including metadata": func(f *contractBuildFixture) {
			f.artifact()["evm"].(map[string]any)["deployedBytecode"].(map[string]any)["object"] = "60006001"
		},
		"missing storage layout": func(f *contractBuildFixture) { delete(f.artifact(), "storageLayout") },
		"changed storage layout": func(f *contractBuildFixture) {
			f.artifact()["storageLayout"] = map[string]any{"storage": []any{map[string]any{"slot": "10"}}, "types": nil}
		},
		"unresolved creation link": func(f *contractBuildFixture) {
			f.artifact()["evm"].(map[string]any)["bytecode"].(map[string]any)["linkReferences"] = map[string]any{"Lib.sol": map[string]any{"Lib": []any{map[string]any{"start": 0, "length": 20}}}}
		},
		"unresolved runtime link": func(f *contractBuildFixture) {
			f.artifact()["evm"].(map[string]any)["deployedBytecode"].(map[string]any)["linkReferences"] = map[string]any{"Lib.sol": map[string]any{}}
		},
		"immutable substitution": func(f *contractBuildFixture) {
			f.artifact()["evm"].(map[string]any)["deployedBytecode"].(map[string]any)["immutableReferences"] = map[string]any{"0": []any{map[string]any{"start": 0, "length": 32}}}
		},
		"null reference map": func(f *contractBuildFixture) {
			f.artifact()["evm"].(map[string]any)["deployedBytecode"].(map[string]any)["immutableReferences"] = nil
		},
		"changed metadata": func(f *contractBuildFixture) { f.artifact()["metadata"] = "{}" },
		"partial release coverage": func(f *contractBuildFixture) {
			f.buildPolicy.Builds[0].Contracts = f.buildPolicy.Builds[0].Contracts[:1]
		},
		"duplicate target": func(f *contractBuildFixture) {
			f.buildPolicy.Builds[0].Contracts = append(f.buildPolicy.Builds[0].Contracts, f.buildPolicy.Builds[0].Contracts[0])
		},
		"duplicate source unit": func(f *contractBuildFixture) {
			f.buildPolicy.Builds[0].Sources = append(f.buildPolicy.Builds[0].Sources, f.buildPolicy.Builds[0].Sources[0])
		},
		"different epoch":   func(f *contractBuildFixture) { f.buildPolicy.EpochID = strings.Repeat("8", 64) },
		"different genesis": func(f *contractBuildFixture) { f.buildPolicy.L2GenesisHash = "0x" + strings.Repeat("8", 64) },
		"different rollup":  func(f *contractBuildFixture) { f.buildPolicy.RollupSHA256 = strings.Repeat("8", 64) },
		"source checkout mismatch": func(f *contractBuildFixture) {
			if err := os.WriteFile(filepath.Join(f.sources, "zvm-core/contracts/Fixture.sol"), []byte("contract Changed {}"), 0600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newContractBuildFixture(t)
			mutate(f)
			f.save(t)
			if _, err := f.manifest.VerifyContractBuilds(f.files, f.sources); err == nil {
				t.Fatal("invalid saved build accepted after its outer pins were updated")
			}
		})
	}
}

func TestContractBuildCoverageCannotOmitGenesisPredeploysFromManifestAndPolicy(t *testing.T) {
	f := newContractBuildFixture(t)
	f.manifest.Contracts = f.manifest.Contracts[:1]
	f.policy.Contracts = f.policy.Contracts[:1]
	f.buildPolicy.Builds[0].Contracts = f.buildPolicy.Builds[0].Contracts[:1]
	f.save(t)
	if _, err := f.manifest.VerifyContractBuilds(f.files, f.sources); err == nil {
		t.Fatal("all-present partial inventory accepted as complete genesis coverage")
	}
}

func TestUndeclaredContractBuildsNeverClaimCompilerExecutionOrCoverage(t *testing.T) {
	f := newFixture(t)
	r, err := f.manifest.Verify(context.Background(), f.policy, f.signatures(t), f.keys, f.files, f.sources)
	if err != nil || r.VerifiedContractBuilds != 0 || r.CompilerExecuted {
		t.Fatalf("undeclared build coverage: %+v %v", r, err)
	}
}

func TestCompilerJSONRejectsDuplicateHiddenKeysTrailingDataAndBounds(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"output":{"ignored":{"value":1,"value":2}}}`),
		[]byte(`{"source":"a","source":"b"}`),
		[]byte(`{"a":0} {"a":1}`),
		[]byte(`{"input":[}`),
		append([]byte(`{"source":"`), 0xff, '"', '}'),
		[]byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)),
	}
	for i, raw := range cases {
		if compilerJSON(raw, 1<<20) == nil {
			t.Fatalf("malformed document %d accepted", i)
		}
	}
	if compilerJSON([]byte(`{"a":1}`), 2) == nil {
		t.Fatal("document byte limit ignored")
	}
	if compilerJSON([]byte(`{"output":{"ignored":{"value":1}},"sources":[]}`), 1<<20) != nil {
		t.Fatal("valid compiler JSON refused")
	}
}

func TestCompilerMetadataSemanticChecksSurviveUpdatedMetadataDigests(t *testing.T) {
	for _, field := range []string{"version", "target", "source-hash"} {
		t.Run(field, func(t *testing.T) {
			f := newContractBuildFixture(t)
			var metadata map[string]any
			if json.Unmarshal([]byte(f.artifact()["metadata"].(string)), &metadata) != nil {
				t.Fatal("fixture metadata invalid")
			}
			switch field {
			case "version":
				metadata["compiler"].(map[string]any)["version"] = "0.8.29+commit.invalid"
			case "target":
				metadata["settings"].(map[string]any)["compilationTarget"] = map[string]any{"Fixture.sol": "Changed"}
			case "source-hash":
				metadata["sources"].(map[string]any)["Fixture.sol"].(map[string]any)["keccak256"] = "0x" + strings.Repeat("1", 64)
			}
			raw := buildRaw(t, metadata)
			f.artifact()["metadata"] = string(raw)
			f.buildPolicy.Builds[0].Contracts[0].MetadataSHA256 = digest(raw)
			f.save(t)
			if _, err := f.manifest.VerifyContractBuilds(f.files, f.sources); err == nil {
				t.Fatal("semantic metadata mismatch accepted")
			}
		})
	}
}

func TestContractBuildPolicyDecoderRejectsUnknownAliasesAndDuplicates(t *testing.T) {
	f := newContractBuildFixture(t)
	raw := buildRaw(t, f.buildPolicy)
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"Schema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"unknown":true`), 1),
		append(slices.Clone(raw), []byte(` {}`)...),
	} {
		var policy ContractBuildPolicy
		if decode(bad, &policy) == nil {
			t.Fatal("ambiguous contract build policy accepted")
		}
	}
}

func TestPinnedCompilerLayoutVectorsBindGenesisFeeSlots(t *testing.T) {
	raw, err := os.ReadFile("testdata/predeploy-layouts.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		CompilerSHA256 string `json:"compilerSha256"`
		InputSHA256    string `json:"compilerInputSha256"`
		Contracts      []struct {
			Name   string          `json:"name"`
			SHA256 string          `json:"sha256"`
			Layout json.RawMessage `json:"layout"`
		} `json:"contracts"`
	}
	if json.Unmarshal(raw, &vector) != nil || vector.CompilerSHA256 != "81475c98b6d2094a821fd9d7b6278556d8095ccc23e0b8a1029b1c08a89cd4b2" || vector.InputSHA256 != "ac8dcb9e2a1f162c1ba62e2d96b4055359603d5ec9cfe4c3beda5f9d1c2b323e" || len(vector.Contracts) != 2 {
		t.Fatal("compiler layout vector identity changed")
	}
	for _, contract := range vector.Contracts {
		normalized, err := canonicalBuildLayout(contract.Layout)
		if err != nil || digest(normalized) != contract.SHA256 {
			t.Fatal("cross-language compiler layout digest differs")
		}
		if contract.Name != "ZVMBridge" {
			continue
		}
		var layout struct {
			Storage []struct {
				Label  string `json:"label"`
				Slot   string `json:"slot"`
				Offset int    `json:"offset"`
				Type   string `json:"type"`
			} `json:"storage"`
		}
		if json.Unmarshal(contract.Layout, &layout) != nil {
			t.Fatal("invalid bridge layout")
		}
		wanted := map[string]int{"feeBps": rollup.BridgeSlotFeeBps, "minFeeZNN": rollup.BridgeSlotMinFeeZNN, "minFeeQSR": rollup.BridgeSlotMinFeeQSR}
		for _, storage := range layout.Storage {
			if slot, present := wanted[storage.Label]; present {
				if storage.Slot != strconv.Itoa(slot) || storage.Offset != 0 || storage.Type != "t_uint256" {
					t.Fatal("genesis fee slot disagrees with the compiler layout")
				}
				delete(wanted, storage.Label)
			}
		}
		if len(wanted) != 0 {
			t.Fatal("compiler layout omits a genesis fee field")
		}
	}
}
