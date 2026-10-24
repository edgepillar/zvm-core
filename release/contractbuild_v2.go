package release

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/Zenoglyphs-VM/zvm-core/l2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Schema two keeps assembly and old Yul material distinct from Solidity. Every
// definition and runtime context has an explicit type; schema one is unchanged.
type ContractBuildPolicyV2 struct {
	Schema        int                  `json:"schema"`
	EpochID       string               `json:"epochId"`
	RollupSHA256  string               `json:"rollupSha256"`
	L2GenesisHash string               `json:"l2GenesisHash"`
	Builds        []TypedContractBuild `json:"builds"`
}

type TypedContractBuild struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Definition json.RawMessage `json:"definition"`
}

type SolidityBuildV2 struct {
	Build           ContractBuild              `json:"build"`
	RuntimeContexts map[string]json.RawMessage `json:"runtimeContexts"`
}

type YulBuildV2 struct {
	Compiler    string                `json:"compiler"`
	BundleFile  string                `json:"bundleFile"`
	InputSHA256 string                `json:"inputSha256"`
	Sources     []ContractBuildSource `json:"sources"`
	Contracts   []YulBuildTarget      `json:"contracts"`
}

type YulBuildTarget struct {
	Contract       string `json:"contract"`
	Unit           string `json:"unit"`
	Name           string `json:"name"`
	CreationSHA256 string `json:"creationSha256"`
	RuntimeSHA256  string `json:"runtimeSha256"`
}

type EIPAssemblyBuildV2 struct {
	Source    ContractBuildSource `json:"source"`
	Contracts []EIPAssemblyTarget `json:"contracts"`
}

type EIPAssemblyTarget struct {
	Contract       string `json:"contract"`
	EIP            int    `json:"eip"`
	AssemblySHA256 string `json:"assemblySha256"`
	CreationSHA256 string `json:"creationSha256"`
	RuntimeSHA256  string `json:"runtimeSha256"`
}

func typedBuildObject(raw []byte, out any) error {
	if err := compilerJSON(raw, MaxDocumentBytes); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errors.New("typed build definition must be an object")
	}
	shape := reflect.TypeOf(out).Elem()
	if len(fields) != shape.NumField() {
		return errors.New("typed build fields must be complete and exact")
	}
	for i := 0; i < shape.NumField(); i++ {
		name := strings.Split(shape.Field(i).Tag.Get("json"), ",")[0]
		if fields[name] == nil || bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return errors.New("typed build field is missing or null")
		}
	}
	return strictBuildDecode(raw, out)
}

func validSolidityBuild(build ContractBuild) bool {
	if !identifier.MatchString(build.ID) || !identifier.MatchString(build.Compiler) || !identifier.MatchString(build.BundleFile) || !hash(build.InputSHA256, 64) || len(build.Sources) == 0 || len(build.Sources) > MaxEntries || len(build.Contracts) == 0 || len(build.Contracts) > MaxEntries {
		return false
	}
	for _, source := range build.Sources {
		if !relative(source.Unit) || !identifier.MatchString(source.File) {
			return false
		}
	}
	for _, target := range build.Contracts {
		if !identifier.MatchString(target.Contract) || !relative(target.Unit) || !solidityName.MatchString(target.Name) || !hash(target.CreationSHA256, 64) || !hash(target.StorageLayoutSHA256, 64) || !hash(target.MetadataSHA256, 64) {
			return false
		}
	}
	return true
}

func (m Manifest) verifyTypedContractBuilds(raw []byte, files, sources *os.Root) (int, error) {
	var policy struct {
		Schema        int               `json:"schema"`
		EpochID       string            `json:"epochId"`
		RollupSHA256  string            `json:"rollupSha256"`
		L2GenesisHash string            `json:"l2GenesisHash"`
		Builds        []json.RawMessage `json:"builds"`
	}
	if typedBuildObject(raw, &policy) != nil || policy.Schema != 2 || policy.EpochID != m.Epoch.ID || policy.RollupSHA256 != m.Epoch.RollupSHA256 || policy.L2GenesisHash != m.Epoch.L2GenesisHash || len(policy.Builds) == 0 || len(policy.Builds) > 64 {
		return 0, errors.New("typed contract policy is invalid or belongs to another epoch")
	}
	byID := map[string]File{}
	for _, pin := range m.Files {
		byID[pin.ID] = pin
	}
	packages := newBuildPackageReader(files, sources, byID)
	var ids, targets []string
	var checks []func() error
	subjects := map[string]applicationBuildSubject{}
	seenBundles := map[string]bool{}
	var bundleBytes int64
	addBundle := func(id string) error {
		pin := byID[id]
		if !identifier.MatchString(id) || pin.ID == "" || pin.Kind != "artifact" || pin.Bytes > 16<<20 || seenBundles[id] {
			return errors.New("invalid or repeated typed compiler bundle")
		}
		seenBundles[id] = true
		bundleBytes += pin.Bytes
		if bundleBytes > 64<<20 {
			return errors.New("typed build bundles exceed their aggregate byte limit")
		}
		return nil
	}
	for _, rawBuild := range policy.Builds {
		var item TypedContractBuild
		if typedBuildObject(rawBuild, &item) != nil || !identifier.MatchString(item.ID) {
			return 0, errors.New("invalid typed build identity or definition")
		}
		ids = append(ids, item.ID)
		switch item.Kind {
		case "solidity":
			var definition struct {
				Build           json.RawMessage            `json:"build"`
				RuntimeContexts map[string]json.RawMessage `json:"runtimeContexts"`
			}
			var build ContractBuild
			if typedBuildObject(item.Definition, &definition) != nil || decode(definition.Build, &build) != nil || build.ID != item.ID || !validSolidityBuild(build) || len(definition.RuntimeContexts) != len(build.Contracts) {
				return 0, errors.New("invalid typed Solidity build or context inventory")
			}
			if err := addBundle(build.BundleFile); err != nil {
				return 0, err
			}
			for _, target := range build.Contracts {
				if definition.RuntimeContexts[target.Contract] == nil {
					return 0, errors.New("runtime context omitted a release contract")
				}
				targets = append(targets, target.Contract)
				subjects[target.Contract] = applicationBuildSubject{Target: target, Context: definition.RuntimeContexts[target.Contract]}
			}
			checks = append(checks, func() error {
				resolve := func(target ContractBuildTarget, contract Contract, bytecode buildBytecode, runtime []byte, output *buildOutput) ([]byte, error) {
					var fields map[string]json.RawMessage
					var kind string
					if json.Unmarshal(definition.RuntimeContexts[target.Contract], &fields) == nil && json.Unmarshal(fields["kind"], &kind) == nil {
						if applicationRuntimeKind(kind) {
							return m.resolveApplicationRuntime(definition.RuntimeContexts[target.Contract], target, contract, bytecode, runtime, output, subjects)
						}
						if kind == "collection-factory-implementation" {
							return m.resolveCollectionFactoryRuntime(definition.RuntimeContexts[target.Contract], target, contract, bytecode, runtime, build, definition.RuntimeContexts, output)
						}
					}
					return m.resolveBuildRuntime(definition.RuntimeContexts[target.Contract], target, contract, bytecode, runtime)
				}
				return m.verifySolidityBuild(build, files, sources, resolve, packages)
			})
		case "solc-yul-fixed-return-v1":
			var build YulBuildV2
			if decode(item.Definition, &build) != nil || !identifier.MatchString(build.Compiler) || !hash(build.InputSHA256, 64) || len(build.Sources) != 1 || len(build.Contracts) == 0 || len(build.Contracts) > 2 || !relative(build.Sources[0].Unit) || !strings.HasSuffix(build.Sources[0].Unit, ".yul") || !identifier.MatchString(build.Sources[0].File) {
				return 0, errors.New("invalid fixed-return Yul build inventory")
			}
			if err := addBundle(build.BundleFile); err != nil {
				return 0, err
			}
			for _, target := range build.Contracts {
				if !identifier.MatchString(target.Contract) || target.Unit != build.Sources[0].Unit || target.Name != "Proxy" || !hash(target.CreationSHA256, 64) || !hash(target.RuntimeSHA256, 64) {
					return 0, errors.New("invalid fixed-return Yul target")
				}
				targets = append(targets, target.Contract)
			}
			checks = append(checks, func() error { return m.verifyYulBuild(build, files, packages, byID) })
		case "eip-evm-assembly-v1":
			var build EIPAssemblyBuildV2
			if decode(item.Definition, &build) != nil || len(build.Contracts) != 1 || !identifier.MatchString(build.Source.File) || !relative(build.Source.Unit) {
				return 0, errors.New("invalid EIP assembly build inventory")
			}
			t := build.Contracts[0]
			if !identifier.MatchString(t.Contract) || (t.EIP != 4788 && t.EIP != 2935) || build.Source.Unit != "EIPS/eip-"+strconv.Itoa(t.EIP)+".md" || !hash(t.AssemblySHA256, 64) || !hash(t.CreationSHA256, 64) || !hash(t.RuntimeSHA256, 64) {
				return 0, errors.New("invalid EIP assembly target")
			}
			targets = append(targets, t.Contract)
			checks = append(checks, func() error { return m.verifyEIPAssembly(build, files, packages, byID) })
		default:
			return 0, errors.New("unsupported typed contract build kind")
		}
	}
	if unique(ids, false) != nil || unique(targets, false) != nil {
		return 0, errors.New("duplicate typed build or release contract identity")
	}
	wanted := []string{}
	addresses := map[string]bool{}
	for _, contract := range m.Contracts {
		wanted = append(wanted, contract.ID)
		addresses[contract.Address] = true
	}
	if exact(wanted, targets) != nil {
		return 0, errors.New("typed builds must cover the complete release contract inventory")
	}
	for _, address := range l2.Predeploys() {
		if !addresses[strings.ToLower(address.Hex())] {
			return 0, errors.New("typed builds must cover every supported genesis predeploy")
		}
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return 0, err
		}
	}
	return len(targets), nil
}

func (m Manifest) releaseContract(id string) (Contract, bool) {
	for _, contract := range m.Contracts {
		if contract.ID == id {
			return contract, true
		}
	}
	return Contract{}, false
}

func (m Manifest) resolveBuildRuntime(raw json.RawMessage, target ContractBuildTarget, contract Contract, bytecode buildBytecode, runtime []byte) ([]byte, error) {
	var discriminator map[string]json.RawMessage
	var kind string
	if json.Unmarshal(raw, &discriminator) != nil || json.Unmarshal(discriminator["kind"], &kind) != nil {
		return nil, errors.New("runtime context kind is missing")
	}
	var templateSHA string
	bindings := map[string]common.Hash{}
	switch kind {
	case "exact":
		var context struct {
			Kind                  string `json:"kind"`
			RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
		}
		if typedBuildObject(raw, &context) != nil || !emptyBuildReferences(bytecode.ImmutableReferences) {
			return nil, errors.New("exact runtime context refuses immutable substitutions")
		}
		templateSHA = context.RuntimeTemplateSHA256
	case "permit2-domain-cache":
		var context struct {
			Kind                  string `json:"kind"`
			RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
			ChainID               string `json:"chainId"`
			ChainIDImmutable      string `json:"chainIdImmutable"`
			DomainImmutable       string `json:"domainImmutable"`
		}
		if typedBuildObject(raw, &context) != nil || target.Name != "Permit2" || contract.Address != strings.ToLower(l2.Predeploys()["Permit2"].Hex()) || context.ChainIDImmutable == context.DomainImmutable {
			return nil, errors.New("invalid declared Permit2 historical context")
		}
		chain, ok := new(big.Int).SetString(context.ChainID, 10)
		if !ok || chain.Sign() <= 0 || chain.BitLen() > 256 || chain.String() != context.ChainID {
			return nil, errors.New("invalid historical chain identity")
		}
		name := crypto.Keccak256([]byte("Permit2"))
		domainType := crypto.Keccak256([]byte("EIP712Domain(string name,uint256 chainId,address verifyingContract)"))
		encoded := append(bytes.Clone(domainType), name...)
		encoded = append(encoded, chain.FillBytes(make([]byte, 32))...)
		encoded = append(encoded, common.LeftPadBytes(common.HexToAddress(contract.Address).Bytes(), 32)...)
		bindings[context.ChainIDImmutable] = common.BigToHash(chain)
		bindings[context.DomainImmutable] = crypto.Keccak256Hash(encoded)
		templateSHA = context.RuntimeTemplateSHA256
	case "entrypoint-sender-creator":
		var context struct {
			Kind                  string `json:"kind"`
			RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
			Immutable             string `json:"immutable"`
			ChildContract         string `json:"childContract"`
			ChildNonce            string `json:"childNonce"`
		}
		if typedBuildObject(raw, &context) != nil || target.Name != "EntryPoint" || contract.Address != strings.ToLower(l2.Predeploys()["EntryPoint_v07"].Hex()) || context.ChildNonce != "1" {
			return nil, errors.New("invalid declared EntryPoint historical context")
		}
		child, ok := m.releaseContract(context.ChildContract)
		derived := crypto.CreateAddress(common.HexToAddress(contract.Address), 1)
		if !ok || child.Address != strings.ToLower(l2.Predeploys()["SenderCreator_v07"].Hex()) || child.Address != strings.ToLower(derived.Hex()) {
			return nil, errors.New("EntryPoint child context disagrees with the release inventory")
		}
		bindings[context.Immutable] = common.BytesToHash(derived.Bytes())
		templateSHA = context.RuntimeTemplateSHA256
	default:
		return nil, errors.New("unsupported runtime context; a separate witness format is required")
	}
	if !hash(templateSHA, 64) || digest(runtime) != templateSHA {
		return nil, errors.New("runtime template differs from the declared context pin")
	}
	if kind == "exact" {
		return runtime, nil
	}
	return bindBuildRuntimeWords(bytecode.ImmutableReferences, runtime, bindings)
}

func bindBuildRuntimeWords(raw json.RawMessage, runtime []byte, bindings map[string]common.Hash) ([]byte, error) {
	var references map[string][]json.RawMessage
	if json.Unmarshal(raw, &references) != nil || references == nil || len(references) != len(bindings) {
		return nil, errors.New("historical binding must cover the exact compiler immutable inventory")
	}
	wanted := bytes.Clone(runtime)
	covered := make([]bool, len(runtime))
	count := 0
	for id, locations := range references {
		word, ok := bindings[id]
		number, err := strconv.ParseUint(id, 10, 64)
		if !ok || err != nil || strconv.FormatUint(number, 10) != id || len(locations) == 0 {
			return nil, errors.New("invalid or undeclared compiler immutable identity")
		}
		for _, rawLocation := range locations {
			var location struct {
				Start  uint64 `json:"start"`
				Length uint64 `json:"length"`
			}
			if typedBuildObject(rawLocation, &location) != nil {
				return nil, errors.New("compiler immutable range fields must be exact")
			}
			count++
			if count > 256 || location.Length != 32 || location.Start > uint64(len(runtime)) || 32 > uint64(len(runtime))-location.Start {
				return nil, errors.New("invalid or excessive compiler immutable ranges")
			}
			for i := location.Start; i < location.Start+32; i++ {
				if covered[i] || runtime[i] != 0 {
					return nil, errors.New("overlapping or prefilled immutable template")
				}
				covered[i] = true
			}
			copy(wanted[location.Start:location.Start+32], word[:])
		}
	}
	return wanted, nil
}

func (m Manifest) compareTypedRuntime(id string, runtime []byte, files *os.Root, byID map[string]File) error {
	contract, ok := m.releaseContract(id)
	if !ok {
		return errors.New("typed runtime omitted a release contract")
	}
	raw, err := readPin(files, byID[contract.RuntimeFile], 8<<20)
	if err != nil {
		return err
	}
	wanted, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
	if err != nil || !bytes.Equal(runtime, wanted) || strings.ToLower(crypto.Keccak256Hash(runtime).Hex()) != contract.RuntimeCodeHash {
		return errors.New("complete typed runtime disagrees with the signed release")
	}
	return nil
}

func ordinaryBuildSource(source ContractBuildSource) bool {
	return source.Member == "" && source.LockFile == "" && source.PackageKey == "" && source.PackageName == "" && source.PackageVersion == ""
}

func (m Manifest) verifyYulBuild(build YulBuildV2, files *os.Root, packages *buildPackageReader, byID map[string]File) error {
	var compiler Artifact
	for _, candidate := range m.Compilers {
		if candidate.ID == build.Compiler {
			compiler = candidate
		}
	}
	if compiler.ID == "" || compiler.Platform != "emscripten/wasm32" || compiler.Version != "0.5.8+commit.23d335f2" || byID[compiler.FileID].Bytes > 16<<20 || !ordinaryBuildSource(build.Sources[0]) {
		return errors.New("fixed-return Yul requires its declared legacy compiler and Git source")
	}
	raw, err := readPin(files, byID[build.BundleFile], 16<<20)
	if err != nil {
		return err
	}
	if compilerJSON(raw, 16<<20) != nil {
		return errors.New("invalid Yul compiler JSON")
	}
	var bundle buildBundle
	var input buildInput
	var output buildOutput
	if strictBuildDecode(raw, &bundle) != nil || bundle.Schema != 1 || bundle.CompilerVersion != compiler.Version+".Emscripten.clang" || digest(bundle.Input) != build.InputSHA256 || strictBuildDecode(bundle.Input, &input) != nil || input.Language != "Yul" || len(input.Sources) != 1 {
		return errors.New("Yul compiler identity or complete input mismatch")
	}
	var settings map[string]json.RawMessage
	var literal struct {
		Content *string `json:"content"`
	}
	source := build.Sources[0]
	pin := byID[source.File]
	if json.Unmarshal(input.Settings, &settings) != nil || settings == nil || pin.ID == "" || pin.Kind != "artifact" || strictBuildDecode(input.Sources[source.Unit], &literal) != nil || literal.Content == nil {
		return errors.New("Yul settings or literal source missing")
	}
	sourceRaw, err := packages.source(source, pin)
	if err != nil || len(sourceRaw) == 0 || !utf8BuildSource(sourceRaw) || string(sourceRaw) != *literal.Content {
		return errors.New("Yul source differs from its signed clean checkout")
	}
	if json.Unmarshal(bundle.Output, &output) != nil || len(output.Contracts) != 1 || len(output.Contracts[source.Unit]) != 1 || len(output.Sources) != 0 {
		return errors.New("legacy Yul output inventory differs")
	}
	for _, diagnostic := range output.Errors {
		if diagnostic.Severity != "warning" && diagnostic.Severity != "info" {
			return errors.New("Yul compiler reported an error")
		}
	}
	var rawOutput struct {
		Contracts map[string]map[string]map[string]json.RawMessage `json:"contracts"`
	}
	if json.Unmarshal(bundle.Output, &rawOutput) != nil {
		return errors.New("invalid raw Yul artifact")
	}
	for _, target := range build.Contracts {
		contract, ok := m.releaseContract(target.Contract)
		if !ok || (contract.Address != strings.ToLower(l2.Predeploys()["Create2Deployer_Arachnid"].Hex()) && contract.Address != strings.ToLower(l2.Predeploys()["SafeSingletonFactory"].Hex())) {
			return errors.New("fixed-return Yul target must name a supported deterministic factory")
		}
		artifact, ok := output.Contracts[target.Unit][target.Name]
		if !ok {
			return errors.New("Yul compiler target missing")
		}
		rawFields := rawOutput.Contracts[target.Unit][target.Name]
		if _, err := packageObject(mustBuildJSON(rawFields), "evm", "metadata", "storageLayout", "abi"); err != nil {
			return errors.New("legacy Yul artifact has ambiguous selected fields")
		}
		for _, field := range []string{"metadata", "storageLayout", "abi"} {
			if _, present := rawFields[field]; present {
				return errors.New("legacy Yul must not invent Solidity ABI, layout or metadata")
			}
		}
		rawEVM, err := packageObject(rawFields["evm"], "bytecode", "deployedBytecode")
		if err != nil {
			return errors.New("legacy Yul EVM fields are ambiguous")
		}
		if _, present := rawEVM["deployedBytecode"]; present {
			return errors.New("legacy Yul output must retain its creation-only representation")
		}
		if _, err := packageObject(rawEVM["bytecode"], "object", "linkReferences", "immutableReferences"); err != nil {
			return errors.New("legacy Yul bytecode fields are ambiguous")
		}
		if !emptyBuildReferences(artifact.EVM.Bytecode.LinkReferences) || !emptyBuildReferences(artifact.EVM.Bytecode.ImmutableReferences) || artifact.EVM.DeployedBytecode.Object != "" || !emptyBuildReferences(artifact.EVM.DeployedBytecode.LinkReferences) || !emptyBuildReferences(artifact.EVM.DeployedBytecode.ImmutableReferences) {
			return errors.New("unexpected Yul runtime or reference material")
		}
		creation, err := buildHex(artifact.EVM.Bytecode.Object)
		prefix, _ := hex.DecodeString("604580600e600039806000f350fe")
		if err != nil || len(creation) != 83 || !bytes.Equal(creation[:14], prefix) || digest(creation) != target.CreationSHA256 || digest(creation[14:]) != target.RuntimeSHA256 {
			return errors.New("fixed Yul creation, return prefix or runtime differs")
		}
		if err := m.compareTypedRuntime(target.Contract, creation[14:], files, byID); err != nil {
			return err
		}
	}
	return nil
}
