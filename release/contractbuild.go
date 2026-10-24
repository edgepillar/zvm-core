package release

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/l2"
)

const ContractBuildPolicyID = "contract-build-policy"

// ContractBuildPolicy is a signed, independently inventoried config file. A
// declared policy requires every release contract and every genesis predeploy.
// It checks saved compiler material; it never executes a compiler.
type ContractBuildPolicy struct {
	Schema        int             `json:"schema"`
	EpochID       string          `json:"epochId"`
	RollupSHA256  string          `json:"rollupSha256"`
	L2GenesisHash string          `json:"l2GenesisHash"`
	Builds        []ContractBuild `json:"builds"`
}

type ContractBuild struct {
	ID          string                `json:"id"`
	Compiler    string                `json:"compiler"`
	BundleFile  string                `json:"bundleFile"`
	InputSHA256 string                `json:"inputSha256"`
	Sources     []ContractBuildSource `json:"sources"`
	Contracts   []ContractBuildTarget `json:"contracts"`
}

type ContractBuildSource struct {
	Unit           string `json:"unit"`
	File           string `json:"file"`
	Member         string `json:"member,omitempty"`
	LockFile       string `json:"lockFile,omitempty"`
	PackageKey     string `json:"packageKey,omitempty"`
	PackageName    string `json:"packageName,omitempty"`
	PackageVersion string `json:"packageVersion,omitempty"`
}

type ContractBuildTarget struct {
	Contract            string `json:"contract"`
	Unit                string `json:"unit"`
	Name                string `json:"name"`
	CreationSHA256      string `json:"creationSha256"`
	StorageLayoutSHA256 string `json:"storageLayoutSha256"`
	MetadataSHA256      string `json:"metadataSha256"`
}

var solidityName = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]{0,127}$`)

type buildBundle struct {
	Schema          int             `json:"schema"`
	CompilerVersion string          `json:"compilerVersion"`
	Input           json.RawMessage `json:"input"`
	Output          json.RawMessage `json:"output"`
}

type buildInput struct {
	Language string                     `json:"language"`
	Sources  map[string]json.RawMessage `json:"sources"`
	Settings json.RawMessage            `json:"settings"`
}

type buildOutput struct {
	raw          json.RawMessage
	inputSources map[string]string
	Contracts    map[string]map[string]struct {
		Metadata      string          `json:"metadata"`
		StorageLayout json.RawMessage `json:"storageLayout"`
		EVM           struct {
			Bytecode         buildBytecode `json:"bytecode"`
			DeployedBytecode buildBytecode `json:"deployedBytecode"`
		} `json:"evm"`
	} `json:"contracts"`
	Sources map[string]struct {
		ID *int `json:"id"`
	} `json:"sources"`
	Errors []struct {
		Severity string `json:"severity"`
	} `json:"errors"`
}

type buildBytecode struct {
	Object              string          `json:"object"`
	LinkReferences      json.RawMessage `json:"linkReferences"`
	ImmutableReferences json.RawMessage `json:"immutableReferences"`
}

// Compiler JSON has dynamic source/contract/type maps. Reject duplicate keys
// before decoding any selected field, including inside ignored compiler output.
func compilerJSON(raw []byte, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return errors.New("compiler document exceeds its encoding or byte bounds")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	remaining := 262144
	var walk func(int) error
	walk = func(depth int) error {
		remaining--
		if depth > 64 || remaining < 0 {
			return errors.New("compiler document exceeds its structure bounds")
		}
		token, err := d.Token()
		if err != nil {
			return errors.New("invalid compiler JSON")
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] || len(seen) >= 65536 {
					return errors.New("duplicate or excessive compiler object members")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid compiler object")
			}
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid compiler array")
			}
		default:
			if _, delimiter := token.(json.Delim); delimiter {
				return errors.New("invalid compiler value")
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing compiler document data")
	}
	return nil
}

func strictBuildDecode(raw []byte, out any) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errors.New("expected a compiler object")
	}
	shape := reflect.TypeOf(out).Elem()
	known := map[string]bool{}
	for i := 0; i < shape.NumField(); i++ {
		known[strings.Split(shape.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	for name := range fields {
		if !known[name] {
			return errors.New("unknown compiler object field or case alias")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func emptyBuildReferences(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var refs map[string]json.RawMessage
	return json.Unmarshal(raw, &refs) == nil && refs != nil && len(refs) == 0
}

func buildHex(text string) ([]byte, error) {
	if len(text) == 0 || len(text) > 8<<20 || strings.ToLower(text) != text {
		return nil, errors.New("empty or oversized compiler bytecode")
	}
	code, err := hex.DecodeString(text)
	if err != nil {
		return nil, errors.New("unresolved or invalid compiler bytecode")
	}
	return code, nil
}

func canonicalBuildLayout(raw json.RawMessage) ([]byte, error) {
	var layout map[string]json.RawMessage
	if json.Unmarshal(raw, &layout) != nil || layout == nil || layout["storage"] == nil || layout["types"] == nil {
		return nil, errors.New("compiler storage layout is missing")
	}
	var storage []json.RawMessage
	if json.Unmarshal(layout["storage"], &storage) != nil || storage == nil || len(storage) > MaxEntries {
		return nil, errors.New("compiler storage inventory is invalid")
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return nil, errors.New("invalid compiler storage layout")
	}
	// encoding/json sorts dynamic object keys. Disable HTML escaping to match
	// the build tool's UTF-8 compact representation, including type labels.
	var normalized bytes.Buffer
	e := json.NewEncoder(&normalized)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(normalized.Bytes(), []byte{'\n'}), nil
}

func (m Manifest) verifyContractBuild(build ContractBuild, files, sources *os.Root) error {
	return m.verifySolidityBuild(build, files, sources, nil, nil)
}

// A resolver is available only to the explicit schema-two policy. Schema one
// always takes the nil path and retains its refusal of every immutable map.
type contractRuntimeResolver func(ContractBuildTarget, Contract, buildBytecode, []byte, *buildOutput) ([]byte, error)

func (m Manifest) verifySolidityBuild(build ContractBuild, files, sources *os.Root, resolve contractRuntimeResolver, packages *buildPackageReader) error {
	byID := map[string]File{}
	for _, pin := range m.Files {
		byID[pin.ID] = pin
	}
	var compiler Artifact
	for _, candidate := range m.Compilers {
		if candidate.ID == build.Compiler {
			compiler = candidate
		}
	}
	if compiler.ID == "" || compiler.Platform != "emscripten/wasm32" || byID[compiler.FileID].Bytes > 16<<20 {
		return errors.New("contract build requires a pinned bounded WASM compiler")
	}
	pin := byID[build.BundleFile]
	if pin.ID == "" || pin.Kind != "artifact" {
		return errors.New("contract build does not bind an artifact bundle")
	}
	raw, err := readPin(files, pin, 16<<20)
	if err != nil {
		return err
	}
	if err := compilerJSON(raw, 16<<20); err != nil {
		return err
	}
	var bundle buildBundle
	if strictBuildDecode(raw, &bundle) != nil || bundle.Schema != 1 || bundle.CompilerVersion != compiler.Version+".Emscripten.clang" || digest(bundle.Input) != build.InputSHA256 {
		return errors.New("compiler bundle, version or exact Standard JSON input mismatch")
	}
	var input buildInput
	if strictBuildDecode(bundle.Input, &input) != nil || input.Language != "Solidity" || len(input.Sources) != len(build.Sources) {
		return errors.New("invalid Solidity input or incomplete source inventory")
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(input.Settings, &settings) != nil || settings == nil {
		return errors.New("compiler settings object is missing")
	}
	contents := map[string]string{}
	if packages == nil {
		packages = newBuildPackageReader(files, sources, byID)
	}
	var sourceBytes int64
	for _, source := range build.Sources {
		pin := byID[source.File]
		if pin.ID == "" || pin.Kind != "artifact" || !relative(source.Unit) || contents[source.Unit] != "" {
			return errors.New("invalid or duplicate compiler source pin")
		}
		var unit struct {
			Content *string `json:"content"`
		}
		if strictBuildDecode(input.Sources[source.Unit], &unit) != nil || unit.Content == nil {
			return errors.New("only literal source content is accepted; import URLs are refused")
		}
		raw, err := packages.source(source, pin)
		if err != nil || len(raw) == 0 || !utf8.Valid(raw) || string(raw) != *unit.Content {
			return errors.New("compiler source does not match its pinned file")
		}
		sourceBytes += int64(len(raw))
		if sourceBytes > 16<<20 {
			return errors.New("compiler sources exceed their aggregate byte limit")
		}
		contents[source.Unit] = *unit.Content
	}
	var output buildOutput
	if json.Unmarshal(bundle.Output, &output) != nil || len(output.Sources) != len(input.Sources) || len(output.Contracts) == 0 {
		return errors.New("compiler output/source inventory is missing")
	}
	output.raw = bundle.Output
	output.inputSources = contents
	seenIDs := map[int]bool{}
	for unit, source := range output.Sources {
		_, present := contents[unit]
		if !present || source.ID == nil || *source.ID < 0 || *source.ID > 65535 || seenIDs[*source.ID] {
			return errors.New("compiler source identities are invalid or duplicated")
		}
		seenIDs[*source.ID] = true
	}
	for _, diagnostic := range output.Errors {
		if diagnostic.Severity != "warning" && diagnostic.Severity != "info" {
			return errors.New("compiler output includes an error or unknown diagnostic severity")
		}
	}
	contracts := map[string]Contract{}
	for _, contract := range m.Contracts {
		contracts[contract.ID] = contract
	}
	for _, target := range build.Contracts {
		contract, present := contracts[target.Contract]
		artifact, compiled := output.Contracts[target.Unit][target.Name]
		if !present || !compiled || contents[target.Unit] == "" {
			return errors.New("compiler target is missing from the release, input or output")
		}
		if !emptyBuildReferences(artifact.EVM.Bytecode.LinkReferences) || !emptyBuildReferences(artifact.EVM.DeployedBytecode.LinkReferences) || !emptyBuildReferences(artifact.EVM.Bytecode.ImmutableReferences) || resolve == nil && !emptyBuildReferences(artifact.EVM.DeployedBytecode.ImmutableReferences) {
			return errors.New("constructor and library reference witnesses are required; masking is refused")
		}
		creation, err := buildHex(artifact.EVM.Bytecode.Object)
		if err != nil || digest(creation) != target.CreationSHA256 {
			return errors.New("compiler creation bytecode digest mismatch")
		}
		runtime, err := buildHex(artifact.EVM.DeployedBytecode.Object)
		if err != nil {
			return err
		}
		if resolve != nil {
			runtime, err = resolve(target, contract, artifact.EVM.DeployedBytecode, runtime, &output)
			if err != nil {
				return err
			}
		}
		raw, err := readPin(files, byID[contract.RuntimeFile], 8<<20)
		if err != nil {
			return err
		}
		expected, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
		if err != nil || !bytes.Equal(runtime, expected) || strings.ToLower(crypto.Keccak256Hash(runtime).Hex()) != contract.RuntimeCodeHash {
			return errors.New("full rebuilt runtime disagrees with the release; metadata is not stripped")
		}
		layout, err := canonicalBuildLayout(artifact.StorageLayout)
		if err != nil || digest(layout) != target.StorageLayoutSHA256 {
			return errors.New("compiler storage-layout digest mismatch")
		}
		if digest([]byte(artifact.Metadata)) != target.MetadataSHA256 || compilerJSON([]byte(artifact.Metadata), 1<<20) != nil {
			return errors.New("compiler metadata is missing, ambiguous or changed")
		}
		var metadata struct {
			Compiler struct {
				Version string `json:"version"`
			} `json:"compiler"`
			Settings struct {
				CompilationTarget map[string]string `json:"compilationTarget"`
			} `json:"settings"`
			Sources map[string]struct {
				Keccak256 string `json:"keccak256"`
			} `json:"sources"`
		}
		if json.Unmarshal([]byte(artifact.Metadata), &metadata) != nil || metadata.Compiler.Version != compiler.Version || len(metadata.Settings.CompilationTarget) != 1 || metadata.Settings.CompilationTarget[target.Unit] != target.Name || len(metadata.Sources) == 0 {
			return errors.New("compiler metadata version or compilation target mismatch")
		}
		if _, present := metadata.Sources[target.Unit]; !present {
			return errors.New("compiler metadata omits the target source")
		}
		for unit, source := range metadata.Sources {
			text, present := contents[unit]
			if !present || source.Keccak256 != crypto.Keccak256Hash([]byte(text)).Hex() {
				return errors.New("compiler metadata source hash mismatch")
			}
		}
	}
	return nil
}

// VerifyContractBuilds verifies saved build consistency after signature, file,
// genesis and clean-source verification. Zero means that no build policy was
// declared, not that any compiler or contract was rebuilt. The current format
// refuses unresolved links and all immutable substitutions.
func (m Manifest) VerifyContractBuilds(filesRoot, sourcesRoot string) (int, error) {
	if err := m.validate(); err != nil {
		return 0, err
	}
	var pin File
	for _, candidate := range m.Files {
		if candidate.ID == ContractBuildPolicyID {
			pin = candidate
		}
	}
	if pin.ID == "" {
		return 0, nil
	}
	if pin.Kind != "config" {
		return 0, errors.New("contract build policy must be an inventoried config file")
	}
	files, err := openDirectory(filesRoot)
	if err != nil {
		return 0, err
	}
	defer files.Close()
	sources, err := openDirectory(sourcesRoot)
	if err != nil {
		return 0, err
	}
	defer sources.Close()
	raw, err := readPin(files, pin, MaxDocumentBytes)
	if err != nil {
		return 0, err
	}
	// Select a new format only by its explicit version. Its dynamic definition
	// objects are checked independently; no new field is accepted by schema one.
	var discriminator map[string]json.RawMessage
	var schema int
	if json.Unmarshal(raw, &discriminator) == nil && json.Unmarshal(discriminator["schema"], &schema) == nil && schema == 2 {
		return m.verifyTypedContractBuilds(raw, files, sources)
	}
	var policy ContractBuildPolicy
	if decode(raw, &policy) != nil || policy.Schema != 1 || policy.EpochID != m.Epoch.ID || policy.RollupSHA256 != m.Epoch.RollupSHA256 || policy.L2GenesisHash != m.Epoch.L2GenesisHash || len(policy.Builds) == 0 || len(policy.Builds) > 64 {
		return 0, errors.New("contract build policy is invalid or belongs to another epoch")
	}
	var ids, targets []string
	var bundleBytes int64
	seenBundles := map[string]bool{}
	for _, build := range policy.Builds {
		ids = append(ids, build.ID)
		if !identifier.MatchString(build.Compiler) || !identifier.MatchString(build.BundleFile) || !hash(build.InputSHA256, 64) || len(build.Sources) == 0 || len(build.Sources) > MaxEntries || len(build.Contracts) == 0 || len(build.Contracts) > MaxEntries || seenBundles[build.BundleFile] {
			return 0, errors.New("invalid contract build references or inventories")
		}
		seenBundles[build.BundleFile] = true
		for _, file := range m.Files {
			if file.ID == build.BundleFile {
				bundleBytes += file.Bytes
			}
		}
		if bundleBytes > 64<<20 {
			return 0, errors.New("contract build bundles exceed their aggregate byte limit")
		}
		for _, source := range build.Sources {
			if !relative(source.Unit) || !identifier.MatchString(source.File) {
				return 0, errors.New("invalid build source reference")
			}
		}
		seenTargets := map[string]bool{}
		for _, target := range build.Contracts {
			key := target.Unit + ":" + target.Name
			if !relative(target.Unit) || !solidityName.MatchString(target.Name) || !hash(target.CreationSHA256, 64) || !hash(target.StorageLayoutSHA256, 64) || !hash(target.MetadataSHA256, 64) || seenTargets[key] {
				return 0, errors.New("invalid or duplicate build target")
			}
			seenTargets[key] = true
			targets = append(targets, target.Contract)
		}
	}
	if unique(ids, false) != nil || unique(targets, false) != nil {
		return 0, errors.New("duplicate or invalid build/contract identifiers")
	}
	var wanted []string
	addresses := map[string]bool{}
	for _, contract := range m.Contracts {
		wanted = append(wanted, contract.ID)
		addresses[contract.Address] = true
	}
	if exact(wanted, targets) != nil {
		return 0, errors.New("contract builds must cover the complete release contract inventory")
	}
	for _, address := range l2.Predeploys() {
		if !addresses[strings.ToLower(address.Hex())] {
			return 0, errors.New("contract builds must cover every supported genesis predeploy")
		}
	}
	for _, build := range policy.Builds {
		if err := m.verifyContractBuild(build, files, sources); err != nil {
			return 0, err
		}
	}
	return len(targets), nil
}
