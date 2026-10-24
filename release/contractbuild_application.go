package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// These contexts describe the reviewed constructor algorithms, not arbitrary
// immutable words. Changing one of these source versions needs a new review.
var applicationSourceDigests = map[string]string{
	"apps/ZVMFarm.sol":                                      "680e6d4f4f34ae538de0095651bf8816df65f878f74eef68f4ee9f370e4e71d7",
	"apps/ZVMFarmFeeStrategy.sol":                           "5dfdd1b32c9d2426ad33a8239ee86aa9a72cb96d7808f7ea327035019f174808",
	"apps/ZVMExchange.sol":                                  "9faef84e62cddc67ef894b8aed5e2771936d9f1ce2789379bd9e7a5eee590788",
	"@openzeppelin/contracts/utils/cryptography/EIP712.sol": "2845caaaf70757b6cce612ae4ffbec2c382cb3d1cb9765c98fa649c0f5f1c794",
	"@openzeppelin/contracts/utils/ShortStrings.sol":        "1cfa08d3c551e9ec0b9cd249b09987f04e7e90f352e1a5e3b0d6a3bc426b3de7",
	"contracts/UniswapV2Router02.sol":                       "acabe6d6c9c275aa5c27d8ed59b3d23d21616523071043e89eea7bca474babb8",
}

type applicationBuildSubject struct {
	Target  ContractBuildTarget
	Context json.RawMessage
}

type farmRuntimeContext struct {
	Kind                  string `json:"kind"`
	RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
	RewardTokenContract   string `json:"rewardTokenContract"`
}

type routerRuntimeContext struct {
	Kind                  string `json:"kind"`
	RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
	FactoryContract       string `json:"factoryContract"`
	WethContract          string `json:"wethContract"`
}

type strategyRuntimeContext struct {
	Kind                  string `json:"kind"`
	RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
	FarmContract          string `json:"farmContract"`
	RouterContract        string `json:"routerContract"`
	FactoryContract       string `json:"factoryContract"`
	WethContract          string `json:"wethContract"`
}

func applicationRuntimeKind(kind string) bool {
	return kind == "farm-reward-token" || kind == "farm-fee-strategy" || kind == "exchange-eip712-domain" || kind == "uniswap-v2-router02"
}

func applicationAddress(contract Contract) (common.Address, error) {
	address := common.HexToAddress(contract.Address)
	if address == (common.Address{}) || contract.Address != strings.ToLower(address.Hex()) {
		return common.Address{}, errors.New("application identity requires a nonzero canonical release address")
	}
	return address, nil
}

func (m Manifest) applicationCounterpart(id string, self Contract) (Contract, common.Address, error) {
	contract, found := m.releaseContract(id)
	address, err := applicationAddress(contract)
	if !found || err != nil || id == self.ID || contract.Address == self.Address {
		return Contract{}, common.Address{}, errors.New("application counterpart is absent, invalid or self-referential")
	}
	return contract, address, nil
}

func applicationRole(subjects map[string]applicationBuildSubject, id, unit, name string) (json.RawMessage, error) {
	subject, found := subjects[id]
	if !found || subject.Target.Contract != id || subject.Target.Unit != unit || subject.Target.Name != name {
		return nil, errors.New("application counterpart has the wrong declared Solidity role")
	}
	return subject.Context, nil
}

func applicationFactoryRole(subjects map[string]applicationBuildSubject, id string) error {
	raw, err := applicationRole(subjects, id, "contracts/UniswapV2Factory.sol", "UniswapV2Factory")
	var context struct {
		Kind                  string `json:"kind"`
		RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
	}
	if err != nil || typedBuildObject(raw, &context) != nil || context.Kind != "exact" || !hash(context.RuntimeTemplateSHA256, 64) {
		return errors.New("router requires an exact declared UniswapV2Factory target")
	}
	return nil
}

// Word derivation is separate from saved-source/AST validation. The production
// resolver always applies both, then checks every complete runtime byte.
func (m Manifest) applicationRuntimeWords(raw json.RawMessage, target ContractBuildTarget, self Contract, subjects map[string]applicationBuildSubject) (string, map[string]common.Hash, error) {
	fail := errors.New("invalid application constructor context or release counterpart graph")
	address, err := applicationAddress(self)
	if err != nil || self.ID != target.Contract {
		return "", nil, fail
	}
	var discriminator struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(raw, &discriminator) != nil {
		return "", nil, fail
	}
	words := map[string]common.Hash{}
	var template string
	switch discriminator.Kind {
	case "farm-reward-token":
		var context farmRuntimeContext
		if typedBuildObject(raw, &context) != nil || target.Unit != "apps/ZVMFarm.sol" || target.Name != "ZVMFarm" {
			return "", nil, fail
		}
		_, token, err := m.applicationCounterpart(context.RewardTokenContract, self)
		if err != nil {
			return "", nil, fail
		}
		template = context.RuntimeTemplateSHA256
		words["rewardToken"] = common.BytesToHash(token.Bytes())
	case "uniswap-v2-router02":
		var context routerRuntimeContext
		if typedBuildObject(raw, &context) != nil || target.Unit != "contracts/UniswapV2Router02.sol" || target.Name != "UniswapV2Router02" || applicationFactoryRole(subjects, context.FactoryContract) != nil {
			return "", nil, fail
		}
		_, factory, e1 := m.applicationCounterpart(context.FactoryContract, self)
		_, weth, e2 := m.applicationCounterpart(context.WethContract, self)
		if e1 != nil || e2 != nil {
			return "", nil, fail
		}
		template = context.RuntimeTemplateSHA256
		words["factory"], words["WETH"] = common.BytesToHash(factory.Bytes()), common.BytesToHash(weth.Bytes())
	case "farm-fee-strategy":
		var context strategyRuntimeContext
		if typedBuildObject(raw, &context) != nil || target.Unit != "apps/ZVMFarmFeeStrategy.sol" || target.Name != "ZVMFarmFeeStrategy" || applicationFactoryRole(subjects, context.FactoryContract) != nil {
			return "", nil, fail
		}
		farm, farmAddress, e1 := m.applicationCounterpart(context.FarmContract, self)
		_, routerAddress, e2 := m.applicationCounterpart(context.RouterContract, self)
		_, factoryAddress, e3 := m.applicationCounterpart(context.FactoryContract, self)
		_, wethAddress, e4 := m.applicationCounterpart(context.WethContract, self)
		farmRaw, e5 := applicationRole(subjects, context.FarmContract, "apps/ZVMFarm.sol", "ZVMFarm")
		routerRaw, e6 := applicationRole(subjects, context.RouterContract, "contracts/UniswapV2Router02.sol", "UniswapV2Router02")
		var farmContext farmRuntimeContext
		var routerContext routerRuntimeContext
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || typedBuildObject(farmRaw, &farmContext) != nil || typedBuildObject(routerRaw, &routerContext) != nil || farmContext.Kind != "farm-reward-token" || routerContext.Kind != "uniswap-v2-router02" || !hash(farmContext.RuntimeTemplateSHA256, 64) || !hash(routerContext.RuntimeTemplateSHA256, 64) || routerContext.FactoryContract != context.FactoryContract || routerContext.WethContract != context.WethContract {
			return "", nil, fail
		}
		_, reward, err := m.applicationCounterpart(farmContext.RewardTokenContract, farm)
		if err != nil {
			return "", nil, fail
		}
		template = context.RuntimeTemplateSHA256
		words["farm"], words["router"], words["factory"] = common.BytesToHash(farmAddress.Bytes()), common.BytesToHash(routerAddress.Bytes()), common.BytesToHash(factoryAddress.Bytes())
		words["rewardToken"], words["weth"] = common.BytesToHash(reward.Bytes()), common.BytesToHash(wethAddress.Bytes())
	case "exchange-eip712-domain":
		var context struct {
			Kind                  string `json:"kind"`
			RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
		}
		chain, ok := new(big.Int).SetString(m.Epoch.L2ChainID, 10)
		if typedBuildObject(raw, &context) != nil || target.Unit != "apps/ZVMExchange.sol" || target.Name != "ZVMExchange" || !ok || chain.Sign() <= 0 || chain.BitLen() > 256 || chain.String() != m.Epoch.L2ChainID {
			return "", nil, fail
		}
		template = context.RuntimeTemplateSHA256
		name, version := crypto.Keccak256Hash([]byte("ZVM Exchange")), crypto.Keccak256Hash([]byte("1"))
		encoded := bytes.Clone(crypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")))
		encoded = append(encoded, name.Bytes()...)
		encoded = append(encoded, version.Bytes()...)
		encoded = append(encoded, chain.FillBytes(make([]byte, 32))...)
		encoded = append(encoded, common.LeftPadBytes(address.Bytes(), 32)...)
		words["_cachedDomainSeparator"], words["_cachedChainId"], words["_cachedThis"] = crypto.Keccak256Hash(encoded), common.BigToHash(chain), common.BytesToHash(address.Bytes())
		words["_hashedName"], words["_hashedVersion"] = name, version
		for key, value := range map[string]string{"_name": "ZVM Exchange", "_version": "1"} {
			var word common.Hash
			copy(word[:], []byte(value))
			word[31] = byte(len(value))
			words[key] = word
		}
	default:
		return "", nil, fail
	}
	if !hash(template, 64) {
		return "", nil, fail
	}
	return template, words, nil
}

type applicationASTContract struct {
	node       collectionAST
	source     string
	fileID     int
	start, end int
}

func applicationSpan(node collectionAST, source string, fileID int) (int, int, error) {
	parts := strings.Split(collectionString(node, "src"), ":")
	if len(parts) != 3 || parts[2] != strconv.Itoa(fileID) {
		return 0, 0, errors.New("invalid application source span identity")
	}
	start, e1 := strconv.Atoi(parts[0])
	length, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || start < 0 || length <= 0 || start > len(source) || length > len(source)-start || strconv.Itoa(start) != parts[0] || strconv.Itoa(length) != parts[1] {
		return 0, 0, errors.New("invalid application source span bounds")
	}
	return start, start + length, nil
}

func applicationASTDefinition(output *buildOutput, unit, name string) (applicationASTContract, error) {
	fail := errors.New("application saved source AST is absent or inconsistent")
	if output == nil {
		return applicationASTContract{}, fail
	}
	source, found := output.inputSources[unit]
	root := collectionNode(output.raw)
	for key := range root {
		if strings.EqualFold(key, "sources") && key != "sources" {
			return applicationASTContract{}, fail
		}
	}
	entry := collectionNode(collectionNode(root["sources"])[unit])
	var fileID int
	if !found || len(entry) != 2 || entry["id"] == nil || entry["ast"] == nil || json.Unmarshal(entry["id"], &fileID) != nil || fileID < 0 || fileID > 65535 {
		return applicationASTContract{}, fail
	}
	ast := collectionNode(entry["ast"])
	if collectionString(ast, "nodeType") != "SourceUnit" || collectionString(ast, "absolutePath") != unit {
		return applicationASTContract{}, fail
	}
	var contract collectionAST
	for _, raw := range collectionNodes(ast, "nodes") {
		n := collectionNode(raw)
		if collectionString(n, "nodeType") == "ContractDefinition" && collectionString(n, "name") == name {
			if contract != nil {
				return applicationASTContract{}, fail
			}
			contract = n
		}
	}
	if collectionID(contract, "id") == 0 || collectionString(contract, "contractKind") != "contract" {
		return applicationASTContract{}, fail
	}
	start, end, err := applicationSpan(contract, source, fileID)
	if err != nil {
		return applicationASTContract{}, fail
	}
	var constructor collectionAST
	for _, raw := range collectionNodes(contract, "nodes") {
		n := collectionNode(raw)
		if collectionString(n, "nodeType") == "FunctionDefinition" && collectionString(n, "kind") == "constructor" {
			if constructor != nil {
				return applicationASTContract{}, fail
			}
			constructor = n
		}
	}
	a, b, err := applicationSpan(constructor, source, fileID)
	if collectionID(constructor, "id") == 0 || collectionID(constructor, "scope") != collectionID(contract, "id") || err != nil || a < start || b > end {
		return applicationASTContract{}, fail
	}
	return applicationASTContract{node: contract, source: source, fileID: fileID, start: start, end: end}, nil
}

type applicationImmutableDeclaration struct{ name, kind, visibility, text string }

func applicationDeclarationIDs(contract applicationASTContract, wanted []applicationImmutableDeclaration) (map[string]string, error) {
	fail := errors.New("application immutable IDs do not match reviewed source declarations")
	result := map[string]string{}
	used := map[string]bool{}
	for _, raw := range collectionNodes(contract.node, "nodes") {
		n := collectionNode(raw)
		if collectionString(n, "nodeType") != "VariableDeclaration" || collectionString(n, "mutability") != "immutable" {
			continue
		}
		name := collectionString(n, "name")
		var spec *applicationImmutableDeclaration
		for i := range wanted {
			if wanted[i].name == name {
				spec = &wanted[i]
			}
		}
		id := strconv.Itoa(collectionID(n, "id"))
		a, b, err := applicationSpan(n, contract.source, contract.fileID)
		if spec == nil || id == "0" || used[id] || result[name] != "" || collectionID(n, "scope") != collectionID(contract.node, "id") || collectionString(n, "visibility") != spec.visibility || collectionString(collectionNode(n["typeDescriptions"]), "typeString") != spec.kind || !bytes.Equal(bytes.TrimSpace(n["stateVariable"]), []byte("true")) || (n["value"] != nil && !bytes.Equal(bytes.TrimSpace(n["value"]), []byte("null"))) || err != nil || a < contract.start || b > contract.end {
			return nil, fail
		}
		if strings.Join(strings.Fields(contract.source[a:b]), " ") != spec.text {
			return nil, fail
		}
		result[name] = id
		used[id] = true
	}
	if len(result) != len(wanted) {
		return nil, fail
	}
	return result, nil
}

func requireApplicationSources(output *buildOutput, pins map[string]string) error {
	if output == nil {
		return errors.New("application source inputs absent")
	}
	for unit, wanted := range pins {
		source, found := output.inputSources[unit]
		if !found || digest([]byte(source)) != wanted {
			return errors.New("application source differs from the reviewed constructor algorithm")
		}
	}
	return nil
}

func applicationImmutableIDs(output *buildOutput, target ContractBuildTarget) (map[string]string, error) {
	unit, name := target.Unit, target.Name
	pins := map[string]string{unit: applicationSourceDigests[unit]}
	var wanted []applicationImmutableDeclaration
	switch name {
	case "ZVMFarm":
		wanted = []applicationImmutableDeclaration{{"rewardToken", "contract IERC20", "public", "IERC20 public immutable rewardToken"}}
	case "ZVMFarmFeeStrategy":
		wanted = []applicationImmutableDeclaration{{"farm", "contract IZVMFarm", "public", "IZVMFarm public immutable farm"}, {"router", "contract IUniswapV2Router", "public", "IUniswapV2Router public immutable router"}, {"factory", "contract IUniswapV2Factory", "public", "IUniswapV2Factory public immutable factory"}, {"rewardToken", "contract IERC20", "public", "IERC20 public immutable rewardToken"}, {"weth", "address", "public", "address public immutable weth"}}
	case "UniswapV2Router02":
		wanted = []applicationImmutableDeclaration{{"factory", "address", "public", "address public immutable override factory"}, {"WETH", "address", "public", "address public immutable override WETH"}}
	case "ZVMExchange":
		unit, name = "@openzeppelin/contracts/utils/cryptography/EIP712.sol", "EIP712"
		pins[unit] = applicationSourceDigests[unit]
		pins["@openzeppelin/contracts/utils/ShortStrings.sol"] = applicationSourceDigests["@openzeppelin/contracts/utils/ShortStrings.sol"]
		for _, d := range []struct{ name, kind string }{{"_cachedDomainSeparator", "bytes32"}, {"_cachedChainId", "uint256"}, {"_cachedThis", "address"}, {"_hashedName", "bytes32"}, {"_hashedVersion", "bytes32"}, {"_name", "ShortString"}, {"_version", "ShortString"}} {
			wanted = append(wanted, applicationImmutableDeclaration{d.name, d.kind, "private", d.kind + " private immutable " + d.name})
		}
	default:
		return nil, errors.New("unsupported application declaration role")
	}
	if pins[target.Unit] == "" || requireApplicationSources(output, pins) != nil {
		return nil, errors.New("application requires exact reviewed source inputs")
	}
	declaration, err := applicationASTDefinition(output, unit, name)
	if err != nil {
		return nil, err
	}
	if target.Name == "ZVMExchange" {
		derived, err := applicationASTDefinition(output, target.Unit, target.Name)
		if err != nil {
			return nil, err
		}
		var bases []int
		if json.Unmarshal(derived.node["linearizedBaseContracts"], &bases) != nil {
			return nil, errors.New("exchange source inheritance missing")
		}
		matched := 0
		for _, id := range bases {
			if id == collectionID(declaration.node, "id") {
				matched++
			}
		}
		if matched != 1 {
			return nil, errors.New("exchange does not inherit its declared EIP712 source")
		}
	}
	return applicationDeclarationIDs(declaration, wanted)
}

func (m Manifest) resolveApplicationRuntime(raw json.RawMessage, target ContractBuildTarget, contract Contract, bytecode buildBytecode, runtime []byte, output *buildOutput, subjects map[string]applicationBuildSubject) ([]byte, error) {
	template, values, err := m.applicationRuntimeWords(raw, target, contract, subjects)
	if err != nil || digest(runtime) != template {
		return nil, errors.New("application runtime template or constructor context differs")
	}
	ids, err := applicationImmutableIDs(output, target)
	if err != nil || len(ids) != len(values) {
		return nil, errors.New("application source declaration inventory differs")
	}
	bindings := map[string]common.Hash{}
	for name, value := range values {
		id, found := ids[name]
		if !found {
			return nil, errors.New("application immutable declaration missing")
		}
		bindings[id] = value
	}
	return bindBuildRuntimeWords(bytecode.ImmutableReferences, runtime, bindings)
}
