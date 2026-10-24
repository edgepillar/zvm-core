package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// This is the reviewed direct-address constructor of ZVMCollectionFactory,
// not a general expression evaluator or a caller-supplied immutable word.
func (m Manifest) resolveCollectionFactoryRuntime(raw json.RawMessage, target ContractBuildTarget, contract Contract, bytecode buildBytecode, runtime []byte, build ContractBuild, contexts map[string]json.RawMessage, output *buildOutput) ([]byte, error) {
	var context struct {
		Kind                   string `json:"kind"`
		RuntimeTemplateSHA256  string `json:"runtimeTemplateSha256"`
		Immutable              string `json:"immutable"`
		ImplementationContract string `json:"implementationContract"`
	}
	if typedBuildObject(raw, &context) != nil || context.Kind != "collection-factory-implementation" || target.Unit != "apps/ZVMCollectionFactory.sol" || target.Name != "ZVMCollectionFactory" || !hash(context.RuntimeTemplateSHA256, 64) || digest(runtime) != context.RuntimeTemplateSHA256 || context.ImplementationContract == target.Contract {
		return nil, errors.New("invalid collection factory constructor context")
	}
	implementation, found := m.releaseContract(context.ImplementationContract)
	address := common.HexToAddress(implementation.Address)
	if !found || address == (common.Address{}) || implementation.Address != strings.ToLower(address.Hex()) || implementation.Address == contract.Address {
		return nil, errors.New("collection implementation identity is absent or invalid")
	}
	matched := 0
	for _, item := range build.Contracts {
		if item.Contract == context.ImplementationContract {
			if item.Unit != "apps/ZVMCollection.sol" || item.Name != "ZVMCollection" {
				return nil, errors.New("collection counterpart is not the declared implementation target")
			}
			matched++
		}
	}
	var exact struct {
		Kind                  string `json:"kind"`
		RuntimeTemplateSHA256 string `json:"runtimeTemplateSha256"`
	}
	if matched != 1 || typedBuildObject(contexts[context.ImplementationContract], &exact) != nil || exact.Kind != "exact" || !hash(exact.RuntimeTemplateSHA256, 64) {
		return nil, errors.New("collection counterpart must have one exact build context")
	}
	identity, err := collectionFactoryDeclaration(output, target.Unit)
	if err != nil || context.Immutable != identity {
		return nil, errors.New("collection immutable does not match its direct source declaration")
	}
	return bindBuildRuntimeWords(bytecode.ImmutableReferences, runtime, map[string]common.Hash{identity: common.BytesToHash(address.Bytes())})
}

type collectionAST map[string]json.RawMessage

func collectionNode(raw json.RawMessage) collectionAST {
	var n collectionAST
	if json.Unmarshal(raw, &n) != nil {
		return nil
	}
	return n
}
func collectionString(n collectionAST, key string) string {
	var v string
	if json.Unmarshal(n[key], &v) != nil {
		return ""
	}
	return v
}
func collectionID(n collectionAST, key string) int {
	var v int
	if json.Unmarshal(n[key], &v) != nil || v <= 0 || v > 1<<30 {
		return 0
	}
	return v
}
func collectionNodes(n collectionAST, key string) []json.RawMessage {
	var v []json.RawMessage
	if json.Unmarshal(n[key], &v) != nil || v == nil {
		return nil
	}
	return v
}
func collectionAddress(n collectionAST) bool {
	t := collectionNode(n["typeDescriptions"])
	name := collectionNode(n["typeName"])
	return collectionString(t, "typeString") == "address" && collectionString(name, "nodeType") == "ElementaryTypeName" && collectionString(name, "name") == "address" && collectionString(name, "stateMutability") == "nonpayable"
}

func collectionFactoryDeclaration(output *buildOutput, unit string) (string, error) {
	fail := errors.New("collection source AST does not prove its supported constructor")
	if output == nil {
		return "", fail
	}
	root := collectionNode(output.raw)
	for key := range root {
		if strings.EqualFold(key, "sources") && key != "sources" {
			return "", fail
		}
	}
	sources := collectionNode(root["sources"])
	entry := collectionNode(sources[unit])
	if len(entry) != 2 || entry["id"] == nil || entry["ast"] == nil {
		return "", fail
	}
	var fileID int
	if json.Unmarshal(entry["id"], &fileID) != nil || fileID < 0 || fileID > 65535 {
		return "", fail
	}
	ast := collectionNode(entry["ast"])
	if collectionString(ast, "nodeType") != "SourceUnit" || collectionString(ast, "absolutePath") != unit {
		return "", fail
	}
	var contract collectionAST
	for _, raw := range collectionNodes(ast, "nodes") {
		n := collectionNode(raw)
		if collectionString(n, "nodeType") == "ContractDefinition" && collectionString(n, "name") == "ZVMCollectionFactory" {
			if contract != nil {
				return "", fail
			}
			contract = n
		}
	}
	if collectionID(contract, "id") == 0 || collectionString(contract, "contractKind") != "contract" || !bytes.Equal(contract["abstract"], []byte("false")) || !bytes.Equal(bytes.TrimSpace(contract["baseContracts"]), []byte("[]")) {
		return "", fail
	}
	var variable, constructor collectionAST
	for _, raw := range collectionNodes(contract, "nodes") {
		n := collectionNode(raw)
		if collectionString(n, "nodeType") == "VariableDeclaration" && collectionString(n, "name") == "implementation" {
			if variable != nil {
				return "", fail
			}
			variable = n
		}
		if collectionString(n, "nodeType") == "FunctionDefinition" && collectionString(n, "kind") == "constructor" {
			if constructor != nil {
				return "", fail
			}
			constructor = n
		}
	}
	if collectionID(variable, "id") == 0 || collectionID(variable, "scope") != collectionID(contract, "id") || !collectionAddress(variable) || collectionString(variable, "mutability") != "immutable" || collectionString(variable, "visibility") != "public" || !bytes.Equal(variable["stateVariable"], []byte("true")) || (variable["value"] != nil && !bytes.Equal(variable["value"], []byte("null"))) {
		return "", fail
	}
	parameters := collectionNodes(collectionNode(constructor["parameters"]), "parameters")
	if collectionID(constructor, "id") == 0 || collectionID(constructor, "scope") != collectionID(contract, "id") || collectionString(constructor, "stateMutability") != "nonpayable" || !bytes.Equal(bytes.TrimSpace(constructor["modifiers"]), []byte("[]")) || len(parameters) != 1 {
		return "", fail
	}
	parameter := collectionNode(parameters[0])
	if collectionID(parameter, "id") == 0 || collectionID(parameter, "id") == collectionID(variable, "id") || collectionID(parameter, "scope") != collectionID(constructor, "id") || collectionString(parameter, "name") != "implementation_" || !collectionAddress(parameter) {
		return "", fail
	}
	statements := collectionNodes(collectionNode(constructor["body"]), "statements")
	if len(statements) != 1 {
		return "", fail
	}
	statement := collectionNode(statements[0])
	assignment := collectionNode(statement["expression"])
	left, right := collectionNode(assignment["leftHandSide"]), collectionNode(assignment["rightHandSide"])
	if collectionString(statement, "nodeType") != "ExpressionStatement" || collectionString(assignment, "nodeType") != "Assignment" || collectionString(assignment, "operator") != "=" || collectionString(left, "nodeType") != "Identifier" || collectionString(right, "nodeType") != "Identifier" || collectionString(left, "name") != "implementation" || collectionString(right, "name") != "implementation_" || collectionID(left, "referencedDeclaration") != collectionID(variable, "id") || collectionID(right, "referencedDeclaration") != collectionID(parameter, "id") {
		return "", fail
	}
	for _, n := range []collectionAST{contract, variable, constructor, parameter, statement, assignment, left, right} {
		parts := strings.Split(collectionString(n, "src"), ":")
		if len(parts) != 3 || parts[2] != strconv.Itoa(fileID) {
			return "", fail
		}
	}
	return strconv.Itoa(collectionID(variable, "id")), nil
}
