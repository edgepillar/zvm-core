package release

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func collectionFixture(t *testing.T) (Manifest, ContractBuild, map[string]json.RawMessage, ContractBuildTarget, Contract, buildBytecode, []byte, *buildOutput) {
	t.Helper()
	address := func() map[string]any {
		return map[string]any{"typeDescriptions": map[string]any{"typeString": "address"}, "typeName": map[string]any{"nodeType": "ElementaryTypeName", "name": "address", "stateMutability": "nonpayable"}}
	}
	variable := address()
	for k, v := range map[string]any{"nodeType": "VariableDeclaration", "name": "implementation", "id": 5, "scope": 7, "src": "0:1:3", "mutability": "immutable", "visibility": "public", "stateVariable": true} {
		variable[k] = v
	}
	parameter := address()
	for k, v := range map[string]any{"nodeType": "VariableDeclaration", "name": "implementation_", "id": 12, "scope": 11, "src": "0:1:3"} {
		parameter[k] = v
	}
	assignment := map[string]any{"nodeType": "Assignment", "operator": "=", "src": "0:1:3", "leftHandSide": map[string]any{"nodeType": "Identifier", "name": "implementation", "referencedDeclaration": 5, "src": "0:1:3"}, "rightHandSide": map[string]any{"nodeType": "Identifier", "name": "implementation_", "referencedDeclaration": 12, "src": "0:1:3"}}
	constructor := map[string]any{"nodeType": "FunctionDefinition", "kind": "constructor", "id": 11, "scope": 7, "src": "0:1:3", "stateMutability": "nonpayable", "modifiers": []any{}, "parameters": map[string]any{"parameters": []any{parameter}}, "body": map[string]any{"statements": []any{map[string]any{"nodeType": "ExpressionStatement", "src": "0:1:3", "expression": assignment}}}}
	ast := map[string]any{"nodeType": "SourceUnit", "absolutePath": "apps/ZVMCollectionFactory.sol", "nodes": []any{map[string]any{"nodeType": "ContractDefinition", "name": "ZVMCollectionFactory", "contractKind": "contract", "id": 7, "src": "0:1:3", "abstract": false, "baseContracts": []any{}, "nodes": []any{variable, constructor}}}}
	raw := buildRaw(t, map[string]any{"sources": map[string]any{"apps/ZVMCollectionFactory.sol": map[string]any{"id": 3, "ast": ast}}})
	implementation := Contract{ID: "implementation", Address: "0x0000000000000000000000000000000000000011"}
	factory := Contract{ID: "factory", Address: "0x0000000000000000000000000000000000000022"}
	target := ContractBuildTarget{Contract: factory.ID, Unit: "apps/ZVMCollectionFactory.sol", Name: "ZVMCollectionFactory"}
	counterpart := ContractBuildTarget{Contract: implementation.ID, Unit: "apps/ZVMCollection.sol", Name: "ZVMCollection"}
	template := make([]byte, 96)
	template[0] = 0x60
	template[95] = 0xf3
	contexts := map[string]json.RawMessage{factory.ID: buildRaw(t, map[string]any{"kind": "collection-factory-implementation", "runtimeTemplateSha256": digest(template), "immutable": "5", "implementationContract": implementation.ID}), implementation.ID: buildRaw(t, map[string]any{"kind": "exact", "runtimeTemplateSha256": strings.Repeat("1", 64)})}
	bytecode := buildBytecode{ImmutableReferences: buildRaw(t, map[string]any{"5": []any{map[string]any{"start": 4, "length": 32}, map[string]any{"start": 40, "length": 32}}})}
	return Manifest{Contracts: []Contract{factory, implementation}}, ContractBuild{Contracts: []ContractBuildTarget{target, counterpart}}, contexts, target, factory, bytecode, template, &buildOutput{raw: raw}
}

func TestCollectionFactorySourceDerivedRuntimeBinding(t *testing.T) {
	m, b, contexts, target, contract, bytecode, template, out := collectionFixture(t)
	got, err := m.resolveCollectionFactoryRuntime(contexts[contract.ID], target, contract, bytecode, template, b, contexts, out)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(template)
	word := common.LeftPadBytes(common.HexToAddress(m.Contracts[1].Address).Bytes(), 32)
	copy(want[4:36], word)
	copy(want[40:72], word)
	if !bytes.Equal(got, want) || template[35] != 0 || template[71] != 0 {
		t.Fatal("Source-derived address changed other bytes or the original template")
	}
	if _, err := m.resolveBuildRuntime(contexts[contract.ID], target, contract, bytecode, template); err == nil {
		t.Fatal("Legacy context resolver accepted a new witness")
	}
}

func TestCollectionFactoryRefusesUnboundContextsAndSource(t *testing.T) {
	for _, name := range []string{"missing AST", "AST alias", "wrong unit", "wrong class", "mutable declaration", "wrong variable type", "declaration initializer", "unbound immutable ID", "wrong parameter", "wrong assignment", "extra statement", "modifier", "base constructor", "foreign source", "missing counterpart", "wrong counterpart target", "nonexact counterpart", "self counterpart", "arbitrary word", "prefilled range", "uncovered map", "changed metadata byte"} {
		t.Run(name, func(t *testing.T) {
			m, b, contexts, target, contract, bytecode, template, out := collectionFixture(t)
			var root map[string]any
			mustDecode := func(raw []byte, value any) {
				t.Helper()
				if err := json.Unmarshal(raw, value); err != nil {
					t.Fatal(err)
				}
			}
			mustDecode(out.raw, &root)
			entry := root["sources"].(map[string]any)[target.Unit].(map[string]any)
			ast := entry["ast"].(map[string]any)
			definition := ast["nodes"].([]any)[0].(map[string]any)
			nodes := definition["nodes"].([]any)
			variable := nodes[0].(map[string]any)
			ctor := nodes[1].(map[string]any)
			param := ctor["parameters"].(map[string]any)["parameters"].([]any)[0].(map[string]any)
			body := ctor["body"].(map[string]any)
			assignment := body["statements"].([]any)[0].(map[string]any)["expression"].(map[string]any)
			var context map[string]any
			mustDecode(contexts[contract.ID], &context)
			switch name {
			case "missing AST":
				delete(entry, "ast")
			case "AST alias":
				entry["AST"] = entry["ast"]
				delete(entry, "ast")
			case "wrong unit":
				ast["absolutePath"] = "different.sol"
			case "wrong class":
				definition["name"] = "OtherFactory"
			case "mutable declaration":
				variable["mutability"] = "mutable"
			case "wrong variable type":
				variable["typeDescriptions"].(map[string]any)["typeString"] = "uint256"
			case "declaration initializer":
				variable["value"] = map[string]any{"nodeType": "Literal"}
			case "unbound immutable ID":
				context["immutable"] = "6"
			case "wrong parameter":
				param["id"] = 13
			case "wrong assignment":
				assignment["rightHandSide"].(map[string]any)["referencedDeclaration"] = 5
			case "extra statement":
				body["statements"] = append(body["statements"].([]any), map[string]any{"nodeType": "ExpressionStatement"})
			case "modifier":
				ctor["modifiers"] = []any{map[string]any{}}
			case "base constructor":
				definition["baseContracts"] = []any{map[string]any{}}
			case "foreign source":
				param["src"] = "0:1:4"
			case "missing counterpart":
				m.Contracts = m.Contracts[:1]
			case "wrong counterpart target":
				b.Contracts[1].Name = "AnotherCollection"
			case "nonexact counterpart":
				contexts["implementation"] = buildRaw(t, map[string]any{"kind": "collection-factory-implementation"})
			case "self counterpart":
				context["implementationContract"] = contract.ID
			case "arbitrary word":
				context["value"] = "0x11"
			case "prefilled range":
				template[4] = 1
				context["runtimeTemplateSha256"] = digest(template)
			case "uncovered map":
				bytecode.ImmutableReferences = buildRaw(t, map[string]any{"5": []any{map[string]any{"start": 4, "length": 32}}, "6": []any{map[string]any{"start": 40, "length": 32}}})
			case "changed metadata byte":
				template[95] ^= 1
			}
			contexts[contract.ID] = buildRaw(t, context)
			out.raw = buildRaw(t, root)
			if _, err := m.resolveCollectionFactoryRuntime(contexts[contract.ID], target, contract, bytecode, template, b, contexts, out); err == nil {
				t.Fatal("Unbound context or source accepted")
			}
		})
	}
}
