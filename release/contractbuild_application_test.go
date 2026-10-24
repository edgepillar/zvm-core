package release

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func applicationTestJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func applicationTestGraph() (Manifest, map[string]applicationBuildSubject) {
	m := Manifest{Epoch: Epoch{L2ChainID: "7340470"}}
	for index, id := range []string{"Farm", "Strategy", "Router", "Factory", "Reward", "Weth"} {
		m.Contracts = append(m.Contracts, Contract{ID: id, Address: fmt.Sprintf("0x%040x", index+1)})
	}
	m.Contracts = append(m.Contracts, Contract{ID: "Exchange", Address: "0xcf5ca9f56421d0dbd8c2b687945f7b2157d5a6db"})
	hash := strings.Repeat("a", 64)
	contexts := map[string]any{
		"Farm":     farmRuntimeContext{"farm-reward-token", hash, "Reward"},
		"Strategy": strategyRuntimeContext{"farm-fee-strategy", hash, "Farm", "Router", "Factory", "Weth"},
		"Router":   routerRuntimeContext{"uniswap-v2-router02", hash, "Factory", "Weth"},
		"Factory":  map[string]string{"kind": "exact", "runtimeTemplateSha256": hash},
		"Exchange": map[string]string{"kind": "exchange-eip712-domain", "runtimeTemplateSha256": hash},
	}
	subjects := map[string]applicationBuildSubject{}
	for id, role := range map[string][2]string{"Farm": {"apps/ZVMFarm.sol", "ZVMFarm"}, "Strategy": {"apps/ZVMFarmFeeStrategy.sol", "ZVMFarmFeeStrategy"}, "Router": {"contracts/UniswapV2Router02.sol", "UniswapV2Router02"}, "Factory": {"contracts/UniswapV2Factory.sol", "UniswapV2Factory"}, "Exchange": {"apps/ZVMExchange.sol", "ZVMExchange"}} {
		subjects[id] = applicationBuildSubject{ContractBuildTarget{Contract: id, Unit: role[0], Name: role[1]}, applicationTestJSON(contexts[id])}
	}
	return m, subjects
}

func applicationTestChangeContext(subjects map[string]applicationBuildSubject, id, key string, value any) {
	s := subjects[id]
	var fields map[string]any
	if err := json.Unmarshal(s.Context, &fields); err != nil {
		panic(err)
	}
	if value == nil {
		delete(fields, key)
	} else {
		fields[key] = value
	}
	s.Context = applicationTestJSON(fields)
	subjects[id] = s
}

func TestApplicationConstructorReleaseGraph(t *testing.T) {
	m, subjects := applicationTestGraph()
	for _, id := range []string{"Farm", "Router", "Strategy"} {
		t.Run(id, func(t *testing.T) {
			self, _ := m.releaseContract(id)
			subject := subjects[id]
			template, words, err := m.applicationRuntimeWords(subject.Context, subject.Target, self, subjects)
			if err != nil || template != strings.Repeat("a", 64) {
				t.Fatalf("valid release graph refused: %v", err)
			}
			roleIDs := map[string]map[string]string{"Farm": {"rewardToken": "Reward"}, "Router": {"factory": "Factory", "WETH": "Weth"}, "Strategy": {"farm": "Farm", "router": "Router", "factory": "Factory", "rewardToken": "Reward", "weth": "Weth"}}[id]
			if len(words) != len(roleIDs) {
				t.Fatal("constructor word inventory differs")
			}
			for name, identity := range roleIDs {
				counterpart, _ := m.releaseContract(identity)
				want := common.HexToHash("0x" + strings.Repeat("0", 24) + counterpart.Address[2:])
				if words[name] != want {
					t.Fatalf("%s does not bind exact release identity", name)
				}
			}
		})
	}
	// A changed signed farm argument changes both the farm and the strategy's
	// staticcall-derived word. There is no independent caller-supplied word.
	applicationTestChangeContext(subjects, "Farm", "rewardTokenContract", "Weth")
	for _, id := range []string{"Farm", "Strategy"} {
		self, _ := m.releaseContract(id)
		_, words, err := m.applicationRuntimeWords(subjects[id].Context, subjects[id].Target, self, subjects)
		if err != nil || words["rewardToken"] != common.HexToHash("0x06") {
			t.Fatal("farm/strategy reward identity diverged", err)
		}
	}
}

func TestApplicationExchangeNativeConstructorWords(t *testing.T) {
	m, subjects := applicationTestGraph()
	self, _ := m.releaseContract("Exchange")
	subject := subjects["Exchange"]
	_, words, err := m.applicationRuntimeWords(subject.Context, subject.Target, self, subjects)
	if err != nil {
		t.Fatal(err)
	}
	// These seven words were independently observed in the actual solc 0.8.30
	// constructor runtime for the synthetic address and chain above.
	want := map[string]string{
		"_cachedDomainSeparator": "49a20348a89e5cd4fa88a79e6d9eee0fcbb61d22e41f39619b37ec2842fd8aa5",
		"_cachedChainId":         "00000000000000000000000000000000000000000000000000000000007001b6",
		"_cachedThis":            "000000000000000000000000cf5ca9f56421d0dbd8c2b687945f7b2157d5a6db",
		"_hashedName":            "bcac45dd843bace2f89cccfae10ecd3d1e1191008c72a07f2681fc23366ba602",
		"_hashedVersion":         "c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6",
		"_name":                  "5a564d2045786368616e6765000000000000000000000000000000000000000c",
		"_version":               "3100000000000000000000000000000000000000000000000000000000000001",
	}
	if len(words) != len(want) {
		t.Fatal("EIP712 immutable inventory differs")
	}
	for name, hex := range want {
		if words[name] != common.HexToHash(hex) {
			t.Fatalf("native constructor word %s differs", name)
		}
	}
	m.Epoch.L2ChainID = "69"
	_, changed, err := m.applicationRuntimeWords(subject.Context, subject.Target, self, subjects)
	if err != nil || changed["_cachedChainId"] != common.HexToHash("0x45") || changed["_cachedDomainSeparator"] == words["_cachedDomainSeparator"] {
		t.Fatal("domain is not bound to the release epoch")
	}
}

func TestApplicationConstructorGraphRefusals(t *testing.T) {
	type change func(*Manifest, map[string]applicationBuildSubject)
	cases := []struct {
		name, id string
		change   change
	}{
		{"arbitrary-word", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Farm", "word", "0x01")
		}},
		{"missing-token", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Farm", "rewardTokenContract", nil)
		}},
		{"unknown-token", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Farm", "rewardTokenContract", "Missing")
		}},
		{"self-token", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Farm", "rewardTokenContract", "Farm")
		}},
		{"wrong-target-unit", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) {
			v := s["Farm"]
			v.Target.Unit = "other.sol"
			s["Farm"] = v
		}},
		{"wrong-target-name", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) {
			v := s["Farm"]
			v.Target.Name = "Other"
			s["Farm"] = v
		}},
		{"short-address", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) { m.Contracts[4].Address = "0x5" }},
		{"zero-address", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) {
			m.Contracts[4].Address = strings.Repeat("0", 40)
		}},
		{"aliased-address", "Farm", func(m *Manifest, s map[string]applicationBuildSubject) {
			m.Contracts[4].Address = m.Contracts[0].Address
		}},
		{"self-factory", "Router", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Router", "factoryContract", "Router")
		}},
		{"missing-weth", "Router", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Router", "wethContract", "Missing")
		}},
		{"wrong-factory-role", "Router", func(m *Manifest, s map[string]applicationBuildSubject) {
			v := s["Factory"]
			v.Target.Name = "ZVMFarm"
			s["Factory"] = v
		}},
		{"wrong-factory-unit", "Router", func(m *Manifest, s map[string]applicationBuildSubject) {
			v := s["Factory"]
			v.Target.Unit = "other.sol"
			s["Factory"] = v
		}},
		{"nonexact-factory", "Router", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Factory", "kind", "permit2-domain-cache")
		}},
		{"factory-arbitrary-word", "Router", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Factory", "word", "0x01")
		}},
		{"missing-factory-subject", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) { delete(s, "Factory") }},
		{"wrong-farm-role", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			v := s["Farm"]
			v.Target.Name = "ZVMCollection"
			s["Farm"] = v
		}},
		{"wrong-router-role", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			v := s["Router"]
			v.Target.Name = "UniswapV2Router01"
			s["Router"] = v
		}},
		{"farm-kind", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Farm", "kind", "exact")
		}},
		{"router-kind", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Router", "kind", "exact")
		}},
		{"router-factory-disagrees", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Router", "factoryContract", "Weth")
		}},
		{"router-weth-disagrees", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Router", "wethContract", "Reward")
		}},
		{"farm-token-absent", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Farm", "rewardTokenContract", "Missing")
		}},
		{"farm-token-self", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Farm", "rewardTokenContract", "Farm")
		}},
		{"strategy-extra-context", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Strategy", "rewardTokenContract", "Reward")
		}},
		{"bad-counterpart-template", "Strategy", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Farm", "runtimeTemplateSha256", strings.Repeat("0", 64))
		}},
		{"caller-chain-override", "Exchange", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Exchange", "chainId", "1")
		}},
		{"noncanonical-self-address", "Exchange", func(m *Manifest, s map[string]applicationBuildSubject) {
			m.Contracts[6].Address = "0xCF5ca9f56421d0dbd8c2b687945f7b2157d5a6db"
		}},
		{"zero-template", "Exchange", func(m *Manifest, s map[string]applicationBuildSubject) {
			applicationTestChangeContext(s, "Exchange", "runtimeTemplateSha256", strings.Repeat("0", 64))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, s := applicationTestGraph()
			c.change(&m, s)
			self, _ := m.releaseContract(c.id)
			subject := s[c.id]
			if _, _, err := m.applicationRuntimeWords(subject.Context, subject.Target, self, s); err == nil {
				t.Fatal("unbound constructor context accepted")
			}
		})
	}
	for _, chain := range []string{"", "0", "-1", "07340470", "0x7001b6", new(big.Int).Lsh(big.NewInt(1), 256).String()} {
		t.Run("invalid-chain-"+chain, func(t *testing.T) {
			m, s := applicationTestGraph()
			m.Epoch.L2ChainID = chain
			self, _ := m.releaseContract("Exchange")
			if _, _, err := m.applicationRuntimeWords(s["Exchange"].Context, s["Exchange"].Target, self, s); err == nil {
				t.Fatal("invalid release chain accepted")
			}
		})
	}
	for _, id := range []string{"Farm", "Strategy", "Router", "Exchange"} {
		t.Run("schema-one-"+id, func(t *testing.T) {
			m, s := applicationTestGraph()
			self, _ := m.releaseContract(id)
			if _, err := m.resolveBuildRuntime(s[id].Context, s[id].Target, self, buildBytecode{}, []byte{1}); err == nil {
				t.Fatal("new context leaked into the old resolver")
			}
		})
	}
}

func applicationTestAST() (*buildOutput, map[string]any, string) {
	unit := "apps/ZVMFarm.sol"
	source := "contract ZVMFarm { IERC20 public immutable rewardToken; constructor() {} }"
	declaration := "IERC20 public immutable rewardToken"
	variableStart := strings.Index(source, declaration)
	ctorStart := strings.Index(source, "constructor")
	variable := map[string]any{"nodeType": "VariableDeclaration", "id": 101, "scope": 100, "name": "rewardToken", "mutability": "immutable", "visibility": "public", "stateVariable": true, "typeDescriptions": map[string]any{"typeString": "contract IERC20"}, "src": fmt.Sprintf("%d:%d:0", variableStart, len(declaration))}
	ctor := map[string]any{"nodeType": "FunctionDefinition", "kind": "constructor", "id": 102, "scope": 100, "src": fmt.Sprintf("%d:%d:0", ctorStart, len("constructor() {}"))}
	contract := map[string]any{"nodeType": "ContractDefinition", "contractKind": "contract", "name": "ZVMFarm", "id": 100, "src": fmt.Sprintf("0:%d:0", len(source)), "nodes": []any{variable, ctor}}
	root := map[string]any{"sources": map[string]any{unit: map[string]any{"id": 0, "ast": map[string]any{"nodeType": "SourceUnit", "absolutePath": unit, "nodes": []any{contract}}}}}
	return &buildOutput{raw: applicationTestJSON(root), inputSources: map[string]string{unit: source}}, root, unit
}

func applicationTestASTNodes(root map[string]any, unit string) (map[string]any, map[string]any, map[string]any) {
	entry := root["sources"].(map[string]any)[unit].(map[string]any)
	contract := entry["ast"].(map[string]any)["nodes"].([]any)[0].(map[string]any)
	nodes := contract["nodes"].([]any)
	return contract, nodes[0].(map[string]any), nodes[1].(map[string]any)
}

func TestApplicationASTDeclarationSpans(t *testing.T) {
	output, _, unit := applicationTestAST()
	contract, err := applicationASTDefinition(output, unit, "ZVMFarm")
	if err != nil {
		t.Fatal(err)
	}
	wanted := []applicationImmutableDeclaration{{"rewardToken", "contract IERC20", "public", "IERC20 public immutable rewardToken"}}
	ids, err := applicationDeclarationIDs(contract, wanted)
	if err != nil || len(ids) != 1 || ids["rewardToken"] != "101" {
		t.Fatal("declaration/source span refused", err)
	}
	// A structurally consistent invented AST cannot replace the qualified source.
	if _, err := applicationImmutableIDs(output, ContractBuildTarget{Unit: unit, Name: "ZVMFarm"}); err == nil {
		t.Fatal("unreviewed source passed the production source gate")
	}
	cases := []struct {
		name   string
		change func(map[string]any, map[string]any, map[string]any)
	}{
		{"zero-id", func(c, v, k map[string]any) { v["id"] = 0 }},
		{"wrong-scope", func(c, v, k map[string]any) { v["scope"] = 999 }},
		{"unknown-name", func(c, v, k map[string]any) { v["name"] = "other" }},
		{"mutable", func(c, v, k map[string]any) { v["mutability"] = "mutable" }},
		{"wrong-visibility", func(c, v, k map[string]any) { v["visibility"] = "private" }},
		{"wrong-type", func(c, v, k map[string]any) { v["typeDescriptions"] = map[string]any{"typeString": "uint256"} }},
		{"not-state-variable", func(c, v, k map[string]any) { v["stateVariable"] = false }},
		{"initializer", func(c, v, k map[string]any) { v["value"] = map[string]any{"nodeType": "Literal", "value": "0"} }},
		{"wrong-file", func(c, v, k map[string]any) { v["src"] = "19:34:1" }},
		{"negative-start", func(c, v, k map[string]any) { v["src"] = "-1:34:0" }},
		{"zero-length", func(c, v, k map[string]any) { v["src"] = "19:0:0" }},
		{"oversized-span", func(c, v, k map[string]any) { v["src"] = "19:999999:0" }},
		{"wrong-lexeme", func(c, v, k map[string]any) { v["src"] = "20:33:0" }},
		{"noncanonical-span", func(c, v, k map[string]any) { v["src"] = "019:34:0" }},
		{"duplicate-declaration", func(c, v, k map[string]any) { c["nodes"] = []any{v, v, k} }},
		{"constructor-scope", func(c, v, k map[string]any) { k["scope"] = 999 }},
		{"constructor-outside-source", func(c, v, k map[string]any) { k["src"] = "1000:1:0" }},
		{"duplicate-constructor", func(c, v, k map[string]any) { c["nodes"] = []any{v, k, k} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			o, root, u := applicationTestAST()
			c, v, k := applicationTestASTNodes(root, u)
			test.change(c, v, k)
			o.raw = applicationTestJSON(root)
			d, err := applicationASTDefinition(o, u, "ZVMFarm")
			if err == nil {
				_, err = applicationDeclarationIDs(d, wanted)
			}
			if err == nil {
				t.Fatal("inconsistent declaration/source span accepted")
			}
		})
	}
	for _, change := range []string{"missing-input", "missing-ast", "aliased-sources", "wrong-unit"} {
		t.Run(change, func(t *testing.T) {
			o, root, u := applicationTestAST()
			switch change {
			case "missing-input":
				o.inputSources = nil
			case "missing-ast":
				delete(root["sources"].(map[string]any)[u].(map[string]any), "ast")
			case "aliased-sources":
				root["Sources"] = root["sources"]
				delete(root, "sources")
			case "wrong-unit":
				root["sources"].(map[string]any)[u].(map[string]any)["ast"].(map[string]any)["absolutePath"] = "other.sol"
			}
			o.raw = applicationTestJSON(root)
			if _, err := applicationASTDefinition(o, u, "ZVMFarm"); err == nil {
				t.Fatal("unbound source AST accepted")
			}
		})
	}
}

func TestApplicationSourceFingerprintGate(t *testing.T) {
	output := &buildOutput{inputSources: map[string]string{"a.sol": "reviewed source a", "b.sol": "reviewed source b"}}
	pins := map[string]string{"a.sol": digest([]byte("reviewed source a")), "b.sol": digest([]byte("reviewed source b"))}
	if err := requireApplicationSources(output, pins); err != nil {
		t.Fatal(err)
	}
	output.inputSources["a.sol"] += " "
	if err := requireApplicationSources(output, pins); err == nil {
		t.Fatal("changed literal accepted")
	}
	delete(output.inputSources, "a.sol")
	if err := requireApplicationSources(output, pins); err == nil {
		t.Fatal("missing literal accepted")
	}
	if err := requireApplicationSources(nil, pins); err == nil {
		t.Fatal("missing source bundle accepted")
	}
}
