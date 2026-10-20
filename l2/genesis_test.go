package l2

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
)

// emptyTrieRoot is the root of an empty Merkle-Patricia trie, which is what an
// account with no storage hashes to.
var emptyTrieRoot = common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

// The L2ToL1MessagePasser has to be in the genesis state even though this chain
// never uses OP's withdrawal path, because Isthmus sets the header's
// withdrawalsRoot to *that account's* storage root. With the account missing the
// spec says nothing and clients disagree: op-geth hashed the zero hash and
// op-reth the empty-trie root, so the two built different genesis blocks and
// the chain would not start (D2). Deleting this predeploy silently splits the
// chain between clients, which is why it is pinned here.
func TestGenesisCarriesTheMessagePasser(t *testing.T) {
	addr := common.HexToAddress("0x4200000000000000000000000000000000000016")
	if _, ok := Predeploys()["L2ToL1MessagePasser"]; !ok {
		t.Fatal("L2ToL1MessagePasser is not a predeploy: op-geth and op-reth will build different genesis blocks")
	}
	cfg, err := rollup.Load(chainDir(t, "l2") + "/rollup.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := BuildGenesis(cfg, cfg.L2GenesisTimestamp)
	if err != nil {
		t.Fatal(err)
	}
	if acct, ok := g.Alloc[addr]; !ok || len(acct.Code) == 0 {
		t.Fatalf("no code at %s in the genesis alloc", addr)
	}
	h := g.ToBlock().Header()
	if h.WithdrawalsHash == nil {
		t.Fatal("genesis has no withdrawalsRoot, but Isthmus is active at genesis")
	}
	if *h.WithdrawalsHash != emptyTrieRoot {
		t.Fatalf("withdrawalsRoot is %s, want the empty-trie root %s — the message passer's storage is meant to be empty, and a zero hash here is the op-geth/op-reth split",
			h.WithdrawalsHash, emptyTrieRoot)
	}
}

// The committed genesis.json is what the execution client is initialised from,
// and rollup.json's l2GenesisHash is what the deriver checks it against. If
// BuildGenesis drifts from either, a chain either refuses to start or — worse —
// starts against a genesis nobody meant. Both chains are checked, because D4
// says every change is carried on both rulesets.
func TestCommittedGenesisMatchesBuildGenesis(t *testing.T) {
	for _, dir := range []string{"l2", "l2-dp"} {
		t.Run(dir, func(t *testing.T) {
			cfg, err := rollup.Load(chainDir(t, dir) + "/rollup.json")
			if err != nil {
				t.Fatal(err)
			}
			built, err := BuildGenesis(cfg, cfg.L2GenesisTimestamp)
			if err != nil {
				t.Fatal(err)
			}
			if got := built.ToBlock().Hash(); got != cfg.L2GenesisHash {
				t.Errorf("BuildGenesis is %s, rollup.json says %s — regenerate with `zvm l2-genesis`", got, cfg.L2GenesisHash)
			}

			raw, err := os.ReadFile(chainDir(t, dir) + "/genesis.json")
			if err != nil {
				t.Fatal(err)
			}
			var committed core.Genesis
			if err := json.Unmarshal(raw, &committed); err != nil {
				t.Fatal(err)
			}
			if got := committed.ToBlock().Hash(); got != cfg.L2GenesisHash {
				t.Errorf("committed genesis.json is %s, rollup.json says %s", got, cfg.L2GenesisHash)
			}
		})
	}
}
