package stateaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
)

var partitionLimits = PartitionLimits{MaxGroups: 64, MaxAddresses: 4096}

func partitionAddress(n int) string { return fmt.Sprintf("0x%040x", n) }
func partitionFixturePolicy() PartitionPolicy {
	return PartitionPolicy{Schema: 1, Groups: []PartitionGroup{
		{ID: "bridge", Addresses: []string{partitionAddress(4096), partitionAddress(4099)}},
		{ID: "fees", Addresses: []string{partitionAddress(4097), partitionAddress(4159)}},
		{ID: "sink", Addresses: []string{partitionAddress(39321)}},
	}}
}
func partitionPin(t *testing.T, p PartitionPolicy) string {
	t.Helper()
	pin, err := p.Fingerprint(partitionLimits)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}
func assertPartitionOracle(t *testing.T, f stateFixture, p PartitionPolicy, result PartitionedSummary) {
	t.Helper()
	s, err := state.New(f.root, f.db)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.StateRoot != f.root || result.Summary.NativeBalanceWei != f.sum || result.Summary.Accounts != f.n || len(result.Groups) != len(p.Groups) {
		t.Fatal("partition lost the complete independently produced state")
	}
	total := new(big.Int)
	present := uint64(0)
	for i, group := range p.Groups {
		balance := new(big.Int)
		count := uint64(0)
		for _, text := range group.Addresses {
			address := common.HexToAddress(text)
			if s.Exist(address) {
				count++
			}
			balance.Add(balance, s.GetBalance(address).ToBig())
		}
		got := result.Groups[i]
		if got.ID != group.ID || got.SelectedAccounts != uint64(len(group.Addresses)) || got.PresentAccounts != count || got.NativeBalanceWei != balance.String() {
			t.Fatalf("group differs from geth state oracle: %+v", got)
		}
		present += count
		total.Add(total, balance)
	}
	remainder, ok := new(big.Int).SetString(result.RemainderBalanceWei, 10)
	if !ok || remainder.Sign() < 0 || result.RemainderAccounts+present != f.n || new(big.Int).Add(total, remainder).String() != f.sum {
		t.Fatal("group and remainder conservation failed")
	}
}
func TestPartitionMeasuresDisjointGroupsDuringCompleteVerificationAndKeepsInputs(t *testing.T) {
	f := fixture(t, 64, true)
	w := collected(t, f)
	p := partitionFixturePolicy()
	before := encJSON(struct {
		Policy  PartitionPolicy
		Witness Witness
	}{p, w})
	result, err := VerifyPartition(context.Background(), f.root, partitionPin(t, p), p, w, testLimits, partitionLimits)
	if err != nil {
		t.Fatal(err)
	}
	assertPartitionOracle(t, f, p, result)
	if result.Groups[1].PresentAccounts != 2 || result.Groups[2].PresentAccounts != 0 || result.Groups[2].NativeBalanceWei != "0" {
		t.Fatal("zero-balance presence and proven absence were conflated")
	}
	if !bytes.Equal(before, encJSON(struct {
		Policy  PartitionPolicy
		Witness Witness
	}{p, w})) {
		t.Fatal("partition verification changed caller inputs")
	}
	raw := encJSON(result)
	for _, group := range p.Groups {
		for _, address := range group.Addresses {
			if bytes.Contains(raw, []byte(address)) {
				t.Fatal("aggregate output exposed an address inventory")
			}
		}
	}
}
func TestPartitionMatchesGethOracleAcrossDisjointSelectionsIncludingFullCoverage(t *testing.T) {
	f := fixture(t, 64, true)
	w := collected(t, f)
	for seed := int64(0); seed < 16; seed++ {
		t.Run(fmt.Sprintf("selection-%d", seed), func(t *testing.T) {
			groups := []PartitionGroup{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
			random := rand.New(rand.NewSource(seed))
			for account := 4096; account < 4160; account++ {
				index := random.Intn(5)
				if index < 4 {
					groups[index].Addresses = append(groups[index].Addresses, partitionAddress(account))
				}
			}
			p := PartitionPolicy{Schema: 1}
			for _, group := range groups {
				if len(group.Addresses) != 0 {
					p.Groups = append(p.Groups, group)
				}
			}
			result, err := VerifyPartition(context.Background(), f.root, partitionPin(t, p), p, w, testLimits, partitionLimits)
			if err != nil {
				t.Fatal(err)
			}
			assertPartitionOracle(t, f, p, result)
		})
	}
	all := PartitionPolicy{Schema: 1, Groups: []PartitionGroup{{ID: "all"}}}
	for account := 4096; account < 4160; account++ {
		all.Groups[0].Addresses = append(all.Groups[0].Addresses, partitionAddress(account))
	}
	all.Groups[0].Addresses = append(all.Groups[0].Addresses, partitionAddress(39321))
	result, err := VerifyPartition(context.Background(), f.root, partitionPin(t, all), all, w, testLimits, partitionLimits)
	if err != nil || result.RemainderAccounts != 0 || result.RemainderBalanceWei != "0" || result.Groups[0].NativeBalanceWei != f.sum {
		t.Fatalf("full selected coverage changed the aggregate: %+v %v", result, err)
	}
	assertPartitionOracle(t, f, all, result)
}
func TestPartitionEmptyStateProvesZeroOnlyAfterCompleteWitnessVerification(t *testing.T) {
	p := PartitionPolicy{Schema: 1, Groups: []PartitionGroup{{ID: "zero-address", Addresses: []string{partitionAddress(0)}}}}
	w := Witness{StateRoot: types.EmptyRootHash}
	result, err := VerifyPartition(context.Background(), types.EmptyRootHash, partitionPin(t, p), p, w, testLimits, partitionLimits)
	if err != nil || result.Groups[0].PresentAccounts != 0 || result.Groups[0].NativeBalanceWei != "0" || result.RemainderAccounts != 0 || result.RemainderBalanceWei != "0" {
		t.Fatal("verified empty state was not represented exactly")
	}
	w.Nodes = [][]byte{{0xc0}}
	if got, err := VerifyPartition(context.Background(), types.EmptyRootHash, partitionPin(t, p), p, w, testLimits, partitionLimits); err == nil || !reflect.DeepEqual(got, PartitionedSummary{}) {
		t.Fatal("extra nodes became a proved zero")
	}
}
func TestPartitionRejectsEveryIncompleteCoverageInsteadOfTreatingMissingAsZero(t *testing.T) {
	f := fixture(t, 8, false)
	w := collected(t, f)
	p := PartitionPolicy{Schema: 1, Groups: []PartitionGroup{{ID: "selected", Addresses: []string{partitionAddress(4096)}}}}
	pin := partitionPin(t, p)
	for i := range w.Nodes {
		partial := Witness{StateRoot: w.StateRoot, Nodes: append(append([][]byte(nil), w.Nodes[:i]...), w.Nodes[i+1:]...)}
		if got, err := VerifyPartition(context.Background(), f.root, pin, p, partial, testLimits, partitionLimits); err == nil || !reflect.DeepEqual(got, PartitionedSummary{}) {
			t.Fatal("omitted selected or unselected state produced a partition")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := VerifyPartition(ctx, f.root, pin, p, w, testLimits, partitionLimits); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, PartitionedSummary{}) {
		t.Fatal("canceled traversal emitted group values")
	}
}
func TestPartitionPolicyRejectsOverlapAmbiguousOrderingAndUnboundedAuthority(t *testing.T) {
	base := partitionFixturePolicy()
	raw := encJSON(base)
	for _, kind := range []string{"schema", "empty-groups", "empty-addresses", "group-order", "group-alias", "duplicate-group", "address-order", "duplicate-address", "overlap", "short-address", "uppercase-address", "invalid-hex", "zero-group-limit", "zero-address-limit", "large-group-limit", "large-address-limit", "group-cap", "address-cap"} {
		t.Run(kind, func(t *testing.T) {
			var p PartitionPolicy
			json.Unmarshal(raw, &p)
			bounds := partitionLimits
			switch kind {
			case "schema":
				p.Schema = 2
			case "empty-groups":
				p.Groups = nil
			case "empty-addresses":
				p.Groups[0].Addresses = nil
			case "group-order":
				p.Groups[0], p.Groups[1] = p.Groups[1], p.Groups[0]
			case "group-alias":
				p.Groups[0].ID = "Bridge"
			case "duplicate-group":
				p.Groups[1].ID = p.Groups[0].ID
			case "address-order":
				p.Groups[0].Addresses[0], p.Groups[0].Addresses[1] = p.Groups[0].Addresses[1], p.Groups[0].Addresses[0]
			case "duplicate-address":
				p.Groups[0].Addresses[1] = p.Groups[0].Addresses[0]
			case "overlap":
				p.Groups[2].Addresses = []string{p.Groups[0].Addresses[0]}
			case "short-address":
				p.Groups[0].Addresses[0] = "0x1"
			case "uppercase-address":
				p.Groups[2].Addresses[0] = "0x" + strings.Repeat("A", 40)
			case "invalid-hex":
				p.Groups[2].Addresses[0] = "0x" + strings.Repeat("g", 40)
			case "zero-group-limit":
				bounds.MaxGroups = 0
			case "zero-address-limit":
				bounds.MaxAddresses = 0
			case "large-group-limit":
				bounds.MaxGroups = 65
			case "large-address-limit":
				bounds.MaxAddresses = 4097
			case "group-cap":
				bounds.MaxGroups = 2
			case "address-cap":
				bounds.MaxAddresses = 4
			}
			if pin, err := p.Fingerprint(bounds); err == nil || pin != "" {
				t.Fatal("invalid partition acquired an accepted fingerprint")
			}
		})
	}
}
func TestPartitionStrictJSONAndDomainSeparatedPolicyPin(t *testing.T) {
	p := partitionFixturePolicy()
	raw := encJSON(p)
	pin := partitionPin(t, p)
	if pin != "5217337bf2230ff2736ba7b254d847d374863e7fee78dbb6128af7dcb527d84e" {
		t.Fatal("canonical partition domain or typed JSON changed")
	}
	pretty, _ := json.MarshalIndent(p, "", "  ")
	decoded, err := DecodePartitionPolicy(pretty, 1<<20, partitionLimits)
	if err != nil || partitionPin(t, decoded) != pin {
		t.Fatal("typed canonical policy pin depends on whitespace")
	}
	for _, kind := range []string{"alias", "duplicate", "unknown", "missing", "null", "null-address", "trailing", "document-cap"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(raw)
			limit := uint64(1 << 20)
			switch kind {
			case "alias":
				bad = bytes.Replace(bad, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "duplicate":
				bad = bytes.Replace(bad, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
			case "unknown":
				bad = append([]byte(`{"unknown":1,`), bad[1:]...)
			case "missing":
				bad = bytes.Replace(bad, []byte(`"schema":1,`), nil, 1)
			case "null":
				bad = bytes.Replace(bad, []byte(`"schema":1`), []byte(`"schema":null`), 1)
			case "null-address":
				bad = bytes.Replace(bad, encJSON(p.Groups[0].Addresses[0]), []byte(`null`), 1)
			case "trailing":
				bad = append(bad, []byte(` {}`)...)
			case "document-cap":
				limit = 1
			}
			if got, err := DecodePartitionPolicy(bad, limit, partitionLimits); err == nil || !reflect.DeepEqual(got, PartitionPolicy{}) {
				t.Fatal("ambiguous JSON became an accepted selection")
			}
		})
	}
	f := fixture(t, 8, false)
	w := collected(t, f)
	for _, badPin := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 64), strings.ToUpper(pin)} {
		if got, err := VerifyPartition(context.Background(), f.root, badPin, p, w, testLimits, partitionLimits); err == nil || !reflect.DeepEqual(got, PartitionedSummary{}) {
			t.Fatal("group selection bypassed its independent pin")
		}
	}
}
func TestBoundAndFramedPartitionPreserveAcceptedContextCheckpointAndWireFormat(t *testing.T) {
	f := snapshotFixture(t)
	p := partitionFixturePolicy()
	pin := partitionPin(t, p)
	bound, err := VerifySnapshotPartition(context.Background(), f.policy, f.snapshot, pin, p, f.witness, nil, fixtureNow, testLimits, bindingLimits, partitionLimits)
	if err != nil || bound.Bound.CheckpointSHA256 != f.result.CheckpointSHA256 || bound.Partition.Summary != f.result.Summary || bound.Partition.PartitionSHA256 != pin {
		t.Fatalf("partition changed accepted snapshot or checkpoint: %+v %v", bound, err)
	}
	var stream bytes.Buffer
	if err := EncodeInput(context.Background(), &stream, resumePolicy(f), f.snapshot, &f.result.Checkpoint, f.witness, testLimits, bindingLimits); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyInputPartition(context.Background(), bytes.NewReader(stream.Bytes()), pin, p, fixtureNow+1, testLimits, bindingLimits, partitionLimits)
	if err != nil || result.Bound.Checkpoint.FirstObservedAt != fixtureNow || result.Partition.Summary != bound.Partition.Summary {
		t.Fatal("partition stream discarded checkpoint history")
	}
	for _, kind := range []string{"stale", "context", "checkpoint", "policy-pin", "truncated", "trailing", "version"} {
		t.Run(kind, func(t *testing.T) {
			now := fixtureNow + 1
			data := bytes.Clone(stream.Bytes())
			expected := pin
			policy := resumePolicy(f)
			previous := f.result.Checkpoint
			switch kind {
			case "stale":
				now += 100
			case "context":
				policy.Expected.ChainID = "1"
			case "checkpoint":
				previous.NativeBalanceWei = "0"
			case "policy-pin":
				expected = strings.Repeat("a", 64)
			case "truncated":
				data = data[:len(data)-1]
			case "trailing":
				data = append(data, 0)
			case "version":
				data[7]++
			}
			if kind == "context" || kind == "checkpoint" {
				var changed bytes.Buffer
				if err := EncodeInput(context.Background(), &changed, policy, f.snapshot, &previous, f.witness, testLimits, bindingLimits); err != nil {
					t.Fatal(err)
				}
				data = changed.Bytes()
			}
			if got, err := VerifyInputPartition(context.Background(), bytes.NewReader(data), expected, p, now, testLimits, bindingLimits, partitionLimits); err == nil || !reflect.DeepEqual(got, BoundPartitionedSummary{}) {
				t.Fatal("invalid context returned partial groups or checkpoint")
			}
		})
	}
}
