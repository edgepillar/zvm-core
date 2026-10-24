package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
)

func protocolFixture(t *testing.T) (*fixture, []byte, ProtocolActivationPolicy) {
	t.Helper()
	f := newFixture(t)
	raw, err := os.ReadFile("../chains/l2/rollup.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := f.manifest.BindConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := ProtocolActivationPolicy{Schema: 1, EpochID: f.manifest.Epoch.ID, ChainID: f.manifest.Epoch.L2ChainID, GenesisHash: f.manifest.Epoch.L2GenesisHash, RollupSHA256: f.manifest.Epoch.RollupSHA256}
	for rule, height := range configuredProtocolRules(cfg) {
		p.Requirements = append(p.Requirements, ProtocolRequirement{rule, 1, height})
	}
	slices.SortFunc(p.Requirements, func(a, b ProtocolRequirement) int { return strings.Compare(a.Rule, b.Rule) })
	return f, raw, p
}

func protocolJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pinProtocol(t *testing.T, f *fixture, raw []byte) {
	t.Helper()
	pin := File{ID: ProtocolPolicyFileID, Kind: "config", Repository: "zvm-core", Path: "protocol.fixture.json", Bytes: int64(len(raw)), SHA256: digest(raw)}
	found := false
	for i := range f.manifest.Files {
		if f.manifest.Files[i].ID == pin.ID {
			f.manifest.Files[i] = pin
			found = true
		}
	}
	if !found {
		f.manifest.Files = append(f.manifest.Files, pin)
		f.policy.Files = append(f.policy.Files, FileRequirement{ID: pin.ID, Kind: pin.Kind, Repository: pin.Repository, Path: pin.Path})
	}
	var err error
	f.manifest.PolicySHA256, err = f.policy.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
}

func acceptedProtocol(t *testing.T, f *fixture, configuration, protocol []byte) (*rollup.Config, *Assertion, *ProtocolGuard, error) {
	t.Helper()
	return DecodeProtocolConfiguration(protocolJSON(t, f.manifest), protocolJSON(t, f.policy), protocolJSON(t, f.signatures(t)), protocolJSON(t, f.keys), configuration, protocol)
}

func TestProtocolGuardSupportedAndUnsupportedActivationBoundaries(t *testing.T) {
	f, configuration, policy := protocolFixture(t)
	policy.Requirements = append(policy.Requirements, ProtocolRequirement{"wire", 2, 400}, ProtocolRequirement{"future-rule", 1, 400})
	raw := protocolJSON(t, policy)
	pinProtocol(t, f, raw)
	cfg, a, guard, err := acceptedProtocol(t, f, configuration, raw)
	if err != nil || a == nil || a.RuntimeObserved || guard == nil {
		t.Fatalf("signed policy not accepted: %v", err)
	}
	for _, height := range []uint64{1, 2, 9, 10, 11, 199, 200, 201, 399} {
		if err := guard.Check(cfg, height); err != nil {
			t.Fatalf("supported momentum %d refused: %v", height, err)
		}
	}
	for _, height := range []uint64{400, 401, math.MaxUint64} {
		var halt *ProtocolHalt
		if err := guard.Check(cfg, height); !errors.As(err, &halt) || halt.Requirement.Rule != "future-rule" || halt.Requirement.Momentum != 400 {
			t.Fatalf("wrong deterministic stop at %d: %v", height, err)
		}
	}
	snapshot := guard.Snapshot()
	if !snapshot.Enforced || snapshot.PolicySHA256 != digest(raw) || snapshot.EpochID != policy.EpochID || len(snapshot.Capabilities) != 7 {
		t.Fatal("incomplete protocol snapshot")
	}
	snapshot.Requirements[0].Momentum = 1
	snapshot.Capabilities[0].Version = math.MaxUint32
	if err := guard.Check(cfg, 400); err == nil || guard.Snapshot().Capabilities[0].Version != 1 {
		t.Fatal("caller mutated the accepted guard")
	}
	cfg.Forks.Wire++
	if err := guard.Check(cfg, 399); err == nil || !strings.Contains(err.Error(), "configuration changed") {
		t.Fatal("changed configuration was accepted")
	}
	if err := guard.Check(nil, 1); err == nil {
		t.Fatal("nil configuration accepted")
	}
	var absent *ProtocolGuard
	if absent.Check(cfg, 1) == nil || absent.Snapshot().Enforced {
		t.Fatal("absent guard fabricated enforcement")
	}
}

func TestProtocolGuardRequiresExactSignedInventoryAndBytes(t *testing.T) {
	f, configuration, p := protocolFixture(t)
	raw := protocolJSON(t, p)
	if cfg, a, g, err := acceptedProtocol(t, f, configuration, nil); err != nil || cfg == nil || a == nil || g != nil {
		t.Fatal("legacy declaration fabricated a guard")
	}
	if _, _, _, err := acceptedProtocol(t, f, configuration, raw); err == nil {
		t.Fatal("unsigned extra policy accepted")
	}
	pinProtocol(t, f, raw)
	for _, body := range [][]byte{nil, {}, append(slices.Clone(raw), '\n')} {
		if cfg, a, g, err := acceptedProtocol(t, f, configuration, body); err == nil || cfg != nil || a != nil || g != nil {
			t.Fatal("missing or changed policy accepted")
		}
	}
	signatures := f.signatures(t)
	signatures.Signatures = signatures.Signatures[:1]
	if _, _, _, err := DecodeProtocolConfiguration(protocolJSON(t, f.manifest), protocolJSON(t, f.policy), protocolJSON(t, signatures), protocolJSON(t, f.keys), configuration, raw); err == nil {
		t.Fatal("insufficient signature quorum accepted")
	}
	if _, _, _, err := acceptedProtocol(t, f, append(slices.Clone(configuration), '\n'), raw); err == nil {
		t.Fatal("different startup configuration accepted")
	}
	changed := f.policy
	changed.Files = slices.Clone(changed.Files[:len(changed.Files)-1])
	if _, _, _, err := DecodeProtocolConfiguration(protocolJSON(t, f.manifest), protocolJSON(t, changed), protocolJSON(t, f.signatures(t)), protocolJSON(t, f.keys), configuration, raw); err == nil {
		t.Fatal("different independent inventory accepted")
	}
}

func TestProtocolPolicyCannotOmitMoveOrInventConfiguredRules(t *testing.T) {
	f, configuration, initial := protocolFixture(t)
	for _, name := range []string{"missing", "moved", "absent configured rule", "epoch", "chain", "genesis", "configuration"} {
		t.Run(name, func(t *testing.T) {
			p := initial
			p.Requirements = slices.Clone(initial.Requirements)
			switch name {
			case "missing":
				p.Requirements = p.Requirements[1:]
			case "moved":
				p.Requirements[0].Momentum++
			case "absent configured rule":
				p.Requirements = append(p.Requirements, ProtocolRequirement{"evm-isthmus", 1, 2})
			case "epoch":
				p.EpochID = strings.Repeat("6", 64)
			case "chain":
				p.ChainID = "2"
			case "genesis":
				p.GenesisHash = "0x" + strings.Repeat("6", 64)
			case "configuration":
				p.RollupSHA256 = strings.Repeat("6", 64)
			}
			raw := protocolJSON(t, p)
			pinProtocol(t, f, raw)
			if _, _, _, err := acceptedProtocol(t, f, configuration, raw); err == nil {
				t.Fatal("policy overrode its accepted configuration or epoch")
			}
		})
	}
}

func TestProtocolPolicyRejectsAmbiguousUnboundedAndRegressingRequirements(t *testing.T) {
	_, _, p := protocolFixture(t)
	raw := protocolJSON(t, p)
	cases := map[string][]byte{
		"duplicate":          bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"case alias":         bytes.Replace(raw, []byte(`"rule":`), []byte(`"Rule":`), 1),
		"unknown":            bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"extra":1`), 1),
		"null version":       bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":null`), 1),
		"negative height":    bytes.Replace(raw, []byte(`"momentum":2`), []byte(`"momentum":-1`), 1),
		"fractional version": bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1.5`), 1),
		"version overflow":   bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":4294967296`), 1),
		"height overflow":    bytes.Replace(raw, []byte(`"momentum":2`), []byte(`"momentum":18446744073709551616`), 1),
		"trailing":           append(slices.Clone(raw), []byte(` {}`)...),
		"oversized":          bytes.Repeat([]byte(" "), MaxProtocolPolicyBytes+1),
	}
	for _, name := range []string{"duplicate requirement", "same version", "decreasing version", "too many", "private rule", "zero version", "zero height", "empty"} {
		q := p
		q.Requirements = slices.Clone(p.Requirements)
		switch name {
		case "duplicate requirement":
			q.Requirements = append(q.Requirements, q.Requirements[0])
		case "same version":
			q.Requirements = append(q.Requirements, ProtocolRequirement{q.Requirements[0].Rule, 1, 4000})
		case "decreasing version":
			q.Requirements[0].Version = 2
			q.Requirements = append(q.Requirements, ProtocolRequirement{q.Requirements[0].Rule, 1, 4000})
		case "too many":
			for len(q.Requirements) <= MaxProtocolRequirements {
				q.Requirements = append(q.Requirements, ProtocolRequirement{"future", uint32(len(q.Requirements)), uint64(4000 + len(q.Requirements))})
			}
		case "private rule":
			q.Requirements[0].Rule = "file:///private/fixture"
		case "zero version":
			q.Requirements[0].Version = 0
		case "zero height":
			q.Requirements[0].Momentum = 0
		case "empty":
			q.Requirements = nil
		}
		cases[name] = protocolJSON(t, q)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeProtocolActivationPolicy(body); err == nil {
				t.Fatal("invalid protocol policy accepted")
			}
		})
	}
}

func TestProtocolPolicyReaderUsesItsSmallerRegularFileLimit(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(name, bytes.Repeat([]byte(" "), MaxProtocolPolicyBytes), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadProtocolPolicyDocument(name); err != nil || len(raw) != MaxProtocolPolicyBytes {
		t.Fatal("bounded regular input refused")
	}
	if err := os.WriteFile(name, bytes.Repeat([]byte(" "), MaxProtocolPolicyBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtocolPolicyDocument(name); err == nil || strings.Contains(err.Error(), dir) {
		t.Fatal("oversized input accepted or private path disclosed")
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtocolPolicyDocument(link); err == nil {
		t.Fatal("linked input accepted")
	}
}
