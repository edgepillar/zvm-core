package release

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
)

const (
	ProtocolPolicyFileID    = "protocol-activation-policy"
	MaxProtocolPolicyBytes  = 64 << 10
	MaxProtocolRequirements = 64
)

// Versions describe these implemented rule families, not a governance-approved
// global protocol version or an execution-client runtime qualification.
type ProtocolCapability struct {
	Rule    string `json:"rule"`
	Version uint32 `json:"version"`
}

func CompiledProtocolCapabilities() []ProtocolCapability {
	return []ProtocolCapability{{"derivation", 1}, {"evm-isthmus", 1}, {"evm-karst", 1}, {"fee-market", 1}, {"gas", 1}, {"native-fee", 1}, {"wire", 1}}
}

type ProtocolRequirement struct {
	Rule     string `json:"rule"`
	Version  uint32 `json:"version"`
	Momentum uint64 `json:"momentum"`
}

type ProtocolActivationPolicy struct {
	Schema       int                   `json:"schema"`
	EpochID      string                `json:"epochId"`
	ChainID      string                `json:"chainId"`
	GenesisHash  string                `json:"genesisHash"`
	RollupSHA256 string                `json:"rollupSha256"`
	Requirements []ProtocolRequirement `json:"requirements"`
}

type ProtocolSnapshot struct {
	Enforced     bool                  `json:"enforced"`
	PolicySHA256 string                `json:"policySha256,omitempty"`
	EpochID      string                `json:"epochId,omitempty"`
	Capabilities []ProtocolCapability  `json:"capabilities"`
	Requirements []ProtocolRequirement `json:"requirements,omitempty"`
}

// ProtocolHalt stops before planning a momentum whose declared rule this binary
// cannot implement. It is an operator-visible hold, never an invalid message.
type ProtocolHalt struct{ Requirement ProtocolRequirement }

func (e *ProtocolHalt) Error() string {
	return fmt.Sprintf("upgrade required: rule %s version %d at momentum %d", e.Requirement.Rule, e.Requirement.Version, e.Requirement.Momentum)
}

type ProtocolGuard struct {
	policy              ProtocolActivationPolicy
	policySHA256        string
	configurationSHA256 string
	unsupported         []ProtocolRequirement
}

func (g *ProtocolGuard) Snapshot() ProtocolSnapshot {
	s := ProtocolSnapshot{Capabilities: CompiledProtocolCapabilities()}
	if g != nil {
		s.Enforced = true
		s.PolicySHA256 = g.policySHA256
		s.EpochID = g.policy.EpochID
		s.Requirements = slices.Clone(g.policy.Requirements)
	}
	return s
}

func (g *ProtocolGuard) Check(cfg *rollup.Config, momentum uint64) error {
	if g == nil || cfg == nil {
		return errors.New("accepted protocol guard is unavailable")
	}
	raw, err := json.Marshal(cfg)
	if err != nil || digest(raw) != g.configurationSHA256 {
		return errors.New("accepted protocol configuration changed; derivation is stopped")
	}
	for _, requirement := range g.unsupported {
		if momentum >= requirement.Momentum {
			return &ProtocolHalt{Requirement: requirement}
		}
	}
	return nil
}

var protocolRule = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

func decodeProtocolActivationPolicy(raw []byte) (ProtocolActivationPolicy, error) {
	var p ProtocolActivationPolicy
	if len(raw) == 0 || len(raw) > MaxProtocolPolicyBytes || decode(raw, &p) != nil || p.Schema != 1 || !hash(p.EpochID, 64) || !decimal(p.ChainID) || !blockHash(p.GenesisHash) || !hash(p.RollupSHA256, 64) || len(p.Requirements) == 0 || len(p.Requirements) > MaxProtocolRequirements {
		return p, errors.New("invalid bounded protocol activation policy")
	}
	for _, r := range p.Requirements {
		if !protocolRule.MatchString(r.Rule) || r.Version == 0 || r.Momentum == 0 {
			return p, errors.New("invalid protocol requirement")
		}
	}
	slices.SortFunc(p.Requirements, func(a, b ProtocolRequirement) int {
		if a.Momentum < b.Momentum {
			return -1
		}
		if a.Momentum > b.Momentum {
			return 1
		}
		if a.Rule < b.Rule {
			return -1
		}
		if a.Rule > b.Rule {
			return 1
		}
		return 0
	})
	last := map[string]ProtocolRequirement{}
	for _, r := range p.Requirements {
		if old, ok := last[r.Rule]; ok && (r.Momentum <= old.Momentum || r.Version <= old.Version) {
			return p, errors.New("protocol rule versions and heights must increase without duplicates")
		}
		last[r.Rule] = r
	}
	return p, nil
}

func configuredProtocolRules(cfg *rollup.Config) map[string]uint64 {
	evm := rollup.EVMIsthmus
	if cfg.IsKarst() {
		evm = rollup.EVMKarst
	}
	rules := map[string]uint64{"derivation": cfg.L1StartHeight, "evm-" + evm: cfg.L1StartHeight}
	if cfg.Forks != nil {
		if cfg.Forks.Gas != 0 {
			rules["gas"] = cfg.Forks.Gas
		}
		if cfg.Forks.Wire != 0 {
			rules["wire"] = cfg.Forks.Wire
		}
	}
	if cfg.Fee != nil && cfg.Fee.FromHeight != 0 {
		rules["native-fee"] = cfg.Fee.FromHeight
	}
	if len(cfg.FeeMarkets) != 0 {
		rules["fee-market"] = cfg.FeeMarkets[0].Momentum
	}
	return rules
}

func newProtocolGuard(m Manifest, cfg *rollup.Config, raw []byte) (*ProtocolGuard, error) {
	var pin *File
	for i := range m.Files {
		if m.Files[i].ID == ProtocolPolicyFileID {
			pin = &m.Files[i]
			break
		}
	}
	if pin == nil {
		if raw != nil {
			return nil, errors.New("protocol policy is absent from the accepted release inventory")
		}
		return nil, nil
	}
	if raw == nil {
		return nil, errors.New("accepted release requires its protocol activation policy")
	}
	if pin.Kind != "config" || pin.Bytes <= 0 || pin.Bytes > MaxProtocolPolicyBytes || int64(len(raw)) != pin.Bytes || digest(raw) != pin.SHA256 {
		return nil, errors.New("protocol policy bytes disagree with the accepted release")
	}
	p, err := decodeProtocolActivationPolicy(raw)
	if err != nil {
		return nil, err
	}
	if p.EpochID != m.Epoch.ID || p.ChainID != m.Epoch.L2ChainID || p.GenesisHash != m.Epoch.L2GenesisHash || p.RollupSHA256 != m.Epoch.RollupSHA256 {
		return nil, errors.New("protocol policy is bound to another epoch or configuration")
	}
	configured := configuredProtocolRules(cfg)
	first := map[string]ProtocolRequirement{}
	for _, r := range p.Requirements {
		if _, ok := first[r.Rule]; !ok {
			first[r.Rule] = r
		}
	}
	for rule, height := range configured {
		if r, ok := first[rule]; !ok || r.Momentum != height {
			return nil, errors.New("protocol policy omits or moves a configured activation")
		}
	}
	capabilities := map[string]uint32{}
	for _, c := range CompiledProtocolCapabilities() {
		capabilities[c.Rule] = c.Version
	}
	var unsupported []ProtocolRequirement
	for _, r := range p.Requirements {
		if capabilities[r.Rule] >= r.Version {
			if configured[r.Rule] == 0 {
				return nil, errors.New("protocol policy activates an implemented rule absent from configuration")
			}
		} else {
			unsupported = append(unsupported, r)
		}
	}
	configuration, err := json.Marshal(cfg)
	if err != nil {
		return nil, errors.New("protocol configuration could not be retained")
	}
	return &ProtocolGuard{policy: p, policySHA256: digest(raw), configurationSHA256: digest(configuration), unsupported: unsupported}, nil
}

// DecodeProtocolConfiguration verifies independent inventory/quorum inputs and
// exact startup bytes before accepting a guard. The policy is a release-pinned
// stop condition; it cannot activate code or replace a NoM upgrade notice.
func DecodeProtocolConfiguration(manifest, policy, signatures, keys, configuration, protocol []byte) (*rollup.Config, *Assertion, *ProtocolGuard, error) {
	m, err := DecodeManifest(manifest)
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := DecodePolicy(policy)
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := DecodeSignatures(signatures)
	if err != nil {
		return nil, nil, nil, err
	}
	k, err := DecodeTrustedKeys(keys)
	if err != nil {
		return nil, nil, nil, err
	}
	a, err := m.NewAssertion(p, s, k, configuration)
	if err != nil {
		return nil, nil, nil, err
	}
	cfg, err := m.BindConfiguration(configuration)
	if err != nil {
		return nil, nil, nil, err
	}
	guard, err := newProtocolGuard(m, cfg, protocol)
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, &a, guard, nil
}
