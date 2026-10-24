package release

import (
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
)

// Assertion carries owner-signed public release data. A consumer provisions its
// own trust keys; neither these signatures nor a node's reply introduce trust.
type Assertion struct {
	Schema          int        `json:"schema"`
	SigningMessage  string     `json:"signingMessage"`
	Signatures      Signatures `json:"signatures"`
	ManifestSHA256  string     `json:"manifestSha256"`
	EpochSHA256     string     `json:"epochSha256"`
	RuntimeObserved bool       `json:"runtimeObserved"`
}

// BindConfiguration checks the exact configuration snapshot the service uses.
// It does not assert a running image, live contract code or L1 genesis proof.
func (m Manifest) BindConfiguration(raw []byte) (*rollup.Config, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	if len(raw) > MaxDocumentBytes || digest(raw) != m.Epoch.RollupSHA256 {
		return nil, errors.New("runtime rollup configuration digest disagrees with the release")
	}
	cfg, err := rollup.Parse(raw)
	if err != nil {
		return nil, errors.New("pinned rollup configuration is invalid")
	}
	evm := rollup.EVMIsthmus
	if cfg.IsKarst() {
		evm = rollup.EVMKarst
	}
	if strconv.FormatUint(cfg.L1ChainID, 10) != m.Epoch.L1ChainID || strconv.FormatUint(cfg.L2ChainID, 10) != m.Epoch.L2ChainID || strings.ToLower(cfg.L2GenesisHash.Hex()) != m.Epoch.L2GenesisHash || evm != m.Epoch.EVM {
		return nil, errors.New("rollup configuration disagrees with the epoch")
	}
	return cfg, nil
}

func (m Manifest) NewAssertion(p Policy, s Signatures, k TrustedKeys, configuration []byte) (Assertion, error) {
	var a Assertion
	if _, err := m.VerifySignatures(p, s, k); err != nil {
		return a, err
	}
	if _, err := m.BindConfiguration(configuration); err != nil {
		return a, err
	}
	message, err := m.SigningMessage()
	if err != nil {
		return a, err
	}
	manifest, err := m.Fingerprint()
	if err != nil {
		return a, err
	}
	epoch, err := m.EpochFingerprint()
	if err != nil {
		return a, err
	}
	return Assertion{Schema: Schema, SigningMessage: base64.StdEncoding.EncodeToString(message), Signatures: Signatures{Schema: s.Schema, Signatures: slices.Clone(s.Signatures)}, ManifestSHA256: manifest, EpochSHA256: epoch, RuntimeObserved: false}, nil
}

func DecodeAssertionInputs(manifest, policy, signatures, keys, configuration []byte) (Assertion, error) {
	var a Assertion
	m, err := DecodeManifest(manifest)
	if err != nil {
		return a, err
	}
	p, err := DecodePolicy(policy)
	if err != nil {
		return a, err
	}
	s, err := DecodeSignatures(signatures)
	if err != nil {
		return a, err
	}
	k, err := DecodeTrustedKeys(keys)
	if err != nil {
		return a, err
	}
	return m.NewAssertion(p, s, k, configuration)
}
