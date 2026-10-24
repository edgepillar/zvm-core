package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

const signatureDomain = "ZVM release manifest v1\n"

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeySHA256 string `json:"keySha256"`
	Value     string `json:"value"`
}
type Signatures struct {
	Schema     int         `json:"schema"`
	Signatures []Signature `json:"signatures"`
}
type TrustedKeys struct {
	Schema int      `json:"schema"`
	Keys   []string `json:"keys"`
}

func DecodeSignatures(raw []byte) (Signatures, error) {
	var s Signatures
	err := decode(raw, &s)
	if err == nil && (s.Schema != Schema || len(s.Signatures) < 1 || len(s.Signatures) > 16) {
		err = errors.New("invalid signature envelope")
	}
	return s, err
}
func DecodeTrustedKeys(raw []byte) (TrustedKeys, error) {
	var k TrustedKeys
	err := decode(raw, &k)
	if err == nil && (k.Schema != Schema || len(k.Keys) < 1 || len(k.Keys) > 16) {
		err = errors.New("invalid trust-key inventory")
	}
	return k, err
}

// SigningMessage is canonical JSON with an explicit domain separator. This
// package deliberately does not read private keys or perform release signing.
func (m Manifest) SigningMessage() ([]byte, error) {
	raw, err := m.Canonical()
	if err != nil {
		return nil, err
	}
	return append([]byte(signatureDomain), raw...), nil
}

// VerifySignatures trusts only caller-supplied public keys. Manifest content
// cannot introduce a trust root. Duplicate signatures never increase quorum.
func (m Manifest) VerifySignatures(p Policy, s Signatures, k TrustedKeys) (int, error) {
	if err := m.ValidateAgainst(p); err != nil {
		return 0, err
	}
	if k.Schema != Schema || s.Schema != Schema || len(k.Keys) < 1 || len(k.Keys) > 16 || len(s.Signatures) < 1 || len(s.Signatures) > 16 {
		return 0, errors.New("invalid signature or trust-key inventory")
	}
	trusted := map[string]ed25519.PublicKey{}
	for _, text := range k.Keys {
		raw, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return 0, errors.New("invalid trusted Ed25519 public key")
		}
		key := digest(raw)
		if trusted[key] != nil {
			return 0, errors.New("duplicate trust key")
		}
		trusted[key] = ed25519.PublicKey(raw)
	}
	message, err := m.SigningMessage()
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, sig := range s.Signatures {
		key := trusted[sig.KeySHA256]
		if sig.Algorithm != "ed25519" || key == nil || seen[sig.KeySHA256] {
			return 0, errors.New("unknown, unsupported or duplicate signature key")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(sig.Value)
		if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(key, message, raw) {
			return 0, errors.New("release signature verification failed")
		}
		seen[sig.KeySHA256] = true
	}
	if len(seen) < p.MinSignatures {
		return 0, errors.New("release signature quorum is incomplete")
	}
	return len(seen), nil
}
