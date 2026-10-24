package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestBrowserAssertionVector(t *testing.T) {
	f := newFixture(t)
	for i := range f.manifest.Repositories {
		if !f.manifest.Repositories[i].Empty {
			f.manifest.Repositories[i].Commit = strings.Repeat("3", 40)
		}
	}
	f.private = nil
	f.keys.Keys = nil
	for _, tag := range []string{"fixture-only-browser-release-key-1", "fixture-only-browser-release-key-2"} {
		seed := sha256.Sum256([]byte(tag))
		key := ed25519.NewKeyFromSeed(seed[:])
		f.private = append(f.private, key)
		f.keys.Keys = append(f.keys.Keys, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	}
	raw, err := os.ReadFile("../chains/l2/rollup.json")
	if err != nil {
		t.Fatal(err)
	}
	a, err := f.manifest.NewAssertion(f.policy, f.signatures(t), f.keys, raw)
	if err != nil {
		t.Fatal(err)
	}
	vector := struct {
		FixtureOnly bool        `json:"fixtureOnly"`
		Quorum      int         `json:"quorum"`
		TrustedKeys TrustedKeys `json:"trustedKeys"`
		Assertion   Assertion   `json:"assertion"`
	}{true, 2, f.keys, a}
	wanted, err := json.Marshal(vector)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ZVM_EXPORT_RELEASE_VECTOR") == "1" {
		fmt.Println("RELEASE_ASSERTION_VECTOR=" + string(wanted))
		return
	}
	stored, err := os.ReadFile("../web/test/fixtures/release-assertion.json")
	if err != nil {
		t.Fatal(err)
	}
	var got any
	if json.Unmarshal(stored, &got) != nil {
		t.Fatal("browser vector is not JSON")
	}
	compact, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var expected any
	if json.Unmarshal(wanted, &expected) != nil {
		t.Fatal("bad generated vector")
	}
	canonical, err := json.Marshal(expected)
	if err != nil || string(compact) != string(canonical) {
		t.Fatal("Go and the retained browser assertion vector disagree")
	}
}

func TestPublicAssertionBindsSignaturesAndTheActualConfigurationSnapshot(t *testing.T) {
	f := newFixture(t)
	raw, err := os.ReadFile("../chains/l2/rollup.json")
	if err != nil {
		t.Fatal(err)
	}
	s := f.signatures(t)
	a, err := f.manifest.NewAssertion(f.policy, s, f.keys, raw)
	if err != nil {
		t.Fatal(err)
	}
	message, err := base64.StdEncoding.DecodeString(a.SigningMessage)
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := f.manifest.SigningMessage()
	if err != nil || string(message) != string(wanted) || a.RuntimeObserved {
		t.Fatal("assertion changed signing data or claimed runtime observation")
	}
	s.Signatures[0].Value = "changed"
	if a.Signatures.Signatures[0].Value == "changed" {
		t.Fatal("caller mutated retained assertion signatures")
	}
	if _, err := f.manifest.NewAssertion(f.policy, f.signatures(t), f.keys, append(raw, ' ')); err == nil {
		t.Fatal("a different configuration snapshot was bound")
	}
	k := f.keys
	k.Keys = k.Keys[:1]
	if _, err := f.manifest.NewAssertion(f.policy, f.signatures(t), k, raw); err == nil {
		t.Fatal("an untrusted signature set produced a public assertion")
	}
}
