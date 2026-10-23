package znn

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The browser helpers read this same synthetic corpus. Missing or malformed
// fixtures fail rather than silently dropping cross-language coverage.
func TestSharedAddressVectors(t *testing.T) {
	var vectors struct {
		Valid []struct {
			Name   string `json:"name"`
			Hex    string `json:"hex"`
			Nom    string `json:"nom"`
			IsUser bool   `json:"isUser"`
		} `json:"valid"`
		InvalidNom []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"invalidNom"`
		InvalidPrefix []string `json:"invalidPrefix"`
	}
	raw, err := os.ReadFile("../vectors/address-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Valid) == 0 || len(vectors.InvalidNom) == 0 || len(vectors.InvalidPrefix) == 0 {
		t.Fatal("shared address vectors are incomplete")
	}
	for _, v := range vectors.Valid {
		t.Run(v.Name, func(t *testing.T) {
			a, err := ParseAddress(v.Nom)
			if err != nil {
				t.Fatal(err)
			}
			if a.Hex() != v.Hex || a.String() != v.Nom || a.IsUser() != v.IsUser {
				t.Fatalf("encoding/type differs from shared vector %s", v.Name)
			}
			bytes, err := hex.DecodeString(v.Hex[2:])
			if err != nil || len(bytes) != len(a) {
				t.Fatalf("invalid hex fixture %s", v.Name)
			}
			var fromHex Address
			copy(fromHex[:], bytes)
			if fromHex.String() != v.Nom {
				t.Fatalf("hex-to-NoM differs from shared vector %s", v.Name)
			}
		})
	}
	for _, v := range vectors.InvalidNom {
		t.Run(v.Name, func(t *testing.T) {
			if _, err := ParseAddress(v.Value); err == nil {
				t.Fatal("accepted malformed NoM address")
			}
		})
	}
	for _, value := range vectors.InvalidPrefix {
		if _, _, err := DecodeBech32(value); err == nil {
			t.Fatal("accepted a non-printable human-readable prefix")
		}
	}
}
