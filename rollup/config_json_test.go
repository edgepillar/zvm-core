package rollup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadJSONFixture(t *testing.T, raw string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rollup.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestLoadRejectsUnknownFieldsAtEveryConfigurationLevel(t *testing.T) {
	const required = `"l1StartHeight":2,"l2ChainId":7340470,"gasLimit":300000000`
	for _, fixture := range []struct {
		name, extra, field string
	}{
		{"root typo", `"finalityDepht":6`, "finalityDepht"},
		{"future version", `"version":2`, "version"},
		{"future protocol", `"protocol":"future"`, "protocol"},
		{"fork", `"forks":{"gas":0,"wire":0,"future":100}`, "future"},
		{"disabled custom fee decoder", `"fee":{"fromHeight":0,"gasPerSuplly":1}`, "gasPerSuplly"},
		{"active custom fee decoder", `"fee":{"fromHeight":100,"gasPerSupply":1,"genesisTimestamp":1,"refZnn":"1","refQsr":"1","future":true}`, "future"},
		{"bridge fee", `"bridgeFee":{"bps":10,"minZnn":1,"minQsr":1,"future":1}`, "future"},
		{"fee market", `"feeMarket":[{"momentum":100,"denominator":8,"elasticity":2,"future":1}]`, "future"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			_, err := loadJSONFixture(t, "{"+required+","+fixture.extra+"}")
			if err == nil || !strings.Contains(err.Error(), `unknown field "`+fixture.field+`"`) {
				t.Fatalf("unknown consensus field was not refused: %v", err)
			}
		})
	}
}

func TestLoadRejectsTrailingValuesAndUnsupportedExecutionRules(t *testing.T) {
	const base = `{"l1StartHeight":2,"l2ChainId":7340470,"gasLimit":300000000}`
	for _, suffix := range []string{`{}`, `null`, `true`, `0`, ` garbage`} {
		if _, err := loadJSONFixture(t, base+suffix); err == nil {
			t.Errorf("accepted trailing input %q", suffix)
		}
	}
	if _, err := loadJSONFixture(t, base+" \n\t"); err != nil {
		t.Fatalf("rejected JSON whitespace: %v", err)
	}
	if _, err := loadJSONFixture(t, strings.TrimSuffix(base, "}")+`,"evm":"future"}`); err == nil {
		t.Fatal("accepted unsupported execution rules")
	}
}

func TestShippedRollupConfigurationsStillLoad(t *testing.T) {
	paths, err := filepath.Glob("../chains/*/rollup.json")
	if err != nil || len(paths) != 3 {
		t.Fatalf("expected all three shipped configurations: paths=%v err=%v", paths, err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			if _, err := Load(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFeeCustomDecoderIsStrictAndPreservesReceiverOnFailure(t *testing.T) {
	f := MainnetSupplyAnchor
	before := f
	if err := json.Unmarshal([]byte(`{"fromHeight":0,"unknown":1}`), &f); err == nil {
		t.Fatal("nested custom decoder accepted an unknown field")
	}
	if f != before {
		t.Fatal("failed decode changed the receiver")
	}
	if err := json.Unmarshal([]byte(`{"fromHeight":100,"gasPerSupply":0}`), &f); err == nil {
		t.Fatal("accepted an invalid fee")
	}
	if f != before {
		t.Fatal("failed fee validation changed the receiver")
	}
}
