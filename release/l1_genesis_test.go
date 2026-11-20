package release

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func pinNoMGenesis(t *testing.T, f *fixture, verifier, path string) nomGenesis {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reconstructNoMGenesis(t.Context(), verifier, raw)
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(f.manifest.Files, func(file File) bool { return file.Kind == "l1-genesis" })
	if index < 0 {
		t.Fatal("missing L1 genesis fixture pin")
	}
	pin := &f.manifest.Files[index]
	if err := os.WriteFile(filepath.Join(f.files, pin.Repository, pin.Path), raw, 0600); err != nil {
		t.Fatal(err)
	}
	pin.Bytes, pin.SHA256 = int64(len(raw)), digest(raw)
	f.manifest.Epoch.L1GenesisHash = got.MomentumHash
	return got
}

func TestSignedReleaseReconstructsNoMGenesis(t *testing.T) {
	verifier := os.Getenv("ZVM_TEST_NOM_GENESIS_VERIFIER")
	if verifier == "" {
		t.Skip("requires the independently built NoM genesis verifier")
	}
	profiles := []struct {
		name, path string
	}{
		{"l2", "../chains/nom/genesis.json"},
		{"l2-69", os.Getenv("ZVM_TEST_NOM_DEVNET_GENESIS")},
		{"l2-dp", "../chains/nom-dp/genesis.json"},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			f := newFixtureForChain(t, profile.name)
			genesis := pinNoMGenesis(t, f, verifier, profile.path)
			if strconv.FormatUint(genesis.ChainID, 10) != f.manifest.Epoch.L1ChainID {
				t.Fatal("NoM fixture has the wrong chain ID")
			}
			receipt, err := f.manifest.VerifyWithL1Genesis(t.Context(), f.policy, f.signatures(t), f.keys, f.files, f.sources, verifier)
			if err != nil || !receipt.VerifiedL1Genesis || receipt.RuntimeObserved {
				t.Fatalf("signed genesis reconstruction failed: %+v, %v", receipt, err)
			}
			t.Logf("Verified NoM chain %d height-1 momentum %s", genesis.ChainID, genesis.MomentumHash)
		})
	}
	t.Run("different-momentum-hash", func(t *testing.T) {
		f := newFixture(t)
		genesis := pinNoMGenesis(t, f, verifier, profiles[0].path)
		f.manifest.Epoch.L1GenesisHash = "0x" + strings.Repeat("1", 64)
		if f.manifest.Epoch.L1GenesisHash == genesis.MomentumHash {
			f.manifest.Epoch.L1GenesisHash = "0x" + strings.Repeat("2", 64)
		}
		receipt, err := f.manifest.VerifyWithL1Genesis(t.Context(), f.policy, f.signatures(t), f.keys, f.files, f.sources, verifier)
		if err == nil || err.Error() != "NoM genesis momentum hash disagrees with the epoch" || receipt != (Receipt{}) {
			t.Fatalf("different signed momentum hash was not refused: %+v, %v", receipt, err)
		}
	})
	t.Run("different-chain", func(t *testing.T) {
		f := newFixture(t)
		pinNoMGenesis(t, f, verifier, profiles[2].path)
		receipt, err := f.manifest.VerifyWithL1Genesis(t.Context(), f.policy, f.signatures(t), f.keys, f.files, f.sources, verifier)
		if err == nil || err.Error() != "NoM genesis chain ID disagrees with the epoch" || receipt != (Receipt{}) {
			t.Fatalf("different signed chain ID was not refused: %+v, %v", receipt, err)
		}
	})
}

func TestSignedReleaseRefusesAnUnavailableNoMVerifier(t *testing.T) {
	f := newFixture(t)
	verifier := filepath.Join(t.TempDir(), "missing-nom-verifier")
	receipt, err := f.manifest.VerifyWithL1Genesis(t.Context(), f.policy, f.signatures(t), f.keys, f.files, f.sources, verifier)
	if err == nil || err.Error() != "NoM genesis verifier failed within its execution limits" || receipt != (Receipt{}) {
		t.Fatalf("unavailable verifier did not stop verification: %+v, %v", receipt, err)
	}
}
