package release

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func checkCandidateFixture(t *testing.T, image Image, tag, project, ociRoot string, executable []byte) {
	t.Helper()
	const chain = "l2-69"
	verifier := os.Getenv("ZVM_TEST_NOM_GENESIS_VERIFIER")
	genesisPath := os.Getenv("ZVM_TEST_NOM_DEVNET_GENESIS")
	if verifier == "" || genesisPath == "" {
		t.Skip("requires the independently built NoM genesis verifier and chain-69 genesis")
	}
	f := newFixtureForChain(t, chain)
	pinNoMGenesis(t, f, verifier, genesisPath)
	f.manifest.Images[0] = image
	policy := runtimeProcessPolicy{
		Schema: Schema,
		Services: []runtimeService{{
			Name: "primary", Image: image.ID, Executable: "fixture-executable",
			Files: []runtimeFile{{Path: "/observer-config", File: "rollup", Mounted: true}},
		}},
		Jobs: []runtimeJob{{
			Name: "genesis-check", Image: image.ID, CommandSHA256: digest([]byte("/observer-fixture\x00complete\x00")),
		}},
	}
	for _, input := range []struct {
		id, kind string
		raw      []byte
	}{
		{"fixture-executable", "artifact", executable},
		{runtimeProcessPolicyID, "config", imageJSON(t, policy)},
	} {
		pin := addProcessFixturePin(f, input.id, input.kind, input.raw)
		if err := os.WriteFile(filepath.Join(f.files, pin.Repository, pin.Path), input.raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	f.manifest.PolicySHA256, err = f.policy.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	rollup, err := os.ReadFile(filepath.Join(f.files, "zvm-core", "rollup.fixture"))
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(ociRoot, "candidate-rollup")
	if err := os.WriteFile(configPath, rollup, 0600); err != nil {
		t.Fatal(err)
	}
	container := startFixtureContainer(t, tag, project, "primary", "type=bind,source="+configPath+",target=/observer-config,readonly")
	job := startFixtureJob(t, tag, project, "genesis-check", "False", "0", "", "complete")
	genesis, block := chainFixtureHeaders(t, chain)
	primaryRPC := observeFixture(t, f.manifest, genesis, block, "")
	witnessRPC := observeFixture(t, f.manifest, genesis, block, "")
	expected, err := f.manifest.expectedNodeEpoch(f.files)
	if err != nil {
		t.Fatal(err)
	}
	primaryNode := serveFixtureNodeEpoch(t, expected, "")
	witnessNode := serveFixtureNodeEpoch(t, expected, "")
	targets := CandidateTargets{
		SourcesRoot: f.sources, L1GenesisVerifier: verifier,
		Services: ServicesTarget{Project: project, DockerContext: "default", OCIRoot: ociRoot, FilesRoot: f.files},
		Chain: ChainTargets{
			L1: [2]string{primaryRPC, witnessRPC}, L2: [2]string{primaryRPC, witnessRPC}, L1Height: 5, L2Height: 3,
			NodeEpoch: [2]string{primaryNode, witnessNode},
		},
	}
	t.Run("one signed release across all observations", func(t *testing.T) {
		inputs := writeReleaseTestInputs(t, f)
		raw := runReleaseTestCLI(t, "release-verify-candidate",
			"-manifest", filepath.Join(inputs, "manifest.json"), "-policy", filepath.Join(inputs, "policy.json"),
			"-signatures", filepath.Join(inputs, "signatures.json"), "-trusted-keys", filepath.Join(inputs, "keys.json"),
			"-files-root", f.files, "-sources-root", f.sources, "-l1-genesis-verifier", verifier,
			"-project", project, "-docker-context", targets.Services.DockerContext, "-oci-root", ociRoot,
			"-l1-rpc", primaryRPC, "-l1-witness-rpc", witnessRPC, "-l1-height", "5",
			"-l2-rpc", primaryRPC, "-l2-witness-rpc", witnessRPC, "-l2-height", "3",
			"-node-epoch-url", primaryNode, "-node-witness-epoch-url", witnessNode)
		var got CandidateObservation
		manifest, _ := f.manifest.Fingerprint()
		epoch, _ := f.manifest.EpochFingerprint()
		if json.Unmarshal(raw, &got) != nil || got.Offline.ManifestSHA256 != manifest || got.Services.ManifestSHA256 != manifest ||
			got.Chain.ManifestSHA256 != manifest || got.Offline.EpochSHA256 != epoch || got.Services.EpochSHA256 != epoch ||
			got.Chain.EpochSHA256 != epoch || got.Offline.TrustedSignatures != 2 || !got.Offline.VerifiedL1Genesis ||
			got.Offline.VerifiedRepositories != 2 || got.Offline.VerifiedFiles != len(f.manifest.Files) ||
			got.Services.ContainersObserved != 1 || len(got.Services.CompletedJobs) != 1 || got.Services.CompletedJobs[0].Name != "genesis-check" ||
			got.Chain.L2.Hash != block.Hash().Hex() || got.Chain.VerifiedContracts != 1 ||
			got.Chain.VerifiedNodeEpochs != 2 || got.Chain.LoadedRollupSHA256 != expected.LoadedRollupSHA256 {
			t.Fatal("candidate CLI did not bind the offline, Docker and chain observations")
		}
		for _, private := range []string{project, configPath, f.files, container, job, primaryRPC, witnessNode} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatal("candidate CLI disclosed observer-specific details")
			}
		}
		t.Logf("Verified one signed release across both genesis checks, %d running replica, %d job and %d node epochs",
			got.Services.ContainersObserved, len(got.Services.CompletedJobs), got.Chain.VerifiedNodeEpochs)
	})
	t.Run("mounted rollup changes while querying witnesses", func(t *testing.T) {
		t.Cleanup(func() {
			if err := os.WriteFile(configPath, rollup, 0600); err != nil {
				t.Error(err)
			}
		})
		var changed atomic.Bool
		witness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if changed.CompareAndSwap(false, true) {
				if err := os.WriteFile(configPath, []byte("changed while querying witnesses\n"), 0600); err != nil {
					t.Error(err)
				}
			}
			if err := json.NewEncoder(w).Encode(expected); err != nil {
				t.Error(err)
			}
		}))
		t.Cleanup(witness.Close)
		selected := targets
		selected.Chain.NodeEpoch[1] = witness.URL + "/api/epoch"
		got, err := f.manifest.VerifyCandidate(t.Context(), f.policy, f.signatures(t), f.keys, selected)
		if err == nil || !changed.Load() || !strings.Contains(err.Error(), "changed since hashing") ||
			got.Offline != (Receipt{}) || got.Services.Services != nil || got.Chain != (ChainObservation{}) {
			t.Fatalf("changed mounted rollup received a candidate observation: %v", err)
		}
	})
}
