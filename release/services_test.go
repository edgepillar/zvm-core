package release

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkServicesFixture(t *testing.T, image Image, tag, project, root string, executable, primaryConfig []byte) {
	t.Helper()
	f := newFixture(t)
	f.manifest.Images[0] = image
	readerConfig := []byte("mode=view\n")
	addProcessFixturePin(f, "fixture-executable", "artifact", executable)
	addProcessFixturePin(f, "fixture-primary-config", "config", primaryConfig)
	readerIndex := len(f.manifest.Files)
	addProcessFixturePin(f, "fixture-reader-config", "config", readerConfig)
	policy := runtimeProcessPolicy{Schema: Schema, Services: []runtimeService{
		{Name: "primary", Image: image.ID, Replicas: 1, Executable: "fixture-executable",
			Files: []runtimeFile{{Path: "/observer-config", File: "fixture-primary-config", Mounted: true}}},
		{Name: "reader", Image: image.ID, Replicas: 2, Executable: "fixture-executable",
			Files: []runtimeFile{{Path: "/observer-config", File: "fixture-reader-config", Mounted: true}}},
	}}
	policyIndex := len(f.manifest.Files)
	addProcessFixturePin(f, runtimeProcessPolicyID, "config", imageJSON(t, policy))
	writePolicy := func(value runtimeProcessPolicy) {
		t.Helper()
		raw := imageJSON(t, value)
		pin := &f.manifest.Files[policyIndex]
		pin.Bytes, pin.SHA256 = int64(len(raw)), digest(raw)
		if err := os.WriteFile(filepath.Join(f.files, pin.Repository, pin.Path), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy(policy)
	var err error
	f.manifest.PolicySHA256, err = f.policy.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	target := ServicesTarget{DockerContext: "default", Project: project, OCIRoot: root, FilesRoot: f.files}
	configPath := filepath.Join(root, "reader-config")
	if err := os.WriteFile(configPath, readerConfig, 0600); err != nil {
		t.Fatal(err)
	}
	firstReader := startFixtureContainer(t, tag, configPath, project, "reader")
	t.Run("missing replica", func(t *testing.T) {
		got, err := f.manifest.ObserveServices(t.Context(), f.policy, f.signatures(t), f.keys, target)
		if err == nil || !strings.Contains(err.Error(), "signed count for reader") || got.Services != nil {
			t.Fatalf("incomplete running inventory received a record: %v", err)
		}
	})
	secondReader := startFixtureContainer(t, tag, configPath, project, "reader")
	t.Run("all signed replicas and roles", func(t *testing.T) {
		inputs := writeReleaseTestInputs(t, f)
		raw := runReleaseTestCLI(t, "release-observe-services", "-manifest", filepath.Join(inputs, "manifest.json"),
			"-policy", filepath.Join(inputs, "policy.json"), "-signatures", filepath.Join(inputs, "signatures.json"),
			"-trusted-keys", filepath.Join(inputs, "keys.json"), "-project", project, "-docker-context", target.DockerContext,
			"-oci-root", target.OCIRoot, "-files-root", target.FilesRoot)
		var got ServicesObservation
		manifest, _ := f.manifest.Fingerprint()
		if json.Unmarshal(raw, &got) != nil || got.ManifestSHA256 != manifest || got.ContainersObserved != 3 || len(got.Services) != 2 ||
			bytes.Contains(raw, []byte(project)) || bytes.Contains(raw, []byte(firstReader)) || bytes.Contains(raw, []byte(secondReader)) ||
			bytes.Contains(raw, []byte(configPath)) {
			t.Fatal("service CLI did not establish the complete signed fixture inventory")
		}
		for i, expected := range policy.Services {
			row := got.Services[i]
			if row.Name != expected.Name || row.Replicas != expected.Replicas || row.ImageID != image.ID ||
				row.ExecutableSHA256 != digest(executable) || row.VerifiedConfigFilesPerReplica != 1 || row.VerifiedMountedFilesPerReplica != 1 {
				t.Fatal("service CLI associated the wrong evidence with a signed role")
			}
		}
		t.Logf("Verified %d running containers for %d signed roles on one image", got.ContainersObserved, len(got.Services))
	})
	t.Run("undeclared running service", func(t *testing.T) {
		incomplete := policy
		incomplete.Services = incomplete.Services[:1]
		writePolicy(incomplete)
		defer writePolicy(policy)
		got, err := f.manifest.ObserveServices(t.Context(), f.policy, f.signatures(t), f.keys, target)
		if err == nil || !strings.Contains(err.Error(), "undeclared service") || got.Services != nil {
			t.Fatalf("undeclared running role received a record: %v", err)
		}
	})
	t.Run("wrong mount for one role of the shared image", func(t *testing.T) {
		pin := &f.manifest.Files[readerIndex]
		pin.SHA256 = digest(primaryConfig)
		got, err := f.manifest.ObserveServices(t.Context(), f.policy, f.signatures(t), f.keys, target)
		if err == nil || !strings.Contains(err.Error(), "service reader") || !strings.Contains(err.Error(), "disagrees with its signed bytes") || got.Services != nil {
			t.Fatalf("shared image hid a mismatched role configuration: %v", err)
		}
	})
}
