package release

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func addProcessFixturePin(f *fixture, id, kind string, raw []byte) File {
	pin := File{
		ID: id, Kind: kind, Repository: "zvm-core", Path: id + ".fixture",
		Bytes: int64(len(raw)), SHA256: digest(raw),
	}
	f.manifest.Files = append(f.manifest.Files, pin)
	f.policy.Files = append(f.policy.Files, FileRequirement{ID: pin.ID, Kind: pin.Kind, Repository: pin.Repository, Path: pin.Path})
	return pin
}

func checkProcessFixture(t *testing.T, f *fixture, target ImageTarget, executable, configuration []byte, configPath string) {
	t.Helper()
	const exeID, configID = "fixture-executable", "fixture-process-config"
	processPolicy := runtimeProcessPolicy{
		Schema: Schema,
		Services: []runtimeService{{
			Image: target.ImageID, Executable: exeID,
			Files: []runtimeFile{{Path: "/observer-config", File: configID, Mounted: true}},
		}},
	}
	policy := imageJSON(t, processPolicy)
	configIndex := len(f.manifest.Files) + 1
	for _, input := range []struct {
		id, kind string
		raw      []byte
	}{
		{exeID, "artifact", executable},
		{configID, "config", configuration},
		{runtimeProcessPolicyID, "config", policy},
	} {
		pin := addProcessFixturePin(f, input.id, input.kind, input.raw)
		if input.id == runtimeProcessPolicyID {
			if err := os.WriteFile(filepath.Join(f.files, pin.Repository, pin.Path), input.raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	var err error
	f.manifest.PolicySHA256, err = f.policy.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	inputs := writeReleaseTestInputs(t, f)
	raw := runReleaseTestCLI(t, "release-observe-process", "-manifest", filepath.Join(inputs, "manifest.json"),
		"-policy", filepath.Join(inputs, "policy.json"), "-signatures", filepath.Join(inputs, "signatures.json"),
		"-trusted-keys", filepath.Join(inputs, "keys.json"), "-image", target.ImageID,
		"-container", target.ContainerID, "-docker-context", target.DockerContext, "-oci-root", target.OCIRoot,
		"-files-root", f.files)
	var got ProcessObservation
	manifestHash, _ := f.manifest.Fingerprint()
	if json.Unmarshal(raw, &got) != nil || got.Image.ManifestSHA256 != manifestHash || !got.Image.ContainerRunning ||
		got.ExecutableSHA256 != digest(executable) || got.ProcessPolicySHA256 != digest(policy) ||
		got.VerifiedConfigFiles != 1 || got.VerifiedMountedFiles != 1 ||
		bytes.Contains(raw, []byte(target.ContainerID)) || bytes.Contains(raw, []byte(configPath)) {
		t.Fatal("release CLI did not establish the signed executable and mounted configuration")
	}
	t.Logf("Verified running executable SHA-256 %s and one mounted file", got.ExecutableSHA256)

	t.Run("different config digest", func(t *testing.T) {
		pin := &f.manifest.Files[configIndex]
		prior := pin.SHA256
		pin.SHA256 = digest([]byte("mode=fail\n"))
		defer func() { pin.SHA256 = prior }()
		got, err := f.manifest.ObserveProcess(t.Context(), f.policy, f.signatures(t), f.keys, target, f.files)
		if err == nil || !strings.Contains(err.Error(), "disagrees with its signed bytes") || got != (ProcessObservation{}) {
			t.Fatalf("different config digest received an observation: %v", err)
		}
	})
	t.Run("bundled file where a mount is expected", func(t *testing.T) {
		pin := &f.manifest.Files[configIndex+1]
		path := filepath.Join(f.files, pin.Repository, pin.Path)
		prior := *pin
		processPolicy.Services[0].Files[0].Path = "/observer-bundled-config"
		raw := imageJSON(t, processPolicy)
		pin.Bytes, pin.SHA256 = int64(len(raw)), digest(raw)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		defer func() {
			*pin = prior
			if err := os.WriteFile(path, policy, 0600); err != nil {
				t.Error(err)
			}
		}()
		got, err := f.manifest.ObserveProcess(t.Context(), f.policy, f.signatures(t), f.keys, target, f.files)
		if err == nil || !strings.Contains(err.Error(), "expected separate mount") || got != (ProcessObservation{}) {
			t.Fatalf("bundled file satisfied a mount requirement: %v", err)
		}
	})
	t.Run("mount changes after hashing", func(t *testing.T) {
		t.Cleanup(func() {
			if err := os.WriteFile(configPath, configuration, 0600); err != nil {
				t.Error(err)
			}
		})
		_, pins, err := f.manifest.runtimePins(f.files, target.ImageID)
		if err != nil {
			t.Fatal(err)
		}
		_, snapshot, err := f.manifest.observeImage(t.Context(), 2, target)
		if err != nil {
			t.Fatal(err)
		}
		err = verifyProcessFiles(t.Context(), snapshot, pins, func() error {
			return os.WriteFile(configPath, []byte("mode=fail\n"), 0600)
		})
		if err == nil || !strings.Contains(err.Error(), "changed during verification") {
			t.Fatalf("changed mount contents were accepted: %v", err)
		}
	})
}
