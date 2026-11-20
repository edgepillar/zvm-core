package release

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func imageJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func putOCI(t *testing.T, root string, raw []byte, mediaType string) ociDescriptor {
	t.Helper()
	hex := digest(raw)
	directory := filepath.Join(root, "blobs", "sha256")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, hex), raw, 0600); err != nil {
		t.Fatal(err)
	}
	size := int64(len(raw))
	return ociDescriptor{Digest: "sha256:" + hex, Size: &size, MediaType: mediaType}
}

func fixtureOCIManifest(t *testing.T, root string, config ociDescriptor, layers []ociDescriptor) ociDescriptor {
	t.Helper()
	return putOCI(t, root, imageJSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": ociManifest, "config": config, "layers": layers,
	}), ociManifest)
}

func fixtureOCIIndex(t *testing.T, root string, entries ...ociDescriptor) ociDescriptor {
	t.Helper()
	return putOCI(t, root, imageJSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": ociIndex, "manifests": entries,
	}), ociIndex)
}

func TestOCIImageResolvesSignedPlatformAndBytes(t *testing.T) {
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	amd := ociPlatform{OS: "linux", Architecture: "amd64"}
	arm := ociPlatform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	config := putOCI(t, rootPath, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`), ociConfig)
	manifest := fixtureOCIManifest(t, rootPath, config, []ociDescriptor{})
	manifest.Platform = &amd
	other := manifest
	other.Platform = &arm
	index := fixtureOCIIndex(t, rootPath, manifest, other)
	duplicate := fixtureOCIIndex(t, rootPath, manifest, manifest)
	wrongSize := manifest
	size := *wrongSize.Size + 1
	wrongSize.Size = &size
	badIndex := fixtureOCIIndex(t, rootPath, wrongSize)
	wrongDigest := config
	wrongDigest.Digest = "sha256:" + strings.Repeat("4", 64)
	configBytes, err := os.ReadFile(filepath.Join(rootPath, "blobs", "sha256", strings.TrimPrefix(config.Digest, "sha256:")))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "blobs", "sha256", strings.Repeat("4", 64)), configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	badManifest := fixtureOCIManifest(t, rootPath, wrongDigest, []ociDescriptor{})
	root, err := openDirectory(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, test := range []struct {
		name, rootDigest, platform, errorText string
	}{
		{"single manifest", manifest.Digest, "linux/amd64", ""},
		{"platform index", index.Digest, "linux/amd64", ""},
		{"duplicate platform", duplicate.Digest, "linux/amd64", "multiple matches"},
		{"wrong descriptor size", badIndex.Digest, "linux/amd64", "bytes disagree"},
		{"wrong configuration digest", badManifest.Digest, "linux/amd64", "bytes disagree"},
		{"conflicting config platform", index.Digest, "linux/arm64/v8", "configuration disagrees"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ref, platform, actual, err := resolveOCIImage(root, Image{
				Platform: test.platform, Reference: "registry.invalid/example/service@" + test.rootDigest,
			})
			if test.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorText) {
					t.Fatalf("inconsistent OCI data was accepted: %v", err)
				}
				return
			}
			if err != nil || ref != test.rootDigest || platform != manifest.Digest || actual != config.Digest {
				t.Fatalf("unexpected resolved OCI image: %q %q %q: %v", ref, platform, actual, err)
			}
		})
	}
}

func fixtureTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	for _, entry := range entries {
		header := tar.Header{Name: entry.name, Mode: entry.mode, Size: int64(len(entry.content))}
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

type tarEntry struct {
	name    string
	mode    int64
	content []byte
}

func compileImageFixture(t *testing.T) []byte {
	t.Helper()
	root := t.TempDir()
	source, executable := filepath.Join(root, "main.go"), filepath.Join(root, "observer-fixture")
	const program = "package main\nimport \"time\"\nfunc main() { time.Sleep(2 * time.Minute) }\n"
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-mod=readonly",
		"-trimpath", "-ldflags=-s -w", "-o", executable, source)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build Docker fixture process: %v: %s", err, raw)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if len(binary) > maxOCIBytes {
		t.Fatal("Docker fixture process exceeds its size budget")
	}
	return binary
}

func fixtureDocker(t *testing.T, input []byte, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"--context", "default"}, args...)...)
	cmd.Stdin = bytes.NewReader(input)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Docker fixture command %s failed: %v: %s", args[0], err, raw)
	}
	return strings.TrimSpace(string(raw))
}

func TestReleaseImageObservationAgainstDockerEngine(t *testing.T) {
	if os.Getenv("ZVM_TEST_DOCKER_IMAGE") != "1" {
		t.Skip("requires the isolated Docker CI lane")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	layer := fixtureTar(t, tarEntry{"observer-fixture", 0755, compileImageFixture(t)})
	layerSize := int64(len(layer))
	layerDescriptor := ociDescriptor{Digest: "sha256:" + digest(layer), Size: &layerSize,
		MediaType: "application/vnd.oci.image.layer.v1.tar"}
	makeConfig := func(label string) []byte {
		return imageJSON(t, map[string]any{
			"os": "linux", "architecture": runtime.GOARCH,
			"rootfs": map[string]any{"type": "layers", "diff_ids": []string{layerDescriptor.Digest}},
			"config": map[string]any{"Entrypoint": []string{"/observer-fixture"}, "Labels": map[string]string{"fixture": label}},
		})
	}
	configRaw := makeConfig("selected")
	config := putOCI(t, root, configRaw, ociConfig)
	manifest := fixtureOCIManifest(t, root, config, []ociDescriptor{layerDescriptor})
	configFile := strings.TrimPrefix(config.Digest, "sha256:") + ".json"
	loadManifest := imageJSON(t, []any{map[string]any{"Config": configFile, "Layers": []string{"layer.tar"}}})
	archive := fixtureTar(t, tarEntry{configFile, 0600, configRaw}, tarEntry{"layer.tar", 0600, layer},
		tarEntry{"manifest.json", 0600, loadManifest})
	fixtureDocker(t, archive, "image", "load", "--quiet")
	container := fixtureDocker(t, nil, "container", "run", "--detach", "--rm", "--pull=never",
		"--network=none", "--read-only", config.Digest)
	if !hash(container, 64) {
		t.Fatal("Docker did not return the full fixture container ID")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "docker", "--context", "default", "container", "stop", "--time", "1", container).Run(); err != nil {
			t.Error("the owned Docker fixture could not be stopped")
		}
	})
	f := newFixture(t)
	image := &f.manifest.Images[0]
	image.Platform = "linux/" + runtime.GOARCH
	image.Reference = "registry.invalid/fixture/engine@" + manifest.Digest
	target := ImageTarget{ImageID: image.ID, ContainerID: container, DockerContext: "default", OCIRoot: root}
	inputs := writeReleaseTestInputs(t, f)
	raw := runReleaseTestCLI(t, "release-observe-image", "-manifest", filepath.Join(inputs, "manifest.json"),
		"-policy", filepath.Join(inputs, "policy.json"), "-signatures", filepath.Join(inputs, "signatures.json"),
		"-trusted-keys", filepath.Join(inputs, "keys.json"), "-image", target.ImageID,
		"-container", target.ContainerID, "-docker-context", target.DockerContext, "-oci-root", target.OCIRoot)
	var observation ImageObservation
	manifestHash, _ := f.manifest.Fingerprint()
	epochHash, _ := f.manifest.EpochFingerprint()
	want := ImageObservation{
		ManifestSHA256: manifestHash, EpochSHA256: epochHash, TrustedSignatures: 2,
		ImageID: image.ID, Platform: image.Platform, ReferenceDigest: manifest.Digest,
		PlatformManifest: manifest.Digest, ImageConfigDigest: config.Digest, ContainerRunning: true,
	}
	if json.Unmarshal(raw, &observation) != nil || observation != want ||
		bytes.Contains(raw, []byte(container)) || bytes.Contains(raw, []byte(root)) {
		t.Fatal("release CLI did not bind the running Docker image to the signed manifest")
	}
	t.Logf("Verified running Docker fixture image configuration %s", observation.ImageConfigDigest)

	otherConfig := putOCI(t, root, makeConfig("different"), ociConfig)
	otherManifest := fixtureOCIManifest(t, root, otherConfig, []ociDescriptor{layerDescriptor})
	image.Reference = "registry.invalid/fixture/engine@" + otherManifest.Digest
	observation, err = f.manifest.ObserveImage(t.Context(), f.policy, f.signatures(t), f.keys, target)
	if err == nil || !strings.Contains(err.Error(), "running container image ID disagrees") || observation != (ImageObservation{}) {
		t.Fatalf("running container received a record for a different signed image: %+v, %v", observation, err)
	}
}
