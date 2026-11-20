package release

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	configBytes := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	config := putOCI(t, rootPath, configBytes, ociConfig)
	manifest := fixtureOCIManifest(t, rootPath, config, []ociDescriptor{})
	manifest.Platform = &amd
	other := manifest
	other.Platform = &arm
	unsupported := manifest
	unsupported.MediaType = "application/vnd.example.other+json"
	index := fixtureOCIIndex(t, rootPath, unsupported, manifest, other)
	duplicate := fixtureOCIIndex(t, rootPath, manifest, manifest)
	wrongSize := manifest
	size := *wrongSize.Size + 1
	wrongSize.Size = &size
	badIndex := fixtureOCIIndex(t, rootPath, wrongSize)
	wrongDigest := config
	wrongDigest.Digest = "sha256:" + strings.Repeat("4", 64)
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

func TestDockerImageObservationRequiresMatchingManifestOrClassicConfig(t *testing.T) {
	id, config, manifest := strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("3", 64)
	different := "sha256:" + strings.Repeat("4", 64)
	for _, test := range []struct {
		name, image, reportedManifest, status, errorText string
	}{
		{"classic store", config, "", "running", ""},
		{"manifest store", different, manifest, "running", ""},
		{"conflicting runtime manifest", config, different, "running", "manifest disagrees"},
		{"classic config differs", different, "", "running", "image ID disagrees"},
		{"paused container", config, "", "paused", "selected container running"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := imageJSON(t, map[string]any{"id": id, "image": test.image, "manifest": test.reportedManifest, "status": test.status, "running": true})
			got, err := checkDockerImage(raw, id, manifest, config)
			if test.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorText) {
					t.Fatalf("unexpected check error: %v", err)
				}
			} else if err != nil || got.Manifest != test.reportedManifest {
				t.Fatalf("unexpected checked manifest: %q: %v", got.Manifest, err)
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
	const program = `package main

import (
	"os"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "complete" {
			return
		}
		os.Exit(1)
	}
	time.Sleep(2 * time.Minute)
}
`
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

func startFixtureContainer(t *testing.T, tag, configPath, project, service string) string {
	t.Helper()
	container := fixtureDocker(t, nil, "container", "run", "--detach", "--rm", "--pull=never",
		"--network=none", "--read-only", "--cap-drop=ALL", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--label", "com.docker.compose.project="+project, "--label", "com.docker.compose.service="+service,
		"--mount", "type=bind,source="+configPath+",target=/observer-config,readonly", tag)
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
	return container
}

func TestReleaseImageObservationAgainstDockerEngine(t *testing.T) {
	if os.Getenv("ZVM_TEST_DOCKER_IMAGE") != "1" {
		t.Skip("requires the isolated Docker CI lane")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	executable := compileImageFixture(t)
	mountedConfig := []byte("mode=test\n")
	layer := fixtureTar(t, tarEntry{"observer-fixture", 0755, executable},
		tarEntry{"observer-bundled-config", 0644, mountedConfig})
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
	blobPath := func(value string) string { return "blobs/sha256/" + strings.TrimPrefix(value, "sha256:") }
	manifestRaw, err := os.ReadFile(filepath.Join(root, blobPath(manifest.Digest)))
	if err != nil {
		t.Fatal(err)
	}
	tag := "docker.io/library/zvm-oci-observation-fixture:" + strings.TrimPrefix(config.Digest, "sha256:")[:12]
	index := imageJSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": ociIndex, "manifests": []any{map[string]any{
			"mediaType": manifest.MediaType, "digest": manifest.Digest, "size": *manifest.Size,
			"platform":    ociPlatform{OS: "linux", Architecture: runtime.GOARCH},
			"annotations": map[string]string{"io.containerd.image.name": tag, "org.opencontainers.image.ref.name": tag},
		}},
	})
	loadManifest := imageJSON(t, []any{map[string]any{
		"Config": blobPath(config.Digest), "RepoTags": []string{tag}, "Layers": []string{blobPath(layerDescriptor.Digest)},
	}})
	archive := fixtureTar(t, tarEntry{blobPath(config.Digest), 0600, configRaw},
		tarEntry{blobPath(layerDescriptor.Digest), 0600, layer}, tarEntry{blobPath(manifest.Digest), 0600, manifestRaw},
		tarEntry{"oci-layout", 0600, []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		tarEntry{"index.json", 0600, index}, tarEntry{"manifest.json", 0600, loadManifest})
	engine := fixtureDocker(t, nil, "version", "--format", "{{.Server.Version}}")
	configPath := filepath.Join(root, "process-config")
	if err := os.WriteFile(configPath, mountedConfig, 0600); err != nil {
		t.Fatal(err)
	}
	fixtureDocker(t, archive, "image", "load", "--quiet")
	project := fmt.Sprintf("zvm-release-fixture-%d", os.Getpid())
	container := startFixtureContainer(t, tag, configPath, project, "primary")
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
	if json.Unmarshal(raw, &observation) != nil ||
		(observation.ObservedPlatformManifest != "" && observation.ObservedPlatformManifest != manifest.Digest) {
		t.Fatal("release CLI returned an invalid observed platform manifest")
	}
	want.ObservedPlatformManifest = observation.ObservedPlatformManifest
	if observation != want ||
		bytes.Contains(raw, []byte(container)) || bytes.Contains(raw, []byte(root)) {
		t.Fatal("release CLI did not bind the running Docker image to the signed manifest")
	}
	t.Logf("Verified Docker %s running fixture image configuration %s, observed platform manifest %t",
		engine, observation.ImageConfigDigest, observation.ObservedPlatformManifest != "")

	otherConfig := putOCI(t, root, makeConfig("different"), ociConfig)
	otherManifest := fixtureOCIManifest(t, root, otherConfig, []ociDescriptor{layerDescriptor})
	image.Reference = "registry.invalid/fixture/engine@" + otherManifest.Digest
	observation, err = f.manifest.ObserveImage(t.Context(), f.policy, f.signatures(t), f.keys, target)
	if err == nil || !strings.Contains(err.Error(), "running container") || !strings.Contains(err.Error(), "disagrees") ||
		observation != (ImageObservation{}) {
		t.Fatalf("running container received a record for a different signed image: %+v, %v", observation, err)
	}
	image.Reference = "registry.invalid/fixture/engine@" + manifest.Digest
	t.Run("process and mounted configuration", func(t *testing.T) {
		checkProcessFixture(t, f, target, executable, mountedConfig, configPath)
	})
	t.Run("signed running service inventory", func(t *testing.T) {
		checkServicesFixture(t, *image, tag, project, root, executable, mountedConfig)
	})
}
