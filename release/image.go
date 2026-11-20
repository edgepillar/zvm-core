package release

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	ociIndex       = "application/vnd.oci.image.index.v1+json"
	ociManifest    = "application/vnd.oci.image.manifest.v1+json"
	ociConfig      = "application/vnd.oci.image.config.v1+json"
	dockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	dockerConfig   = "application/vnd.docker.container.image.v1+json"
	maxOCIBytes    = 4 << 20
)

// ImageTarget selects a signed image ID and an exact container on an
// independently chosen Docker context. OCIRoot supplies content-addressed JSON.
type ImageTarget struct {
	ImageID       string
	ContainerID   string
	DockerContext string
	OCIRoot       string
}

// ImageObservation binds a Docker container's selected image to the signed
// reference and platform manifest.
type ImageObservation struct {
	ManifestSHA256           string `json:"manifestSha256"`
	EpochSHA256              string `json:"epochSha256"`
	TrustedSignatures        int    `json:"trustedSignatures"`
	ImageID                  string `json:"imageId"`
	Platform                 string `json:"platform"`
	ReferenceDigest          string `json:"referenceDigest"`
	PlatformManifest         string `json:"platformManifestDigest"`
	ImageConfigDigest        string `json:"imageConfigDigest"`
	ObservedPlatformManifest string `json:"observedPlatformManifestDigest,omitempty"`
	ContainerRunning         bool   `json:"containerRunning"`
}

type ociPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant"`
}

type ociDescriptor struct {
	MediaType string       `json:"mediaType"`
	Digest    string       `json:"digest"`
	Size      *int64       `json:"size"`
	Platform  *ociPlatform `json:"platform"`
}

type ociImageDocument struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
	Config        *ociDescriptor  `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

func sha256Descriptor(value string) bool {
	hex, ok := strings.CutPrefix(value, "sha256:")
	return ok && hash(hex, 64)
}

func readOCIBlob(root *os.Root, digestValue string, size *int64, out any) error {
	if !sha256Descriptor(digestValue) || (size != nil && (*size <= 0 || *size > maxOCIBytes)) {
		return errors.New("OCI document descriptor is invalid")
	}
	f, err := openFile(root, "blobs/sha256/"+strings.TrimPrefix(digestValue, "sha256:"))
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxOCIBytes+1))
	if err != nil || len(raw) > maxOCIBytes || (size != nil && *size != int64(len(raw))) ||
		"sha256:"+digest(raw) != digestValue {
		return errors.New("OCI document bytes disagree with the descriptor")
	}
	if compilerJSON(raw, maxOCIBytes) != nil || json.Unmarshal(raw, out) != nil {
		return errors.New("OCI document JSON is invalid or ambiguous")
	}
	return nil
}

func matchesOCIPlatform(p ociPlatform, want []string) bool {
	return p.OS == want[0] && p.Architecture == want[1] &&
		(len(want) == 2 || p.Variant == "" || p.Variant == want[2])
}

func selectOCIManifest(index ociImageDocument, want []string) (ociDescriptor, error) {
	if index.Config != nil || index.Layers != nil || len(index.Manifests) == 0 ||
		len(index.Manifests) > MaxEntries || (index.MediaType != "" && index.MediaType != ociIndex && index.MediaType != dockerList) {
		return ociDescriptor{}, errors.New("OCI image index is invalid")
	}
	var selected ociDescriptor
	for _, child := range index.Manifests {
		if (child.MediaType != ociManifest && child.MediaType != dockerManifest) ||
			child.Platform == nil || !matchesOCIPlatform(*child.Platform, want) {
			continue
		}
		if selected.Platform != nil {
			return ociDescriptor{}, errors.New("OCI image index has multiple matches for the signed platform")
		}
		selected = child
	}
	if selected.Size == nil {
		return ociDescriptor{}, errors.New("OCI image index has no supported manifest for the signed platform")
	}
	return selected, nil
}

func resolveOCIImage(root *os.Root, image Image) (reference, manifest, config string, err error) {
	_, reference, _ = strings.Cut(image.Reference, "@")
	manifest = reference
	want := strings.Split(image.Platform, "/")
	var document ociImageDocument
	if err := readOCIBlob(root, reference, nil, &document); err != nil {
		return "", "", "", err
	}
	var indexedVariant string
	if document.Manifests != nil {
		if document.SchemaVersion != 2 {
			return "", "", "", errors.New("OCI image index has an unsupported schema")
		}
		child, err := selectOCIManifest(document, want)
		if err != nil {
			return "", "", "", err
		}
		manifest, indexedVariant = child.Digest, child.Platform.Variant
		document = ociImageDocument{}
		if err := readOCIBlob(root, manifest, child.Size, &document); err != nil {
			return "", "", "", err
		}
		if document.MediaType != "" && document.MediaType != child.MediaType {
			return "", "", "", errors.New("OCI platform manifest type disagrees with the index")
		}
	}
	if document.SchemaVersion != 2 || document.Manifests != nil || document.Config == nil ||
		document.Config.Size == nil || document.Layers == nil || len(document.Layers) > MaxEntries ||
		(document.MediaType != "" && document.MediaType != ociManifest && document.MediaType != dockerManifest) ||
		(document.Config.MediaType != ociConfig && document.Config.MediaType != dockerConfig) {
		return "", "", "", errors.New("OCI platform manifest is invalid")
	}
	var configuration struct {
		ociPlatform
		RootFS struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	config = document.Config.Digest
	if err := readOCIBlob(root, config, document.Config.Size, &configuration); err != nil {
		return "", "", "", err
	}
	if indexedVariant != "" && configuration.Variant != "" && configuration.Variant != indexedVariant {
		return "", "", "", errors.New("OCI configuration variant disagrees with the index")
	}
	if configuration.Variant == "" {
		configuration.Variant = indexedVariant
	}
	if !matchesOCIPlatform(configuration.ociPlatform, want) || (len(want) == 3 && configuration.Variant != want[2]) ||
		configuration.RootFS.Type != "layers" || configuration.RootFS.DiffIDs == nil ||
		len(configuration.RootFS.DiffIDs) != len(document.Layers) {
		return "", "", "", errors.New("OCI configuration disagrees with the signed platform or manifest")
	}
	return reference, manifest, config, nil
}

func observeDockerImage(parent context.Context, target ImageTarget, platform, config string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	// Use the JSON field names across Docker API versions. The selected image
	// descriptor is optional on engines with the classic image store.
	const projected = `{"id":{{json (index . "Id")}},"image":{{json (index . "Image")}},"status":{{json (index (index . "State") "Status")}},"running":{{json (index (index . "State") "Running")}},"manifest":{{with index . "ImageManifestDescriptor"}}{{json (index . "digest")}}{{else}}""{{end}}}`
	cmd := exec.CommandContext(ctx, "docker", "--context", target.DockerContext, "container", "inspect",
		"--format", projected, "--", target.ContainerID)
	cmd.WaitDelay = time.Second
	var output commandOutput
	cmd.Stdout = &output
	if cmd.Run() != nil || output.overflow || output.data.Len() > 1024 {
		return "", errors.New("Docker container observation was unavailable")
	}
	return checkDockerImage(output.data.Bytes(), target.ContainerID, platform, config)
}

func checkDockerImage(raw []byte, container, platform, config string) (string, error) {
	var observed struct {
		ID       string `json:"id"`
		Image    string `json:"image"`
		Status   string `json:"status"`
		Running  bool   `json:"running"`
		Manifest string `json:"manifest"`
	}
	if decode(raw, &observed) != nil || observed.ID != container || !observed.Running || observed.Status != "running" || !sha256Descriptor(observed.Image) {
		return "", errors.New("Docker did not report the selected container running with a valid image ID")
	}
	if observed.Manifest != "" {
		if observed.Manifest != platform {
			return "", errors.New("running container manifest disagrees with the signed platform manifest")
		}
		return observed.Manifest, nil
	}
	if observed.Image != config {
		return "", errors.New("running container image ID disagrees with the signed image configuration")
	}
	return "", nil
}

// ObserveImage authenticates the release before reading OCI blobs or inspecting
// the observer's explicitly selected container. It performs no registry lookup.
func (m Manifest) ObserveImage(ctx context.Context, p Policy, s Signatures, k TrustedKeys, target ImageTarget) (ImageObservation, error) {
	var result ImageObservation
	count, err := m.VerifySignatures(p, s, k)
	if err != nil {
		return result, err
	}
	index := slices.IndexFunc(m.Images, func(image Image) bool { return image.ID == target.ImageID })
	if index < 0 || !hash(target.ContainerID, 64) || target.DockerContext == "" || target.OCIRoot == "" {
		return result, errors.New("signed image ID, full container ID, Docker context and OCI root are required")
	}
	root, err := openDirectory(target.OCIRoot)
	if err != nil {
		return result, err
	}
	defer root.Close()
	image := m.Images[index]
	reference, platformManifest, config, err := resolveOCIImage(root, image)
	if err != nil {
		return result, err
	}
	manifest, err := m.Fingerprint()
	if err != nil {
		return result, err
	}
	epoch, err := m.EpochFingerprint()
	if err != nil {
		return result, err
	}
	observedManifest, err := observeDockerImage(ctx, target, platformManifest, config)
	if err != nil {
		return result, err
	}
	return ImageObservation{
		ManifestSHA256: manifest, EpochSHA256: epoch, TrustedSignatures: count,
		ImageID: image.ID, Platform: image.Platform, ReferenceDigest: reference,
		PlatformManifest: platformManifest, ImageConfigDigest: config,
		ObservedPlatformManifest: observedManifest, ContainerRunning: true,
	}, nil
}
