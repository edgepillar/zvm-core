package release

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"
)

const runtimeProcessPolicyID = "runtime-process-policy"

// ProcessObservation binds process-visible files to the signed release and
// the same container snapshot used to observe the image.
type ProcessObservation struct {
	Image                ImageObservation `json:"image"`
	ProcessPolicySHA256  string           `json:"processPolicySha256"`
	ExecutableSHA256     string           `json:"executableSha256"`
	VerifiedConfigFiles  int              `json:"verifiedConfigFiles"`
	VerifiedMountedFiles int              `json:"verifiedMountedFiles"`
}

type runtimeFile struct {
	Path    string `json:"path"`
	File    string `json:"file"`
	Mounted bool   `json:"mounted"`
}

type runtimeService struct {
	Image      string        `json:"image"`
	Executable string        `json:"executable"`
	Files      []runtimeFile `json:"files"`
}

type runtimeProcessPolicy struct {
	Schema   int              `json:"schema"`
	Services []runtimeService `json:"services"`
}

type processPin struct {
	file    File
	path    string
	mounted bool
}

func configFileKind(kind string) bool {
	switch kind {
	case "config", "rollup", "l1-genesis", "l2-genesis", "deployments":
		return true
	default:
		return false
	}
}

func (m Manifest) runtimePins(directory, imageID string) (string, []processPin, error) {
	files := make(map[string]File, len(m.Files))
	for _, file := range m.Files {
		files[file.ID] = file
	}
	pin := files[runtimeProcessPolicyID]
	if pin.Kind != "config" {
		return "", nil, errors.New("a signed runtime process policy is required")
	}
	root, err := openDirectory(directory)
	if err != nil {
		return "", nil, err
	}
	defer root.Close()
	raw, err := readPin(root, pin, MaxDocumentBytes)
	if err != nil {
		return "", nil, err
	}
	var policy runtimeProcessPolicy
	if decode(raw, &policy) != nil || policy.Schema != Schema || len(policy.Services) == 0 {
		return "", nil, errors.New("signed runtime process policy is invalid")
	}
	images := make(map[string]bool, len(m.Images))
	for _, image := range m.Images {
		images[image.ID] = true
	}
	var selected []processPin
	for _, service := range policy.Services {
		if !images[service.Image] {
			return "", nil, errors.New("runtime process policy requires unique signed image IDs")
		}
		delete(images, service.Image)
		executable := files[service.Executable]
		if executable.Kind != "artifact" || executable.Bytes <= 0 || service.Files == nil {
			return "", nil, errors.New("runtime process policy requires a signed executable and a file list")
		}
		bindings := []processPin{{file: executable}}
		seen := make(map[string]bool, len(service.Files))
		total := executable.Bytes
		for _, binding := range service.Files {
			path, absolute := strings.CutPrefix(binding.Path, "/")
			file := files[binding.File]
			if !absolute || !relative(path) || seen[path] || !configFileKind(file.Kind) {
				return "", nil, errors.New("runtime process policy has an invalid file binding")
			}
			seen[path] = true
			total += file.Bytes
			if total > 4<<30 {
				return "", nil, errors.New("runtime process file bindings exceed their byte budget")
			}
			bindings = append(bindings, processPin{file: file, path: path, mounted: binding.Mounted})
		}
		if service.Image == imageID {
			selected = bindings
		}
	}
	if len(selected) == 0 {
		return "", nil, errors.New("runtime process policy does not include the selected image")
	}
	return pin.SHA256, selected, nil
}

// ObserveProcess checks the Docker init process and signed file paths on its host.
func (m Manifest) ObserveProcess(parent context.Context, p Policy, s Signatures, k TrustedKeys, target ImageTarget, filesRoot string) (ProcessObservation, error) {
	var result ProcessObservation
	count, err := m.VerifySignatures(p, s, k)
	if err != nil {
		return result, err
	}
	if runtime.GOOS != "linux" {
		return result, errors.New("process observation requires the Linux Docker host")
	}
	policy, pins, err := m.runtimePins(filesRoot, target.ImageID)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	image, snapshot, err := m.observeImage(ctx, count, target)
	if err != nil {
		return result, err
	}
	startedAt, err := time.Parse(time.RFC3339Nano, snapshot.StartedAt)
	if err != nil || startedAt.IsZero() || snapshot.PID <= 0 {
		return result, errors.New("Docker did not report a valid running process identity")
	}
	recheck := func() error {
		current, err := observeDockerImage(ctx, target, image.PlatformManifest, image.ImageConfigDigest)
		if err != nil || current != snapshot {
			return errors.New("Docker changed the observed container during process verification")
		}
		return nil
	}
	if err := verifyProcessFiles(ctx, snapshot, pins, recheck); err != nil {
		return result, err
	}
	var mounted int
	for _, pin := range pins {
		if pin.mounted {
			mounted++
		}
	}
	return ProcessObservation{
		Image: image, ProcessPolicySHA256: policy, ExecutableSHA256: pins[0].file.SHA256,
		VerifiedConfigFiles: len(pins) - 1, VerifiedMountedFiles: mounted,
	}, nil
}
