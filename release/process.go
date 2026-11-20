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
	Name       string        `json:"name,omitempty"`
	Image      string        `json:"image"`
	Replicas   int           `json:"replicas,omitempty"`
	Executable string        `json:"executable"`
	Files      []runtimeFile `json:"files"`
}

type runtimeProcessPolicy struct {
	Schema   int              `json:"schema"`
	Services []runtimeService `json:"services"`
	Jobs     []runtimeJob     `json:"jobs,omitempty"`
}

type processPin struct {
	file    File
	path    string
	mounted bool
}

type servicePins struct {
	image    string
	replicas int
	files    []processPin
}

type runtimeInventory struct {
	policySHA256 string
	services     map[string]servicePins
	jobs         map[string]runtimeJob
}

func configFileKind(kind string) bool {
	switch kind {
	case "config", "rollup", "l1-genesis", "l2-genesis", "deployments":
		return true
	default:
		return false
	}
}

func (m Manifest) runtimeInventory(directory string) (runtimeInventory, error) {
	files := make(map[string]File, len(m.Files))
	for _, file := range m.Files {
		files[file.ID] = file
	}
	pin := files[runtimeProcessPolicyID]
	if pin.Kind != "config" {
		return runtimeInventory{}, errors.New("a signed runtime process policy is required")
	}
	root, err := openDirectory(directory)
	if err != nil {
		return runtimeInventory{}, err
	}
	defer root.Close()
	raw, err := readPin(root, pin, MaxDocumentBytes)
	if err != nil {
		return runtimeInventory{}, err
	}
	var policy runtimeProcessPolicy
	if decode(raw, &policy) != nil || policy.Schema != Schema || len(policy.Services) == 0 {
		return runtimeInventory{}, errors.New("signed runtime process policy is invalid")
	}
	images := make(map[string]bool, len(m.Images))
	for _, image := range m.Images {
		images[image.ID] = true
	}
	services := make(map[string]servicePins, len(policy.Services))
	instances := len(policy.Jobs)
	for _, service := range policy.Services {
		name := service.Name
		if name == "" {
			name = service.Image
		}
		if !identifier.MatchString(name) || services[name].files != nil || !images[service.Image] {
			return runtimeInventory{}, errors.New("runtime process policy requires unique service names and signed image IDs")
		}
		replicas := service.Replicas
		if replicas == 0 {
			replicas = 1
		}
		if replicas < 0 || replicas > MaxEntries-instances {
			return runtimeInventory{}, errors.New("runtime process policy exceeds the container limit")
		}
		instances += replicas
		executable := files[service.Executable]
		if executable.Kind != "artifact" || executable.Bytes <= 0 || service.Files == nil {
			return runtimeInventory{}, errors.New("runtime process policy requires a signed executable and a file list")
		}
		bindings := []processPin{{file: executable}}
		seen := make(map[string]bool, len(service.Files))
		total := executable.Bytes
		for _, binding := range service.Files {
			path, absolute := strings.CutPrefix(binding.Path, "/")
			file := files[binding.File]
			if !absolute || !relative(path) || seen[path] || !configFileKind(file.Kind) {
				return runtimeInventory{}, errors.New("runtime process policy has an invalid file binding")
			}
			seen[path] = true
			total += file.Bytes
			if total > 4<<30 {
				return runtimeInventory{}, errors.New("runtime process file bindings exceed their byte budget")
			}
			bindings = append(bindings, processPin{file: file, path: path, mounted: binding.Mounted})
		}
		services[name] = servicePins{image: service.Image, replicas: replicas, files: bindings}
	}
	jobs := make(map[string]runtimeJob, len(policy.Jobs))
	for _, job := range policy.Jobs {
		if !identifier.MatchString(job.Name) || services[job.Name].files != nil || jobs[job.Name].Name != "" ||
			!images[job.Image] || !hash(job.CommandSHA256, 64) {
			return runtimeInventory{}, errors.New("runtime process policy requires unique job names, signed image IDs and command digests")
		}
		jobs[job.Name] = job
	}
	return runtimeInventory{policySHA256: pin.SHA256, services: services, jobs: jobs}, nil
}

func (m Manifest) runtimePins(directory, imageID string) (string, []processPin, error) {
	inventory, err := m.runtimeInventory(directory)
	if err != nil {
		return "", nil, err
	}
	var selected []processPin
	for _, service := range inventory.services {
		if service.image == imageID {
			if selected != nil {
				return "", nil, errors.New("several runtime services share the selected image")
			}
			selected = service.files
		}
	}
	if len(selected) == 0 {
		return "", nil, errors.New("runtime process policy does not include the selected image")
	}
	return inventory.policySHA256, selected, nil
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
	return observePinnedProcess(ctx, target, image, snapshot, policy, pins)
}

func confirmDockerProcess(ctx context.Context, target ImageTarget, image ImageObservation, snapshot dockerSnapshot) error {
	current, err := observeDockerImage(ctx, target, image.PlatformManifest, image.ImageConfigDigest)
	if err != nil || current != snapshot {
		return errors.New("Docker changed the observed container during process verification")
	}
	return nil
}

func observePinnedProcess(ctx context.Context, target ImageTarget, image ImageObservation, snapshot dockerSnapshot, policy string, pins []processPin) (ProcessObservation, error) {
	var result ProcessObservation
	startedAt, err := time.Parse(time.RFC3339Nano, snapshot.StartedAt)
	if err != nil || startedAt.IsZero() || snapshot.PID <= 0 {
		return result, errors.New("Docker did not report a valid running process identity")
	}
	recheck := func() error {
		return confirmDockerProcess(ctx, target, image, snapshot)
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
