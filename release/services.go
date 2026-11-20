package release

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"
)

// ServicesTarget selects one Compose project on the observer's Docker host.
type ServicesTarget struct {
	DockerContext string
	Project       string
	OCIRoot       string
	FilesRoot     string
}

type ServiceObservation struct {
	Name                           string `json:"name"`
	Replicas                       int    `json:"replicas"`
	ImageID                        string `json:"imageId"`
	Platform                       string `json:"platform"`
	PlatformManifestDigest         string `json:"platformManifestDigest"`
	ImageConfigDigest              string `json:"imageConfigDigest"`
	ReplicasWithObservedManifest   int    `json:"replicasWithObservedManifest"`
	ExecutableSHA256               string `json:"executableSha256"`
	VerifiedConfigFilesPerReplica  int    `json:"verifiedConfigFilesPerReplica"`
	VerifiedMountedFilesPerReplica int    `json:"verifiedMountedFilesPerReplica"`
	VerifiedJobOutputsPerReplica   int    `json:"verifiedJobOutputsPerReplica,omitempty"`
}

// ServicesObservation records the signed running replicas and completed jobs.
type ServicesObservation struct {
	ManifestSHA256      string               `json:"manifestSha256"`
	EpochSHA256         string               `json:"epochSha256"`
	ProcessPolicySHA256 string               `json:"processPolicySha256"`
	TrustedSignatures   int                  `json:"trustedSignatures"`
	ContainersObserved  int                  `json:"containersObserved"`
	Services            []ServiceObservation `json:"services"`
	CompletedJobs       []JobObservation     `json:"completedJobs,omitempty"`
}

type composeMember struct {
	ID      string `json:"id"`
	Service string `json:"service"`
	State   string `json:"state"`
}

func composeMembers(parent context.Context, target ServicesTarget, jobs map[string]runtimeJob) ([]composeMember, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	const projection = `{"id":{{json .ID}},"service":{{json (.Label "com.docker.compose.service")}},"state":{{json .State}}}`
	args := []string{"--context", target.DockerContext, "container", "ls",
		"--no-trunc", "--filter", "label=com.docker.compose.project=" + target.Project, "--format", projection}
	if len(jobs) != 0 {
		args = append(args, "--all")
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.WaitDelay = time.Second
	var output commandOutput
	cmd.Stdout = &output
	if cmd.Run() != nil || output.overflow {
		return nil, errors.New("Compose inventory could not be read")
	}
	var members []composeMember
	seen := map[string]bool{}
	for line := range bytes.SplitSeq(bytes.TrimSpace(output.data.Bytes()), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var member composeMember
		if len(seen) >= MaxEntries || len(line) > 1024 || decode(line, &member) != nil ||
			!hash(member.ID, 64) || !identifier.MatchString(member.Service) || seen[member.ID] {
			return nil, errors.New("Compose inventory has an invalid or unlabelled container")
		}
		seen[member.ID] = true
		switch member.State {
		case "running", "restarting", "paused":
		case "created", "exited", "dead", "removing":
			if _, required := jobs[member.Service]; !required {
				continue
			}
		default:
			return nil, errors.New("Compose inventory has an unknown container state")
		}
		members = append(members, member)
	}
	slices.SortFunc(members, func(a, b composeMember) int { return strings.Compare(a.ID, b.ID) })
	return members, nil
}

func matchServiceInventory(members []composeMember, inventory runtimeInventory) error {
	counts := make(map[string]int, len(inventory.services)+len(inventory.jobs))
	for _, member := range members {
		if _, isJob := inventory.jobs[member.Service]; isJob {
			if member.State != "exited" {
				return fmt.Errorf("Compose job %s did not exit", member.Service)
			}
		} else if _, exists := inventory.services[member.Service]; !exists {
			return errors.New("running Compose inventory contains an undeclared service")
		}
		counts[member.Service]++
	}
	for service, pins := range inventory.services {
		if counts[service] != pins.replicas {
			return fmt.Errorf("running Compose replicas disagree with the signed count for %s", service)
		}
	}
	for job := range inventory.jobs {
		if counts[job] != 1 {
			return fmt.Errorf("Compose inventory requires one completed container for job %s", job)
		}
	}
	return nil
}

func (target ServicesTarget) validate() error {
	if runtime.GOOS != "linux" {
		return errors.New("service observation requires the Linux Docker host")
	}
	if !identifier.MatchString(target.Project) || target.DockerContext == "" || target.OCIRoot == "" || target.FilesRoot == "" {
		return errors.New("Compose project, Docker context, OCI root and signed files root are required")
	}
	return nil
}

// ObserveServices authenticates and checks the signed running service and
// completed job inventories in one Compose project.
func (m Manifest) ObserveServices(parent context.Context, p Policy, s Signatures, k TrustedKeys, target ServicesTarget) (ServicesObservation, error) {
	count, err := m.VerifySignatures(p, s, k)
	if err != nil {
		return ServicesObservation{}, err
	}
	if err := target.validate(); err != nil {
		return ServicesObservation{}, err
	}
	return m.observeServices(parent, count, target, nil)
}

func (m Manifest) observeServices(parent context.Context, count int, target ServicesTarget, observeChain func(context.Context) error) (ServicesObservation, error) {
	var result ServicesObservation
	inventory, err := m.runtimeInventory(target.FilesRoot)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	members, err := composeMembers(ctx, target, inventory.jobs)
	if err != nil {
		return result, err
	}
	if err := matchServiceInventory(members, inventory); err != nil {
		return result, err
	}
	type checkedContainer struct {
		target   ImageTarget
		image    ImageObservation
		snapshot dockerSnapshot
		pins     []processPin
		files    *processFilesSnapshot
	}
	type checkedJob struct {
		target           ImageTarget
		image            ImageObservation
		pin              runtimeJob
		snapshot         dockerJobSnapshot
		expectedBindings int
	}
	checked := make([]checkedContainer, 0, len(members)-len(inventory.jobs))
	jobs := make([]checkedJob, 0, len(inventory.jobs))
	images := make(map[string]ImageObservation)
	observed := make(map[string]ServiceObservation, len(inventory.services))
	loadImage := func(id string) (ImageObservation, error) {
		if image, exists := images[id]; exists {
			return image, nil
		}
		image, err := m.expectedImage(count, id, target.OCIRoot)
		if err == nil {
			images[id] = image
		}
		return image, err
	}
	for _, member := range members {
		job, isJob := inventory.jobs[member.Service]
		if !isJob {
			continue
		}
		image, err := loadImage(job.Image)
		if err != nil {
			return result, err
		}
		selected := ImageTarget{ImageID: job.Image, ContainerID: member.ID, DockerContext: target.DockerContext, OCIRoot: target.OCIRoot}
		snapshot, err := observeDockerJob(ctx, selected, target.Project, job, image)
		if err != nil {
			return result, fmt.Errorf("job %s: %w", member.Service, err)
		}
		var expectedBindings int
		for i, output := range job.Outputs {
			service := inventory.services[output.Service]
			path := strings.TrimPrefix(output.ServicePath, "/")
			index := slices.IndexFunc(service.files, func(pin processPin) bool { return pin.path == path })
			service.files[index].output = snapshot.Outputs[i]
			expectedBindings += service.replicas
		}
		jobs = append(jobs, checkedJob{
			target: selected, image: image, pin: job, snapshot: snapshot, expectedBindings: expectedBindings,
		})
	}
	for _, member := range members {
		service, running := inventory.services[member.Service]
		if !running {
			continue
		}
		wanted, err := loadImage(service.image)
		if err != nil {
			return result, err
		}
		selected := ImageTarget{ImageID: service.image, ContainerID: member.ID, DockerContext: target.DockerContext, OCIRoot: target.OCIRoot}
		image, snapshot, err := observeExpectedImage(ctx, selected, wanted)
		if err != nil {
			return result, fmt.Errorf("service %s: %w", member.Service, err)
		}
		if snapshot.Project != target.Project || snapshot.Service != member.Service {
			return result, errors.New("Compose container labels changed during service observation")
		}
		var files *processFilesSnapshot
		if observeChain != nil {
			files = &processFilesSnapshot{}
		}
		process, err := observePinnedProcess(ctx, selected, image, snapshot, inventory.policySHA256, service.files, files)
		if err != nil {
			return result, fmt.Errorf("service %s: %w", member.Service, err)
		}
		checked = append(checked, checkedContainer{target: selected, image: image, snapshot: snapshot, pins: service.files, files: files})
		role := observed[member.Service]
		role.Name, role.Replicas = member.Service, role.Replicas+1
		role.ImageID, role.Platform = image.ImageID, image.Platform
		role.PlatformManifestDigest, role.ImageConfigDigest = image.PlatformManifest, image.ImageConfigDigest
		role.ExecutableSHA256 = process.ExecutableSHA256
		role.VerifiedConfigFilesPerReplica = process.VerifiedConfigFiles
		role.VerifiedMountedFilesPerReplica = process.VerifiedMountedFiles
		role.VerifiedJobOutputsPerReplica = process.VerifiedJobOutputs
		if image.ObservedPlatformManifest != "" {
			role.ReplicasWithObservedManifest++
		}
		observed[member.Service] = role
	}
	if observeChain != nil {
		if err := observeChain(ctx); err != nil {
			return result, err
		}
	}
	for _, entry := range checked {
		if entry.files != nil {
			recheck := func() error { return confirmDockerProcess(ctx, entry.target, entry.image, entry.snapshot) }
			if err := verifyProcessFiles(ctx, entry.snapshot, entry.pins, recheck, entry.files); err != nil {
				return result, fmt.Errorf("service %s changed during chain observation: %w", entry.snapshot.Service, err)
			}
			continue
		}
		if err := confirmDockerProcess(ctx, entry.target, entry.image, entry.snapshot); err != nil {
			return result, err
		}
	}
	var completed []JobObservation
	for _, job := range jobs {
		current, err := observeDockerJob(ctx, job.target, target.Project, job.pin, job.image)
		if err != nil || !current.matches(job.snapshot) {
			return result, fmt.Errorf("Compose job %s changed during verification", job.pin.Name)
		}
		completed = append(completed, JobObservation{
			Name: job.pin.Name, ImageID: job.image.ImageID,
			PlatformManifest: job.image.PlatformManifest, ImageConfigDigest: job.image.ImageConfigDigest,
			ObservedPlatformManifest: current.Container.Manifest, CommandSHA256: job.pin.CommandSHA256, ExitCode: 0,
			VerifiedOutputBindings: job.expectedBindings,
		})
	}
	current, err := composeMembers(ctx, target, inventory.jobs)
	if err != nil || !slices.Equal(current, members) {
		return result, errors.New("Compose inventory changed during service observation")
	}
	result = ServicesObservation{
		ManifestSHA256: checked[0].image.ManifestSHA256, EpochSHA256: checked[0].image.EpochSHA256,
		ProcessPolicySHA256: inventory.policySHA256, TrustedSignatures: count, ContainersObserved: len(checked),
		Services: make([]ServiceObservation, 0, len(observed)), CompletedJobs: completed,
	}
	for _, service := range observed {
		result.Services = append(result.Services, service)
	}
	slices.SortFunc(result.Services, func(a, b ServiceObservation) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(result.CompletedJobs, func(a, b JobObservation) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}
