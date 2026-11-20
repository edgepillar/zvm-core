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
}

// ServicesObservation records every signed running service and replica.
type ServicesObservation struct {
	ManifestSHA256      string               `json:"manifestSha256"`
	EpochSHA256         string               `json:"epochSha256"`
	ProcessPolicySHA256 string               `json:"processPolicySha256"`
	TrustedSignatures   int                  `json:"trustedSignatures"`
	ContainersObserved  int                  `json:"containersObserved"`
	Services            []ServiceObservation `json:"services"`
}

type composeMember struct {
	ID      string `json:"id"`
	Service string `json:"service"`
}

func runningComposeMembers(parent context.Context, target ServicesTarget) ([]composeMember, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	const projection = `{"id":{{json .ID}},"service":{{json (.Label "com.docker.compose.service")}}}`
	cmd := exec.CommandContext(ctx, "docker", "--context", target.DockerContext, "container", "ls",
		"--no-trunc", "--filter", "label=com.docker.compose.project="+target.Project, "--format", projection)
	cmd.WaitDelay = time.Second
	var output commandOutput
	cmd.Stdout = &output
	if cmd.Run() != nil || output.overflow {
		return nil, errors.New("running Compose inventory could not be read")
	}
	var members []composeMember
	seen := map[string]bool{}
	for line := range bytes.SplitSeq(bytes.TrimSpace(output.data.Bytes()), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var member composeMember
		if len(members) >= MaxEntries || len(line) > 1024 || decode(line, &member) != nil ||
			!hash(member.ID, 64) || !identifier.MatchString(member.Service) || seen[member.ID] {
			return nil, errors.New("running Compose inventory has an invalid or unlabelled container")
		}
		seen[member.ID] = true
		members = append(members, member)
	}
	slices.SortFunc(members, func(a, b composeMember) int { return strings.Compare(a.ID, b.ID) })
	return members, nil
}

func matchServiceInventory(members []composeMember, expected map[string]servicePins) error {
	counts := make(map[string]int, len(expected))
	for _, member := range members {
		if _, exists := expected[member.Service]; !exists {
			return errors.New("running Compose inventory contains an undeclared service")
		}
		counts[member.Service]++
	}
	for service, pins := range expected {
		if counts[service] != pins.replicas {
			return fmt.Errorf("running Compose replicas disagree with the signed count for %s", service)
		}
	}
	return nil
}

// ObserveServices authenticates the release and observes every required running
// container in one Compose project, including distinct roles sharing an image.
func (m Manifest) ObserveServices(parent context.Context, p Policy, s Signatures, k TrustedKeys, target ServicesTarget) (ServicesObservation, error) {
	var result ServicesObservation
	count, err := m.VerifySignatures(p, s, k)
	if err != nil {
		return result, err
	}
	if runtime.GOOS != "linux" {
		return result, errors.New("service observation requires the Linux Docker host")
	}
	if !identifier.MatchString(target.Project) || target.DockerContext == "" || target.OCIRoot == "" || target.FilesRoot == "" {
		return result, errors.New("Compose project, Docker context, OCI root and signed files root are required")
	}
	policy, services, err := m.runtimeServices(target.FilesRoot)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	members, err := runningComposeMembers(ctx, target)
	if err != nil {
		return result, err
	}
	if err := matchServiceInventory(members, services); err != nil {
		return result, err
	}
	type checkedContainer struct {
		target   ImageTarget
		image    ImageObservation
		snapshot dockerSnapshot
	}
	checked := make([]checkedContainer, 0, len(members))
	images := make(map[string]ImageObservation)
	observed := make(map[string]ServiceObservation, len(services))
	for _, member := range members {
		service := services[member.Service]
		wanted, exists := images[service.image]
		if !exists {
			wanted, err = m.expectedImage(count, service.image, target.OCIRoot)
			if err != nil {
				return result, err
			}
			images[service.image] = wanted
		}
		selected := ImageTarget{
			ImageID: service.image, ContainerID: member.ID,
			DockerContext: target.DockerContext, OCIRoot: target.OCIRoot,
		}
		image, snapshot, err := observeExpectedImage(ctx, selected, wanted)
		if err != nil {
			return result, fmt.Errorf("service %s: %w", member.Service, err)
		}
		if snapshot.Project != target.Project || snapshot.Service != member.Service {
			return result, errors.New("Compose container labels changed during service observation")
		}
		process, err := observePinnedProcess(ctx, selected, image, snapshot, policy, service.files)
		if err != nil {
			return result, fmt.Errorf("service %s: %w", member.Service, err)
		}
		checked = append(checked, checkedContainer{target: selected, image: image, snapshot: snapshot})
		role := observed[member.Service]
		role.Name, role.Replicas = member.Service, role.Replicas+1
		role.ImageID, role.Platform = image.ImageID, image.Platform
		role.PlatformManifestDigest, role.ImageConfigDigest = image.PlatformManifest, image.ImageConfigDigest
		role.ExecutableSHA256 = process.ExecutableSHA256
		role.VerifiedConfigFilesPerReplica = process.VerifiedConfigFiles
		role.VerifiedMountedFilesPerReplica = process.VerifiedMountedFiles
		if image.ObservedPlatformManifest != "" {
			role.ReplicasWithObservedManifest++
		}
		observed[member.Service] = role
	}
	for _, entry := range checked {
		if err := confirmDockerProcess(ctx, entry.target, entry.image, entry.snapshot); err != nil {
			return result, err
		}
	}
	current, err := runningComposeMembers(ctx, target)
	if err != nil || !slices.Equal(current, members) {
		return result, errors.New("Compose project membership changed during service observation")
	}
	result = ServicesObservation{
		ManifestSHA256: checked[0].image.ManifestSHA256, EpochSHA256: checked[0].image.EpochSHA256,
		ProcessPolicySHA256: policy, TrustedSignatures: count, ContainersObserved: len(checked),
		Services: make([]ServiceObservation, 0, len(observed)),
	}
	for _, service := range observed {
		result.Services = append(result.Services, service)
	}
	slices.SortFunc(result.Services, func(a, b ServiceObservation) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}
