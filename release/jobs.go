package release

import (
	"context"
	"errors"
	"path"
	"slices"
	"strings"
	"time"
)

type runtimeJob struct {
	Name          string             `json:"name"`
	Image         string             `json:"image"`
	CommandSHA256 string             `json:"commandSha256"`
	Outputs       []runtimeJobOutput `json:"outputs,omitempty"`
}

type runtimeJobOutput struct {
	Path        string `json:"path"`
	Service     string `json:"service"`
	ServicePath string `json:"servicePath"`
}

type volumeFile struct {
	root string
	path string
}

// JobObservation describes the latest completed container retained by Docker
// for a signed Compose job.
type JobObservation struct {
	Name                     string `json:"name"`
	ImageID                  string `json:"imageId"`
	PlatformManifest         string `json:"platformManifestDigest"`
	ImageConfigDigest        string `json:"imageConfigDigest"`
	ObservedPlatformManifest string `json:"observedPlatformManifestDigest,omitempty"`
	CommandSHA256            string `json:"commandSha256"`
	ExitCode                 int    `json:"exitCode"`
	VerifiedOutputBindings   int    `json:"verifiedOutputBindings,omitempty"`
}

type dockerOutputMount struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Driver      string `json:"driver"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Writable    bool   `json:"writable"`
}

type dockerVolumeSubpath struct {
	Destination string `json:"destination"`
	Subpath     string `json:"subpath"`
}

type dockerJobRecord struct {
	Container  dockerSnapshot        `json:"container"`
	FinishedAt string                `json:"finishedAt"`
	ExitCode   *int                  `json:"exitCode"`
	OOMKilled  *bool                 `json:"oomKilled"`
	StartError string                `json:"startError"`
	OneOff     string                `json:"oneOff"`
	Path       string                `json:"path"`
	Args       []string              `json:"args"`
	Mounts     []dockerOutputMount   `json:"mounts"`
	Subpaths   []dockerVolumeSubpath `json:"subpaths"`
}

type dockerJobSnapshot struct {
	Container  dockerSnapshot
	FinishedAt string
	Outputs    []volumeFile
}

func (s dockerJobSnapshot) matches(other dockerJobSnapshot) bool {
	return s.Container == other.Container && s.FinishedAt == other.FinishedAt && slices.Equal(s.Outputs, other.Outputs)
}

const dockerJobProjection = `{"container":` + dockerImageProjection + `,
	"finishedAt":{{json (index (index . "State") "FinishedAt")}},
	"exitCode":{{json (index (index . "State") "ExitCode")}},
	"oomKilled":{{json (index (index . "State") "OOMKilled")}},
	"startError":{{json (index (index . "State") "Error")}},
	"oneOff":{{with index (index . "Config") "Labels"}}{{with index . "com.docker.compose.oneoff"}}{{json .}}{{else}}""{{end}}{{else}}""{{end}},
	"path":{{json (index . "Path")}},"args":{{json (index . "Args")}}`

const dockerOutputProjection = `,
	"mounts":[{{range $i, $m := index . "Mounts"}}{{if $i}},{{end}}{
		"type":{{json (index $m "Type")}},
		"name":{{with index $m "Name"}}{{json .}}{{else}}""{{end}},
		"driver":{{with index $m "Driver"}}{{json .}}{{else}}""{{end}},
		"source":{{with index $m "Source"}}{{json .}}{{else}}""{{end}},
		"destination":{{json (index $m "Destination")}},"writable":{{json (index $m "RW")}}
	}{{end}}],
	"subpaths":[{{range $i, $m := index (index . "HostConfig") "Mounts"}}{{if $i}},{{end}}{
		"destination":{{json (index $m "Target")}},
		"subpath":{{with index $m "VolumeOptions"}}{{with index . "Subpath"}}{{json .}}{{else}}""{{end}}{{else}}""{{end}}
	}{{end}}]`

func (record dockerJobRecord) volumeOutput(output string) (volumeFile, error) {
	var selected dockerOutputMount
	for _, mount := range record.Mounts {
		if output != mount.Destination && !strings.HasPrefix(output, mount.Destination+"/") {
			continue
		}
		if selected.Destination == mount.Destination {
			return volumeFile{}, errors.New("Docker job output has an ambiguous mount")
		}
		if len(mount.Destination) > len(selected.Destination) {
			selected = mount
		}
	}
	file, under := strings.CutPrefix(output, selected.Destination+"/")
	if !under || !relative(file) || selected.Type != "volume" || selected.Driver != "local" || selected.Name == "" ||
		!selected.Writable || !path.IsAbs(selected.Source) || path.Clean(selected.Source) != selected.Source ||
		selected.Source == "/" || len(selected.Source) >= 4096 || strings.ContainsRune(selected.Source, 0) {
		return volumeFile{}, errors.New("Docker job output requires a writable local volume")
	}
	for _, spec := range record.Subpaths {
		if spec.Destination == selected.Destination && spec.Subpath != "" {
			sub := strings.TrimPrefix(spec.Subpath, "/")
			if !relative(sub) || !relative(sub+"/"+file) {
				return volumeFile{}, errors.New("Docker job output volume subpath is invalid")
			}
			file = sub + "/" + file
			break
		}
	}
	return volumeFile{root: selected.Source, path: file}, nil
}

func observeDockerJob(ctx context.Context, target ImageTarget, project string, job runtimeJob, image ImageObservation) (dockerJobSnapshot, error) {
	projection := dockerJobProjection
	if len(job.Outputs) != 0 {
		projection += dockerOutputProjection
	}
	raw, err := inspectDockerContainer(ctx, target, projection+"}", 64<<10)
	if err != nil {
		return dockerJobSnapshot{}, err
	}
	var record dockerJobRecord
	if decode(raw, &record) != nil {
		return dockerJobSnapshot{}, errors.New("Docker job observation is invalid")
	}
	snapshot := record.Container
	if snapshot.ID != target.ContainerID || snapshot.Project != project || snapshot.Service != job.Name ||
		!strings.EqualFold(record.OneOff, "false") {
		return dockerJobSnapshot{}, errors.New("Docker job does not match the selected Compose service container")
	}
	started, startErr := time.Parse(time.RFC3339Nano, snapshot.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, record.FinishedAt)
	if snapshot.Running || snapshot.Status != "exited" || snapshot.PID != 0 ||
		record.ExitCode == nil || *record.ExitCode != 0 || record.OOMKilled == nil || *record.OOMKilled || record.StartError != "" ||
		startErr != nil || finishErr != nil || started.IsZero() || !finished.After(started) {
		return dockerJobSnapshot{}, errors.New("Docker did not report a successful job exit")
	}
	if !sha256Descriptor(snapshot.Image) {
		return dockerJobSnapshot{}, errors.New("Docker job image ID is invalid")
	}
	if err := matchDockerImage(snapshot, image.PlatformManifest, image.ImageConfigDigest); err != nil {
		return dockerJobSnapshot{}, err
	}
	argv := append([]string{record.Path}, record.Args...)
	var command strings.Builder
	for _, arg := range argv {
		if strings.ContainsRune(arg, 0) {
			return dockerJobSnapshot{}, errors.New("Docker job command is invalid")
		}
		command.WriteString(arg)
		command.WriteByte(0)
	}
	if record.Path == "" || digest([]byte(command.String())) != job.CommandSHA256 {
		return dockerJobSnapshot{}, errors.New("Docker job command disagrees with the signed command digest")
	}
	result := dockerJobSnapshot{Container: snapshot, FinishedAt: record.FinishedAt}
	for _, output := range job.Outputs {
		file, err := record.volumeOutput(output.Path)
		if err != nil {
			return dockerJobSnapshot{}, err
		}
		result.Outputs = append(result.Outputs, file)
	}
	return result, nil
}
