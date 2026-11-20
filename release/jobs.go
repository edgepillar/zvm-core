package release

import (
	"context"
	"errors"
	"strings"
	"time"
)

type runtimeJob struct {
	Name          string `json:"name"`
	Image         string `json:"image"`
	CommandSHA256 string `json:"commandSha256"`
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
}

type dockerJobRecord struct {
	Container  dockerSnapshot `json:"container"`
	FinishedAt string         `json:"finishedAt"`
	ExitCode   *int           `json:"exitCode"`
	OOMKilled  *bool          `json:"oomKilled"`
	StartError string         `json:"startError"`
	OneOff     string         `json:"oneOff"`
	Path       string         `json:"path"`
	Args       []string       `json:"args"`
}

type dockerJobSnapshot struct {
	Container  dockerSnapshot
	FinishedAt string
}

const dockerJobProjection = `{"container":` + dockerImageProjection + `,
	"finishedAt":{{json (index (index . "State") "FinishedAt")}},
	"exitCode":{{json (index (index . "State") "ExitCode")}},
	"oomKilled":{{json (index (index . "State") "OOMKilled")}},
	"startError":{{json (index (index . "State") "Error")}},
	"oneOff":{{with index (index . "Config") "Labels"}}{{with index . "com.docker.compose.oneoff"}}{{json .}}{{else}}""{{end}}{{else}}""{{end}},
	"path":{{json (index . "Path")}},"args":{{json (index . "Args")}}}`

func observeDockerJob(ctx context.Context, target ImageTarget, project string, job runtimeJob, image ImageObservation) (dockerJobSnapshot, error) {
	raw, err := inspectDockerContainer(ctx, target, dockerJobProjection, 64<<10)
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
	return dockerJobSnapshot{Container: snapshot, FinishedAt: record.FinishedAt}, nil
}
