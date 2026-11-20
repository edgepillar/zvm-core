package release

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func checkServicesFixture(t *testing.T, image Image, tag, project, root string, executable, primaryConfig []byte) {
	t.Helper()
	f := newFixture(t)
	f.manifest.Images[0] = image
	readerConfig := []byte("mode=view\n")
	addProcessFixturePin(f, "fixture-executable", "artifact", executable)
	addProcessFixturePin(f, "fixture-primary-config", "config", primaryConfig)
	readerIndex := len(f.manifest.Files)
	addProcessFixturePin(f, "fixture-reader-config", "config", readerConfig)
	policy := runtimeProcessPolicy{Schema: Schema, Services: []runtimeService{
		{Name: "primary", Image: image.ID, Replicas: 1, Executable: "fixture-executable",
			Files: []runtimeFile{{Path: "/observer-config", File: "fixture-primary-config", Mounted: true}}},
		{Name: "reader", Image: image.ID, Replicas: 2, Executable: "fixture-executable",
			Files: []runtimeFile{{Path: "/observer-config", File: "fixture-reader-config", Mounted: true}}},
	}}
	policyIndex := len(f.manifest.Files)
	addProcessFixturePin(f, runtimeProcessPolicyID, "config", imageJSON(t, policy))
	writePolicy := func(value runtimeProcessPolicy) {
		t.Helper()
		raw := imageJSON(t, value)
		pin := &f.manifest.Files[policyIndex]
		pin.Bytes, pin.SHA256 = int64(len(raw)), digest(raw)
		if err := os.WriteFile(filepath.Join(f.files, pin.Repository, pin.Path), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy(policy)
	var err error
	f.manifest.PolicySHA256, err = f.policy.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	target := ServicesTarget{DockerContext: "default", Project: project, OCIRoot: root, FilesRoot: f.files}
	configPath := filepath.Join(root, "reader-config")
	if err := os.WriteFile(configPath, readerConfig, 0600); err != nil {
		t.Fatal(err)
	}
	firstReader := startFixtureContainer(t, tag, configPath, project, "reader")
	t.Run("missing replica", func(t *testing.T) {
		got, err := f.manifest.ObserveServices(t.Context(), f.policy, f.signatures(t), f.keys, target)
		if err == nil || !strings.Contains(err.Error(), "signed count for reader") || got.Services != nil {
			t.Fatalf("incomplete running inventory received a record: %v", err)
		}
	})
	secondReader := startFixtureContainer(t, tag, configPath, project, "reader")
	t.Run("all signed replicas and roles", func(t *testing.T) {
		inputs := writeReleaseTestInputs(t, f)
		raw := runReleaseTestCLI(t, "release-observe-services", "-manifest", filepath.Join(inputs, "manifest.json"),
			"-policy", filepath.Join(inputs, "policy.json"), "-signatures", filepath.Join(inputs, "signatures.json"),
			"-trusted-keys", filepath.Join(inputs, "keys.json"), "-project", project, "-docker-context", target.DockerContext,
			"-oci-root", target.OCIRoot, "-files-root", target.FilesRoot)
		var got ServicesObservation
		manifest, _ := f.manifest.Fingerprint()
		if json.Unmarshal(raw, &got) != nil || got.ManifestSHA256 != manifest || got.ContainersObserved != 3 || len(got.Services) != 2 ||
			bytes.Contains(raw, []byte(project)) || bytes.Contains(raw, []byte(firstReader)) || bytes.Contains(raw, []byte(secondReader)) ||
			bytes.Contains(raw, []byte(configPath)) {
			t.Fatal("service CLI did not establish the complete signed fixture inventory")
		}
		for i, expected := range policy.Services {
			row := got.Services[i]
			if row.Name != expected.Name || row.Replicas != expected.Replicas || row.ImageID != image.ID ||
				row.ExecutableSHA256 != digest(executable) || row.VerifiedConfigFilesPerReplica != 1 || row.VerifiedMountedFilesPerReplica != 1 {
				t.Fatal("service CLI associated the wrong evidence with a signed role")
			}
		}
		t.Logf("Verified %d running containers for %d signed roles on one image", got.ContainersObserved, len(got.Services))
	})
	t.Run("undeclared running service", func(t *testing.T) {
		incomplete := policy
		incomplete.Services = incomplete.Services[:1]
		writePolicy(incomplete)
		defer writePolicy(policy)
		got, err := f.manifest.ObserveServices(t.Context(), f.policy, f.signatures(t), f.keys, target)
		if err == nil || !strings.Contains(err.Error(), "undeclared service") || got.Services != nil {
			t.Fatalf("undeclared running role received a record: %v", err)
		}
	})
	t.Run("signed completed Compose jobs", func(t *testing.T) {
		withJobs := policy
		withJobs.Jobs = []runtimeJob{
			{Name: "genesis", Image: image.ID, CommandSHA256: digest([]byte("/observer-fixture\x00complete\x00fixture-genesis-argument\x00"))},
			{Name: "setup", Image: image.ID, CommandSHA256: digest([]byte("/observer-fixture\x00complete\x00fixture-setup-argument\x00"))},
		}
		writePolicy(withJobs)
		defer writePolicy(policy)
		setup := startFixtureJob(t, tag, project, "setup", "False", "0", "complete", "fixture-setup-argument")
		startFixtureJob(t, tag, project, "retired", "False", "0", "complete")
		for _, test := range []struct {
			name, oneOff, exitCode, wantError string
			args                              []string
		}{
			{name: "missing job", wantError: "requires one completed container for job genesis"},
			{name: "failed job", oneOff: "False", exitCode: "1", args: []string{"fail"}, wantError: "successful job exit"},
			{name: "ad hoc run", oneOff: "True", exitCode: "0", args: []string{"complete", "fixture-genesis-argument"},
				wantError: "does not match the selected Compose service container"},
			{name: "command mismatch", oneOff: "False", exitCode: "0", args: []string{"complete", "fixture-other-argument"},
				wantError: "disagrees with the signed command digest"},
		} {
			t.Run(test.name, func(t *testing.T) {
				if test.args != nil {
					startFixtureJob(t, tag, project, "genesis", test.oneOff, test.exitCode, test.args...)
				}
				got, err := f.manifest.ObserveServices(t.Context(), f.policy, f.signatures(t), f.keys, target)
				if err == nil || !strings.Contains(err.Error(), test.wantError) || got.Services != nil || got.CompletedJobs != nil {
					t.Fatalf("unqualified job received an inventory receipt: %v", err)
				}
			})
		}
		genesis := startFixtureJob(t, tag, project, "genesis", "False", "0", "complete", "fixture-genesis-argument")
		t.Run("two successful jobs and three running replicas", func(t *testing.T) {
			inputs := writeReleaseTestInputs(t, f)
			raw := runReleaseTestCLI(t, "release-observe-services", "-manifest", filepath.Join(inputs, "manifest.json"),
				"-policy", filepath.Join(inputs, "policy.json"), "-signatures", filepath.Join(inputs, "signatures.json"),
				"-trusted-keys", filepath.Join(inputs, "keys.json"), "-project", project, "-docker-context", target.DockerContext,
				"-oci-root", target.OCIRoot, "-files-root", target.FilesRoot)
			var got ServicesObservation
			if json.Unmarshal(raw, &got) != nil || got.ContainersObserved != 3 || len(got.Services) != 2 || len(got.CompletedJobs) != 2 {
				t.Fatal("service CLI did not record the signed running replicas and jobs")
			}
			for i, expected := range withJobs.Jobs {
				job := got.CompletedJobs[i]
				if job.Name != expected.Name || job.ImageID != image.ID || job.ExitCode != 0 || job.CommandSHA256 != expected.CommandSHA256 ||
					job.PlatformManifest != got.Services[0].PlatformManifestDigest || job.ImageConfigDigest != got.Services[0].ImageConfigDigest {
					t.Fatal("completed job was not bound to its signed invocation and image")
				}
			}
			for _, private := range []string{genesis, setup, project, "/observer-fixture", "fixture-genesis-argument", "fixture-setup-argument"} {
				if bytes.Contains(raw, []byte(private)) {
					t.Fatal("service CLI disclosed job execution details")
				}
			}
			t.Logf("Verified %d successful jobs with %d running replicas on the same image", len(got.CompletedJobs), got.ContainersObserved)
		})
		t.Run("ambiguous completed container", func(t *testing.T) {
			startFixtureJob(t, tag, project, "genesis", "False", "0", "complete", "fixture-genesis-argument")
			got, err := f.manifest.ObserveServices(t.Context(), f.policy, f.signatures(t), f.keys, target)
			if err == nil || !strings.Contains(err.Error(), "requires one completed container for job genesis") || got.CompletedJobs != nil {
				t.Fatalf("duplicated job received an inventory receipt: %v", err)
			}
		})
	})
	t.Run("wrong mount for one role of the shared image", func(t *testing.T) {
		pin := &f.manifest.Files[readerIndex]
		pin.SHA256 = digest(primaryConfig)
		got, err := f.manifest.ObserveServices(t.Context(), f.policy, f.signatures(t), f.keys, target)
		if err == nil || !strings.Contains(err.Error(), "service reader") || !strings.Contains(err.Error(), "disagrees with its signed bytes") || got.Services != nil {
			t.Fatalf("shared image hid a mismatched role configuration: %v", err)
		}
	})
}

func startFixtureJob(t *testing.T, tag, project, service, oneOff, exitCode string, command ...string) string {
	t.Helper()
	args := []string{"container", "run", "--detach", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--label", "com.docker.compose.project=" + project,
		"--label", "com.docker.compose.service=" + service, "--label", "com.docker.compose.oneoff=" + oneOff, tag}
	container := fixtureDocker(t, nil, append(args, command...)...)
	if !hash(container, 64) {
		t.Fatal("Docker did not return the full fixture job container ID")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "docker", "--context", "default", "container", "rm", "--force", container).Run(); err != nil {
			t.Error("the owned Docker job fixture could not be removed")
		}
	})
	if actual := fixtureDocker(t, nil, "container", "wait", container); actual != exitCode {
		t.Fatalf("fixture job exit code was %q, expected %q", actual, exitCode)
	}
	return container
}
