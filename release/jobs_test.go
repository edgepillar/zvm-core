package release

import (
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

func checkJobOutputsFixture(t *testing.T, image Image, tag, project, ociRoot string, executable []byte) {
	t.Helper()
	f := newFixture(t)
	f.manifest.Images[0] = image
	addProcessFixturePin(f, "fixture-executable", "artifact", executable)
	addProcessFixturePin(f, "fixture-output", "config", []byte("epoch=fixture\n"))
	policy := runtimeProcessPolicy{
		Schema: Schema,
		Services: []runtimeService{{
			Name: "reader", Image: image.ID, Replicas: 2, Executable: "fixture-executable",
			Files: []runtimeFile{{Path: "/consumer-volume/epoch.json", File: "fixture-output", Mounted: true}},
		}},
		Jobs: []runtimeJob{{
			Name: "genesis", Image: image.ID, CommandSHA256: digest([]byte("/observer-fixture\x00write-output\x00")),
			Outputs: []runtimeJobOutput{{Path: "/job-output/epoch.json", Service: "reader", ServicePath: "/consumer-volume/epoch.json"}},
		}},
	}
	pin := addProcessFixturePin(f, runtimeProcessPolicyID, "config", imageJSON(t, policy))
	if err := os.WriteFile(filepath.Join(f.files, pin.Repository, pin.Path), imageJSON(t, policy), 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	f.manifest.PolicySHA256, err = f.policy.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	inputs := writeReleaseTestInputs(t, f)
	volume := fixtureVolume(t)
	otherVolume := fixtureVolume(t)
	producer := startFixtureJob(t, tag, project, "genesis", "False", "0",
		"type=volume,source="+volume+",target=/job-output,volume-nocopy", "write-output")
	startFixtureJob(t, tag, project, "other-writer", "False", "0",
		"type=volume,source="+otherVolume+",target=/job-output,volume-nocopy", "write-output")
	mount := "type=volume,source=" + volume + ",target=/consumer-volume,readonly,volume-nocopy"
	startFixtureContainer(t, tag, project, "reader", mount)
	for _, test := range []struct {
		name, secondMount, wantError string
	}{
		{name: "same file on two read-only replicas", secondMount: mount},
		{
			name: "equal bytes from a different volume", wantError: "disagrees with its Docker job output identity",
			secondMount: "type=volume,source=" + otherVolume + ",target=/consumer-volume,readonly,volume-nocopy",
		},
		{
			name: "same file on a writable mount", wantError: "must view its job output on a read-only mount",
			secondMount: "type=volume,source=" + volume + ",target=/consumer-volume,volume-nocopy",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := startFixtureContainer(t, tag, project, "reader", test.secondMount)
			raw, stderr, err := observeHostedFixtureVolumes(t, inputs, f.files, ociRoot, project)
			for _, private := range []string{volume, otherVolume, project, producer, reader, "/job-output", "/consumer-volume", ociRoot} {
				if bytes.Contains(raw, []byte(private)) || bytes.Contains(stderr, []byte(private)) {
					t.Fatal("verification disclosed a Docker volume or process path")
				}
			}
			if test.wantError != "" {
				if err == nil || len(raw) != 0 || !strings.Contains(string(stderr), test.wantError) {
					t.Fatalf("unqualified output received evidence: %v, %s", err, stderr)
				}
				return
			}
			var got ServicesObservation
			if err != nil || json.Unmarshal(raw, &got) != nil {
				t.Fatalf("Docker output observation failed: %v, %s", err, stderr)
			}
			if got.ContainersObserved != 2 || len(got.Services) != 1 || len(got.CompletedJobs) != 1 ||
				got.Services[0].VerifiedJobOutputsPerReplica != 1 || got.CompletedJobs[0].VerifiedOutputBindings != 2 {
				t.Fatal("completion record did not bind the signed file to both running replicas")
			}
			t.Logf("Verified %d job output bindings across %d running replicas",
				got.CompletedJobs[0].VerifiedOutputBindings, got.ContainersObserved)
		})
	}
}

func fixtureVolume(t *testing.T) string {
	t.Helper()
	volume := fixtureDocker(t, nil, "volume", "create", "--driver", "local")
	if !hash(volume, 64) {
		t.Fatal("Docker did not allocate a unique fixture volume name")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "docker", "--context", "default", "volume", "rm", volume).Run(); err != nil {
			t.Error("the owned Docker fixture volume could not be removed")
		}
	})
	return volume
}

func observeHostedFixtureVolumes(t *testing.T, inputs, filesRoot, ociRoot, project string) ([]byte, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	tool := filepath.Join(runtime.GOROOT(), "bin", "go")
	args := []string{"run", "-mod=readonly"}
	if os.Geteuid() != 0 {
		// Only the observer runs with access to the owned Docker volume files
		// on the isolated host. Use the existing runner user for the build.
		args = append(args, "-exec", "sudo -n --")
	}
	args = append(args, "../cmd/zvm", "release-observe-services", "-manifest", filepath.Join(inputs, "manifest.json"),
		"-policy", filepath.Join(inputs, "policy.json"), "-signatures", filepath.Join(inputs, "signatures.json"),
		"-trusted-keys", filepath.Join(inputs, "keys.json"), "-project", project, "-docker-context", "default",
		"-oci-root", ociRoot, "-files-root", filesRoot)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	return raw, stderr.Bytes(), err
}
