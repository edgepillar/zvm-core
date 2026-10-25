package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequiredArgumentsAndPrivateErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"-unknown=/private/not-for-output"}, {"-policy", "/private/not-for-output", "-go-mod", "/private/not-for-output", "-go-sum", "/private/not-for-output", "-subject", "/private/not-for-output"}} {
		var out, errout bytes.Buffer
		err := run(args, &out, &errout)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "not-for-output") {
			t.Fatal("invalid input produced output or leaked its path")
		}
	}
	var out, errout bytes.Buffer
	if run([]string{"-h"}, &out, &errout) != nil || out.Len() != 0 || !strings.Contains(errout.String(), "unqualified") {
		t.Fatal("help invented success")
	}
}

func TestActualGenerateAndCheckCommand(t *testing.T) {
	dir := os.Getenv("ZVM_GO_SBOM_FIXTURE_DIRECTORY")
	if dir == "" {
		t.Skip("independently qualified Go SBOM command inputs were not provisioned")
	}
	args := []string{"-policy", filepath.Join(dir, "policy.json"), "-go-mod", filepath.Join(dir, "go.mod"), "-go-sum", filepath.Join(dir, "go.sum"), "-subject", filepath.Join(dir, "subject")}
	var out, errout bytes.Buffer
	if err := run(args, &out, &errout); err != nil || errout.Len() != 0 || !strings.Contains(out.String(), `"spdxVersion": "SPDX-2.3"`) {
		t.Fatal("actual SPDX command generation failed")
	}
	path := filepath.Join(t.TempDir(), "selected.spdx.json")
	if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(append(append([]string{}, args...), "-check", path), &out, &errout); err != nil || !strings.Contains(out.String(), `"spdxProfileVerified":true`) || !strings.Contains(out.String(), `"releaseAccepted":false`) {
		t.Fatal("actual selected SPDX check failed")
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(append(append([]string{}, args...), "-check", path), &out, &errout); err == nil || out.Len() != 0 {
		t.Fatal("SPDX refusal produced a success receipt")
	}
}

func TestActualLocalSourceCommand(t *testing.T) {
	dir := os.Getenv("ZVM_GO_SOURCE_FIXTURE_DIRECTORY")
	if dir == "" {
		t.Skip("qualified local-source command inputs were not provisioned")
	}
	args := []string{"-policy", filepath.Join(dir, "policy.json"), "-go-mod", filepath.Join(dir, "go.mod"), "-go-sum", filepath.Join(dir, "go.sum"), "-subject", filepath.Join(dir, "subject"), "-source-inputs", filepath.Join(dir, "directories.json"), "-source-controls", filepath.Join(dir, "controls")}
	var out, errout bytes.Buffer
	if err := run(args, &out, &errout); err != nil || errout.Len() != 0 || !strings.Contains(out.String(), "spdx-2.3-go-local-source-v1") {
		t.Fatal("actual local-source command generation failed")
	}
	file := filepath.Join(t.TempDir(), "source.spdx.json")
	if os.WriteFile(file, out.Bytes(), 0600) != nil {
		t.Fatal("document write failed")
	}
	out.Reset()
	if err := run(append(append([]string{}, args...), "-check", file), &out, &errout); err != nil || !strings.Contains(out.String(), `"localSourceTreesVerified":1`) || !strings.Contains(out.String(), `"sourceCommitAuthenticated":false`) {
		t.Fatal("actual source check failed")
	}
	out.Reset()
	if err := run(args[:len(args)-2], &out, &errout); err == nil || out.Len() != 0 {
		t.Fatal("partial source options accepted")
	}
}
