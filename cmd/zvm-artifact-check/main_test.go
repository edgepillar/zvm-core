package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSelectedFixtureThroughCommand(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("native file checks support Linux and macOS")
	}
	base, err := filepath.Abs("../../release/artifacts/testdata/synthetic")
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err = run([]string{"-manifest", filepath.Join(base, "manifest.json"), "-policy", filepath.Join(base, "policy.json"), "-directory", filepath.Join(base, "payloads")}, &stdout, &stderr)
	if err != nil || stderr.Len() != 0 {
		t.Fatalf("command failed: %v / %s", err, stderr.String())
	}
	var result struct {
		FilesVerified                int  `json:"filesVerified"`
		SelectionVerified            bool `json:"selectionVerified"`
		ReleaseAccepted              bool `json:"releaseAccepted"`
		ProvenanceSignaturesVerified bool `json:"provenanceSignaturesVerified"`
		SBOMContentsVerified         bool `json:"sbomContentsVerified"`
	}
	if err = json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.FilesVerified != 5 || !result.SelectionVerified || result.ReleaseAccepted || result.ProvenanceSignaturesVerified || result.SBOMContentsVerified {
		t.Fatalf("wrong selection scope: %+v", result)
	}
	for _, field := range []string{`"releaseAccepted":false`, `"provenanceSignaturesVerified":false`, `"sbomContentsVerified":false`} {
		if !strings.Contains(stdout.String(), field) {
			t.Fatalf("explicit acceptance limit missing: %s", field)
		}
	}
}

func TestArgumentRefusalsAndPrivatePathDiagnostics(t *testing.T) {
	for _, args := range [][]string{{}, {"-unknown=/private/not-for-output"}, {"-manifest", "/private/not-for-output"}, {"-manifest", "/private/not-for-output", "-policy", "/private/not-for-output", "-directory", "/private/not-for-output"}, {"-manifest", "m", "-policy", "p", "-directory", "d", "positional"}} {
		var stdout, stderr bytes.Buffer
		err := run(args, &stdout, &stderr)
		if err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), "not-for-output") || strings.Contains(stderr.String(), "not-for-output") {
			t.Fatalf("bad refusal scope: %v / %q / %q", err, stdout.String(), stderr.String())
		}
	}
}

func TestHelpDoesNotProduceSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-h"}, &stdout, &stderr); err != nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Signatures") {
		t.Fatalf("unexpected help: %v %q %q", err, stdout.String(), stderr.String())
	}
}

func TestProvenanceOptionsRequireCompleteIndependentInputs(t *testing.T) {
	base, err := filepath.Abs("../../release/artifacts/testdata/synthetic")
	if err != nil {
		t.Fatal(err)
	}
	common := []string{"-manifest", filepath.Join(base, "manifest.json"), "-policy", filepath.Join(base, "policy.json"), "-directory", filepath.Join(base, "payloads")}
	for _, option := range []string{"-provenance-policy", "-verifier", "-trusted-root", "-temporary-directory"} {
		var stdout, stderr bytes.Buffer
		err := run(append(append([]string{}, common...), option, "/private/not-for-output"), &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "required together") || stdout.Len() != 0 || stderr.Len() != 0 || strings.Contains(err.Error(), "not-for-output") {
			t.Fatal("partial provenance options were not refused privately")
		}
	}
}

func TestProvenanceFailureReturnsNoSuccessReceipt(t *testing.T) {
	base, err := filepath.Abs("../../release/artifacts/testdata/synthetic")
	if err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(t.TempDir(), "provenance-policy.json")
	if err := os.WriteFile(invalid, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err = run([]string{"-manifest", filepath.Join(base, "manifest.json"), "-policy", filepath.Join(base, "policy.json"), "-directory", filepath.Join(base, "payloads"),
		"-provenance-policy", invalid, "-verifier", "/private/not-for-output", "-trusted-root", "/private/not-for-output", "-temporary-directory", "/private/not-for-output"}, &stdout, &stderr)
	if err == nil || stdout.Len() != 0 || stderr.Len() != 0 || strings.Contains(err.Error(), "not-for-output") {
		t.Fatal("failed provenance verification produced a success receipt")
	}
}

func TestContentsOptionsAndFailureDoNotProduceSuccess(t *testing.T) {
	base, err := filepath.Abs("../../release/artifacts/testdata/synthetic")
	if err != nil {
		t.Fatal(err)
	}
	common := []string{"-manifest", filepath.Join(base, "manifest.json"), "-policy", filepath.Join(base, "policy.json"), "-directory", filepath.Join(base, "payloads")}
	for _, option := range []string{"-contents-policy", "-content-inputs"} {
		var out, errout bytes.Buffer
		err := run(append(append([]string{}, common...), option, "/private/not-for-output"), &out, &errout)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "not-for-output") {
			t.Fatal("partial contents options produced output or disclosed input path")
		}
	}
	invalid := filepath.Join(t.TempDir(), "contents.json")
	if err := os.WriteFile(invalid, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	err = run(append(append([]string{}, common...), "-contents-policy", invalid, "-content-inputs", t.TempDir()), &out, &errout)
	if err == nil || out.Len() != 0 {
		t.Fatal("failed content verification produced a success receipt")
	}
}
