package main

import (
	"bytes"
	"encoding/json"
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
