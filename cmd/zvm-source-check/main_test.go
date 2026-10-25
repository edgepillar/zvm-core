package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/release/artifacts"
)

func sha(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

type shortWriter struct{}

func (shortWriter) Write(raw []byte) (int, error) { return len(raw) / 2, nil }

func TestSourceCommandCompleteExportAndNoPartialOutput(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native source verification currently supports Linux and macOS")
	}
	root, controls := t.TempDir(), t.TempDir()
	mod := []byte("module example.invalid/fixture\n\ngo 1.25.0\n")
	commit := []byte("tree 1edb8aacdffed0f4f3ea7fe27aaec9ae7b4696de\nauthor Fixture <fixture.invalid> 0 +0000\ncommitter Fixture <fixture.invalid> 0 +0000\n\nSource fixture.\n")
	p := artifacts.GoSourceTreePolicy{Schema: 1, Profile: artifacts.GoSourceTreeProfile,
		Source:      artifacts.Source{Repository: "Example/fixture", Commit: "db8ef26825a52efff272bd37fc575ce19d0ede87", Tree: "1edb8aacdffed0f4f3ea7fe27aaec9ae7b4696de", Gitlinks: []artifacts.Gitlink{}},
		GoModSHA256: sha(mod), CommitObject: artifacts.File{Path: "parent.commit", Bytes: int64(len(commit)), SHA256: sha(commit)},
		Files: []artifacts.SourceFile{{Path: "go.mod", Bytes: int64(len(mod)), SHA256: sha(mod), Mode: "100644"}}}
	raw, err := json.Marshal(p)
	if err != nil || os.WriteFile(filepath.Join(root, "go.mod"), mod, 0600) != nil || os.WriteFile(filepath.Join(controls, "parent.commit"), commit, 0600) != nil {
		t.Fatal("fixture setup failed")
	}
	policy := filepath.Join(t.TempDir(), "policy.json")
	if os.WriteFile(policy, raw, 0600) != nil {
		t.Fatal("policy setup failed")
	}
	args := []string{"-policy", policy, "-policy-sha256", sha(raw), "-directory", root, "-controls", controls}
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil || stderr.Len() != 0 {
		t.Fatal("source CLI refused a complete selected export", err)
	}
	var result artifacts.GoSourceTreeResult
	if json.Unmarshal(stdout.Bytes(), &result) != nil || !result.SourceTreeVerified || result.SourceFilesVerified != 1 || result.SourceBytesVerified != 42 || result.GitlinksBound != 0 || result.ReleaseAccepted {
		t.Fatal("source CLI scope is wrong")
	}
	if strings.Contains(stdout.String(), root) || strings.Contains(stdout.String(), controls) || strings.Contains(stdout.String(), "fixture.invalid") {
		t.Fatal("source CLI emitted physical locations or commit data")
	}
	if err := run(args, shortWriter{}, &stderr); err == nil {
		t.Fatal("source command accepted an incomplete result write")
	}
	args[3] = strings.Repeat("0", 64)
	stdout.Reset()
	if err := run(args, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("failed source check emitted a partial success receipt")
	}
}

func TestSourceCommandArgumentsAndPrivacy(t *testing.T) {
	for _, args := range [][]string{nil, {"-unknown"}, {"-policy", "/private/no-export", "-policy-sha256", strings.Repeat("1", 64), "-directory", "/private/no-export", "-controls", "/private/no-export"}} {
		var stdout, stderr bytes.Buffer
		err := run(args, &stdout, &stderr)
		if err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), "no-export") {
			t.Fatal("invalid source arguments accepted or runtime location disclosed")
		}
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-h"}, &stdout, &stderr); err != nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "policy-sha256") {
		t.Fatal("source command usage failed")
	}
}
