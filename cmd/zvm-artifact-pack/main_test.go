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

func TestPackCommandArgumentsAndDiagnostics(t *testing.T) {
	for _, args := range [][]string{nil, {"-unknown=/private/not-for-output"}, {"-manifest", "/private/not-for-output", "-policy", "p", "-archive-policy", "a", "-directory", "d"}} {
		var out, errout bytes.Buffer
		err := run(args, &out, &errout)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "not-for-output") {
			t.Fatal("invalid pack arguments leaked paths or produced success")
		}
	}
	var out, errout bytes.Buffer
	if run([]string{"-h"}, &out, &errout) != nil || out.Len() != 0 || !strings.Contains(errout.String(), "unverified") {
		t.Fatal("help produced archive bytes")
	}
}

func TestActualPackCommandAndIndependentReadback(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native archive file operations support Linux and macOS")
	}
	base, err := filepath.Abs("../../release/artifacts/testdata/synthetic")
	if err != nil {
		t.Fatal(err)
	}
	m, err := os.ReadFile(filepath.Join(base, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.ReadFile(filepath.Join(base, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy artifacts.Policy
	if json.Unmarshal(p, &policy) != nil {
		t.Fatal("invalid fixture")
	}
	canonical, err := artifacts.CanonicalPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	sha := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	a := artifacts.ArchivePolicy{Schema: 1, Format: artifacts.ArchiveFormat, ManifestSHA256: sha(m), SelectionPolicySHA256: sha(canonical), SourceDateEpoch: 1767225600}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	ap := filepath.Join(temp, "archive-policy.json")
	if os.WriteFile(ap, data, 0600) != nil {
		t.Fatal("policy write failed")
	}
	common := []string{"-manifest", filepath.Join(base, "manifest.json"), "-policy", filepath.Join(base, "policy.json"), "-archive-policy", ap}
	var output, stderr bytes.Buffer
	if err := run(append(append([]string{}, common...), "-directory", filepath.Join(base, "payloads")), &output, &stderr); err != nil || stderr.Len() != 0 {
		t.Fatal("actual ZIP command failed")
	}
	archive := filepath.Join(temp, "candidate.zip")
	if os.WriteFile(archive, output.Bytes(), 0600) != nil {
		t.Fatal("archive write failed")
	}
	pin := artifacts.File{Path: "candidate.zip", Bytes: int64(output.Len()), SHA256: sha(output.Bytes())}
	data, _ = json.Marshal(pin)
	pp := filepath.Join(temp, "pin.json")
	if os.WriteFile(pp, data, 0600) != nil {
		t.Fatal("pin write failed")
	}
	output.Reset()
	if err := run(append(append([]string{}, common...), "-check", archive, "-archive-pin", pp), &output, &stderr); err != nil || !strings.Contains(output.String(), `"archiveSelectionVerified":true`) || !strings.Contains(output.String(), `"releaseAccepted":false`) {
		t.Fatal("actual ZIP command readback failed")
	}
	pin.SHA256 = sha([]byte("changed"))
	data, _ = json.Marshal(pin)
	os.WriteFile(pp, data, 0600)
	output.Reset()
	if err := run(append(append([]string{}, common...), "-check", archive, "-archive-pin", pp), &output, &stderr); err == nil || output.Len() != 0 {
		t.Fatal("bad archive produced acceptance")
	}
}
