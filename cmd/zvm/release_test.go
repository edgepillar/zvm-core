package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseCommandsRequireCompleteExplicitInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"-manifest=missing.fixture"}, {"-manifest=missing.fixture", "-policy=missing.fixture", "unexpected"}} {
		var output bytes.Buffer
		if err := releaseVerify(args, &output); err == nil || output.Len() != 0 {
			t.Fatal("incomplete verification emitted a receipt")
		}
		if err := releaseMessage(args, &output); err == nil || output.Len() != 0 {
			t.Fatal("incomplete canonicalization emitted a signing message")
		}
	}
}

func TestReleaseDocumentRejectsLinksOversizeAndPrivatePathErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(file, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseDocument(link); err == nil || strings.Contains(err.Error(), dir) {
		t.Fatal("linked input or private path reached the decoder")
	}
	if err := os.WriteFile(file, bytes.Repeat([]byte(" "), (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseDocument(file); err == nil || strings.Contains(err.Error(), dir) {
		t.Fatal("oversized document was read")
	}
}
