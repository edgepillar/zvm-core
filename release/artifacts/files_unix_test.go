//go:build linux || darwin

package artifacts

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNonblockingNativeOpenRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(name, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := openEntry(root, "fifo", false)
	if file != nil {
		file.Close()
	}
	if err == nil {
		t.Fatal("FIFO accepted as a regular file")
	}
	if _, err = ReadDocument(name); err == nil {
		t.Fatal("FIFO accepted as a document")
	}
}

func TestNativeOpenDoesNotFollowFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("plain", filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := openEntry(root, "linked", false)
	if file != nil {
		file.Close()
	}
	if err == nil {
		t.Fatal("final symlink accepted")
	}
}

func TestNativeOpenDoesNotFollowAncestorSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "plain"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain", "file"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("plain", filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := openEntry(root, "linked/file", false)
	if file != nil {
		file.Close()
	}
	if err == nil {
		t.Fatal("ancestor symlink accepted")
	}
}
