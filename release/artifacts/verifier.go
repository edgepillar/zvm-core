package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type pinnedVerifier struct {
	dir    *directory
	file   *os.File
	before os.FileInfo
	name   string
}

func (v *pinnedVerifier) close() { v.file.Close(); v.dir.root.Close() }
func (v *pinnedVerifier) unchanged() error {
	opened, err := v.file.Stat()
	named, pathErr := v.dir.root.Lstat(v.name)
	if err != nil || pathErr != nil || !stable(v.before, opened) || !stable(v.before, named) {
		return errors.New("verifier identity changed")
	}
	return v.dir.checkAncestors()
}

func pinVerifier(name, expected string) (*pinnedVerifier, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errors.New("an absolute pinned verifier path is required")
	}
	d, err := openDirectory(filepath.Dir(name))
	if err != nil {
		return nil, errors.New("verifier directory is unavailable")
	}
	v := &pinnedVerifier{dir: d, name: filepath.Base(name)}
	before, err := d.root.Lstat(v.name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&0111 == 0 || before.Size() <= 0 || before.Size() > 128<<20 || !singleLink(before) {
		d.root.Close()
		return nil, errors.New("verifier is missing, nonregular or exceeds its limit")
	}
	v.before = before
	f, err := openEntry(d.root, v.name, false)
	if err != nil {
		d.root.Close()
		return nil, errors.New("verifier could not be opened")
	}
	v.file = f
	opened, err := f.Stat()
	if err != nil || !stable(before, opened) {
		v.close()
		return nil, errors.New("verifier changed while opening")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if err != nil || n != before.Size() || hex.EncodeToString(h.Sum(nil)) != expected {
		v.close()
		return nil, errors.New("verifier SHA-256 does not match independent policy")
	}
	if err := v.unchanged(); err != nil {
		v.close()
		return nil, err
	}
	return v, nil
}

type cappedOutput struct {
	buffer    bytes.Buffer
	remaining int
	cancel    context.CancelFunc
}

func (w *cappedOutput) Write(raw []byte) (int, error) {
	if len(raw) > w.remaining {
		w.cancel()
		return 0, errors.New("verifier output limit exceeded")
	}
	w.remaining -= len(raw)
	return w.buffer.Write(raw)
}

func (w *cappedOutput) Bytes() []byte { return w.buffer.Bytes() }

func runVerifier(ctx context.Context, verifier, work string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, verifier, args...)
	cmd.Dir = work
	config := filepath.Join(work, "config")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "TZ=UTC", "GH_HOST=github.com", "GH_CONFIG_DIR=" + config,
		"GH_CACHE_DIR=" + config, "XDG_CONFIG_HOME=" + config, "XDG_CACHE_HOME=" + config, "TMPDIR=" + work,
		"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "GH_NO_EXTENSION_UPDATE_NOTIFIER=1", "NO_COLOR=1"}
	stdout := &cappedOutput{remaining: MaxDocumentBytes, cancel: cancel}
	stderr := &cappedOutput{remaining: 64 << 10, cancel: cancel}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = stdout, stderr, time.Second
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return nil, errors.New("pinned verifier refused or did not complete within its limits")
	}
	return stdout.Bytes(), nil
}
