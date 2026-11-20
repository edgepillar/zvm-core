package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type commandOutput struct {
	data     bytes.Buffer
	overflow bool
}

func (b *commandOutput) Write(p []byte) (int, error) {
	if len(p) > 2<<20-b.data.Len() {
		b.overflow = true
		return 0, errors.New("Git output exceeds its limit")
	}
	return b.data.Write(p)
}

func gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	argv := append([]string{"--no-optional-locks", "--no-lazy-fetch", "--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull, "-c", "core.untrackedCache=false", "-c", "submodule.recurse=false", "-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", argv...)
	// Do not inherit repository redirection, credential helpers, fsmonitor or
	// global configuration. No network command is used.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C"}
	if value := os.Getenv("SystemRoot"); value != "" {
		cmd.Env = append(cmd.Env, "SystemRoot="+value)
	}
	cmd.WaitDelay = time.Second
	return cmd
}

func git(ctx context.Context, dir string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := gitCommand(ctx, dir, args...)
	var stdout, stderr commandOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, -1, errors.New("Git read deadline exceeded")
	}
	if stdout.overflow || stderr.overflow {
		return nil, -1, errors.New("Git read output limit exceeded")
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return stdout.data.Bytes(), exit.ExitCode(), nil
		}
		return nil, -1, errors.New("Git could not be executed")
	}
	return stdout.data.Bytes(), 0, nil
}

type lockDigestWriter struct {
	digest    io.Writer
	remaining int64
}

func (w *lockDigestWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("source lock exceeds its declared size")
	}
	n, err := w.digest.Write(data)
	w.remaining -= int64(n)
	return n, err
}

func verifySourceLock(parent context.Context, dir, object string, pin File) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	cmd := gitCommand(ctx, dir, "cat-file", "blob", object)
	h := sha256.New()
	output := lockDigestWriter{digest: h, remaining: pin.Bytes}
	var stderr commandOutput
	cmd.Stdout, cmd.Stderr = &output, &stderr
	if err := cmd.Run(); err != nil || stderr.overflow {
		return fmt.Errorf("source lock %s could not be read within its limits", pin.ID)
	}
	if output.remaining != 0 || hex.EncodeToString(h.Sum(nil)) != pin.SHA256 {
		return fmt.Errorf("source lock %s differs from its pinned bytes", pin.ID)
	}
	return nil
}

func inspectSource(ctx context.Context, dir, expected, prefix string, empty bool, depth int, remaining *int, locks map[string]File) ([]Gitlink, error) {
	if depth > 8 || *remaining <= 0 {
		return nil, errors.New("recursive source inventory exceeds its budget")
	}
	*remaining--
	root, err := openDirectory(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	top, code, err := git(ctx, dir, "rev-parse", "--show-toplevel")
	want, absErr := filepath.Abs(dir)
	if err != nil || absErr != nil || code != 0 || filepath.Clean(strings.TrimSpace(string(top))) != want {
		return nil, errors.New("source is missing, uninitialized or not its own Git worktree")
	}
	head, code, err := git(ctx, dir, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return nil, err
	}
	if empty {
		refs, refCode, refErr := git(ctx, dir, "show-ref", "--head")
		unborn, unbornCode, unbornErr := git(ctx, dir, "symbolic-ref", "-q", "HEAD")
		if code == 0 || refErr != nil || refCode != 1 || len(refs) != 0 || unbornErr != nil || unbornCode != 0 || !strings.HasPrefix(string(unborn), "refs/heads/") {
			return nil, errors.New("source is not an empty unborn repository")
		}
	} else if code != 0 || strings.TrimSpace(string(head)) != expected {
		return nil, errors.New("source HEAD disagrees with its pinned commit")
	}
	clean := func() error {
		// Inspect children explicitly using builtins. Do not invoke the external
		// submodule command or any locally configured submodule alias/update.
		status, code, err := git(ctx, dir, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all")
		if err != nil || code != 0 || len(status) != 0 {
			return errors.New("source worktree is dirty or unreadable")
		}
		return nil
	}
	if err := clean(); err != nil {
		return nil, err
	}
	var links []Gitlink
	if !empty {
		tree, code, err := git(ctx, dir, "ls-tree", "-r", "-z", expected)
		if err != nil || code != 0 {
			return nil, errors.New("source tree is unreadable without fetching")
		}
		for _, row := range bytes.Split(tree, []byte{0}) {
			meta, name, ok := bytes.Cut(row, []byte{'\t'})
			if !ok {
				continue
			}
			fields := strings.Fields(string(meta))
			lockPath := prefix + string(name)
			if pin, ok := locks[lockPath]; ok {
				if len(fields) != 3 || (fields[0] != "100644" && fields[0] != "100755") ||
					fields[1] != "blob" || !commit(fields[2]) {
					return nil, fmt.Errorf("source lock %s is not a tracked regular file", pin.ID)
				}
				if err := verifySourceLock(ctx, dir, fields[2], pin); err != nil {
					return nil, err
				}
				delete(locks, lockPath)
			}
			if len(fields) != 3 || fields[0] != "160000" {
				continue
			}
			if !relative(string(name)) || !commit(fields[2]) {
				return nil, errors.New("invalid committed gitlink")
			}
			link := Gitlink{Path: string(name), Commit: fields[2]}
			links = append(links, link)
			if _, err := inspectSource(ctx, filepath.Join(dir, filepath.FromSlash(link.Path)), link.Commit,
				prefix+link.Path+"/", false, depth+1, remaining, locks); err != nil {
				return nil, err
			}
		}
	}
	if err := clean(); err != nil {
		return nil, err
	}
	final, code, err := git(ctx, dir, "rev-parse", "--verify", "HEAD")
	if err != nil || (!empty && (code != 0 || strings.TrimSpace(string(final)) != expected)) || (empty && code == 0) {
		return nil, errors.New("source HEAD changed during verification")
	}
	return links, nil
}

// VerifySources checks clean source snapshots and binds dependency lock pins
// to the Git blobs at their declared commits.
func (m Manifest) VerifySources(parent context.Context, directory string) (int, error) {
	if err := m.validate(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	root, err := openDirectory(directory)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	locks := make(map[string]map[string]File)
	for _, pin := range m.Files {
		if pin.Kind == "lock" {
			if locks[pin.Repository] == nil {
				locks[pin.Repository] = make(map[string]File)
			}
			locks[pin.Repository][pin.Path] = pin
		}
	}
	remaining := MaxEntries
	for _, repo := range m.Repositories {
		requiredLocks := locks[repo.Name]
		links, err := inspectSource(ctx, filepath.Join(directory, repo.Name), repo.Commit, "", repo.Empty, 0, &remaining, requiredLocks)
		if err != nil {
			return 0, fmt.Errorf("repository %s: %w", repo.Name, err)
		}
		expected := slices.Clone(repo.Gitlinks)
		less := func(a, b Gitlink) int { return strings.Compare(a.Path, b.Path) }
		slices.SortFunc(links, less)
		slices.SortFunc(expected, less)
		if !slices.Equal(links, expected) {
			return 0, fmt.Errorf("repository %s gitlinks disagree", repo.Name)
		}
		if len(requiredLocks) != 0 {
			return 0, fmt.Errorf("repository %s is missing %d tracked release lock files", repo.Name, len(requiredLocks))
		}
	}
	return len(m.Repositories), nil
}

var _ io.Writer = (*commandOutput)(nil)
