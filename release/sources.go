package release

import (
	"bytes"
	"context"
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

func git(ctx context.Context, dir string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	argv := append([]string{"--no-optional-locks", "--no-lazy-fetch", "--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull, "-c", "core.untrackedCache=false", "-c", "submodule.recurse=false", "-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", argv...)
	// Do not inherit repository redirection, credential helpers, fsmonitor or
	// global configuration. No network command is used.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C"}
	if value := os.Getenv("SystemRoot"); value != "" {
		cmd.Env = append(cmd.Env, "SystemRoot="+value)
	}
	var stdout, stderr commandOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
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

func inspectSource(ctx context.Context, dir, expected string, empty bool, depth int, remaining *int) ([]Gitlink, error) {
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
		tree, code, err := git(ctx, dir, "ls-tree", "-r", "-z", "HEAD")
		if err != nil || code != 0 {
			return nil, errors.New("source tree is unreadable without fetching")
		}
		for _, row := range bytes.Split(tree, []byte{0}) {
			meta, name, ok := bytes.Cut(row, []byte{'\t'})
			if !ok {
				continue
			}
			fields := strings.Fields(string(meta))
			if len(fields) != 3 || fields[0] != "160000" {
				continue
			}
			if !relative(string(name)) || !commit(fields[2]) {
				return nil, errors.New("invalid committed gitlink")
			}
			link := Gitlink{Path: string(name), Commit: fields[2]}
			links = append(links, link)
			if _, err := inspectSource(ctx, filepath.Join(dir, filepath.FromSlash(link.Path)), link.Commit, false, depth+1, remaining); err != nil {
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
	remaining := MaxEntries
	for _, repo := range m.Repositories {
		links, err := inspectSource(ctx, filepath.Join(directory, repo.Name), repo.Commit, repo.Empty, 0, &remaining)
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
	}
	return len(m.Repositories), nil
}

var _ io.Writer = (*commandOutput)(nil)
