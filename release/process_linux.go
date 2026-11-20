//go:build linux

package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const pathFlags = unix.O_PATH | unix.O_CLOEXEC

type runtimeIdentity struct {
	mount, inode, size uint64
	deviceMajor        uint32
	deviceMinor        uint32
	mode               uint16
	mtime, ctime       unix.StatxTimestamp
}

type processFilesSnapshot struct {
	root  runtimeIdentity
	files []runtimeIdentity
}

func sameRuntimeRoot(a, b runtimeIdentity) bool {
	return a.mount == b.mount && a.inode == b.inode && a.deviceMajor == b.deviceMajor && a.deviceMinor == b.deviceMinor
}

func runtimeFileIdentity(fd int) (runtimeIdentity, error) {
	const mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_SIZE | unix.STATX_MTIME | unix.STATX_CTIME | unix.STATX_MNT_ID
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, mask, &stat); err != nil || stat.Mask&mask != mask {
		return runtimeIdentity{}, errors.New("runtime file identity could not be established")
	}
	return runtimeIdentity{
		mount: stat.Mnt_id, inode: stat.Ino, size: stat.Size,
		deviceMajor: stat.Dev_major, deviceMinor: stat.Dev_minor, mode: stat.Mode & unix.S_IFMT,
		mtime: stat.Mtime, ctime: stat.Ctime,
	}, nil
}

func readProcRecord(dir int, path string) (string, error) {
	fd, err := unix.Openat(dir, path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("process identity record could not be opened")
	}
	file := os.NewFile(uintptr(fd), "process record")
	defer file.Close()
	const limit = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(raw) > limit {
		return "", errors.New("process identity record could not be read")
	}
	return string(raw), nil
}

func verifyProcessCgroup(dir int, container string) error {
	raw, err := readProcRecord(dir, "cgroup")
	if err != nil {
		return err
	}
	scope := "docker-" + container + ".scope"
	for line := range strings.Lines(raw) {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) == 3 {
			for part := range strings.SplitSeq(parts[2], "/") {
				if part == container || part == scope {
					return nil
				}
			}
		}
	}
	return errors.New("local process cgroup does not identify the selected Docker container")
}

func activeProcess(pidfd int) error {
	n, err := unix.Poll([]unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}, 0)
	if err != nil || n != 0 {
		return errors.New("the observed process exited or could no longer be checked")
	}
	return nil
}

func verifyProcessHandle(proc, pidfd, pid int) error {
	raw, err := readProcRecord(proc, "self/fdinfo/"+strconv.Itoa(pidfd))
	if err != nil {
		return err
	}
	for line := range strings.Lines(raw) {
		if value, found := strings.CutPrefix(line, "Pid:"); found && strings.TrimSpace(value) == strconv.Itoa(pid) {
			return nil
		}
	}
	return errors.New("Linux process handle does not match the Docker PID in local procfs")
}

func openProcessFile(dir, root int, path string) (int, error) {
	var fd int
	var err error
	if path == "" {
		fd, err = unix.Openat(dir, "exe", pathFlags, 0)
	} else {
		fd, err = unix.Openat2(root, path, &unix.OpenHow{
			Flags: pathFlags, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
	}
	if err != nil {
		return -1, errors.New("signed executable or process configuration path could not be opened")
	}
	return fd, nil
}

type processReader struct {
	ctx context.Context
	src io.Reader
}

func (r processReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.src.Read(p)
}

func hashProcessFile(ctx context.Context, proc, fd int, pin File, found runtimeIdentity, buffer []byte) error {
	if found.mode != unix.S_IFREG || found.size != uint64(pin.Bytes) {
		return fmt.Errorf("runtime file %s has the wrong type or size", pin.ID)
	}
	// The O_PATH handle pins the regular inode before a readable file is opened.
	reader, err := unix.Openat(proc, "self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("runtime file %s could not be read", pin.ID)
	}
	file := os.NewFile(uintptr(reader), "runtime file")
	defer file.Close()
	before, err := runtimeFileIdentity(reader)
	if err != nil || before != found {
		return fmt.Errorf("runtime file %s changed before hashing", pin.ID)
	}
	digest := sha256.New()
	n, readErr := io.CopyBuffer(digest, io.LimitReader(processReader{ctx: ctx, src: file}, pin.Bytes+1), buffer)
	after, statErr := runtimeFileIdentity(reader)
	if readErr != nil || statErr != nil || n != pin.Bytes || after != before || hex.EncodeToString(digest.Sum(nil)) != pin.SHA256 {
		return fmt.Errorf("runtime file %s disagrees with its signed bytes", pin.ID)
	}
	return nil
}

func verifyJobOutputFile(fd int, found runtimeIdentity, pin processPin) error {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return fmt.Errorf("runtime file %s must view its job output on a read-only mount", pin.file.ID)
	}
	root, err := unix.Open(pin.output.root, pathFlags|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("local Docker job output volume for %s could not be opened", pin.file.ID)
	}
	defer unix.Close(root)
	file, err := unix.Openat2(root, pin.output.path, &unix.OpenHow{
		Flags: pathFlags, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return fmt.Errorf("local Docker job output for %s could not be opened", pin.file.ID)
	}
	defer unix.Close(file)
	volumeIdentity, err := runtimeFileIdentity(file)
	// Both views must identify the same file across their distinct mounts.
	volumeIdentity.mount = found.mount
	if err != nil || volumeIdentity.mode != unix.S_IFREG || volumeIdentity != found {
		return fmt.Errorf("runtime file %s disagrees with its Docker job output identity", pin.file.ID)
	}
	return nil
}

func verifyProcessFiles(ctx context.Context, snapshot dockerSnapshot, pins []processPin, recheck func() error, evidence *processFilesSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	proc, err := unix.Open("/proc", pathFlags|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("local procfs could not be opened")
	}
	defer unix.Close(proc)
	var fs unix.Statfs_t
	if err := unix.Fstatfs(proc, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return errors.New("process observer requires local procfs")
	}
	pidfd, err := unix.PidfdOpen(snapshot.PID, 0)
	if err != nil {
		return errors.New("a Linux process handle could not be obtained")
	}
	defer unix.Close(pidfd)
	if err := verifyProcessHandle(proc, pidfd, snapshot.PID); err != nil {
		return err
	}
	dir, err := unix.Openat(proc, strconv.Itoa(snapshot.PID), pathFlags|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("the Docker process directory could not be opened")
	}
	defer unix.Close(dir)
	if err := activeProcess(pidfd); err != nil {
		return err
	}
	if err := verifyProcessCgroup(dir, snapshot.ID); err != nil {
		return err
	}
	root, err := unix.Openat(dir, "root", pathFlags|unix.O_DIRECTORY, 0)
	if err != nil {
		return errors.New("the process filesystem view could not be opened")
	}
	defer unix.Close(root)
	rootIdentity, err := runtimeFileIdentity(root)
	if err != nil {
		return err
	}
	confirming := evidence != nil && evidence.files != nil
	if confirming && (len(pins) != len(evidence.files) || !sameRuntimeRoot(rootIdentity, evidence.root)) {
		return errors.New("the process filesystem view changed since hashing")
	}
	identities := make([]runtimeIdentity, len(pins))
	var buffer []byte
	if !confirming {
		buffer = make([]byte, 128<<10)
	}
	for i, pin := range pins {
		fd, err := openProcessFile(dir, root, pin.path)
		if err != nil {
			return err
		}
		found, err := runtimeFileIdentity(fd)
		if err == nil && pin.mounted && found.mount == rootIdentity.mount {
			err = fmt.Errorf("runtime file %s is outside its expected separate mount", pin.file.ID)
		}
		if err == nil && pin.output.root != "" {
			err = verifyJobOutputFile(fd, found, pin)
		}
		if err == nil {
			if !confirming {
				err = hashProcessFile(ctx, proc, fd, pin.file, found, buffer)
			} else if found != evidence.files[i] {
				err = fmt.Errorf("runtime file %s changed since hashing", pin.file.ID)
			}
		}
		unix.Close(fd)
		if err != nil {
			return err
		}
		identities[i] = found
	}
	if err := recheck(); err != nil {
		return err
	}
	if err := verifyProcessCgroup(dir, snapshot.ID); err != nil {
		return err
	}
	currentRoot, err := unix.Openat(dir, "root", pathFlags|unix.O_DIRECTORY, 0)
	if err != nil {
		return errors.New("the process filesystem view could not be confirmed")
	}
	defer unix.Close(currentRoot)
	currentIdentity, err := runtimeFileIdentity(currentRoot)
	if err != nil || !sameRuntimeRoot(currentIdentity, rootIdentity) {
		return errors.New("the process filesystem view changed during verification")
	}
	for i, pin := range pins {
		fd, err := openProcessFile(dir, currentRoot, pin.path)
		if err != nil {
			return err
		}
		found, err := runtimeFileIdentity(fd)
		if err == nil && pin.output.root != "" {
			err = verifyJobOutputFile(fd, found, pin)
		}
		unix.Close(fd)
		if err != nil || found != identities[i] {
			return fmt.Errorf("runtime file %s changed during verification", pin.file.ID)
		}
	}
	if err := activeProcess(pidfd); err != nil {
		return err
	}
	if evidence != nil && !confirming {
		*evidence = processFilesSnapshot{root: rootIdentity, files: identities}
	}
	return nil
}
