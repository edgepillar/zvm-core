//go:build linux || darwin

package artifacts

import (
	"errors"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func singleLink(info os.FileInfo) bool {
	identity, ok := info.Sys().(*syscall.Stat_t)
	return ok && identity.Nlink == 1
}

func openEntry(root *os.Root, name string, directory bool) (*os.File, error) {
	// Root.OpenFile resolves in-root symlinks itself, including after an ELOOP.
	// Open each single component relative to an owned descriptor instead.
	anchor, err := root.Open(".")
	if err != nil {
		return nil, errors.New("root descriptor could not be opened")
	}
	defer anchor.Close()
	parent := int(anchor.Fd())
	owned := -1
	defer func() {
		if owned >= 0 {
			unix.Close(owned)
		}
	}()
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "" || part == ".." || (part == "." && name != ".") {
			return nil, errors.New("invalid selected entry component")
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		if i < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, part, flags, 0)
		if err != nil {
			return nil, errors.New("selected entry could not be opened without following links")
		}
		if owned >= 0 {
			unix.Close(owned)
		}
		owned = fd
		parent = fd
	}
	f := os.NewFile(uintptr(owned), "selected entry")
	if f == nil {
		return nil, errors.New("selected entry descriptor is invalid")
	}
	owned = -1
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, errors.New("selected entry could not be inspected")
	}
	if directory {
		if !info.IsDir() {
			f.Close()
			return nil, errors.New("selected directory is not a directory")
		}
	} else {
		if !info.Mode().IsRegular() || !singleLink(info) {
			f.Close()
			return nil, errors.New("selected file is nonregular or has hard links")
		}
	}
	return f, nil
}
