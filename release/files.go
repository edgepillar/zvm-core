package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func openDirectory(directory string) (*os.Root, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.New("invalid input root")
	}
	current := filepath.VolumeName(abs) + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("input root has a missing, linked or non-directory ancestor")
		}
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, errors.New("input root could not be opened")
	}
	return root, nil
}

// OpenRoot confines reads to the declared input directory. Refuse link
// ancestors as well; a matching payload name alone is not a verified file.
func openFile(root *os.Root, name string) (*os.File, error) {
	parts := strings.Split(name, "/")
	for i := range parts {
		info, err := root.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil {
			return nil, errors.New("declared file is missing or unreadable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("link ancestors are not accepted")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, errors.New("file ancestor is not a directory")
		}
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, errors.New("declared file could not be opened")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("declared input is not a regular file")
	}
	return f, nil
}

// VerifyFiles streams exact byte counts and hashes. It does not copy inputs,
// unpack archives, install compilers or execute build/deployment code.
func (m Manifest) VerifyFiles(directory string) (int, error) {
	if err := m.validate(); err != nil {
		return 0, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("file root must be a real directory")
	}
	root, err := openDirectory(directory)
	if err != nil {
		return 0, errors.New("file root could not be opened")
	}
	defer root.Close()
	var total int64
	for _, pin := range m.Files {
		total += pin.Bytes
		if total > 4<<30 {
			return 0, errors.New("declared file set exceeds the four-GiB verification budget")
		}
	}
	for _, pin := range m.Files {
		f, err := openFile(root, pin.Repository+"/"+pin.Path)
		if err != nil {
			return 0, fmt.Errorf("file %s: %w", pin.ID, err)
		}
		before, err := f.Stat()
		if err != nil || before.Size() != pin.Bytes {
			f.Close()
			return 0, fmt.Errorf("file %s: byte count mismatch", pin.ID)
		}
		h := sha256.New()
		n, readErr := io.Copy(h, io.LimitReader(f, pin.Bytes+1))
		after, statErr := f.Stat()
		closeErr := f.Close()
		if readErr != nil || statErr != nil || closeErr != nil || n != pin.Bytes || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || hex.EncodeToString(h.Sum(nil)) != pin.SHA256 {
			return 0, fmt.Errorf("file %s: content changed or SHA-256 mismatch", pin.ID)
		}
	}
	return len(m.Files), nil
}
