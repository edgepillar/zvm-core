package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

func stable(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) &&
		(!a.Mode().IsRegular() || (singleLink(a) && singleLink(b)))
}

type directory struct {
	root      *os.Root
	ancestors map[string]os.FileInfo
}

func openDirectory(name string) (*directory, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, errors.New("invalid artifact directory")
	}
	current := filepath.VolumeName(abs) + string(filepath.Separator)
	ancestors := map[string]os.FileInfo{}
	parts := strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator))
	for _, part := range append([]string{""}, parts...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("directory has a missing, linked or non-directory ancestor")
		}
		ancestors[current] = info
	}
	r, err := os.OpenRoot(abs)
	if err != nil {
		return nil, errors.New("artifact directory could not be opened")
	}
	info, err := r.Stat(".")
	if err != nil || !os.SameFile(ancestors[abs], info) {
		r.Close()
		return nil, errors.New("artifact directory changed while opening")
	}
	d := &directory{r, ancestors}
	if err := d.checkAncestors(); err != nil {
		r.Close()
		return nil, err
	}
	return d, nil
}

func (d *directory) checkAncestors() error {
	for name, before := range d.ancestors {
		after, err := os.Lstat(name)
		// Parent directory modification times may change for unrelated siblings.
		if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(before, after) {
			return errors.New("directory ancestor identity changed")
		}
	}
	return nil
}

// ReadDocument reads one explicitly named regular document without following
// symlink ancestors, copying dependencies or including its local path in errors.
func ReadDocument(name string) ([]byte, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, errors.New("invalid document path")
	}
	d, err := openDirectory(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	defer d.root.Close()
	base := filepath.Base(abs)
	before, err := d.root.Lstat(base)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > MaxDocumentBytes {
		return nil, errors.New("document is missing, nonregular or exceeds its byte limit")
	}
	f, err := openEntry(d.root, base, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !stable(before, opened) {
		return nil, errors.New("document changed while opening")
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, MaxDocumentBytes+1))
	after, statErr := f.Stat()
	named, pathErr := d.root.Lstat(base)
	if readErr != nil || statErr != nil || pathErr != nil || int64(len(raw)) != before.Size() || !stable(before, after) || !stable(before, named) {
		return nil, errors.New("document changed while reading")
	}
	if err := d.checkAncestors(); err != nil {
		return nil, err
	}
	return raw, nil
}

func inventory(d *directory, files map[string]File) (map[string]os.FileInfo, error) {
	dirs := map[string]bool{".": true}
	for name := range files {
		for prefix := path.Dir(name); prefix != "."; prefix = path.Dir(prefix) {
			dirs[prefix] = true
		}
	}
	budget := len(dirs) + len(files)
	observed := map[string]os.FileInfo{}
	entriesRead := 0
	var walk func(string) error
	walk = func(name string) error {
		before, err := d.root.Lstat(name)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return errors.New("artifact directory is missing or linked")
		}
		f, err := openEntry(d.root, name, true)
		if err != nil {
			return err
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !stable(before, opened) {
			return errors.New("artifact directory changed while opening")
		}
		entries, err := f.ReadDir(budget - entriesRead + 1)
		if err != nil && err != io.EOF {
			return errors.New("artifact directory could not be enumerated")
		}
		entriesRead += len(entries)
		if entriesRead > budget {
			return errors.New("artifact directory exceeds its closed inventory")
		}
		observed[name] = before
		for _, entry := range entries {
			rel := entry.Name()
			if name != "." {
				rel = name + "/" + rel
			}
			if !relative(rel) {
				return errors.New("artifact directory contains an unsafe name")
			}
			info, err := d.root.Lstat(rel)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("artifact entry is missing or linked")
			}
			if info.IsDir() {
				if !dirs[rel] {
					return errors.New("unlisted artifact directory")
				}
				if err := walk(rel); err != nil {
					return err
				}
			} else {
				if _, ok := files[rel]; !ok || !info.Mode().IsRegular() {
					return errors.New("unlisted or nonregular artifact file")
				}
				observed[rel] = info
			}
		}
		after, err := f.Stat()
		named, pathErr := d.root.Lstat(name)
		if err != nil || pathErr != nil || !stable(before, after) || !stable(before, named) {
			return errors.New("artifact directory changed while enumerating")
		}
		return nil
	}
	if err := walk("."); err != nil {
		return nil, err
	}
	if len(observed) != len(dirs)+len(files) {
		return nil, errors.New("artifact file inventory is incomplete")
	}
	return observed, nil
}

func readFile(d *directory, pin File, before os.FileInfo, afterOpen func(string)) error {
	named, err := d.root.Lstat(pin.Path)
	if err != nil || !stable(before, named) || before.Size() != pin.Bytes {
		return errors.New("artifact identity or size changed before reading")
	}
	f, err := openEntry(d.root, pin.Path, false)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !stable(before, opened) {
		return errors.New("artifact changed while opening")
	}
	if afterOpen != nil {
		afterOpen(pin.Path)
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.LimitReader(f, pin.Bytes+1))
	after, statErr := f.Stat()
	named, pathErr := d.root.Lstat(pin.Path)
	if readErr != nil || statErr != nil || pathErr != nil || n != pin.Bytes || !stable(before, after) || !stable(before, named) || hex.EncodeToString(h.Sum(nil)) != pin.SHA256 {
		return errors.New("artifact changed or its SHA-256 does not match")
	}
	return nil
}

// Check verifies selection and byte closure only. The policy is an independently
// supplied expectation, not authenticated by a hash supplied by the manifest.
func Check(manifestBytes, policyBytes []byte, root string) (Result, error) {
	return check(manifestBytes, policyBytes, root, nil)
}

func check(manifestBytes, policyBytes []byte, root string, afterOpen func(string)) (Result, error) {
	return checkSelected(manifestBytes, policyBytes, root, afterOpen, nil)
}

// The extra verifier runs inside the same observed file inventory as selection.
// A successful byte-only Check still reports no signature/content acceptance.
func checkSelected(manifestBytes, policyBytes []byte, root string, afterOpen func(string), verify func(*directory, map[string]File, map[string]os.FileInfo) error) (Result, error) {
	var m Manifest
	var p Policy
	if err := decode(manifestBytes, &m); err != nil {
		return Result{}, err
	}
	if err := decode(policyBytes, &p); err != nil {
		return Result{}, err
	}
	files, err := validate(m, p)
	if err != nil {
		return Result{}, err
	}
	if err := validateChecksums(m, files); err != nil {
		return Result{}, err
	}
	d, err := openDirectory(root)
	if err != nil {
		return Result{}, err
	}
	defer d.root.Close()
	before, err := inventory(d, files)
	if err != nil {
		return Result{}, err
	}
	var total int64
	for _, pin := range m.Files {
		if err := readFile(d, pin, before[pin.Path], afterOpen); err != nil {
			return Result{}, err
		}
		total += pin.Bytes
	}
	if verify != nil {
		if err := verify(d, files, before); err != nil {
			return Result{}, err
		}
	}
	last, err := inventory(d, files)
	if err != nil {
		return Result{}, err
	}
	if len(last) != len(before) {
		return Result{}, errors.New("artifact inventory changed")
	}
	for name, info := range before {
		if !stable(info, last[name]) {
			return Result{}, errors.New("artifact identity changed during verification")
		}
	}
	if err := d.checkAncestors(); err != nil {
		return Result{}, err
	}
	canonical, _ := CanonicalPolicy(p)
	return Result{ManifestSHA256: sum(manifestBytes), PolicySHA256: sum(canonical), FilesVerified: len(files), BytesVerified: total, SelectionVerified: true}, nil
}

// SHA256SUMS lists every selected file except itself in sorted path order;
// the manifest pins the checksums file without a self-hash cycle.
func validateChecksums(m Manifest, files map[string]File) error {
	if files[m.ChecksumsPath].Bytes > MaxDocumentBytes {
		return errors.New("checksums text exceeds its byte limit")
	}
	var expected strings.Builder
	for _, pin := range m.Files {
		if pin.Path != m.ChecksumsPath {
			expected.WriteString(pin.SHA256 + "  " + pin.Path + "\n")
		}
	}
	checksum := files[m.ChecksumsPath]
	if int64(expected.Len()) != checksum.Bytes || sum([]byte(expected.String())) != checksum.SHA256 {
		return errors.New("checksums text does not exactly describe the selected files")
	}
	return nil
}

// ExpectedPaths is useful for producers preparing a dedicated selected-file
// directory. It neither generates files nor qualifies a produced artifact.
func ExpectedPaths(p Policy) ([]string, error) {
	roles, err := p.validate()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(roles))
	for name := range roles {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}
