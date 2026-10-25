package artifacts

import (
	"bytes"
	"crypto/sha1" // Git SHA-1 object identity; never a signature or artifact checksum.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"slices"
	"strings"
)

const MaxLocalSources = 16
const MaxLocalSourceBytes int64 = 64 << 20
const MaxLocalSourceFileBytes int64 = 16 << 20

type SourceFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
}

type GoLocalSource struct {
	Module       string       `json:"module"`
	Version      string       `json:"version"`
	Path         string       `json:"path"`
	Source       Source       `json:"source"`
	GoModSHA256  string       `json:"goModSha256"`
	CommitObject File         `json:"commitObject"`
	Files        []SourceFile `json:"files"`
}

func gitHash(width int) hash.Hash {
	if width == 64 {
		return sha256.New()
	}
	return sha1.New()
}
func gitObject(kind string, data []byte, width int) []byte {
	h := gitHash(width)
	fmt.Fprintf(h, "%s %d\x00", kind, len(data))
	h.Write(data)
	return h.Sum(nil)
}

type gitNode struct {
	mode     string
	oid      []byte
	children map[string]*gitNode
}

func (n *gitNode) add(name, mode string, oid []byte) error {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if n.children == nil {
			return errors.New("source file/directory alias")
		}
		old := n.children[part]
		if i == len(parts)-1 {
			if old != nil {
				return errors.New("source object path collides")
			}
			n.children[part] = &gitNode{mode: mode, oid: oid}
			return nil
		}
		if old == nil {
			old = &gitNode{mode: "40000", children: map[string]*gitNode{}}
			n.children[part] = old
		}
		n = old
	}
	return errors.New("missing source object path")
}
func (n *gitNode) digest(width int) []byte {
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		left, right := a, b
		if n.children[a].children != nil {
			left += "/"
		}
		if n.children[b].children != nil {
			right += "/"
		}
		return strings.Compare(left, right)
	})
	var raw bytes.Buffer
	for _, name := range names {
		child := n.children[name]
		oid := child.oid
		if child.children != nil {
			oid = child.digest(width)
		}
		fmt.Fprintf(&raw, "%s %s\x00", child.mode, name)
		raw.Write(oid)
	}
	return gitObject("tree", raw.Bytes(), width)
}

func sourceFilePins(s GoLocalSource) (map[string]File, int64, error) {
	files := map[string]File{}
	aliases := map[string]string{}
	var total int64
	last := ""
	for _, f := range s.Files {
		if !relative(f.Path) || f.Path <= last || f.Path == ".git" || strings.HasPrefix(f.Path, ".git/") || f.Bytes < 0 || f.Bytes > MaxLocalSourceFileBytes || !digest(f.SHA256, 64) || (f.Mode != "100644" && f.Mode != "100755") {
			return nil, 0, errors.New("invalid sorted regular source-file inventory")
		}
		for name := f.Path; name != "."; name = path.Dir(name) {
			folded := strings.ToLower(name)
			if old, ok := aliases[folded]; ok && old != name {
				return nil, 0, errors.New("source case alias")
			}
			aliases[folded] = name
		}
		files[f.Path] = File{f.Path, f.Bytes, f.SHA256}
		total += f.Bytes
		last = f.Path
	}
	if len(files) == 0 || len(files) > MaxFiles || total > MaxLocalSourceBytes || files["go.mod"].Bytes <= 0 || files["go.mod"].Bytes > MaxDocumentBytes || files["go.mod"].SHA256 != s.GoModSHA256 {
		return nil, 0, errors.New("source tree or module input exceeds its declared scope")
	}
	for name := range files {
		for prefix := path.Dir(name); prefix != "."; prefix = path.Dir(prefix) {
			if _, ok := files[prefix]; ok {
				return nil, 0, errors.New("source file/directory alias")
			}
		}
	}
	return files, total, nil
}

type observedSource struct {
	dir    *directory
	files  map[string]File
	before map[string]os.FileInfo
}

func (s *observedSource) unchanged() error {
	last, err := inventoryWithMetadata(s.dir, s.files, true)
	if err != nil || len(last) != len(s.before) {
		return errors.New("source inventory changed")
	}
	for name, before := range s.before {
		if !stable(before, last[name]) {
			return errors.New("source identity changed during verification")
		}
	}
	return s.dir.checkAncestors()
}

// inspectLocalSource verifies SHA-256 pins and Git blob/tree identity in one
// streaming observation. Git metadata, subprocesses and network are never used.
func inspectLocalSource(source GoLocalSource, root string, commitBytes []byte) (*observedSource, int64, error) {
	if len(source.Source.Gitlinks) != 0 {
		return nil, 0, errors.New("local replacement inspection requires a flat source tree")
	}
	return inspectSourceTree(source, root, commitBytes)
}

func inspectSourceTree(source GoLocalSource, root string, commitBytes []byte) (*observedSource, int64, error) {
	files, total, err := sourceFilePins(source)
	if err != nil {
		return nil, 0, err
	}
	if !bytes.HasPrefix(commitBytes, []byte("tree "+source.Source.Tree+"\n")) || hex.EncodeToString(gitObject("commit", commitBytes, len(source.Source.Commit))) != source.Source.Commit {
		return nil, 0, errors.New("selected commit object does not bind the expected source tree")
	}
	d, err := openDirectory(root)
	if err != nil {
		return nil, 0, err
	}
	snapshot := &observedSource{dir: d, files: files}
	good := false
	defer func() {
		if !good {
			d.root.Close()
		}
	}()
	snapshot.before, err = inventoryWithMetadata(d, files, true)
	if err != nil {
		return nil, 0, err
	}
	tree := &gitNode{children: map[string]*gitNode{}}
	for _, link := range source.Source.Gitlinks {
		oid, err := hex.DecodeString(link.Commit)
		if err != nil || len(link.Commit) != len(source.Source.Tree) {
			return nil, 0, errors.New("source Gitlink object format does not match its parent")
		}
		if err := tree.add(link.Path, "160000", oid); err != nil {
			return nil, 0, err
		}
	}
	for _, pin := range source.Files {
		before := snapshot.before[pin.Path]
		if before.Size() != pin.Bytes || (before.Mode().Perm()&0111 != 0) != (pin.Mode == "100755") {
			return nil, 0, errors.New("source size or executable mode does not match policy")
		}
		f, err := openEntry(d.root, pin.Path, false)
		if err != nil {
			return nil, 0, err
		}
		opened, err := f.Stat()
		if err != nil || !stable(before, opened) {
			f.Close()
			return nil, 0, errors.New("source changed while opening")
		}
		blob, strong := gitHash(len(source.Source.Tree)), sha256.New()
		fmt.Fprintf(blob, "blob %d\x00", pin.Bytes)
		n, readErr := io.Copy(io.MultiWriter(blob, strong), io.LimitReader(f, pin.Bytes+1))
		after, statErr := f.Stat()
		named, pathErr := d.root.Lstat(pin.Path)
		f.Close()
		if readErr != nil || statErr != nil || pathErr != nil || n != pin.Bytes || !stable(before, after) || !stable(before, named) || hex.EncodeToString(strong.Sum(nil)) != pin.SHA256 {
			return nil, 0, errors.New("source bytes or identity do not match policy")
		}
		if err := tree.add(pin.Path, pin.Mode, blob.Sum(nil)); err != nil {
			return nil, 0, err
		}
	}
	if hex.EncodeToString(tree.digest(len(source.Source.Tree))) != source.Source.Tree {
		return nil, 0, errors.New("source file inventory does not reproduce the selected Git tree")
	}
	if err := snapshot.unchanged(); err != nil {
		return nil, 0, err
	}
	good = true
	return snapshot, total, nil
}
