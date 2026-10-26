package artifacts

import (
	"errors"
	"path"
	"strings"
)

const GoSourceTreeProfile = "git-go-source-tree-v1"

// GoSourceTreePolicy selects a complete parent export. Gitlinks are object
// references only; their directories must be absent from the regular-file export.
type GoSourceTreePolicy struct {
	Schema       int          `json:"schema"`
	Profile      string       `json:"profile"`
	Source       Source       `json:"source"`
	GoModSHA256  string       `json:"goModSha256"`
	CommitObject File         `json:"commitObject"`
	Files        []SourceFile `json:"files"`
}

// Physical input locations are never included in policies or result receipts.
type GoSourceTreeOptions struct {
	Directory        string
	ControlDirectory string
}

type GoSourceTreeResult struct {
	Schema                    int    `json:"schema"`
	Profile                   string `json:"profile"`
	PolicySHA256              string `json:"policySha256"`
	Repository                string `json:"repository"`
	Commit                    string `json:"commit"`
	Tree                      string `json:"tree"`
	SourceTreeVerified        bool   `json:"sourceTreeVerified"`
	SourceFilesVerified       int    `json:"sourceFilesVerified"`
	SourceBytesVerified       int64  `json:"sourceBytesVerified"`
	GitlinksBound             int    `json:"gitlinksBound"`
	CommitObjectsVerified     int    `json:"commitObjectsVerified"`
	ChildSourceTreesVerified  bool   `json:"childSourceTreesVerified"`
	SourceCommitAuthenticated bool   `json:"sourceCommitAuthenticated"`
	CompilerUseOfTreeProven   bool   `json:"compilerUseOfTreeProven"`
	ReleaseAccepted           bool   `json:"releaseAccepted"`
}

func (p GoSourceTreePolicy) validate() (GoLocalSource, error) {
	s := p.Source
	if p.Schema != 1 || p.Profile != GoSourceTreeProfile || !validRepository(s.Repository) || !commit(s.Commit) || !commit(s.Tree) || len(s.Commit) != len(s.Tree) || s.Gitlinks == nil || len(s.Gitlinks) > 64 || !digest(p.GoModSHA256, 64) {
		return GoLocalSource{}, errors.New("invalid selected Go source-tree policy")
	}
	control := p.CommitObject
	if !relative(control.Path) || control.Bytes <= 0 || control.Bytes > MaxDocumentBytes || !digest(control.SHA256, 64) {
		return GoLocalSource{}, errors.New("invalid selected source commit-object control")
	}
	selected := GoLocalSource{Source: s, GoModSHA256: p.GoModSHA256, Files: p.Files}
	files, _, err := sourceFilePins(selected)
	if err != nil {
		return GoLocalSource{}, err
	}
	aliases := map[string]string{}
	leaves := map[string]bool{}
	add := func(name string) error {
		if !relative(name) || name == ".git" || strings.HasPrefix(name, ".git/") || leaves[name] {
			return errors.New("source object path collides")
		}
		for prefix := name; prefix != "."; prefix = path.Dir(prefix) {
			folded := strings.ToLower(prefix)
			if old, ok := aliases[folded]; ok && old != prefix {
				return errors.New("source Gitlink or file case alias")
			}
			aliases[folded] = prefix
			if prefix != name && leaves[prefix] {
				return errors.New("source object file/directory alias")
			}
		}
		for leaf := range leaves {
			if strings.HasPrefix(leaf, name+"/") {
				return errors.New("source object directory/file alias")
			}
		}
		leaves[name] = true
		return nil
	}
	for name := range files {
		if err := add(name); err != nil {
			return GoLocalSource{}, err
		}
	}
	last := ""
	for _, link := range s.Gitlinks {
		if link.Path <= last || !validRepository(link.Repository) || !commit(link.Commit) || len(link.Commit) != len(s.Tree) {
			return GoLocalSource{}, errors.New("invalid sorted source Gitlink inventory")
		}
		if err := add(link.Path); err != nil {
			return GoLocalSource{}, err
		}
		last = link.Path
	}
	return selected, nil
}

// CheckGoSourceTree checks content binding only. The expected policy hash must
// come from the caller's independent input selection, never from a proposed
// replacement policy. The result does not prove compiler use, source authority,
// child contents or a jointly verified artifact/attestation observation.
func CheckGoSourceTree(raw []byte, expectedPolicySHA256 string, options GoSourceTreeOptions) (GoSourceTreeResult, error) {
	var zero GoSourceTreeResult
	observed, err := observeGoSourceTree(raw, expectedPolicySHA256, options)
	if err != nil {
		return zero, err
	}
	defer observed.close()
	if err := observed.unchanged(); err != nil {
		return zero, err
	}
	return observed.result, nil
}

type goSourceTreeObservation struct {
	sourceObservation
	policy GoSourceTreePolicy
	result GoSourceTreeResult
}

func observeGoSourceTree(raw []byte, expectedPolicySHA256 string, options GoSourceTreeOptions) (*goSourceTreeObservation, error) {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes || !digest(expectedPolicySHA256, 64) || sum(raw) != expectedPolicySHA256 {
		return nil, errors.New("source policy differs from the independently selected SHA-256")
	}
	if options.Directory == "" || options.ControlDirectory == "" {
		return nil, errors.New("explicit source export and commit controls are required")
	}
	var p GoSourceTreePolicy
	if err := decode(raw, &p); err != nil {
		return nil, err
	}
	selected, err := p.validate()
	if err != nil {
		return nil, err
	}
	d, err := openDirectory(options.ControlDirectory)
	if err != nil {
		return nil, err
	}
	observation := &goSourceTreeObservation{policy: p, sourceObservation: sourceObservation{control: &observedSource{dir: d, files: map[string]File{p.CommitObject.Path: p.CommitObject}}}}
	good := false
	defer func() {
		if !good {
			observation.close()
		}
	}()
	observation.control.before, err = inventory(d, observation.control.files)
	if err != nil {
		return nil, err
	}
	commitBytes, err := selectedControlDocument(d, p.CommitObject, observation.control.before[p.CommitObject.Path], true)
	if err != nil {
		return nil, err
	}
	tree, size, err := inspectSourceTree(selected, options.Directory, commitBytes)
	if err != nil {
		return nil, err
	}
	observation.trees = append(observation.trees, tree)
	observation.result = GoSourceTreeResult{Schema: 1, Profile: GoSourceTreeProfile, PolicySHA256: expectedPolicySHA256,
		Repository: p.Source.Repository, Commit: p.Source.Commit, Tree: p.Source.Tree,
		SourceTreeVerified: true, SourceFilesVerified: len(p.Files), SourceBytesVerified: size,
		GitlinksBound: len(p.Source.Gitlinks), CommitObjectsVerified: 1}
	good = true
	return observation, nil
}
