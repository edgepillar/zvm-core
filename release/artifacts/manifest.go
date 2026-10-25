// Package artifacts checks a bounded, explicitly selected release file set.
// CheckProvenance additionally verifies selected signatures and exact workflow
// identities using an independently pinned external verifier and trust root.
// Neither mode executes a build or accepts a release.
package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

const (
	Schema           = 1
	MaxDocumentBytes = 1 << 20
	MaxFiles         = 256
	MaxArtifacts     = 64
	MaxFileBytes     = 1 << 30
	MaxTotalBytes    = 4 << 30
)

type Gitlink struct {
	Path       string `json:"path"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

type Source struct {
	Repository string    `json:"repository"`
	Commit     string    `json:"commit"`
	Tree       string    `json:"tree"`
	Gitlinks   []Gitlink `json:"gitlinks"`
}

type Release struct {
	ID                  string `json:"id"`
	EpochSHA256         string `json:"epochSha256"`
	QualificationSHA256 string `json:"qualificationSha256"`
	Tag                 string `json:"tag"`
	TagCommit           string `json:"tagCommit"`
	Source              Source `json:"source"`
}

type Input struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

type Build struct {
	WorkflowPath            string   `json:"workflowPath"`
	WorkflowCommit          string   `json:"workflowCommit"`
	RecipeSHA256            string   `json:"recipeSha256"`
	EnvironmentPolicySHA256 string   `json:"environmentPolicySha256"`
	Flags                   []string `json:"flags"`
	Toolchains              []Input  `json:"toolchains"`
	Images                  []Input  `json:"images"`
	Materials               []Input  `json:"materials"`
}

// Artifact binds one expected platform output and its sidecars. Multiple
// outputs may share a sidecar of the same role, but never an executable subject.
type Artifact struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Platform       string `json:"platform"`
	SubjectPath    string `json:"subjectPath"`
	SBOMPath       string `json:"sbomPath"`
	ProvenancePath string `json:"provenancePath"`
}

// Policy must be selected independently of the untrusted manifest. Loading
// this document does not establish who reviewed or authenticated it.
type Policy struct {
	Schema        int        `json:"schema"`
	Release       Release    `json:"release"`
	Build         Build      `json:"build"`
	Artifacts     []Artifact `json:"artifacts"`
	ChecksumsPath string     `json:"checksumsPath"`
	NotesPath     string     `json:"notesPath"`
}

type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Schema        int        `json:"schema"`
	PolicySHA256  string     `json:"policySha256"`
	Release       Release    `json:"release"`
	Build         Build      `json:"build"`
	Artifacts     []Artifact `json:"artifacts"`
	ChecksumsPath string     `json:"checksumsPath"`
	NotesPath     string     `json:"notesPath"`
	Files         []File     `json:"files"`
}

type Result struct {
	ManifestSHA256               string `json:"manifestSha256"`
	PolicySHA256                 string `json:"policySha256"`
	FilesVerified                int    `json:"filesVerified"`
	BytesVerified                int64  `json:"bytesVerified"`
	SelectionVerified            bool   `json:"selectionVerified"`
	ProvenanceSignaturesVerified bool   `json:"provenanceSignaturesVerified"`
	SBOMContentsVerified         bool   `json:"sbomContentsVerified"`
	ReleaseAccepted              bool   `json:"releaseAccepted"`
}

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
var repository = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9_.-]{1,100}$`)
var versionTag = regexp.MustCompile(`^v[0-9][A-Za-z0-9.+_-]{0,63}$`)
var platform = regexp.MustCompile(`^[a-z0-9]{1,16}/[a-z0-9]{1,16}(/[a-z0-9]{1,16})?$`)

func digest(value string, size int) bool {
	if len(value) != size || strings.ToLower(value) != value {
		return false
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(raw, func(b byte) bool { return b != 0 })
}

func commit(value string) bool { return digest(value, 40) || digest(value, 64) }

// Use a deliberately portable filename grammar. This also rejects Windows
// device names and trailing-dot/space aliases on a Unix verification host.
func relative(name string) bool {
	if name == "" || len(name) > 256 || path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 64 || strings.HasSuffix(part, ".") {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return false
		}
		if strings.EqualFold(part, ".git") {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validRepository(value string) bool {
	if !repository.MatchString(value) {
		return false
	}
	parts := strings.Split(value, "/")
	return parts[1] != "." && parts[1] != ".."
}

func inputs(values []Input, required bool) error {
	if values == nil || len(values) > 64 || (required && len(values) == 0) {
		return errors.New("invalid build input count")
	}
	last := ""
	for _, value := range values {
		if !identifier.MatchString(value.ID) || value.ID <= last || !digest(value.SHA256, 64) {
			return errors.New("build inputs must have sorted unique IDs and exact digests")
		}
		last = value.ID
	}
	return nil
}

func (p Policy) validate() (map[string]string, error) {
	if p.Schema != Schema || !identifier.MatchString(p.Release.ID) || !digest(p.Release.EpochSHA256, 64) || !digest(p.Release.QualificationSHA256, 64) {
		return nil, errors.New("invalid release identity")
	}
	s := p.Release.Source
	if !validRepository(s.Repository) || !commit(s.Commit) || !commit(s.Tree) || len(s.Commit) != len(s.Tree) || s.Gitlinks == nil || len(s.Gitlinks) > 64 ||
		!versionTag.MatchString(p.Release.Tag) || strings.Contains(p.Release.Tag, "..") || strings.HasSuffix(p.Release.Tag, ".") || strings.HasSuffix(p.Release.Tag, ".lock") || p.Release.TagCommit != s.Commit {
		return nil, errors.New("invalid source or tag binding")
	}
	last := ""
	gitlinkAliases := map[string]bool{}
	for _, link := range s.Gitlinks {
		folded := strings.ToLower(link.Path)
		if !relative(link.Path) || link.Path <= last || gitlinkAliases[folded] || !validRepository(link.Repository) || !commit(link.Commit) {
			return nil, errors.New("invalid sorted gitlink inventory")
		}
		gitlinkAliases[folded] = true
		last = link.Path
	}
	b := p.Build
	if !relative(b.WorkflowPath) || !strings.HasPrefix(b.WorkflowPath, ".github/workflows/") || !commit(b.WorkflowCommit) ||
		!digest(b.RecipeSHA256, 64) || !digest(b.EnvironmentPolicySHA256, 64) || b.Flags == nil || len(b.Flags) > 32 {
		return nil, errors.New("invalid build binding")
	}
	for _, flag := range b.Flags {
		if flag == "" || len(flag) > 512 {
			return nil, errors.New("invalid build flag")
		}
		for _, c := range flag {
			if c < 32 || c > 126 {
				return nil, errors.New("invalid build flag")
			}
		}
	}
	for _, list := range []struct {
		values   []Input
		required bool
	}{{b.Toolchains, true}, {b.Images, false}, {b.Materials, true}} {
		if err := inputs(list.values, list.required); err != nil {
			return nil, err
		}
	}
	if len(p.Artifacts) == 0 || len(p.Artifacts) > MaxArtifacts {
		return nil, errors.New("invalid artifact count")
	}
	roles := map[string]string{}
	aliases := map[string]string{}
	add := func(name, role string) error {
		if !relative(name) {
			return errors.New("invalid artifact path")
		}
		folded := strings.ToLower(name)
		if other, ok := aliases[folded]; ok && other != name {
			return errors.New("artifact path case alias")
		}
		if old, ok := roles[name]; ok && (old != role || role == "subject") {
			return errors.New("artifact file roles collide")
		}
		roles[name] = role
		aliases[folded] = name
		return nil
	}
	last = ""
	for _, artifact := range p.Artifacts {
		if !identifier.MatchString(artifact.ID) || artifact.ID <= last || !platform.MatchString(artifact.Platform) ||
			(artifact.Kind != "binary" && artifact.Kind != "archive" && artifact.Kind != "oci-manifest") {
			return nil, errors.New("invalid sorted artifact requirement")
		}
		last = artifact.ID
		for _, field := range []struct{ name, role string }{{artifact.SubjectPath, "subject"}, {artifact.SBOMPath, "sbom"}, {artifact.ProvenancePath, "provenance"}} {
			if err := add(field.name, field.role); err != nil {
				return nil, err
			}
		}
	}
	if err := add(p.ChecksumsPath, "checksums"); err != nil {
		return nil, err
	}
	if err := add(p.NotesPath, "notes"); err != nil {
		return nil, err
	}
	if len(roles) > MaxFiles {
		return nil, errors.New("release file inventory exceeds limit")
	}
	// A file cannot also be an ancestor directory of another required file.
	for name := range roles {
		for prefix := path.Dir(name); prefix != "."; prefix = path.Dir(prefix) {
			if _, exists := aliases[strings.ToLower(prefix)]; exists {
				return nil, errors.New("artifact file/directory alias")
			}
		}
	}
	components := map[string]string{}
	for name := range roles {
		for prefix := name; prefix != "."; prefix = path.Dir(prefix) {
			folded := strings.ToLower(prefix)
			if old, ok := components[folded]; ok && old != prefix {
				return nil, errors.New("artifact directory case alias")
			}
			components[folded] = prefix
		}
	}
	return roles, nil
}

// CanonicalPolicy uses this schema's fixed-field JSON serialization. It is
// neither a signature nor a claim of general JSON canonicalization.
func CanonicalPolicy(p Policy) ([]byte, error) {
	if _, err := p.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func sum(raw []byte) string { value := sha256.Sum256(raw); return hex.EncodeToString(value[:]) }

func (m Manifest) policy() Policy {
	return Policy{m.Schema, m.Release, m.Build, m.Artifacts, m.ChecksumsPath, m.NotesPath}
}

func validate(m Manifest, p Policy) (map[string]File, error) {
	roles, err := p.validate()
	if err != nil {
		return nil, err
	}
	canonical, _ := CanonicalPolicy(p)
	claimed, err := CanonicalPolicy(m.policy())
	if err != nil || m.PolicySHA256 != sum(canonical) || string(claimed) != string(canonical) {
		return nil, errors.New("manifest does not match the independently selected policy")
	}
	if m.Files == nil || len(m.Files) != len(roles) {
		return nil, errors.New("manifest file inventory is incomplete or excessive")
	}
	files := make(map[string]File, len(m.Files))
	last := ""
	var total int64
	for _, file := range m.Files {
		if !relative(file.Path) || file.Path <= last || roles[file.Path] == "" || file.Bytes <= 0 || file.Bytes > MaxFileBytes || !digest(file.SHA256, 64) {
			return nil, fmt.Errorf("invalid sorted release file at index %d", len(files))
		}
		last = file.Path
		total += file.Bytes
		if total > MaxTotalBytes {
			return nil, errors.New("release exceeds total byte budget")
		}
		files[file.Path] = file
	}
	return files, nil
}
