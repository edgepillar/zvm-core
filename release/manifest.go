// Package release verifies a declared release offline. Its receipts do not
// establish that a running network or container uses the declared inputs.
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	Schema           = 1
	MaxDocumentBytes = 1 << 20
	MaxEntries       = 1024
)

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
var platform = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`)
var version = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// Policy is reviewed independently of the manifest. Exact inventories prevent
// a signed document from declaring its own omissions acceptable.
type Policy struct {
	Schema        int               `json:"schema"`
	MinSignatures int               `json:"minSignatures"`
	Repositories  []string          `json:"repositories"`
	Gitlinks      []string          `json:"gitlinks"` // repository:path
	Toolchains    []string          `json:"toolchains"`
	Images        []string          `json:"images"`
	Compilers     []string          `json:"compilers"`
	Files         []FileRequirement `json:"files"`
	Contracts     []string          `json:"contracts"`
}

type FileRequirement struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Repository string `json:"repository"`
	Path       string `json:"path"`
}

type Epoch struct {
	ID                string `json:"id"`
	L1ChainID         string `json:"l1ChainId"`
	L2ChainID         string `json:"l2ChainId"`
	L1GenesisHash     string `json:"l1GenesisHash"`
	L2GenesisHash     string `json:"l2GenesisHash"`
	RollupSHA256      string `json:"rollupSha256"`
	DeploymentsSHA256 string `json:"deploymentsSha256"`
	EVM               string `json:"evm"`
}

type Gitlink struct {
	Path   string `json:"path"`
	Commit string `json:"commit"`
}

type Repository struct {
	Name     string    `json:"name"`
	Commit   string    `json:"commit"`
	Empty    bool      `json:"empty"`
	Gitlinks []Gitlink `json:"gitlinks"`
}

type Artifact struct {
	ID       string `json:"id"`
	FileID   string `json:"fileId"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	SHA256   string `json:"sha256"`
}

type Image struct {
	ID        string `json:"id"`
	Platform  string `json:"platform"`
	Reference string `json:"reference"` // OCI name@sha256:digest, never a tag
}

type File struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

type Contract struct {
	ID              string `json:"id"`
	RuntimeFile     string `json:"runtimeFile"`
	Address         string `json:"address"`
	RuntimeCodeHash string `json:"runtimeCodeHash"` // EVM keccak256, not SHA-256
}

type Manifest struct {
	Schema       int          `json:"schema"`
	PolicySHA256 string       `json:"policySha256"`
	Epoch        Epoch        `json:"epoch"`
	Repositories []Repository `json:"repositories"`
	Toolchains   []Artifact   `json:"toolchains"`
	Images       []Image      `json:"images"`
	Compilers    []Artifact   `json:"compilers"`
	Files        []File       `json:"files"`
	Contracts    []Contract   `json:"contracts"`
}

func hash(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return false
	}
	for _, x := range b {
		if x != 0 {
			return true
		}
	}
	return false
}
func blockHash(s string) bool { return strings.HasPrefix(s, "0x") && hash(s[2:], 64) }
func commit(s string) bool    { return hash(s, 40) || hash(s, 64) }
func relative(s string) bool {
	if s == "" || len(s) > 512 || path.Clean(s) != s || strings.HasPrefix(s, "/") || s == "." {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." || part == ".git" || part == "" {
			return false
		}
		for _, c := range part {
			if c < 33 || c > 126 || strings.ContainsRune(`\:*?"<>|`, c) {
				return false
			}
		}
	}
	return true
}
func decimal(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
func digest(raw []byte) string { x := sha256.Sum256(raw); return hex.EncodeToString(x[:]) }

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err == nil && len(raw) > MaxDocumentBytes {
		return nil, errors.New("canonical document exceeds its byte limit")
	}
	return raw, err
}

func unique(values []string, allowEmpty bool) error {
	if len(values) > MaxEntries || (!allowEmpty && len(values) == 0) {
		return errors.New("inventory size is outside its bounds")
	}
	seen := map[string]bool{}
	for _, id := range values {
		if (!identifier.MatchString(id) && id != ".github") || seen[id] {
			return fmt.Errorf("invalid or duplicate inventory identifier %q", id)
		}
		seen[id] = true
	}
	return nil
}
func exact(wanted, actual []string) error {
	w, a := slices.Clone(wanted), slices.Clone(actual)
	slices.Sort(w)
	slices.Sort(a)
	if !slices.Equal(w, a) {
		return errors.New("declared inventory does not match the independent policy")
	}
	return nil
}

func (p Policy) Validate() error {
	if p.Schema != Schema || p.MinSignatures < 1 || p.MinSignatures > 16 {
		return errors.New("unsupported policy schema or signature quorum")
	}
	for _, ids := range [][]string{p.Repositories, p.Toolchains, p.Images, p.Compilers, p.Contracts} {
		if err := unique(ids, false); err != nil {
			return err
		}
	}
	var ids []string
	for _, f := range p.Files {
		ids = append(ids, f.ID)
		if !slices.Contains(p.Repositories, f.Repository) || !relative(f.Path) || !fileKind(f.Kind) {
			return errors.New("invalid independent file requirement")
		}
	}
	if err := unique(ids, false); err != nil {
		return err
	}
	seen := map[string]bool{}
	if len(p.Gitlinks) > MaxEntries {
		return errors.New("too many policy gitlinks")
	}
	for _, key := range p.Gitlinks {
		repo, ref, ok := strings.Cut(key, ":")
		if !ok || !slices.Contains(p.Repositories, repo) || !relative(ref) || seen[key] {
			return errors.New("invalid or duplicate policy gitlink")
		}
		seen[key] = true
	}
	return nil
}
func (p Policy) Canonical() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	copy := p
	fields := []*[]string{&copy.Repositories, &copy.Gitlinks, &copy.Toolchains, &copy.Images, &copy.Compilers, &copy.Contracts}
	for _, f := range fields {
		*f = append([]string{}, (*f)...)
		slices.Sort(*f)
	}
	copy.Files = slices.Clone(copy.Files)
	slices.SortFunc(copy.Files, func(a, b FileRequirement) int { return strings.Compare(a.ID, b.ID) })
	return canonicalJSON(copy)
}

func fileKind(kind string) bool {
	switch kind {
	case "rollup", "l1-genesis", "l2-genesis", "deployments", "lock", "artifact", "config", "runtime-code":
		return true
	}
	return false
}
func (p Policy) Fingerprint() (string, error) {
	raw, err := p.Canonical()
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func (m Manifest) validate() error {
	if m.Schema != Schema || !hash(m.PolicySHA256, 64) {
		return errors.New("unsupported manifest schema or policy digest")
	}
	e := m.Epoch
	if !hash(e.ID, 64) || !decimal(e.L1ChainID) || !decimal(e.L2ChainID) || !blockHash(e.L1GenesisHash) || !blockHash(e.L2GenesisHash) || !hash(e.RollupSHA256, 64) || !hash(e.DeploymentsSHA256, 64) || (e.EVM != "isthmus" && e.EVM != "karst") {
		return errors.New("incomplete or unsupported chain epoch")
	}
	var ids []string
	repos := map[string]Repository{}
	for _, r := range m.Repositories {
		ids = append(ids, r.Name)
		repos[r.Name] = r
		if (r.Empty && (r.Commit != "" || len(r.Gitlinks) != 0)) || (!r.Empty && !commit(r.Commit)) {
			return errors.New("repository needs an exact commit or an explicit empty declaration")
		}
		seen := map[string]bool{}
		if len(r.Gitlinks) > MaxEntries {
			return errors.New("too many gitlinks")
		}
		for _, g := range r.Gitlinks {
			if !relative(g.Path) || !commit(g.Commit) || seen[g.Path] {
				return errors.New("invalid or duplicate gitlink")
			}
			seen[g.Path] = true
		}
	}
	if err := unique(ids, false); err != nil {
		return err
	}
	for _, list := range [][]Artifact{m.Toolchains, m.Compilers} {
		ids = nil
		for _, a := range list {
			ids = append(ids, a.ID)
			if !platform.MatchString(a.Platform) || !hash(a.SHA256, 64) || !version.MatchString(a.Version) {
				return errors.New("artifact needs a version, platform and SHA-256")
			}
		}
		if err := unique(ids, false); err != nil {
			return err
		}
	}
	ids = nil
	for _, i := range m.Images {
		ids = append(ids, i.ID)
		name, sha, ok := strings.Cut(i.Reference, "@sha256:")
		if !ok || !hash(sha, 64) || !platform.MatchString(i.Platform) || !relative(name) || strings.Contains(name, "@") || !strings.Contains(name, "/") {
			return errors.New("image needs a platform and a digest-only OCI reference")
		}
	}
	if err := unique(ids, false); err != nil {
		return err
	}
	ids = nil
	seenFiles := map[string]bool{}
	kinds := map[string]int{}
	byID := map[string]File{}
	var totalBytes int64
	for _, f := range m.Files {
		ids = append(ids, f.ID)
		byID[f.ID] = f
		r, ok := repos[f.Repository]
		if !ok || r.Empty || !relative(f.Path) || !hash(f.SHA256, 64) || f.Bytes < 0 || f.Bytes > 1<<30 {
			return errors.New("invalid file pin")
		}
		totalBytes += f.Bytes
		if totalBytes > 4<<30 {
			return errors.New("declared file set exceeds its four-GiB budget")
		}
		key := f.Repository + ":" + f.Path
		if seenFiles[key] {
			return errors.New("duplicate file path")
		}
		seenFiles[key] = true
		if !fileKind(f.Kind) {
			return errors.New("unknown pinned file kind")
		}
		kinds[f.Kind]++
		if f.Kind == "rollup" && f.SHA256 != e.RollupSHA256 {
			return errors.New("rollup file and epoch disagree")
		}
		if f.Kind == "deployments" && f.SHA256 != e.DeploymentsSHA256 {
			return errors.New("deployment file and epoch disagree")
		}
	}
	for _, kind := range []string{"rollup", "l1-genesis", "l2-genesis", "deployments"} {
		if kinds[kind] != 1 {
			return fmt.Errorf("exactly one %s file is required", kind)
		}
	}
	if kinds["lock"] < 1 {
		return errors.New("at least one dependency lock pin is required")
	}
	if err := unique(ids, false); err != nil {
		return err
	}
	for _, list := range [][]Artifact{m.Toolchains, m.Compilers} {
		for _, a := range list {
			f, ok := byID[a.FileID]
			if !ok || f.Kind != "artifact" || f.Bytes <= 0 || f.SHA256 != a.SHA256 {
				return errors.New("toolchain/compiler does not bind a pinned artifact file")
			}
		}
	}
	ids = nil
	addresses := map[string]bool{}
	for _, c := range m.Contracts {
		ids = append(ids, c.ID)
		if !strings.HasPrefix(c.Address, "0x") || !hash(c.Address[2:], 40) || !blockHash(c.RuntimeCodeHash) || addresses[c.Address] {
			return errors.New("invalid or duplicate contract address/code hash")
		}
		addresses[c.Address] = true
		f, ok := byID[c.RuntimeFile]
		if !ok || f.Kind != "runtime-code" || f.Bytes <= 0 || f.Bytes > 8<<20 {
			return errors.New("contract does not bind a bounded runtime-code file")
		}
	}
	return unique(ids, false)
}

func (m Manifest) ValidateAgainst(p Policy) error {
	if err := m.validate(); err != nil {
		return err
	}
	sha, err := p.Fingerprint()
	if err != nil {
		return err
	}
	if sha != m.PolicySHA256 {
		return errors.New("manifest does not bind the supplied policy")
	}
	var repos, links, tools, images, compilers, contracts []string
	var files []FileRequirement
	for _, r := range m.Repositories {
		repos = append(repos, r.Name)
		for _, g := range r.Gitlinks {
			links = append(links, r.Name+":"+g.Path)
		}
	}
	for _, a := range m.Toolchains {
		tools = append(tools, a.ID)
	}
	for _, i := range m.Images {
		images = append(images, i.ID)
	}
	for _, a := range m.Compilers {
		compilers = append(compilers, a.ID)
	}
	for _, f := range m.Files {
		files = append(files, FileRequirement{ID: f.ID, Kind: f.Kind, Repository: f.Repository, Path: f.Path})
	}
	for _, c := range m.Contracts {
		contracts = append(contracts, c.ID)
	}
	for _, pair := range [][2][]string{{p.Repositories, repos}, {p.Gitlinks, links}, {p.Toolchains, tools}, {p.Images, images}, {p.Compilers, compilers}, {p.Contracts, contracts}} {
		if err := exact(pair[0], pair[1]); err != nil {
			return err
		}
	}
	wanted := slices.Clone(p.Files)
	slices.SortFunc(files, func(a, b FileRequirement) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(wanted, func(a, b FileRequirement) int { return strings.Compare(a.ID, b.ID) })
	if !slices.Equal(wanted, files) {
		return errors.New("file paths or roles disagree with the independent policy")
	}
	return nil
}

func (m Manifest) Canonical() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	// A deep copy keeps canonicalization from reordering caller-owned slices.
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var c Manifest
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	slices.SortFunc(c.Repositories, func(a, b Repository) int { return strings.Compare(a.Name, b.Name) })
	for i := range c.Repositories {
		if c.Repositories[i].Gitlinks == nil {
			c.Repositories[i].Gitlinks = []Gitlink{}
		}
		slices.SortFunc(c.Repositories[i].Gitlinks, func(a, b Gitlink) int { return strings.Compare(a.Path, b.Path) })
	}
	slices.SortFunc(c.Toolchains, func(a, b Artifact) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Compilers, func(a, b Artifact) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Images, func(a, b Image) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Files, func(a, b File) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Contracts, func(a, b Contract) int { return strings.Compare(a.ID, b.ID) })
	return canonicalJSON(c)
}

func (m Manifest) Fingerprint() (string, error) {
	raw, err := m.Canonical()
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

// EpochFingerprint is the context applications retain for pending operations.
// A reset, rule/config change or deployment/code change yields a new identity.
func (m Manifest) EpochFingerprint() (string, error) {
	if err := m.validate(); err != nil {
		return "", err
	}
	contracts := slices.Clone(m.Contracts)
	slices.SortFunc(contracts, func(a, b Contract) int { return strings.Compare(a.ID, b.ID) })
	raw, err := json.Marshal(struct {
		Epoch     Epoch      `json:"epoch"`
		Contracts []Contract `json:"contracts"`
	}{m.Epoch, contracts})
	if err != nil {
		return "", err
	}
	return digest(append([]byte("ZVM chain epoch v1\n"), raw...)), nil
}
