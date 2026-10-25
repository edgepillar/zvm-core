package artifacts

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"time"
)

const GoSBOMProfile = "spdx-2.3-go-buildinfo-v1"
const MaxGoSBOMModules = 254

type GoSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// GoSBOMModule retains the requested coordinate and its effective versioned
// replacement. Sum is the Go h1 file-tree checksum, never an artifact SHA-256.
type GoSBOMModule struct {
	Path             string `json:"path"`
	Version          string `json:"version"`
	Replacement      string `json:"replacement"`
	EffectivePath    string `json:"effectivePath"`
	EffectiveVersion string `json:"effectiveVersion"`
	Sum              string `json:"sum"`
}

// GoSBOMPolicy must come from independent qualified source/package-graph and
// artifact evidence. Inferring its module list from the subject is circular.
type GoSBOMPolicy struct {
	Schema                int            `json:"schema"`
	Profile               string         `json:"profile"`
	Subject               File           `json:"subject"`
	Source                Source         `json:"source"`
	QualifiedInputsSHA256 string         `json:"qualifiedInputsSha256"`
	GoModSHA256           string         `json:"goModSha256"`
	GoSumSHA256           string         `json:"goSumSha256"`
	MainPackage           string         `json:"mainPackage"`
	MainModule            string         `json:"mainModule"`
	MainVersion           string         `json:"mainVersion"`
	GoVersion             string         `json:"goVersion"`
	BuildSettings         []GoSetting    `json:"buildSettings"`
	Modules               []GoSBOMModule `json:"modules"`
	DocumentName          string         `json:"documentName"`
	DocumentNamespace     string         `json:"documentNamespace"`
	Created               string         `json:"created"`
}

type GoSBOMResult struct {
	Profile                             string `json:"profile"`
	PolicySHA256                        string `json:"policySha256"`
	SBOMSHA256                          string `json:"sbomSha256"`
	SubjectSHA256                       string `json:"subjectSha256"`
	ModulesVerified                     int    `json:"modulesVerified"`
	SPDXProfileVerified                 bool   `json:"spdxProfileVerified"`
	SubjectBytesVerified                bool   `json:"subjectBytesVerified"`
	GoBuildInfoMatched                  bool   `json:"goBuildInfoMatched"`
	LockedModulesMatched                bool   `json:"lockedModulesMatched"`
	SourceCommitAuthenticated           bool   `json:"sourceCommitAuthenticated"`
	ToolchainIdentityAuthenticated      bool   `json:"toolchainIdentityAuthenticated"`
	CompleteRuntimeInventoryEstablished bool   `json:"completeRuntimeInventoryEstablished"`
	LicenseCoverageEstablished          bool   `json:"licenseCoverageEstablished"`
	ReleaseAccepted                     bool   `json:"releaseAccepted"`
}

var goVersion = regexp.MustCompile(`^go1\.[0-9]+\.[0-9]+$`)
var moduleVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*$`)

func goModulePath(value string) bool {
	if value == "" || len(value) > 512 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || !strings.Contains(value, "/") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("/._-~!", c)) {
			return false
		}
	}
	return true
}

func goH1(value string) bool {
	if !strings.HasPrefix(value, "h1:") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "h1:"))
	return err == nil && len(raw) == sha256.Size && base64.StdEncoding.EncodeToString(raw) == value[3:]
}

func (p GoSBOMPolicy) validate() error {
	if p.Schema != 1 || p.Profile != GoSBOMProfile || !relative(p.Subject.Path) || p.Subject.Bytes <= 0 || p.Subject.Bytes > MaxFileBytes || !digest(p.Subject.SHA256, 64) ||
		!validRepository(p.Source.Repository) || !commit(p.Source.Commit) || !commit(p.Source.Tree) || len(p.Source.Commit) != len(p.Source.Tree) || p.Source.Gitlinks == nil || len(p.Source.Gitlinks) > 64 ||
		!digest(p.QualifiedInputsSHA256, 64) || !digest(p.GoModSHA256, 64) || !digest(p.GoSumSHA256, 64) || !goModulePath(p.MainModule) || !goModulePath(p.MainPackage) ||
		(p.MainPackage != p.MainModule && !strings.HasPrefix(p.MainPackage, p.MainModule+"/")) || (p.MainVersion != "(devel)" && !moduleVersion.MatchString(p.MainVersion)) || !goVersion.MatchString(p.GoVersion) ||
		!identifier.MatchString(p.DocumentName) || p.Modules == nil || len(p.Modules) > MaxGoSBOMModules || p.BuildSettings == nil || len(p.BuildSettings) == 0 || len(p.BuildSettings) > 32 {
		return errors.New("invalid independent Go SBOM policy")
	}
	last := ""
	for _, link := range p.Source.Gitlinks {
		if !relative(link.Path) || link.Path <= last || !validRepository(link.Repository) || !commit(link.Commit) {
			return errors.New("invalid Go SBOM source inventory")
		}
		last = link.Path
	}
	u, err := url.Parse(p.DocumentNamespace)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.String() != p.DocumentNamespace || len(p.DocumentNamespace) > 512 {
		return errors.New("independent SPDX namespace must be an absolute HTTPS identifier")
	}
	created, err := time.Parse(time.RFC3339, p.Created)
	if err != nil || created.Format(time.RFC3339) != p.Created || !strings.HasSuffix(p.Created, "Z") {
		return errors.New("explicit canonical UTC creation time is required")
	}
	settings := map[string]string{}
	last = ""
	for _, setting := range p.BuildSettings {
		if setting.Key == "" || setting.Key <= last || len(setting.Key) > 64 || len(setting.Value) > 512 {
			return errors.New("build settings must be sorted and unique")
		}
		for _, c := range setting.Key + setting.Value {
			if c < 32 || c > 126 {
				return errors.New("invalid build setting")
			}
		}
		settings[setting.Key] = setting.Value
		last = setting.Key
	}
	if settings["CGO_ENABLED"] != "0" || settings["-trimpath"] != "true" || settings["-buildmode"] != "exe" || settings["-compiler"] != "gc" || !platform.MatchString(settings["GOOS"]+"/"+settings["GOARCH"]) {
		return errors.New("this profile requires a pure Go trimpath executable with an explicit target")
	}
	last = ""
	for _, module := range p.Modules {
		if !goModulePath(module.Path) || module.Path <= last || module.Path == p.MainModule || !moduleVersion.MatchString(module.Version) || !goModulePath(module.EffectivePath) || !moduleVersion.MatchString(module.EffectiveVersion) || !goH1(module.Sum) {
			return errors.New("invalid sorted expected Go module inventory")
		}
		if module.Replacement != "none" && module.Replacement != "versioned" {
			return errors.New("local or unqualified Go replacements require a separate source profile")
		}
		if module.Replacement == "none" && (module.Path != module.EffectivePath || module.Version != module.EffectiveVersion) {
			return errors.New("unexpected effective Go module coordinate")
		}
		last = module.Path
	}
	return nil
}

func lockModules(raw []byte) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes {
		return nil, errors.New("Go checksum input exceeds its limit")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || !goModulePath(fields[0]) || !moduleVersion.MatchString(strings.TrimSuffix(fields[1], "/go.mod")) || !goH1(fields[2]) {
			return nil, errors.New("malformed Go checksum record")
		}
		key := fields[0] + " " + fields[1]
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate Go checksum record")
		}
		values[key] = fields[2]
	}
	return values, nil
}

type metadataReader struct {
	reader    io.ReaderAt
	size      int64
	remaining int64
}

func (r *metadataReader) ReadAt(raw []byte, offset int64) (int, error) {
	if offset < 0 || offset > r.size || int64(len(raw)) > r.size-offset || len(raw) > 1<<20 || int64(len(raw)) > r.remaining {
		return 0, errors.New("Go metadata read exceeds its budget")
	}
	r.remaining -= int64(len(raw))
	return r.reader.ReadAt(raw, offset)
}

func readGoSubject(name string, pin File) (*debug.BuildInfo, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, errors.New("invalid Go subject path")
	}
	d, err := openDirectory(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	defer d.root.Close()
	base := filepath.Base(abs)
	before, err := d.root.Lstat(base)
	if err != nil || !before.Mode().IsRegular() || before.Size() != pin.Bytes || !singleLink(before) {
		return nil, errors.New("Go subject is missing, nonregular or has the wrong size")
	}
	f, err := openEntry(d.root, base, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !stable(before, opened) {
		return nil, errors.New("Go subject changed while opening")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, pin.Bytes+1))
	if err != nil || n != pin.Bytes || hex.EncodeToString(h.Sum(nil)) != pin.SHA256 {
		return nil, errors.New("Go subject SHA-256 does not match independent policy")
	}
	info, readErr := buildinfo.Read(&metadataReader{reader: f, size: pin.Bytes, remaining: 16 << 20})
	after, statErr := f.Stat()
	named, pathErr := d.root.Lstat(base)
	if readErr != nil || statErr != nil || pathErr != nil || !stable(before, after) || !stable(before, named) {
		return nil, errors.New("Go build metadata is unavailable, unbounded or changed")
	}
	if err := d.checkAncestors(); err != nil {
		return nil, err
	}
	return info, nil
}

func matchGoInventory(info *debug.BuildInfo, p GoSBOMPolicy) error {
	if info == nil || info.GoVersion != p.GoVersion || info.Path != p.MainPackage || info.Main.Path != p.MainModule || info.Main.Version != p.MainVersion || info.Main.Replace != nil || len(info.Deps) != len(p.Modules) || len(info.Deps) > MaxGoSBOMModules {
		return errors.New("Go main/toolchain/module inventory does not match independent policy")
	}
	settings := make([]GoSetting, 0, len(info.Settings))
	for _, setting := range info.Settings {
		settings = append(settings, GoSetting{setting.Key, setting.Value})
	}
	slices.SortFunc(settings, func(a, b GoSetting) int { return strings.Compare(a.Key, b.Key) })
	if !reflect.DeepEqual(settings, p.BuildSettings) {
		return errors.New("Go build settings do not match independent policy")
	}
	modules := make([]GoSBOMModule, 0, len(info.Deps))
	for _, module := range info.Deps {
		if module == nil {
			return errors.New("incomplete Go module metadata")
		}
		effective := module
		kind := "none"
		if module.Replace != nil {
			effective = module.Replace
			kind = "versioned"
			if effective.Replace != nil || effective.Version == "" || !goModulePath(effective.Path) {
				return errors.New("local or nested Go replacement metadata is outside this profile")
			}
		}
		modules = append(modules, GoSBOMModule{Path: module.Path, Version: module.Version, Replacement: kind, EffectivePath: effective.Path, EffectiveVersion: effective.Version, Sum: effective.Sum})
	}
	slices.SortFunc(modules, func(a, b GoSBOMModule) int { return strings.Compare(a.Path, b.Path) })
	if !reflect.DeepEqual(modules, p.Modules) {
		return errors.New("effective Go dependency records do not match independent source inventory")
	}
	return nil
}

// GenerateGoSBOM reads the selected executable; it never runs it, extracts it,
// resolves modules or infers the expected inventory from its own observations.
func GenerateGoSBOM(policyBytes, goModBytes, goSumBytes []byte, subject string) ([]byte, GoSBOMResult, error) {
	var p GoSBOMPolicy
	if err := decode(policyBytes, &p); err != nil {
		return nil, GoSBOMResult{}, err
	}
	if err := p.validate(); err != nil {
		return nil, GoSBOMResult{}, err
	}
	if len(goModBytes) == 0 || len(goModBytes) > MaxDocumentBytes || sum(goModBytes) != p.GoModSHA256 || sum(goSumBytes) != p.GoSumSHA256 {
		return nil, GoSBOMResult{}, errors.New("qualified Go module/checksum inputs do not match policy")
	}
	locks, err := lockModules(goSumBytes)
	if err != nil {
		return nil, GoSBOMResult{}, err
	}
	for _, module := range p.Modules {
		if locks[module.EffectivePath+" "+module.EffectiveVersion] != module.Sum {
			return nil, GoSBOMResult{}, errors.New("effective Go module checksum is absent or changed in the selected lock")
		}
	}
	info, err := readGoSubject(subject, p.Subject)
	if err != nil {
		return nil, GoSBOMResult{}, err
	}
	if err := matchGoInventory(info, p); err != nil {
		return nil, GoSBOMResult{}, err
	}
	canonical, _ := json.Marshal(p)
	policySHA := sum(canonical)
	doc := goSPDX(p, policySHA)
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil || len(raw)+1 > MaxDocumentBytes {
		return nil, GoSBOMResult{}, errors.New("generated SPDX profile exceeds its byte limit")
	}
	raw = append(raw, '\n')
	return raw, GoSBOMResult{Profile: GoSBOMProfile, PolicySHA256: policySHA, SBOMSHA256: sum(raw), SubjectSHA256: p.Subject.SHA256, ModulesVerified: len(p.Modules),
		SPDXProfileVerified: true, SubjectBytesVerified: true, GoBuildInfoMatched: true, LockedModulesMatched: true}, nil
}

// CheckGoSBOM validates this exact bounded profile, including subject, complete
// expected module records, IDs, relationships and unknown-coverage declarations.
// It is not a general SPDX validator or a complete runtime/license inventory.
func CheckGoSBOM(document, policyBytes, goModBytes, goSumBytes []byte, subject string) (GoSBOMResult, error) {
	if _, err := objectDocument(document); err != nil {
		return GoSBOMResult{}, err
	}
	expected, result, err := GenerateGoSBOM(policyBytes, goModBytes, goSumBytes, subject)
	if err != nil {
		return GoSBOMResult{}, err
	}
	var actualValue, expectedValue any
	if json.Unmarshal(document, &actualValue) != nil || json.Unmarshal(expected, &expectedValue) != nil || !reflect.DeepEqual(actualValue, expectedValue) {
		return GoSBOMResult{}, errors.New("SPDX profile, subject, package inventory or relationships do not match independent inputs")
	}
	result.SBOMSHA256 = sum(document)
	return result, nil
}
