package artifacts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
)

const GoSourceSBOMProfile = "spdx-2.3-go-local-source-v1"

type GoSourceSBOMPolicy struct {
	Schema       int             `json:"schema"`
	Profile      string          `json:"profile"`
	Go           GoSBOMPolicy    `json:"go"`
	LocalSources []GoLocalSource `json:"localSources"`
}

// Directories are caller-owned runtime locations, excluded from policy and SPDX.
// ControlDirectory contains exactly the independently pinned raw commit objects.
type GoSourceOptions struct {
	Directories      map[string]string
	ControlDirectory string
}

type GoSourceSBOMResult struct {
	GoSBOMResult
	LocalSourceTreesVerified   int   `json:"localSourceTreesVerified"`
	LocalSourceFilesVerified   int   `json:"localSourceFilesVerified"`
	LocalSourceBytesVerified   int64 `json:"localSourceBytesVerified"`
	LocalCommitObjectsVerified int   `json:"localCommitObjectsVerified"`
	CompilerUseOfTreesProven   bool  `json:"compilerUseOfTreesProven"`
	ParentSourceTreeVerified   bool  `json:"parentSourceTreeVerified"`
}

func GoSBOMPolicyProfile(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes {
		return "", errors.New("invalid bounded policy document")
	}
	var head struct {
		Profile string `json:"profile"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return "", errors.New("invalid Go policy profile")
	}
	switch head.Profile {
	case GoSBOMProfile:
		var p GoSBOMPolicy
		if err := decode(raw, &p); err != nil {
			return "", err
		}
	case GoSourceSBOMProfile:
		var p GoSourceSBOMPolicy
		if err := decode(raw, &p); err != nil {
			return "", err
		}
	default:
		return "", errors.New("unsupported independent Go SBOM profile")
	}
	return head.Profile, nil
}

// ParseGoSourceDirectories reads a private mapping, never emitted in a receipt.
func ParseGoSourceDirectories(raw []byte) (map[string]string, error) {
	var inputs struct {
		Schema  int `json:"schema"`
		Sources []struct {
			Path      string `json:"path"`
			Directory string `json:"directory"`
		} `json:"sources"`
	}
	if err := decode(raw, &inputs); err != nil {
		return nil, err
	}
	if inputs.Schema != 1 || len(inputs.Sources) == 0 || len(inputs.Sources) > MaxLocalSources {
		return nil, errors.New("invalid private source-directory mapping")
	}
	result := map[string]string{}
	aliases := map[string]bool{}
	last := ""
	for _, source := range inputs.Sources {
		if !relative(source.Path) || source.Path <= last || aliases[strings.ToLower(source.Path)] || !filepath.IsAbs(source.Directory) || strings.ContainsRune(source.Directory, 0) {
			return nil, errors.New("invalid sorted source-directory binding")
		}
		result[source.Path] = source.Directory
		aliases[strings.ToLower(source.Path)] = true
		last = source.Path
	}
	return result, nil
}

func (p GoSourceSBOMPolicy) validate() (map[string]File, error) {
	if p.Schema != 1 || p.Profile != GoSourceSBOMProfile || p.Go.Profile != GoSBOMProfile || len(p.LocalSources) == 0 || len(p.LocalSources) > MaxLocalSources || len(p.Go.Modules)+len(p.LocalSources) > MaxGoSBOMModules {
		return nil, errors.New("invalid selected local-source Go profile")
	}
	if err := p.Go.validate(); err != nil {
		return nil, err
	}
	modules := map[string]bool{}
	for _, m := range p.Go.Modules {
		modules[m.Path] = true
	}
	controls := map[string]File{}
	aliases := map[string]string{}
	paths := map[string]bool{}
	var total int64
	last := ""
	for _, local := range p.LocalSources {
		if !goModulePath(local.Module) || local.Module <= last || local.Module == p.Go.MainModule || modules[local.Module] || !moduleVersion.MatchString(local.Version) || !relative(local.Path) || paths[strings.ToLower(local.Path)] || !digest(local.GoModSHA256, 64) {
			return nil, errors.New("invalid unique local-source module binding")
		}
		modules[local.Module] = true
		for prior := range paths {
			folded := strings.ToLower(local.Path)
			if strings.HasPrefix(prior, folded+"/") || strings.HasPrefix(folded, prior+"/") {
				return nil, errors.New("local source paths overlap")
			}
		}
		paths[strings.ToLower(local.Path)] = true
		probe := p.Go
		probe.Source = local.Source
		if err := probe.validate(); err != nil || local.Source.Gitlinks == nil || len(local.Source.Gitlinks) != 0 {
			return nil, errors.New("local sources require a complete flat independently pinned repository tree")
		}
		bound := false
		for _, link := range p.Go.Source.Gitlinks {
			if link.Path == local.Path && link.Repository == local.Source.Repository && link.Commit == local.Source.Commit {
				bound = true
			}
		}
		if !bound {
			return nil, errors.New("local source is absent from the parent policy gitlinks")
		}
		_, size, err := sourceFilePins(local)
		if err != nil {
			return nil, err
		}
		total += size
		f := local.CommitObject
		if !relative(f.Path) || f.Bytes <= 0 || f.Bytes > MaxDocumentBytes || !digest(f.SHA256, 64) {
			return nil, errors.New("invalid selected commit-object control")
		}
		for name := f.Path; name != "."; name = filepath.ToSlash(filepath.Dir(name)) {
			folded := strings.ToLower(name)
			if old, ok := aliases[folded]; ok && old != name {
				return nil, errors.New("commit control case alias")
			}
			aliases[folded] = name
		}
		if old, ok := controls[f.Path]; ok && old != f {
			return nil, errors.New("commit control pins collide")
		}
		controls[f.Path] = f
		last = local.Module
	}
	if total > MaxLocalSourceBytes {
		return nil, errors.New("local source set exceeds its byte limit")
	}
	for name := range controls {
		for prefix := filepath.ToSlash(filepath.Dir(name)); prefix != "."; prefix = filepath.ToSlash(filepath.Dir(prefix)) {
			if _, ok := controls[prefix]; ok {
				return nil, errors.New("commit control file/directory alias")
			}
		}
	}
	return controls, nil
}

type sourceObservation struct {
	control *observedSource
	trees   []*observedSource
	files   int
	bytes   int64
}

func (s *sourceObservation) close() {
	if s.control != nil {
		s.control.dir.root.Close()
	}
	for _, tree := range s.trees {
		tree.dir.root.Close()
	}
}
func (s *sourceObservation) unchanged() error {
	last, err := inventory(s.control.dir, s.control.files)
	if err != nil || len(last) != len(s.control.before) {
		return errors.New("commit control inventory changed")
	}
	for name, before := range s.control.before {
		if !stable(before, last[name]) {
			return errors.New("commit control identity changed")
		}
	}
	if err := s.control.dir.checkAncestors(); err != nil {
		return err
	}
	for _, tree := range s.trees {
		if err := tree.unchanged(); err != nil {
			return err
		}
	}
	return nil
}
func observeGoSources(p GoSourceSBOMPolicy, controls map[string]File, options GoSourceOptions) (*sourceObservation, error) {
	if len(options.Directories) != len(p.LocalSources) || options.ControlDirectory == "" {
		return nil, errors.New("exact source mappings and commit controls are required")
	}
	for _, local := range p.LocalSources {
		if options.Directories[local.Path] == "" {
			return nil, errors.New("a required local source directory was not selected")
		}
	}
	result := &sourceObservation{}
	good := false
	defer func() {
		if !good {
			result.close()
		}
	}()
	d, err := openDirectory(options.ControlDirectory)
	if err != nil {
		return nil, err
	}
	result.control = &observedSource{dir: d, files: controls}
	result.control.before, err = inventory(d, controls)
	if err != nil {
		return nil, err
	}
	data := map[string][]byte{}
	for name, pin := range controls {
		data[name], err = selectedDocument(d, pin, result.control.before[name])
		if err != nil {
			return nil, err
		}
	}
	for _, local := range p.LocalSources {
		tree, size, err := inspectLocalSource(local, options.Directories[local.Path], data[local.CommitObject.Path])
		if err != nil {
			return nil, err
		}
		result.trees = append(result.trees, tree)
		for _, previous := range result.trees[:len(result.trees)-1] {
			if os.SameFile(previous.before["."], tree.before["."]) {
				return nil, errors.New("distinct local sources alias the same physical directory")
			}
		}
		result.files += len(local.Files)
		result.bytes += size
	}
	if err := result.unchanged(); err != nil {
		return nil, err
	}
	good = true
	return result, nil
}

func matchGoSourceInventory(info *debug.BuildInfo, p GoSourceSBOMPolicy) error {
	if info == nil || len(info.Deps) != len(p.Go.Modules)+len(p.LocalSources) {
		return errors.New("complete expected Go source/module inventory does not match")
	}
	locals := map[string]GoLocalSource{}
	for _, source := range p.LocalSources {
		locals[source.Module] = source
	}
	seen := map[string]bool{}
	remote := make([]*debug.Module, 0, len(p.Go.Modules))
	for _, module := range info.Deps {
		if module == nil || seen[module.Path] {
			return errors.New("duplicate or incomplete Go dependency metadata")
		}
		seen[module.Path] = true
		if local, ok := locals[module.Path]; ok {
			if module.Version != local.Version || module.Sum != "" || module.Replace == nil || module.Replace.Path != "./"+local.Path || module.Replace.Version != "(devel)" || module.Replace.Sum != "" || module.Replace.Replace != nil {
				return errors.New("local Go replacement does not match its independently selected source binding")
			}
		} else {
			remote = append(remote, module)
		}
	}
	copy := *info
	copy.Deps = remote
	return matchGoInventory(&copy, p.Go)
}

func goSourceSPDX(p GoSourceSBOMPolicy, policySHA string) spdxDocument {
	doc := goSPDX(p.Go, policySHA)
	doc.Comment = "Profile " + GoSourceSBOMProfile + "; independent policy SHA256 " + policySHA + "; qualification reference SHA256 " + p.Go.QualifiedInputsSHA256 + ". Scope: embedded Go module records and selected flat local source trees. Commit objects, file SHA256 pins and Git blob/tree identities are content bindings, not source authority or proof of compiler use. Parent source tree, standard-library/OS/native/asset and license coverage remain unqualified."
	for _, local := range p.LocalSources {
		id := "SPDXRef-LocalSource-" + sum([]byte(local.Module+"\x00"+local.Version+"\x00"+local.Source.Repository+"\x00"+local.Source.Commit+"\x00"+local.Source.Tree))
		pkg := spdxPackage{ID: id, Name: local.Module, Version: local.Source.Commit, Download: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", Copyright: "NOASSERTION", Purpose: "SOURCE",
			Comment:    "Requested Go module " + local.Module + "@" + local.Version + "; local source repository " + local.Source.Repository + ". Complete selected regular files and executable modes reproduce the Git tree; the selected commit object binds that tree. No Go h1 sum is invented for local source. Compiler use, source authority and license coverage are not established.",
			References: []spdxReference{{"OTHER", "https://git-scm.com/docs/gitformat-pack", "git-tree:" + local.Source.Tree}, {"OTHER", "https://git-scm.com/docs/gitformat-pack", "git-commit:" + local.Source.Commit}}}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, spdxRelationship{id, "BUILD_DEPENDENCY_OF", "SPDXRef-Artifact"})
	}
	slices.SortFunc(doc.Packages, func(a, b spdxPackage) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(doc.Relationships, func(a, b spdxRelationship) int {
		return strings.Compare(a.ID+"\x00"+a.Type+"\x00"+a.Related, b.ID+"\x00"+b.Type+"\x00"+b.Related)
	})
	return doc
}

func GenerateGoSourceSBOM(policyBytes, goModBytes, goSumBytes []byte, subject string, options GoSourceOptions) ([]byte, GoSourceSBOMResult, error) {
	var p GoSourceSBOMPolicy
	if err := decode(policyBytes, &p); err != nil {
		return nil, GoSourceSBOMResult{}, err
	}
	controls, err := p.validate()
	if err != nil {
		return nil, GoSourceSBOMResult{}, err
	}
	if len(goModBytes) == 0 || len(goModBytes) > MaxDocumentBytes || len(goSumBytes) > MaxDocumentBytes || sum(goModBytes) != p.Go.GoModSHA256 || sum(goSumBytes) != p.Go.GoSumSHA256 {
		return nil, GoSourceSBOMResult{}, errors.New("qualified Go module/checksum inputs do not match source policy")
	}
	if len(goSumBytes) != 0 || len(p.Go.Modules) != 0 {
		locks, err := lockModules(goSumBytes)
		if err != nil {
			return nil, GoSourceSBOMResult{}, err
		}
		for _, module := range p.Go.Modules {
			if locks[module.EffectivePath+" "+module.EffectiveVersion] != module.Sum {
				return nil, GoSourceSBOMResult{}, errors.New("remote Go checksum is absent or changed")
			}
		}
	}
	sources, err := observeGoSources(p, controls, options)
	if err != nil {
		return nil, GoSourceSBOMResult{}, err
	}
	defer sources.close()
	info, err := readGoSubject(subject, p.Go.Subject)
	if err != nil {
		return nil, GoSourceSBOMResult{}, err
	}
	if err := matchGoSourceInventory(info, p); err != nil {
		return nil, GoSourceSBOMResult{}, err
	}
	if err := sources.unchanged(); err != nil {
		return nil, GoSourceSBOMResult{}, err
	}
	canonical, _ := json.Marshal(p)
	policySHA := sum(canonical)
	raw, err := json.MarshalIndent(goSourceSPDX(p, policySHA), "", "  ")
	if err != nil || len(raw)+1 > MaxDocumentBytes {
		return nil, GoSourceSBOMResult{}, errors.New("generated source SPDX profile exceeds its limit")
	}
	raw = append(raw, '\n')
	return raw, GoSourceSBOMResult{GoSBOMResult: GoSBOMResult{Profile: GoSourceSBOMProfile, PolicySHA256: policySHA, SBOMSHA256: sum(raw), SubjectSHA256: p.Go.Subject.SHA256, ModulesVerified: len(p.Go.Modules) + len(p.LocalSources), SPDXProfileVerified: true, SubjectBytesVerified: true, GoBuildInfoMatched: true, LockedModulesMatched: true}, LocalSourceTreesVerified: len(p.LocalSources), LocalSourceFilesVerified: sources.files, LocalSourceBytesVerified: sources.bytes, LocalCommitObjectsVerified: len(controls)}, nil
}
func CheckGoSourceSBOM(document, policyBytes, goModBytes, goSumBytes []byte, subject string, options GoSourceOptions) (GoSourceSBOMResult, error) {
	if _, err := objectDocumentBudget(document, 32768); err != nil {
		return GoSourceSBOMResult{}, err
	}
	expected, result, err := GenerateGoSourceSBOM(policyBytes, goModBytes, goSumBytes, subject, options)
	if err != nil {
		return GoSourceSBOMResult{}, err
	}
	var a, b any
	if json.Unmarshal(document, &a) != nil || json.Unmarshal(expected, &b) != nil || !reflect.DeepEqual(a, b) {
		return GoSourceSBOMResult{}, errors.New("source SPDX profile, subjects, package inventory or relationships differ from independent inputs")
	}
	result.SBOMSHA256 = sum(document)
	return result, nil
}
