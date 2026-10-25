package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const MaxContentInputBytes = 32 << 20

type SBOMRequirement struct {
	ID      string `json:"id"`
	Profile string `json:"profile"`
	Policy  File   `json:"policy"`
	GoMod   File   `json:"goMod"`
	GoSum   File   `json:"goSum"`
}

// ContentsPolicy independently selects every SBOM profile and control-file pin.
// Its selection-policy digest prevents mixing source/build/release expectations.
type ContentsPolicy struct {
	Schema                int               `json:"schema"`
	SelectionPolicySHA256 string            `json:"selectionPolicySha256"`
	Artifacts             []SBOMRequirement `json:"artifacts"`
}

type SBOMVerification struct {
	ContentsPolicySHA256                string `json:"contentsPolicySha256"`
	ControlFilesVerified                int    `json:"controlFilesVerified"`
	SBOMProfilesVerified                int    `json:"sbomProfilesVerified"`
	GoModuleRecordsVerified             int    `json:"goModuleRecordsVerified"`
	SBOMProfileScope                    string `json:"sbomProfileScope"`
	CompleteRuntimeInventoryEstablished bool   `json:"completeRuntimeInventoryEstablished"`
	LicenseCoverageEstablished          bool   `json:"licenseCoverageEstablished"`
	SourceCommitAuthenticated           bool   `json:"sourceCommitAuthenticated"`
	ToolchainIdentityAuthenticated      bool   `json:"toolchainIdentityAuthenticated"`
}

type ContentsResult struct {
	Result
	SBOMVerification
	BuildRecipeReproduced bool `json:"buildRecipeReproduced"`
}
type BundleResult struct {
	ProvenanceResult
	SBOMVerification
}
type selectionVerifier func(*directory, map[string]File, map[string]os.FileInfo) error

type contentVerifier struct {
	selection   Policy
	policy      ContentsPolicy
	dir         *directory
	files       map[string]File
	before      map[string]os.FileInfo
	data        map[string][]byte
	commits     map[string][]File
	directories map[string]map[string]string
	sources     []*sourceObservation
	local       LocalSourceVerification
	details     SBOMVerification
}

func (c ContentsPolicy) validate(p Policy) (map[string]File, error) {
	if c.Schema != 1 {
		return nil, errors.New("unsupported legacy contents policy schema")
	}
	return validateContents(p, c.SelectionPolicySHA256, c.Artifacts, nil)
}

func validateContents(p Policy, selectionSHA string, requirements []SBOMRequirement, commits map[string][]File) (map[string]File, error) {
	canonical, err := CanonicalPolicy(p)
	if err != nil || selectionSHA != sum(canonical) || len(requirements) != len(p.Artifacts) {
		return nil, errors.New("contents policy does not match the independent selection policy")
	}
	files := map[string]File{}
	roles := map[string]string{}
	aliases := map[string]string{}
	var total int64
	for i, required := range requirements {
		local := commits != nil && required.Profile == GoSourceSBOMProfile
		if required.ID != p.Artifacts[i].ID || (!local && required.Profile != GoSBOMProfile) || p.Artifacts[i].Kind != "binary" {
			return nil, errors.New("every selected artifact must have a supported exact SBOM requirement")
		}
		entries := []struct {
			pin  File
			role string
		}{{required.Policy, "policy"}, {required.GoMod, "goMod"}, {required.GoSum, "goSum"}}
		if commits != nil {
			pins := commits[required.ID]
			if pins == nil || (local && (len(pins) == 0 || len(pins) > MaxLocalSources)) || (!local && len(pins) != 0) {
				return nil, errors.New("exact commit controls are required only for local-source profiles")
			}
			last := ""
			for _, pin := range pins {
				if pin.Path <= last {
					return nil, errors.New("commit controls must be sorted and unique")
				}
				entries = append(entries, struct {
					pin  File
					role string
				}{pin, "commitObject"})
				last = pin.Path
			}
		}
		for _, entry := range entries {
			f := entry.pin
			folded := strings.ToLower(f.Path)
			emptyLock := local && entry.role == "goSum" && f.Bytes == 0 && f.SHA256 == sum(nil)
			if !relative(f.Path) || (f.Bytes <= 0 && !emptyLock) || f.Bytes > MaxDocumentBytes || !digest(f.SHA256, 64) {
				return nil, errors.New("invalid bounded SBOM control-file pin")
			}
			if other, exists := aliases[folded]; exists && other != f.Path {
				return nil, errors.New("SBOM control-file case alias")
			}
			for name := f.Path; name != "."; name = filepath.ToSlash(filepath.Dir(name)) {
				key := strings.ToLower(name)
				if other, exists := aliases[key]; exists && other != name {
					return nil, errors.New("SBOM control-directory case alias")
				}
				aliases[key] = name
			}
			if old, exists := files[f.Path]; exists {
				if old != f || roles[f.Path] != entry.role {
					return nil, errors.New("SBOM control-file roles or pins collide")
				}
			} else {
				files[f.Path] = f
				roles[f.Path] = entry.role
				aliases[folded] = f.Path
				total += f.Bytes
			}
		}
	}
	if len(files) > MaxFiles || total > MaxContentInputBytes {
		return nil, errors.New("SBOM control input set exceeds its limit")
	}
	for name := range files {
		for prefix := filepath.ToSlash(filepath.Dir(name)); prefix != "."; prefix = filepath.ToSlash(filepath.Dir(prefix)) {
			if _, exists := files[prefix]; exists {
				return nil, errors.New("SBOM control file/directory alias")
			}
		}
	}
	return files, nil
}

func prepareContents(policyBytes, contentsBytes []byte, root string) (*contentVerifier, error) {
	return prepareContentsWithOptions(policyBytes, contentsBytes, root, ContentsOptions{})
}

func prepareContentsWithOptions(policyBytes, contentsBytes []byte, root string, options ContentsOptions) (*contentVerifier, error) {
	var p Policy
	if err := decode(policyBytes, &p); err != nil {
		return nil, err
	}
	if _, err := p.validate(); err != nil {
		return nil, err
	}
	c, commits, files, err := parseContentsPolicy(contentsBytes, p)
	if err != nil {
		return nil, err
	}
	directories, scope, err := contentsDirectories(c.Artifacts, options)
	if err != nil {
		return nil, err
	}
	if root == "" {
		return nil, errors.New("explicit SBOM control directory is required")
	}
	d, err := openDirectory(root)
	if err != nil {
		return nil, err
	}
	before, err := inventory(d, files)
	if err != nil {
		d.root.Close()
		return nil, err
	}
	v := &contentVerifier{selection: p, policy: c, dir: d, files: files, before: before, commits: commits, directories: directories, data: map[string][]byte{}, details: SBOMVerification{
		ContentsPolicySHA256: sum(contentsBytes), ControlFilesVerified: len(files), SBOMProfileScope: scope}}
	for name, pin := range files {
		raw, err := selectedControlDocument(d, pin, before[name], commits != nil)
		if err != nil {
			d.root.Close()
			return nil, err
		}
		v.data[name] = raw
	}
	return v, nil
}

func (v *contentVerifier) close() {
	for _, source := range v.sources {
		source.close()
	}
	v.dir.root.Close()
}
func (v *contentVerifier) unchanged() error {
	for _, source := range v.sources {
		if err := source.unchanged(); err != nil {
			return err
		}
	}
	last, err := inventory(v.dir, v.files)
	if err != nil {
		return err
	}
	if len(last) != len(v.before) {
		return errors.New("SBOM control inventory changed")
	}
	for name, info := range v.before {
		if !stable(info, last[name]) {
			return errors.New("SBOM control identity changed during verification")
		}
	}
	return v.dir.checkAncestors()
}

func (v *contentVerifier) verify(d *directory, files map[string]File, before map[string]os.FileInfo) error {
	for i, required := range v.policy.Artifacts {
		artifact := v.selection.Artifacts[i]
		var goPolicy GoSBOMPolicy
		if required.Profile == GoSourceSBOMProfile {
			var sourcePolicy GoSourceSBOMPolicy
			if err := decode(v.data[required.Policy.Path], &sourcePolicy); err != nil {
				return err
			}
			controls, err := sourcePolicy.validate()
			if err != nil {
				return err
			}
			if len(controls) != len(v.commits[required.ID]) {
				return errors.New("local commit controls do not match independent contents policy")
			}
			for _, pin := range v.commits[required.ID] {
				if controls[pin.Path] != pin {
					return errors.New("local commit control differs from independent contents policy")
				}
			}
			goPolicy = sourcePolicy.Go
		} else {
			if err := decode(v.data[required.Policy.Path], &goPolicy); err != nil {
				return err
			}
		}
		settings := map[string]string{}
		for _, s := range goPolicy.BuildSettings {
			settings[s.Key] = s.Value
		}
		if goPolicy.Profile != GoSBOMProfile || goPolicy.Subject != files[artifact.SubjectPath] ||
			!reflect.DeepEqual(goPolicy.Source, v.selection.Release.Source) || goPolicy.QualifiedInputsSHA256 != v.selection.Release.QualificationSHA256 ||
			goPolicy.GoModSHA256 != required.GoMod.SHA256 || goPolicy.GoSumSHA256 != required.GoSum.SHA256 || artifact.Platform != settings["GOOS"]+"/"+settings["GOARCH"] {
			return errors.New("SBOM source, qualification, subject, platform or lock inputs do not match selected release")
		}
		doc, err := selectedDocument(d, files[artifact.SBOMPath], before[artifact.SBOMPath])
		if err != nil {
			return err
		}
		subject := filepath.Join(d.root.Name(), filepath.FromSlash(artifact.SubjectPath))
		var modules int
		if required.Profile == GoSourceSBOMProfile {
			result, source, err := checkGoSourceSBOMObserved(doc, v.data[required.Policy.Path], v.data[required.GoMod.Path], v.data[required.GoSum.Path], subject, GoSourceOptions{Directories: v.directories[required.ID], ControlDirectory: v.dir.root.Name()}, v.files)
			if err != nil {
				return err
			}
			v.sources = append(v.sources, source)
			modules = result.ModulesVerified
			v.local.LocalSourceTreesVerified += result.LocalSourceTreesVerified
			v.local.LocalSourceFilesVerified += result.LocalSourceFilesVerified
			v.local.LocalSourceBytesVerified += result.LocalSourceBytesVerified
			v.local.LocalCommitObjectsVerified += result.LocalCommitObjectsVerified
		} else {
			result, err := CheckGoSBOM(doc, v.data[required.Policy.Path], v.data[required.GoMod.Path], v.data[required.GoSum.Path], subject)
			if err != nil {
				return err
			}
			modules = result.ModulesVerified
		}
		v.details.SBOMProfilesVerified++
		v.details.GoModuleRecordsVerified += modules
	}
	return v.unchanged()
}

// CheckContents verifies the complete selected file set plus every independently
// selected Go SBOM profile. SBOMContentsVerified denotes that explicit profile
// scope; complete runtime/license coverage and release acceptance remain false.
func CheckContents(manifestBytes, policyBytes, contentsBytes []byte, root, controlRoot string) (ContentsResult, error) {
	v, err := prepareContents(policyBytes, contentsBytes, controlRoot)
	if err != nil {
		return ContentsResult{}, err
	}
	defer v.close()
	result, err := checkSelected(manifestBytes, policyBytes, root, nil, v.verify)
	if err != nil {
		return ContentsResult{}, err
	}
	result.SBOMContentsVerified = true
	return ContentsResult{Result: result, SBOMVerification: v.details}, nil
}

// CheckBundle composes the actual signature verifier and every selected SBOM
// profile inside one observed artifact inventory, with no partial success.
func CheckBundle(ctx context.Context, manifestBytes, policyBytes, provenanceBytes, contentsBytes []byte, root, controlRoot string, options ProvenanceOptions) (BundleResult, error) {
	return checkBundle(ctx, manifestBytes, policyBytes, provenanceBytes, contentsBytes, root, controlRoot, options, runVerifier)
}

func checkBundle(ctx context.Context, manifestBytes, policyBytes, provenanceBytes, contentsBytes []byte, root, controlRoot string, options ProvenanceOptions, run verifierRunner) (BundleResult, error) {
	v, err := prepareContents(policyBytes, contentsBytes, controlRoot)
	if err != nil {
		return BundleResult{}, err
	}
	defer v.close()
	result, err := checkProvenanceObserved(ctx, manifestBytes, policyBytes, provenanceBytes, root, options, run, v.verify, v.unchanged)
	if err != nil {
		return BundleResult{}, err
	}
	result.SBOMContentsVerified = true
	return BundleResult{ProvenanceResult: result, SBOMVerification: v.details}, nil
}

// CanonicalContentsPolicy serializes the exact schema after validating its
// source/build binding and complete profile/control-file inventory.
func CanonicalContentsPolicy(c ContentsPolicy, p Policy) ([]byte, error) {
	if _, err := c.validate(p); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}
