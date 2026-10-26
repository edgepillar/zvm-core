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

const ParentSourceContentsProfile = "git-go-parent-contents-v1"
const MaxParentSourceTrees = 16

// GoParentSourceInput is independently supplied by the caller. Physical input
// paths and policy bytes are runtime inputs, never selected from an artifact.
type GoParentSourceInput struct {
	Policy           []byte
	PolicySHA256     string
	Directory        string
	ControlDirectory string
}

type ParentContentsOptions struct {
	ContentsOptions
	Parents map[string]GoParentSourceInput
}

type ParentSourceVerification struct {
	ParentSourceProfile          string `json:"parentSourceProfile"`
	ParentSourcePolicySetSHA256  string `json:"parentSourcePolicySetSha256"`
	ParentSourcePoliciesVerified int    `json:"parentSourcePoliciesVerified"`
	ParentSourceTreesVerified    int    `json:"parentSourceTreesVerified"`
	ParentSourceFilesVerified    int    `json:"parentSourceFilesVerified"`
	ParentSourceBytesVerified    int64  `json:"parentSourceBytesVerified"`
	ParentCommitObjectsVerified  int    `json:"parentCommitObjectsVerified"`
	ParentGitlinksBound          int    `json:"parentGitlinksBound"`
}

type ParentContentsResult struct {
	SourceContentsResult
	ParentSourceVerification
}

type ParentBundleResult struct {
	SourceBundleResult
	ParentSourceVerification
}

type parentContentsVerifier struct {
	contents *contentVerifier
	parents  []*goSourceTreeObservation
	details  ParentSourceVerification
}

func prepareParentContents(policyBytes, contentsBytes []byte, controlRoot string, options ParentContentsOptions) (*parentContentsVerifier, error) {
	v, err := prepareContentsWithOptions(policyBytes, contentsBytes, controlRoot, options.ContentsOptions)
	if err != nil {
		return nil, err
	}
	p := &parentContentsVerifier{contents: v, details: ParentSourceVerification{ParentSourceProfile: ParentSourceContentsProfile}}
	good := false
	defer func() {
		if !good {
			p.close()
		}
	}()
	if len(options.Parents) == 0 || len(options.Parents) > MaxParentSourceTrees || len(options.Parents) != len(v.policy.Artifacts) {
		return nil, errors.New("every selected artifact requires exactly one independent parent source input")
	}
	var total int
	selected := []struct {
		ID           string `json:"id"`
		PolicySHA256 string `json:"policySha256"`
	}{}
	for _, required := range v.policy.Artifacts {
		input, ok := options.Parents[required.ID]
		if !ok {
			return nil, errors.New("parent source mapping includes missing or unselected artifact IDs")
		}
		total += len(input.Policy)
		if total > MaxContentInputBytes {
			return nil, errors.New("parent source policy set exceeds its byte limit")
		}
		observed, err := observeGoSourceTree(input.Policy, input.PolicySHA256, GoSourceTreeOptions{input.Directory, input.ControlDirectory})
		if err != nil {
			return nil, err
		}
		p.parents = append(p.parents, observed)
		selected = append(selected, struct {
			ID           string `json:"id"`
			PolicySHA256 string `json:"policySha256"`
		}{required.ID, input.PolicySHA256})
		if !reflect.DeepEqual(observed.policy.Source, v.selection.Release.Source) || observed.policy.GoModSHA256 != required.GoMod.SHA256 {
			return nil, errors.New("parent source differs from independently selected release source or module input")
		}
		files := map[string]SourceFile{}
		for _, file := range observed.policy.Files {
			files[file.Path] = file
		}
		mod, lock := files["go.mod"], files["go.sum"]
		// An absent tracked go.sum is supported only for an independently selected
		// empty lock. Its control is still present in the contents observation.
		if mod.Bytes != required.GoMod.Bytes || mod.SHA256 != required.GoMod.SHA256 ||
			(lock.Path == "" && (required.GoSum.Bytes != 0 || required.GoSum.SHA256 != sum(nil))) ||
			(lock.Path != "" && (lock.Bytes != required.GoSum.Bytes || lock.SHA256 != required.GoSum.SHA256)) {
			return nil, errors.New("parent source module or lock does not match contents controls")
		}
		p.details.ParentSourcePoliciesVerified++
		p.details.ParentSourceTreesVerified++
		p.details.ParentSourceFilesVerified += observed.result.SourceFilesVerified
		p.details.ParentSourceBytesVerified += observed.result.SourceBytesVerified
		p.details.ParentCommitObjectsVerified++
		p.details.ParentGitlinksBound += observed.result.GitlinksBound
	}
	raw, err := json.Marshal(selected)
	if err != nil {
		return nil, errors.New("parent source selection could not be represented")
	}
	p.details.ParentSourcePolicySetSHA256 = sum(raw)
	good = true
	return p, nil
}

func (p *parentContentsVerifier) close() {
	for _, observed := range p.parents {
		observed.close()
	}
	p.contents.close()
}

func (p *parentContentsVerifier) unchanged() error {
	for _, observed := range p.parents {
		if err := observed.unchanged(); err != nil {
			return err
		}
	}
	return p.contents.unchanged()
}

func (p *parentContentsVerifier) verify(d *directory, files map[string]File, before map[string]os.FileInfo) error {
	if err := p.contents.verify(d, files, before); err != nil {
		return err
	}
	return p.unchanged()
}

// Parent source observations remain open through contents/signature verification
// and final checks. This does not prove compiler use, source authority or release
// acceptance, and does not change the behavior of existing contents APIs.
func CheckContentsWithParentSources(manifestBytes, policyBytes, contentsBytes []byte, root, controlRoot string, options ParentContentsOptions) (ParentContentsResult, error) {
	v, err := prepareParentContents(policyBytes, contentsBytes, controlRoot, options)
	if err != nil {
		return ParentContentsResult{}, err
	}
	defer v.close()
	result, err := checkSelected(manifestBytes, policyBytes, root, nil, v.verify)
	if err != nil {
		return ParentContentsResult{}, err
	}
	if err := v.unchanged(); err != nil {
		return ParentContentsResult{}, err
	}
	result.SBOMContentsVerified = true
	local := v.contents.local
	local.ParentSourceTreeVerified = true
	return ParentContentsResult{SourceContentsResult{ContentsResult{Result: result, SBOMVerification: v.contents.details}, local}, v.details}, nil
}

func CheckBundleWithParentSources(ctx context.Context, manifestBytes, policyBytes, provenanceBytes, contentsBytes []byte, root, controlRoot string, contentsOptions ParentContentsOptions, provenanceOptions ProvenanceOptions) (ParentBundleResult, error) {
	return checkParentSourceBundle(ctx, manifestBytes, policyBytes, provenanceBytes, contentsBytes, root, controlRoot, contentsOptions, provenanceOptions, runVerifier)
}

func checkParentSourceBundle(ctx context.Context, manifestBytes, policyBytes, provenanceBytes, contentsBytes []byte, root, controlRoot string, contentsOptions ParentContentsOptions, provenanceOptions ProvenanceOptions, run verifierRunner) (ParentBundleResult, error) {
	v, err := prepareParentContents(policyBytes, contentsBytes, controlRoot, contentsOptions)
	if err != nil {
		return ParentBundleResult{}, err
	}
	defer v.close()
	result, err := checkProvenanceObserved(ctx, manifestBytes, policyBytes, provenanceBytes, root, provenanceOptions, run, v.verify, v.unchanged)
	if err != nil {
		return ParentBundleResult{}, err
	}
	result.SBOMContentsVerified = true
	local := v.contents.local
	local.ParentSourceTreeVerified = true
	return ParentBundleResult{SourceBundleResult{BundleResult{ProvenanceResult: result, SBOMVerification: v.contents.details}, local}, v.details}, nil
}

// ReadParentSourceInputs reads a strict private runtime mapping. Policy digests
// must come from independent input selection; paths are not exported in results.
func ReadParentSourceInputs(raw []byte) (map[string]GoParentSourceInput, error) {
	var mapping struct {
		Schema    int `json:"schema"`
		Artifacts []struct {
			ID           string `json:"id"`
			Policy       string `json:"policy"`
			PolicySHA256 string `json:"policySha256"`
			Directory    string `json:"directory"`
			Controls     string `json:"controls"`
		} `json:"artifacts"`
	}
	if err := decode(raw, &mapping); err != nil {
		return nil, err
	}
	if mapping.Schema != 1 || len(mapping.Artifacts) == 0 || len(mapping.Artifacts) > MaxParentSourceTrees {
		return nil, errors.New("invalid private parent source mapping")
	}
	inputs := map[string]GoParentSourceInput{}
	aliases := map[string]bool{}
	last, total := "", 0
	for _, a := range mapping.Artifacts {
		if !relative(a.ID) || strings.Contains(a.ID, "/") || a.ID <= last || aliases[strings.ToLower(a.ID)] ||
			!filepath.IsAbs(a.Policy) || !filepath.IsAbs(a.Directory) || !filepath.IsAbs(a.Controls) || !digest(a.PolicySHA256, 64) {
			return nil, errors.New("invalid sorted private parent source mapping entry")
		}
		policy, err := ReadDocument(a.Policy)
		if err != nil {
			return nil, err
		}
		if sum(policy) != a.PolicySHA256 {
			return nil, errors.New("parent source policy differs from the independent mapping digest")
		}
		total += len(policy)
		if total > MaxContentInputBytes {
			return nil, errors.New("private parent source policies exceed their byte limit")
		}
		inputs[a.ID] = GoParentSourceInput{policy, a.PolicySHA256, a.Directory, a.Controls}
		aliases[strings.ToLower(a.ID)], last = true, a.ID
	}
	return inputs, nil
}
