package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// Schema 2 adds an explicit per-artifact commit-control inventory. Schema 1
// keeps its exact shape and supports only the original remote-module profile.
type SourceSBOMRequirement struct {
	ID            string `json:"id"`
	Profile       string `json:"profile"`
	Policy        File   `json:"policy"`
	GoMod         File   `json:"goMod"`
	GoSum         File   `json:"goSum"`
	CommitObjects []File `json:"commitObjects"`
}

type SourceContentsPolicy struct {
	Schema                int                     `json:"schema"`
	SelectionPolicySHA256 string                  `json:"selectionPolicySha256"`
	Artifacts             []SourceSBOMRequirement `json:"artifacts"`
}

// SourceDirectories maps artifact ID, then logical Gitlink path, to a private
// runtime directory. It is never selected from a manifest or emitted in receipts.
type ContentsOptions struct {
	SourceDirectories map[string]map[string]string
}

type LocalSourceVerification struct {
	LocalSourceTreesVerified   int   `json:"localSourceTreesVerified"`
	LocalSourceFilesVerified   int   `json:"localSourceFilesVerified"`
	LocalSourceBytesVerified   int64 `json:"localSourceBytesVerified"`
	LocalCommitObjectsVerified int   `json:"localCommitObjectsVerified"`
	CompilerUseOfTreesProven   bool  `json:"compilerUseOfTreesProven"`
	ParentSourceTreeVerified   bool  `json:"parentSourceTreeVerified"`
}

type SourceContentsResult struct {
	ContentsResult
	LocalSourceVerification
}

type SourceBundleResult struct {
	BundleResult
	LocalSourceVerification
}

func (c SourceContentsPolicy) requirements() (ContentsPolicy, map[string][]File) {
	base := ContentsPolicy{Schema: 2, SelectionPolicySHA256: c.SelectionPolicySHA256, Artifacts: []SBOMRequirement{}}
	commits := map[string][]File{}
	for _, a := range c.Artifacts {
		base.Artifacts = append(base.Artifacts, SBOMRequirement{a.ID, a.Profile, a.Policy, a.GoMod, a.GoSum})
		commits[a.ID] = a.CommitObjects
	}
	return base, commits
}

func (c SourceContentsPolicy) validate(p Policy) (map[string]File, error) {
	if c.Schema != 2 {
		return nil, errors.New("unsupported source contents policy schema")
	}
	base, commits := c.requirements()
	return validateContents(p, c.SelectionPolicySHA256, base.Artifacts, commits)
}

func CanonicalSourceContentsPolicy(c SourceContentsPolicy, p Policy) ([]byte, error) {
	if _, err := c.validate(p); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

func parseContentsPolicy(raw []byte, p Policy) (ContentsPolicy, map[string][]File, map[string]File, error) {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes {
		return ContentsPolicy{}, nil, nil, errors.New("invalid bounded contents policy")
	}
	var header struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return ContentsPolicy{}, nil, nil, errors.New("invalid contents policy schema")
	}
	switch header.Schema {
	case 1:
		var c ContentsPolicy
		if err := decode(raw, &c); err != nil {
			return ContentsPolicy{}, nil, nil, err
		}
		files, err := c.validate(p)
		return c, nil, files, err
	case 2:
		var c SourceContentsPolicy
		if err := decode(raw, &c); err != nil {
			return ContentsPolicy{}, nil, nil, err
		}
		files, err := c.validate(p)
		base, commits := c.requirements()
		return base, commits, files, err
	default:
		return ContentsPolicy{}, nil, nil, errors.New("unsupported contents policy schema")
	}
}

func contentsDirectories(requirements []SBOMRequirement, options ContentsOptions) (map[string]map[string]string, string, error) {
	directories := map[string]map[string]string{}
	profiles := []string{}
	for _, a := range requirements {
		if !slices.Contains(profiles, a.Profile) {
			profiles = append(profiles, a.Profile)
		}
		if a.Profile == GoSourceSBOMProfile {
			selected := options.SourceDirectories[a.ID]
			if len(selected) == 0 || len(selected) > MaxLocalSources {
				return nil, "", errors.New("local-source contents require exact private source directories")
			}
			directories[a.ID] = map[string]string{}
			for path, dir := range selected {
				directories[a.ID][path] = dir
			}
		}
	}
	if len(directories) != len(options.SourceDirectories) {
		return nil, "", errors.New("source directories include an unselected artifact or profile")
	}
	slices.Sort(profiles)
	return directories, strings.Join(profiles, ","), nil
}

// ParseContentsSourceDirectories accepts a strict private schema 1 mapping with
// sorted artifact IDs and sorted per-artifact logical source paths.
func ParseContentsSourceDirectories(raw []byte) (map[string]map[string]string, error) {
	type source struct {
		Path      string `json:"path"`
		Directory string `json:"directory"`
	}
	var mapping struct {
		Schema    int `json:"schema"`
		Artifacts []struct {
			ID      string   `json:"id"`
			Sources []source `json:"sources"`
		} `json:"artifacts"`
	}
	if err := decode(raw, &mapping); err != nil {
		return nil, err
	}
	if mapping.Schema != 1 || len(mapping.Artifacts) == 0 {
		return nil, errors.New("invalid private contents source mapping")
	}
	result := map[string]map[string]string{}
	last := ""
	aliases := map[string]bool{}
	for _, a := range mapping.Artifacts {
		if !relative(a.ID) || strings.Contains(a.ID, "/") || a.ID <= last || aliases[strings.ToLower(a.ID)] {
			return nil, errors.New("invalid sorted source-mapping artifact ID")
		}
		raw, _ := json.Marshal(struct {
			Schema  int      `json:"schema"`
			Sources []source `json:"sources"`
		}{1, a.Sources})
		dirs, err := ParseGoSourceDirectories(raw)
		if err != nil {
			return nil, err
		}
		result[a.ID] = dirs
		aliases[strings.ToLower(a.ID)] = true
		last = a.ID
	}
	return result, nil
}

func CheckContentsWithOptions(manifestBytes, policyBytes, contentsBytes []byte, root, controlRoot string, options ContentsOptions) (SourceContentsResult, error) {
	v, err := prepareContentsWithOptions(policyBytes, contentsBytes, controlRoot, options)
	if err != nil {
		return SourceContentsResult{}, err
	}
	defer v.close()
	result, err := checkSelected(manifestBytes, policyBytes, root, nil, v.verify)
	if err != nil {
		return SourceContentsResult{}, err
	}
	result.SBOMContentsVerified = true
	return SourceContentsResult{ContentsResult{Result: result, SBOMVerification: v.details}, v.local}, nil
}

func CheckBundleWithOptions(ctx context.Context, manifestBytes, policyBytes, provenanceBytes, contentsBytes []byte, root, controlRoot string, contentsOptions ContentsOptions, provenanceOptions ProvenanceOptions) (SourceBundleResult, error) {
	return checkSourceBundle(ctx, manifestBytes, policyBytes, provenanceBytes, contentsBytes, root, controlRoot, contentsOptions, provenanceOptions, runVerifier)
}

func checkSourceBundle(ctx context.Context, manifestBytes, policyBytes, provenanceBytes, contentsBytes []byte, root, controlRoot string, contentsOptions ContentsOptions, provenanceOptions ProvenanceOptions, run verifierRunner) (SourceBundleResult, error) {
	v, err := prepareContentsWithOptions(policyBytes, contentsBytes, controlRoot, contentsOptions)
	if err != nil {
		return SourceBundleResult{}, err
	}
	defer v.close()
	result, err := checkProvenanceObserved(ctx, manifestBytes, policyBytes, provenanceBytes, root, provenanceOptions, run, v.verify, v.unchanged)
	if err != nil {
		return SourceBundleResult{}, err
	}
	result.SBOMContentsVerified = true
	return SourceBundleResult{BundleResult{ProvenanceResult: result, SBOMVerification: v.details}, v.local}, nil
}
