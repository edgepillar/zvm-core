package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const provenanceType = "https://slsa.dev/provenance/v1"
const githubIssuer = "https://token.actions.githubusercontent.com"
const githubBuildType = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
const githubBuilder = "https://github.com/actions/runner/github-hosted"

type Signer struct {
	Repository   string `json:"repository"`
	WorkflowPath string `json:"workflowPath"`
	Ref          string `json:"ref"`
	Commit       string `json:"commit"`
}

type AttestedArtifact struct {
	ID              string `json:"id"`
	SubjectName     string `json:"subjectName"`
	DigestAlgorithm string `json:"digestAlgorithm"`
}

// ProvenancePolicy is an independent expectation, never inferred from a
// bundle's certificate or statement. Provision the verifier and trust root
// through a separately reviewed process; their hashes do not choose an owner.
type ProvenancePolicy struct {
	Schema            int                `json:"schema"`
	VerifierSHA256    string             `json:"verifierSha256"`
	TrustedRootSHA256 string             `json:"trustedRootSha256"`
	SourceRef         string             `json:"sourceRef"`
	Signer            Signer             `json:"signer"`
	Artifacts         []AttestedArtifact `json:"artifacts"`
}

type ProvenanceOptions struct {
	VerifierPath       string
	TrustedRootPath    string
	TemporaryDirectory string
}

type ProvenanceResult struct {
	Result
	ProvenancePolicySHA256   string `json:"provenancePolicySha256"`
	VerifierSHA256           string `json:"verifierSha256"`
	TrustedRootSHA256        string `json:"trustedRootSha256"`
	AttestationsVerified     int    `json:"attestationsVerified"`
	WorkflowIdentityVerified bool   `json:"workflowIdentityVerified"`
	BuildRecipeReproduced    bool   `json:"buildRecipeReproduced"`
}

func validRef(value string) bool {
	if !relative(value) || !(strings.HasPrefix(value, "refs/heads/") || strings.HasPrefix(value, "refs/tags/")) || strings.Contains(value, "..") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func workflow(name string) bool {
	return relative(name) && strings.HasPrefix(name, ".github/workflows/") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml"))
}

func (v ProvenancePolicy) validate(p Policy) error {
	if v.Schema != 1 || !digest(v.VerifierSHA256, 64) || !digest(v.TrustedRootSHA256, 64) || !validRef(v.SourceRef) ||
		!validRepository(v.Signer.Repository) || !workflow(v.Signer.WorkflowPath) || !validRef(v.Signer.Ref) || !commit(v.Signer.Commit) ||
		!workflow(p.Build.WorkflowPath) || len(v.Artifacts) != len(p.Artifacts) {
		return errors.New("invalid independent provenance policy")
	}
	for i, artifact := range v.Artifacts {
		if artifact.ID != p.Artifacts[i].ID || artifact.SubjectName == "" || len(artifact.SubjectName) > 512 ||
			(artifact.DigestAlgorithm != "sha256" && artifact.DigestAlgorithm != "sha512") {
			return errors.New("provenance policy must cover every selected artifact exactly")
		}
		for _, c := range artifact.SubjectName {
			if c < 33 || c > 126 {
				return errors.New("invalid attestation subject name")
			}
		}
	}
	return nil
}

// objectDocument rejects concatenated/multiple records and duplicate keys before
// delegating cryptography to the pinned verifier. It does not verify a signature.
func objectDocument(raw []byte) (map[string]json.RawMessage, error) {
	return objectDocumentBudget(raw, 8192)
}

func objectDocumentBudget(raw []byte, maxNodes int) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes || !utf8.Valid(raw) {
		return nil, errors.New("invalid bounded JSON document")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > 32 || nodes > maxNodes {
			return errors.New("JSON structure exceeds limit")
		}
		token, err := d.Token()
		if err != nil {
			return errors.New("invalid JSON token")
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[strings.ToLower(name)] {
						return errors.New("duplicate or case-aliased JSON member")
					}
					seen[strings.ToLower(name)] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("invalid JSON container")
			}
			if _, err := d.Token(); err != nil {
				return errors.New("invalid JSON ending")
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("multiple JSON records are refused")
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return nil, errors.New("expected one JSON object")
	}
	return value, nil
}

func selectedDocument(d *directory, pin File, before os.FileInfo) ([]byte, error) {
	if pin.Bytes <= 0 || pin.Bytes > MaxDocumentBytes {
		return nil, errors.New("sidecar exceeds document limit")
	}
	f, err := openEntry(d.root, pin.Path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !stable(before, opened) {
		return nil, errors.New("sidecar identity changed")
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, MaxDocumentBytes+1))
	after, statErr := f.Stat()
	named, pathErr := d.root.Lstat(pin.Path)
	if readErr != nil || statErr != nil || pathErr != nil || int64(len(raw)) != pin.Bytes || sum(raw) != pin.SHA256 || !stable(before, after) || !stable(before, named) {
		return nil, errors.New("sidecar changed while reading")
	}
	return raw, nil
}

func subjectDigest(d *directory, pin File, before os.FileInfo, algorithm string) (string, error) {
	if algorithm == "sha256" {
		return pin.SHA256, nil
	}
	f, err := openEntry(d.root, pin.Path, false)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !stable(before, opened) {
		return "", errors.New("subject identity changed")
	}
	a, b := sha256.New(), sha512.New()
	n, readErr := io.Copy(io.MultiWriter(a, b), io.LimitReader(f, pin.Bytes+1))
	after, statErr := f.Stat()
	named, pathErr := d.root.Lstat(pin.Path)
	if readErr != nil || statErr != nil || pathErr != nil || n != pin.Bytes || !stable(before, after) || !stable(before, named) || hex.EncodeToString(a.Sum(nil)) != pin.SHA256 {
		return "", errors.New("subject changed while hashing")
	}
	return hex.EncodeToString(b.Sum(nil)), nil
}

// CheckProvenance adds actual certificate/signature and exact source/workflow
// checks to byte selection. Local bundle/root flags disable API/TUF acquisition;
// the caller owns host isolation and independent trust-policy review. No build,
// signing, extraction, SBOM completeness or release acceptance follows from it.
func CheckProvenance(ctx context.Context, manifestBytes, policyBytes, provenancePolicyBytes []byte, root string, options ProvenanceOptions) (ProvenanceResult, error) {
	return checkProvenance(ctx, manifestBytes, policyBytes, provenancePolicyBytes, root, options, runVerifier)
}

type verifierRunner func(context.Context, string, string, []string) ([]byte, error)

func checkProvenance(ctx context.Context, manifestBytes, policyBytes, provenancePolicyBytes []byte, root string, options ProvenanceOptions, run verifierRunner) (ProvenanceResult, error) {
	return checkProvenanceObserved(ctx, manifestBytes, policyBytes, provenancePolicyBytes, root, options, run, nil, nil)
}

func checkProvenanceObserved(ctx context.Context, manifestBytes, policyBytes, provenancePolicyBytes []byte, root string, options ProvenanceOptions, run verifierRunner, additional selectionVerifier, finish func() error) (ProvenanceResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return ProvenanceResult{}, errors.New("verification context is unavailable")
	}
	if options.VerifierPath == "" || options.TrustedRootPath == "" || options.TemporaryDirectory == "" {
		return ProvenanceResult{}, errors.New("verifier, trust root and explicit temporary directory are required")
	}
	var p Policy
	var v ProvenancePolicy
	if err := decode(policyBytes, &p); err != nil {
		return ProvenanceResult{}, err
	}
	if _, err := p.validate(); err != nil {
		return ProvenanceResult{}, err
	}
	if err := decode(provenancePolicyBytes, &v); err != nil {
		return ProvenanceResult{}, err
	}
	if err := v.validate(p); err != nil {
		return ProvenanceResult{}, err
	}
	trust, err := ReadDocument(options.TrustedRootPath)
	if err != nil || sum(trust) != v.TrustedRootSHA256 || !bytes.HasSuffix(trust, []byte("\n")) {
		return ProvenanceResult{}, errors.New("independent trust root does not match")
	}
	if _, err := objectDocument(trust); err != nil {
		return ProvenanceResult{}, errors.New("expected one complete trusted-root JSON record")
	}
	tool, err := pinVerifier(options.VerifierPath, v.VerifierSHA256)
	if err != nil {
		return ProvenanceResult{}, err
	}
	defer tool.close()
	parent, err := openDirectory(options.TemporaryDirectory)
	if err != nil {
		return ProvenanceResult{}, errors.New("explicit temporary directory is unavailable")
	}
	defer parent.root.Close()
	work, err := os.MkdirTemp(parent.root.Name(), "zvm-provenance-")
	if err != nil {
		return ProvenanceResult{}, errors.New("private verifier workspace could not be created")
	}
	defer os.RemoveAll(work)
	if err := parent.checkAncestors(); err != nil {
		return ProvenanceResult{}, err
	}
	trustPath := filepath.Join(work, "trusted-root.jsonl")
	if err := os.WriteFile(trustPath, trust, 0600); err != nil {
		return ProvenanceResult{}, errors.New("private trust input could not be prepared")
	}
	if err := os.Mkdir(filepath.Join(work, "config"), 0700); err != nil {
		return ProvenanceResult{}, errors.New("isolated verifier configuration could not be prepared")
	}
	count := 0
	result, err := checkSelected(manifestBytes, policyBytes, root, nil, func(d *directory, files map[string]File, before map[string]os.FileInfo) error {
		if additional != nil {
			if err := additional(d, files, before); err != nil {
				return err
			}
		}
		for i, artifact := range p.Artifacts {
			if ctx.Err() != nil {
				return errors.New("verification was canceled")
			}
			bundle, err := selectedDocument(d, files[artifact.ProvenancePath], before[artifact.ProvenancePath])
			if err != nil {
				return err
			}
			one, err := objectDocument(bundle)
			if err != nil || one["dsseEnvelope"] == nil || one["messageSignature"] != nil {
				return errors.New("each required provenance must contain exactly one DSSE bundle")
			}
			if _, err := member(one, "dsseEnvelope"); err != nil {
				return errors.New("DSSE envelope is absent")
			}
			bundlePath := filepath.Join(work, fmt.Sprintf("bundle-%03d.json", i))
			if err := os.WriteFile(bundlePath, bundle, 0600); err != nil {
				return errors.New("private bundle input could not be prepared")
			}
			expectedDigest, err := subjectDigest(d, files[artifact.SubjectPath], before[artifact.SubjectPath], v.Artifacts[i].DigestAlgorithm)
			if err != nil {
				return err
			}
			args := []string{"attestation", "verify", filepath.Join(d.root.Name(), filepath.FromSlash(artifact.SubjectPath)),
				"--repo", p.Release.Source.Repository, "--bundle", bundlePath, "--custom-trusted-root", trustPath,
				"--digest-alg", v.Artifacts[i].DigestAlgorithm, "--predicate-type", provenanceType,
				"--cert-oidc-issuer", githubIssuer, "--cert-identity", signerURI(v.Signer),
				"--signer-digest", v.Signer.Commit, "--source-digest", p.Release.Source.Commit, "--source-ref", v.SourceRef,
				"--deny-self-hosted-runners", "--hostname", "github.com", "--format", "json"}
			raw, err := run(ctx, options.VerifierPath, work, args)
			if err != nil {
				return err
			}
			if err := verifyResult(raw, p, v, v.Artifacts[i], expectedDigest); err != nil {
				return err
			}
			count++
		}
		if err := parent.checkAncestors(); err != nil {
			return err
		}
		if err := tool.unchanged(); err != nil {
			return err
		}
		if finish != nil {
			return finish()
		}
		return nil
	})
	if err != nil {
		return ProvenanceResult{}, err
	}
	result.ProvenanceSignaturesVerified = true
	return ProvenanceResult{Result: result, ProvenancePolicySHA256: sum(provenancePolicyBytes), VerifierSHA256: v.VerifierSHA256,
		TrustedRootSHA256: v.TrustedRootSHA256, AttestationsVerified: count, WorkflowIdentityVerified: true}, nil
}

func signerURI(s Signer) string {
	return "https://github.com/" + s.Repository + "/" + s.WorkflowPath + "@" + s.Ref
}
