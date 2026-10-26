package artifacts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parentObservationFixture(t *testing.T) (Policy, SourceContentsPolicy, string, ParentContentsOptions) {
	t.Helper()
	sp, roots := sourceTreeFixture(t, 40)
	p := fixturePolicy()
	p.Release.Source, p.Release.TagCommit = sp.Source, sp.Source.Commit
	root := t.TempDir()
	pin := func(name string, raw []byte) File {
		t.Helper()
		if os.WriteFile(filepath.Join(root, name), raw, 0600) != nil {
			t.Fatal("control write failed")
		}
		return File{name, int64(len(raw)), independentSHA(raw)}
	}
	mod, err := os.ReadFile(filepath.Join(roots.Directory, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	// This fixture tests parent observation/binding only. It supplies no valid
	// subject or SPDX document and cannot establish a complete contents result.
	c := SourceContentsPolicy{2, independentSHA(canonical), []SourceSBOMRequirement{{p.Artifacts[0].ID,
		GoSourceSBOMProfile, pin("policy.json", []byte("{}\n")), pin("go.mod", mod), pin("go.sum", nil),
		[]File{pin("local.commit", []byte("x"))}}}}
	raw := marshal(t, sp)
	return p, c, root, ParentContentsOptions{ContentsOptions: ContentsOptions{SourceDirectories: map[string]map[string]string{p.Artifacts[0].ID: {"deps/core": t.TempDir()}}}, Parents: map[string]GoParentSourceInput{
		p.Artifacts[0].ID: {raw, independentSHA(raw), roots.Directory, roots.ControlDirectory}}}
}

func TestParentSourceObservationClosureAndFinalChecks(t *testing.T) {
	for _, name := range []string{"complete", "late-source-bytes", "late-source-extra", "late-parent-commit", "late-commit-extra", "late-contents-lock", "late-source-identity"} {
		t.Run(name, func(t *testing.T) {
			p, c, root, options := parentObservationFixture(t)
			v, err := prepareParentContents(marshal(t, p), marshal(t, c), root, options)
			if err != nil {
				t.Fatal(err)
			}
			defer v.close()
			input := options.Parents[p.Artifacts[0].ID]
			switch name {
			case "late-source-bytes":
				err = os.WriteFile(filepath.Join(input.Directory, "a.b"), []byte("changed"), 0600)
			case "late-source-extra":
				err = os.WriteFile(filepath.Join(input.Directory, "extra"), []byte("x"), 0600)
			case "late-parent-commit":
				err = os.WriteFile(filepath.Join(input.ControlDirectory, "parent.commit"), []byte("changed"), 0600)
			case "late-commit-extra":
				err = os.WriteFile(filepath.Join(input.ControlDirectory, "extra"), []byte("x"), 0600)
			case "late-contents-lock":
				err = os.WriteFile(filepath.Join(root, "go.sum"), []byte("changed"), 0600)
			case "late-source-identity":
				path := filepath.Join(input.Directory, "a.b")
				raw, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if os.WriteFile(path+".replacement", raw, 0600) != nil {
					t.Fatal("replacement write failed")
				}
				err = os.Rename(path+".replacement", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if (v.unchanged() == nil) != (name == "complete") {
				t.Fatal("parent observation missed a late substitution")
			}
			if v.details.ParentSourceTreesVerified != 1 || v.details.ParentSourceFilesVerified != 4 || v.details.ParentSourceBytesVerified != 94 || v.details.ParentGitlinksBound != 1 || v.details.ParentCommitObjectsVerified != 1 {
				t.Fatal("parent observation counts are wrong")
			}
			selected := []struct {
				ID           string `json:"id"`
				PolicySHA256 string `json:"policySha256"`
			}{{p.Artifacts[0].ID, input.PolicySHA256}}
			if v.details.ParentSourcePolicySetSHA256 != independentSHA(marshal(t, selected)) {
				t.Fatal("parent policy selection digest differs")
			}
		})
	}
}

func TestParentSourceIndependentSelectionAndLockBinding(t *testing.T) {
	for _, name := range []string{"missing", "extra", "wrong-id", "wrong-policy-hash", "other-release-source", "wrong-module-pin", "nonempty-missing-lock", "wrong-module-size"} {
		t.Run(name, func(t *testing.T) {
			p, c, root, options := parentObservationFixture(t)
			id := p.Artifacts[0].ID
			input := options.Parents[id]
			switch name {
			case "missing":
				options.Parents = nil
			case "extra":
				options.Parents["unselected"] = input
			case "wrong-id":
				delete(options.Parents, id)
				options.Parents["unselected"] = input
			case "wrong-policy-hash":
				input.PolicySHA256 = strings.Repeat("1", 64)
				options.Parents[id] = input
			case "other-release-source":
				p.Release.Source.Repository = "Other/project"
				c.SelectionPolicySHA256 = independentSHA(marshal(t, p))
			case "wrong-module-pin":
				c.Artifacts[0].GoMod.SHA256 = strings.Repeat("2", 64)
			case "nonempty-missing-lock":
				c.Artifacts[0].GoSum = File{"go.sum", 1, independentSHA([]byte("x"))}
				if os.WriteFile(filepath.Join(root, "go.sum"), []byte("x"), 0600) != nil {
					t.Fatal("lock setup failed")
				}
			case "wrong-module-size":
				c.Artifacts[0].GoMod.Bytes++
			}
			v, err := prepareParentContents(marshal(t, p), marshal(t, c), root, options)
			if v != nil {
				v.close()
			}
			if err == nil || v != nil {
				t.Fatal("unselected parent/source/lock binding accepted")
			}
		})
	}
}

func TestParentSourcePrivateMappingStrictness(t *testing.T) {
	p, _, _, options := parentObservationFixture(t)
	input := options.Parents[p.Artifacts[0].ID]
	policy := filepath.Join(t.TempDir(), "parent.json")
	if os.WriteFile(policy, input.Policy, 0600) != nil {
		t.Fatal("policy write failed")
	}
	value := map[string]any{"schema": 1, "artifacts": []map[string]string{{"id": p.Artifacts[0].ID, "policy": policy, "policySha256": input.PolicySHA256, "directory": input.Directory, "controls": input.ControlDirectory}}}
	raw := marshal(t, value)
	read, err := ReadParentSourceInputs(raw)
	if err != nil || !bytes.Equal(read[p.Artifacts[0].ID].Policy, input.Policy) {
		t.Fatal("selected private mapping refused", err)
	}
	for _, change := range []func(map[string]string){
		func(a map[string]string) { a["id"] = "../outside" },
		func(a map[string]string) { a["policy"] = "relative" },
		func(a map[string]string) { a["directory"] = "relative" },
		func(a map[string]string) { a["controls"] = "relative" },
		func(a map[string]string) { a["policySha256"] = strings.Repeat("1", 64) },
	} {
		var copy map[string]any
		if json.Unmarshal(raw, &copy) != nil {
			t.Fatal("mapping reset failed")
		}
		a := map[string]string{}
		for k, v := range copy["artifacts"].([]any)[0].(map[string]any) {
			a[k] = v.(string)
		}
		change(a)
		copy["artifacts"] = []map[string]string{a}
		if got, err := ReadParentSourceInputs(marshal(t, copy)); err == nil || got != nil {
			t.Fatal("invalid private parent mapping accepted")
		}
	}
	for _, bad := range [][]byte{[]byte(`{}`), []byte(`{"schema":1,"schema":1,"artifacts":[]}`), append(append([]byte{}, raw...), []byte(" {}")...)} {
		if got, err := ReadParentSourceInputs(bad); err == nil || got != nil {
			t.Fatal("ambiguous private mapping accepted")
		}
	}
}

func actualParentSourceInput(t *testing.T) GoParentSourceInput {
	t.Helper()
	directory := os.Getenv("ZVM_PARENT_SOURCE_FIXTURE_DIRECTORY")
	if directory == "" {
		t.Skip("independently pinned parent export and commit controls were not provisioned")
	}
	raw, err := ReadDocument(filepath.Join(directory, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The independent digest is provisioned by the qualification controller,
	// not selected from this proposed policy.
	expected := os.Getenv("ZVM_PARENT_SOURCE_FIXTURE_POLICY_SHA256")
	if !digest(expected, 64) {
		t.Fatal("independent parent policy SHA-256 was not provisioned")
	}
	return GoParentSourceInput{raw, expected, filepath.Join(directory, "source"), filepath.Join(directory, "controls")}
}

func TestActualParentSourceContentsAndSignatureObservation(t *testing.T) {
	for _, name := range []string{"contents", "protocol-success", "signature-refusal", "late-parent-source", "late-parent-extra", "late-parent-commit", "late-child-source", "late-SBOM-control"} {
		t.Run(name, func(t *testing.T) {
			input := actualParentSourceInput(t)
			var policy GoSourceTreePolicy
			if decode(input.Policy, &policy) != nil {
				t.Fatal("parent fixture policy invalid")
			}
			// Mutation controls use fresh regular files; retained inputs remain read-only.
			source, controls := t.TempDir(), t.TempDir()
			for _, file := range policy.Files {
				raw, err := os.ReadFile(filepath.Join(input.Directory, file.Path))
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(source, file.Path)
				if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, raw, 0600|os.FileMode(mustExecutable(file.Mode))) != nil {
					t.Fatal("parent copy failed")
				}
			}
			commit, err := os.ReadFile(filepath.Join(input.ControlDirectory, policy.CommitObject.Path))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(controls, policy.CommitObject.Path)
			if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, commit, 0600) != nil {
				t.Fatal("parent control copy failed")
			}
			input.Directory, input.ControlDirectory = source, controls
			c := actualSourceContents(t)
			f := c.f
			options := ParentContentsOptions{ContentsOptions{c.directories}, map[string]GoParentSourceInput{f.p.Artifacts[0].ID: input}}
			m, p, contents := marshal(t, f.m), marshal(t, f.p), marshal(t, c.policy)
			if name == "contents" {
				result, err := CheckContentsWithParentSources(m, p, contents, f.root, c.root, options)
				if err != nil || !result.ParentSourceTreeVerified || !result.SelectionVerified || !result.SBOMContentsVerified || result.ParentSourceTreesVerified != 1 || result.ParentSourceFilesVerified != len(policy.Files) || result.ParentGitlinksBound != 1 || result.LocalSourceFilesVerified != 112 || result.ProvenanceSignaturesVerified || result.CompilerUseOfTreesProven || result.SourceCommitAuthenticated || result.ReleaseAccepted {
					t.Fatalf("parent/source/contents scope failed: %+v %v", result, err)
				}
				if bytes.Contains(marshal(t, result), []byte(source)) || bytes.Contains(marshal(t, result), []byte(controls)) {
					t.Fatal("parent result disclosed runtime paths")
				}
				return
			}
			_, provenance, verifierOptions := provenanceFixture(t)
			provenance.SourceRef = "refs/heads/main"
			provenance.Signer = Signer{Repository: f.p.Release.Source.Repository, WorkflowPath: f.p.Build.WorkflowPath, Ref: "refs/heads/main", Commit: f.p.Release.Source.Commit}
			provenance.Artifacts = []AttestedArtifact{{ID: f.p.Artifacts[0].ID, SubjectName: f.p.Artifacts[0].SubjectPath, DigestAlgorithm: "sha256"}}
			called := false
			runner := func(context.Context, string, string, []string) ([]byte, error) {
				called = true
				var mutation error
				switch name {
				case "signature-refusal":
					return nil, errors.New("declared signature refusal")
				case "late-parent-source":
					mutation = os.WriteFile(filepath.Join(source, "go.mod"), []byte("changed"), 0600)
				case "late-parent-extra":
					mutation = os.WriteFile(filepath.Join(source, "extra"), []byte("x"), 0600)
				case "late-parent-commit":
					mutation = os.WriteFile(path, []byte("changed"), 0600)
				case "late-child-source":
					mutation = os.WriteFile(filepath.Join(c.sourceRoot, "zvm-core", "go.mod"), []byte("changed"), 0600)
				case "late-SBOM-control":
					mutation = os.WriteFile(filepath.Join(c.root, "parent/go.sum"), []byte("changed"), 0600)
				}
				if mutation != nil {
					return nil, mutation
				}
				return marshal(t, []any{protocolResult(t, f.p, provenance, c.sourcePolicy.Go.Subject.SHA256)}), nil
			}
			result, err := checkParentSourceBundle(context.Background(), m, p, marshal(t, provenance), contents, f.root, c.root, options, verifierOptions, runner)
			if !called {
				t.Fatal("declared verifier protocol was not exercised", err)
			}
			if name == "protocol-success" {
				if err != nil || !result.ParentSourceTreeVerified || !result.ProvenanceSignaturesVerified || !result.SBOMContentsVerified || result.ReleaseAccepted || result.CompilerUseOfTreesProven || result.SourceCommitAuthenticated {
					t.Fatalf("parent joint protocol failed: %+v %v", result, err)
				}
			} else if err == nil || result != (ParentBundleResult{}) {
				t.Fatal("failed parent joint observation emitted success")
			}
		})
	}
}
