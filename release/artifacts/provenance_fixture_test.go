package artifacts

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Actual cryptographic integration is opt-in with preprovisioned, pinned inputs.
// No test fetches binaries, roots, bundles, dependencies or a subject. The three
// opaque public fixtures are from cli/cli at the commit documented in README.
func TestActualOfflineGitHubSignatureFixture(t *testing.T) {
	tool := os.Getenv("ZVM_ATTESTATION_VERIFIER")
	toolSHA := os.Getenv("ZVM_ATTESTATION_VERIFIER_SHA256")
	inputs := os.Getenv("ZVM_ATTESTATION_FIXTURE_DIRECTORY")
	if tool == "" && toolSHA == "" && inputs == "" {
		t.Skip("external pinned verifier and signed public fixture were not provisioned")
	}
	if tool == "" || inputs == "" || !digest(toolSHA, 64) {
		t.Fatal("all explicit signed-fixture inputs are required")
	}
	fixtureHost(t)
	read := func(name, expected string) []byte {
		t.Helper()
		raw, err := ReadDocument(filepath.Join(inputs, name))
		if err != nil || independentSHA(raw) != expected {
			t.Fatal("public signed fixture does not match its independent source pin")
		}
		return raw
	}
	subject := read("subject.tgz", "f0c641fce0310cb43208f4272dc1423153630e44ba8cdc0b5ce8466f724e0eed")
	bundle := read("bundle.json", "cfadddd579b9fb45947530cd0e860986ec610a28f7fa6de3ef31cc051f07f761")
	root := read("trusted-root.json", "455b3fe53e2678889f093d66ebbfda5f12ebb9d682b146c3535fa04e97689787")
	root = append(bytes.TrimRight(root, "\r\n"), '\n')
	rootPath := filepath.Join(t.TempDir(), "trusted-root.jsonl")
	if err := os.WriteFile(rootPath, root, 0600); err != nil {
		t.Fatal(err)
	}
	const sourceCommit = "26d16513386ffaa790b1c32f927544f1322e4194"
	newFixture := func(t *testing.T) (*fixture, ProvenancePolicy, ProvenanceOptions) {
		t.Helper()
		p := fixturePolicy()
		p.Release.Source.Repository = "sigstore/sigstore-js"
		p.Release.Source.Commit = sourceCommit
		p.Release.TagCommit = sourceCommit
		p.Build.WorkflowCommit = sourceCommit
		p.Artifacts[0].Kind = "archive"
		p.Artifacts[0].Platform = "js/any"
		f := prepare(t, p)
		f.payloads[p.Artifacts[0].SubjectPath] = append([]byte{}, subject...)
		f.payloads[p.Artifacts[0].ProvenancePath] = append([]byte{}, bundle...)
		f.sync(t)
		v := ProvenancePolicy{Schema: 1, VerifierSHA256: toolSHA, TrustedRootSHA256: independentSHA(root), SourceRef: "refs/heads/main",
			Signer:    Signer{"sigstore/sigstore-js", ".github/workflows/release.yml", "refs/heads/main", sourceCommit},
			Artifacts: []AttestedArtifact{{p.Artifacts[0].ID, "pkg:npm/sigstore@2.1.0", "sha512"}}}
		return f, v, ProvenanceOptions{VerifierPath: tool, TrustedRootPath: rootPath, TemporaryDirectory: t.TempDir()}
	}
	t.Run("actual-certificate-signature-and-exact-workflow", func(t *testing.T) {
		f, v, opts := newFixture(t)
		r, err := CheckProvenance(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), f.root, opts)
		if err != nil || !r.ProvenanceSignaturesVerified || !r.WorkflowIdentityVerified || r.AttestationsVerified != 1 || r.ReleaseAccepted || r.SBOMContentsVerified || r.BuildRecipeReproduced {
			t.Fatalf("actual signed fixture failed: %+v %v", r, err)
		}
	})
	cases := []struct {
		name   string
		change func(*fixture, *ProvenancePolicy)
	}{
		{"wrong-source-commit", func(f *fixture, v *ProvenancePolicy) {
			f.p.Release.Source.Commit = strings.Repeat("1", 40)
			f.p.Release.TagCommit = f.p.Release.Source.Commit
			bind(t, &f.m, f.p)
		}},
		{"wrong-signer-commit", func(f *fixture, v *ProvenancePolicy) { v.Signer.Commit = strings.Repeat("1", 40) }},
		{"wrong-source-ref", func(f *fixture, v *ProvenancePolicy) { v.SourceRef = "refs/heads/other" }},
		{"wrong-signer-workflow", func(f *fixture, v *ProvenancePolicy) { v.Signer.WorkflowPath = ".github/workflows/other.yml" }},
		{"changed-subject", func(f *fixture, v *ProvenancePolicy) {
			name := f.p.Artifacts[0].SubjectPath
			f.payloads[name] = append(f.payloads[name], 0)
			f.sync(t)
		}},
		{"changed-signature", func(f *fixture, v *ProvenancePolicy) {
			name := f.p.Artifacts[0].ProvenancePath
			var b map[string]any
			if err := json.Unmarshal(f.payloads[name], &b); err != nil {
				t.Fatal(err)
			}
			sig := b["dsseEnvelope"].(map[string]any)["signatures"].([]any)[0].(map[string]any)
			s := sig["sig"].(string)
			first := "A"
			if s[0] == 'A' {
				first = "B"
			}
			sig["sig"] = first + s[1:]
			f.payloads[name] = marshal(t, b)
			f.sync(t)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, v, opts := newFixture(t)
			tc.change(f, &v)
			r, err := CheckProvenance(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), f.root, opts)
			if err == nil || r != (ProvenanceResult{}) {
				t.Fatal("actual verifier accepted the changed identity, digest or signature")
			}
		})
	}
}
