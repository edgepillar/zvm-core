package artifacts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func provenanceFixture(t *testing.T) (*fixture, ProvenancePolicy, ProvenanceOptions) {
	t.Helper()
	f := prepare(t, fixturePolicy())
	tool, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(tool)
	if err != nil {
		t.Fatal(err)
	}
	trust := []byte("{\"syntheticProtocolControl\":true}\n")
	trustPath := filepath.Join(t.TempDir(), "root.jsonl")
	if err := os.WriteFile(trustPath, trust, 0600); err != nil {
		t.Fatal(err)
	}
	v := ProvenancePolicy{Schema: 1, VerifierSHA256: independentSHA(raw), TrustedRootSHA256: independentSHA(trust),
		SourceRef: "refs/tags/v0.1.0", Signer: Signer{"Example/builder", ".github/workflows/build.yml", "refs/heads/main", strings.Repeat("4", 40)},
		Artifacts: []AttestedArtifact{{f.p.Artifacts[0].ID, "selected-subject", "sha256"}}}
	f.payloads[f.p.Artifacts[0].ProvenancePath] = []byte("{\"dsseEnvelope\":{\"syntheticProtocolControl\":true}}\n")
	f.sync(t)
	return f, v, ProvenanceOptions{VerifierPath: tool, TrustedRootPath: trustPath, TemporaryDirectory: t.TempDir()}
}

func (f *fixture) sync(t *testing.T) {
	t.Helper()
	f.repin(t)
	for name, raw := range f.payloads {
		if err := os.WriteFile(filepath.Join(f.root, filepath.FromSlash(name)), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// This is a deliberately synthetic parser/transport oracle. It is never an
// actual signature fixture or evidence that cryptography succeeded.
func protocolResult(t *testing.T, p Policy, v ProvenancePolicy, digest string) map[string]any {
	t.Helper()
	source := "https://github.com/" + p.Release.Source.Repository
	return map[string]any{"verificationResult": map[string]any{
		"signature": map[string]any{"certificate": map[string]any{
			"issuer": githubIssuer, "subjectAlternativeName": signerURI(v.Signer), "buildSignerURI": signerURI(v.Signer),
			"buildSignerDigest": v.Signer.Commit, "runnerEnvironment": "github-hosted", "sourceRepositoryURI": source,
			"sourceRepositoryDigest": p.Release.Source.Commit, "sourceRepositoryRef": v.SourceRef,
			"buildConfigURI": source + "/" + p.Build.WorkflowPath + "@" + v.SourceRef, "buildConfigDigest": p.Build.WorkflowCommit}},
		"verifiedTimestamps": []any{map[string]any{"type": "Tlog", "uri": "https://example.invalid/log", "timestamp": "2026-01-01T00:00:00Z"}},
		"statement": map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": provenanceType,
			"subject": []any{map[string]any{"name": v.Artifacts[0].SubjectName, "digest": map[string]any{v.Artifacts[0].DigestAlgorithm: digest}}},
			"predicate": map[string]any{"buildDefinition": map[string]any{"buildType": githubBuildType,
				"externalParameters":   map[string]any{"workflow": map[string]any{"repository": source, "path": p.Build.WorkflowPath, "ref": v.SourceRef}},
				"resolvedDependencies": []any{map[string]any{"uri": "git+" + source + "@" + v.SourceRef, "digest": map[string]any{"gitCommit": p.Release.Source.Commit}}}},
				"runDetails": map[string]any{"builder": map[string]any{"id": githubBuilder}}}}}}
}

func TestProvenanceProtocolAndObservedClosure(t *testing.T) {
	f, v, opts := provenanceFixture(t)
	calls := 0
	runner := func(ctx context.Context, tool, work string, args []string) ([]byte, error) {
		calls++
		joined := strings.Join(args, " ")
		for _, expected := range []string{"--repo " + f.p.Release.Source.Repository, "--cert-identity " + signerURI(v.Signer),
			"--source-digest " + f.p.Release.Source.Commit, "--source-ref " + v.SourceRef, "--signer-digest " + v.Signer.Commit,
			"--deny-self-hosted-runners", "--bundle ", "--custom-trusted-root ", "--hostname github.com", "--format json"} {
			if !strings.Contains(joined, expected) {
				t.Fatal("required exact verifier argument is absent")
			}
		}
		if tool != opts.VerifierPath {
			t.Fatal("unexpected verifier")
		}
		return marshal(t, []any{protocolResult(t, f.p, v, independentSHA(f.payloads[f.p.Artifacts[0].SubjectPath]))}), nil
	}
	r, err := checkProvenance(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), f.root, opts, runner)
	if err != nil || calls != 1 || !r.SelectionVerified || !r.ProvenanceSignaturesVerified || !r.WorkflowIdentityVerified || r.AttestationsVerified != 1 || r.ReleaseAccepted || r.SBOMContentsVerified || r.BuildRecipeReproduced {
		t.Fatalf("unexpected protocol control result: %+v %v", r, err)
	}
	legacy, err := f.check(t)
	if err != nil || legacy.ProvenanceSignaturesVerified {
		t.Fatal("byte-only API invented signature acceptance")
	}
	mutation := func(ctx context.Context, tool, work string, args []string) ([]byte, error) {
		raw, err := runner(ctx, tool, work, args)
		if err := os.WriteFile(filepath.Join(f.root, "extra"), []byte("changed closure"), 0600); err != nil {
			t.Fatal(err)
		}
		return raw, err
	}
	r, err = checkProvenance(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), f.root, opts, mutation)
	if err == nil || r != (ProvenanceResult{}) {
		t.Fatal("changed artifact closure was accepted")
	}
}

func TestVerifiedResultBindings(t *testing.T) {
	f, v, _ := provenanceFixture(t)
	digest := independentSHA(f.payloads[f.p.Artifacts[0].SubjectPath])
	fields := []string{"issuer", "subjectAlternativeName", "buildSignerURI", "buildSignerDigest", "runnerEnvironment",
		"sourceRepositoryURI", "sourceRepositoryDigest", "sourceRepositoryRef", "buildConfigURI", "buildConfigDigest"}
	for _, key := range fields {
		t.Run("certificate-"+key, func(t *testing.T) {
			value := protocolResult(t, f.p, v, digest)
			value["verificationResult"].(map[string]any)["signature"].(map[string]any)["certificate"].(map[string]any)[key] = "unexpected"
			if verifyResult(marshal(t, []any{value}), f.p, v, v.Artifacts[0], digest) == nil {
				t.Fatal("certificate mismatch accepted")
			}
		})
	}
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"timestamp", func(r map[string]any) { r["verifiedTimestamps"] = []any{} }},
		{"timestamp-fields", func(r map[string]any) { r["verifiedTimestamps"] = []any{map[string]any{"type": "Tlog"}} }},
		{"statement-type", func(r map[string]any) { r["statement"].(map[string]any)["_type"] = "wrong" }},
		{"predicate-type", func(r map[string]any) { r["statement"].(map[string]any)["predicateType"] = "wrong" }},
		{"subject", func(r map[string]any) { r["statement"].(map[string]any)["subject"] = []any{} }},
		{"subject-name", func(r map[string]any) {
			r["statement"].(map[string]any)["subject"].([]any)[0].(map[string]any)["name"] = "other"
		}},
		{"subject-digest", func(r map[string]any) {
			r["statement"].(map[string]any)["subject"].([]any)[0].(map[string]any)["digest"] = map[string]any{"sha256": strings.Repeat("9", 64)}
		}},
		{"subject-duplicate", func(r map[string]any) {
			s := r["statement"].(map[string]any)
			s["subject"] = append(s["subject"].([]any), s["subject"].([]any)[0])
		}},
		{"workflow", func(r map[string]any) {
			r["statement"].(map[string]any)["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"] = nil
		}},
		{"source", func(r map[string]any) {
			r["statement"].(map[string]any)["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["resolvedDependencies"] = []any{}
		}},
		{"builder", func(r map[string]any) {
			r["statement"].(map[string]any)["predicate"].(map[string]any)["runDetails"] = nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := protocolResult(t, f.p, v, digest)
			tc.change(value["verificationResult"].(map[string]any))
			if verifyResult(marshal(t, []any{value}), f.p, v, v.Artifacts[0], digest) == nil {
				t.Fatal("result mismatch accepted")
			}
		})
	}
	good := protocolResult(t, f.p, v, digest)
	for _, raw := range [][]byte{nil, []byte("null"), marshal(t, []any{}), marshal(t, []any{good, good}), []byte(`[{"verificationResult":{},"VerificationResult":{}}]`), []byte(strings.Repeat("x", MaxDocumentBytes+1))} {
		if verifyResult(raw, f.p, v, v.Artifacts[0], digest) == nil {
			t.Fatal("incomplete, ambiguous or multiple result accepted")
		}
	}
}

func TestProvenancePolicyAndBundleRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ProvenancePolicy)
	}{
		{"schema", func(v *ProvenancePolicy) { v.Schema = 2 }}, {"verifier", func(v *ProvenancePolicy) { v.VerifierSHA256 = strings.Repeat("0", 64) }},
		{"root", func(v *ProvenancePolicy) { v.TrustedRootSHA256 = strings.Repeat("0", 64) }}, {"source-ref", func(v *ProvenancePolicy) { v.SourceRef = "main" }},
		{"signer-repository", func(v *ProvenancePolicy) { v.Signer.Repository = "https://example.invalid" }},
		{"signer-workflow", func(v *ProvenancePolicy) { v.Signer.WorkflowPath = ".github/workflows/../release.yml" }},
		{"signer-ref", func(v *ProvenancePolicy) { v.Signer.Ref = "refs/heads/main.lock" }},
		{"signer-commit", func(v *ProvenancePolicy) { v.Signer.Commit = "main" }},
		{"omitted-artifact", func(v *ProvenancePolicy) { v.Artifacts = nil }},
		{"extra-artifact", func(v *ProvenancePolicy) { v.Artifacts = append(v.Artifacts, v.Artifacts[0]) }},
		{"artifact-id", func(v *ProvenancePolicy) { v.Artifacts[0].ID = "other" }},
		{"algorithm", func(v *ProvenancePolicy) { v.Artifacts[0].DigestAlgorithm = "sha1" }},
		{"subject-name", func(v *ProvenancePolicy) { v.Artifacts[0].SubjectName = "bad\nname" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, v, _ := provenanceFixture(t)
			tc.change(&v)
			if v.validate(f.p) == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	f, v, opts := provenanceFixture(t)
	never := func(context.Context, string, string, []string) ([]byte, error) {
		t.Fatal("invalid input launched verifier")
		return nil, nil
	}
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`{"dsseEnvelope":null}`), []byte(`{"dsseEnvelope":{},"dsseEnvelope":{}}`), []byte(`{"dsseEnvelope":{}} {"dsseEnvelope":{}}`), []byte(`[{}]`)} {
		f.payloads[f.p.Artifacts[0].ProvenancePath] = raw
		f.sync(t)
		r, err := checkProvenance(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), f.root, opts, never)
		if err == nil || r != (ProvenanceResult{}) {
			t.Fatal("invalid single-record policy accepted")
		}
	}
	for _, opts := range []ProvenanceOptions{{}, {VerifierPath: opts.VerifierPath, TrustedRootPath: opts.TrustedRootPath}} {
		if _, err := checkProvenance(context.Background(), marshal(t, f.m), marshal(t, f.p), marshal(t, v), f.root, opts, never); err == nil {
			t.Fatal("implicit scratch accepted")
		}
	}
	for _, raw := range [][]byte{[]byte(`null`), []byte(`[]`), []byte(`{"x":1,"\u0078":2}`), []byte(`{"x":1,"X":2}`), []byte(`{"x":` + strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34) + `}`)} {
		if _, err := objectDocument(raw); err == nil {
			t.Fatal("ambiguous/unbounded document accepted")
		}
	}
}

func TestVerifierProcessLimitsAndEnvironment(t *testing.T) {
	fixtureHost(t)
	work := t.TempDir()
	t.Setenv("GH_TOKEN", "synthetic-parent-secret")
	out, err := runVerifier(context.Background(), "/bin/sh", work, []string{"-c", `printf '%s' "${GH_TOKEN-unset}|${GH_AUTH_TOKEN-unset}|${HOME-unset}"`})
	if err != nil || string(out) != "unset|unset|unset" {
		t.Fatal("verifier inherited unrelated credentials or home configuration")
	}
	for _, script := range []string{`printf 'private diagnostic' >&2; exit 7`, `/usr/bin/head -c 1100000 /dev/zero`} {
		if _, err := runVerifier(context.Background(), "/bin/sh", work, []string{"-c", script}); err == nil || strings.Contains(err.Error(), "private diagnostic") {
			t.Fatal("verifier failure/output limit or diagnostic privacy was lost")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := runVerifier(ctx, "/bin/sh", work, []string{"-c", `while :; do :; done`}); err == nil {
		t.Fatal("canceled verifier was accepted")
	}
	c := &cappedOutput{remaining: 2, cancel: func() {}}
	if _, err := c.Write([]byte("abc")); err == nil {
		t.Fatal("stream limit was ignored")
	}
}
