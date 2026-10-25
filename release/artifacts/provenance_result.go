package artifacts

import (
	"encoding/json"
	"errors"
)

func member(object map[string]json.RawMessage, key string) (map[string]json.RawMessage, error) {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(object[key], &value); err != nil || value == nil {
		return nil, errors.New("verified result is missing a required object")
	}
	return value, nil
}

func textEquals(object map[string]json.RawMessage, key, expected string) bool {
	var value string
	return json.Unmarshal(object[key], &value) == nil && value == expected && expected != ""
}

func verifyResult(raw []byte, p Policy, v ProvenancePolicy, a AttestedArtifact, expectedDigest string) error {
	// Inspect every returned record, never count an exit status or filtered
	// nonempty subset as complete verification of a supplied bundle collection.
	if len(raw) == 0 || len(raw) > MaxDocumentBytes {
		return errors.New("invalid verifier result size")
	}
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil || len(records) != 1 {
		return errors.New("expected exactly one verified attestation result")
	}
	outer, err := objectDocument(records[0])
	if err != nil {
		return err
	}
	result, err := member(outer, "verificationResult")
	if err != nil {
		return err
	}
	signature, err := member(result, "signature")
	if err != nil {
		return err
	}
	cert, err := member(signature, "certificate")
	if err != nil {
		return err
	}
	sourceURI := "https://github.com/" + p.Release.Source.Repository
	configURI := sourceURI + "/" + p.Build.WorkflowPath + "@" + v.SourceRef
	for key, expected := range map[string]string{
		"issuer": githubIssuer, "subjectAlternativeName": signerURI(v.Signer), "buildSignerURI": signerURI(v.Signer),
		"buildSignerDigest": v.Signer.Commit, "runnerEnvironment": "github-hosted",
		"sourceRepositoryURI": sourceURI, "sourceRepositoryDigest": p.Release.Source.Commit, "sourceRepositoryRef": v.SourceRef,
		"buildConfigURI": configURI, "buildConfigDigest": p.Build.WorkflowCommit,
	} {
		if !textEquals(cert, key, expected) {
			return errors.New("verified certificate does not match independent source/workflow policy")
		}
	}
	var timestamps []map[string]json.RawMessage
	if err := json.Unmarshal(result["verifiedTimestamps"], &timestamps); err != nil || len(timestamps) == 0 || len(timestamps) > 16 {
		return errors.New("verified timestamp evidence is absent")
	}
	for _, stamp := range timestamps {
		for _, key := range []string{"type", "uri", "timestamp"} {
			var value string
			if json.Unmarshal(stamp[key], &value) != nil || value == "" {
				return errors.New("verified timestamp evidence is incomplete")
			}
		}
	}
	statement, err := member(result, "statement")
	if err != nil {
		return err
	}
	if !textEquals(statement, "_type", "https://in-toto.io/Statement/v1") || !textEquals(statement, "predicateType", provenanceType) {
		return errors.New("unexpected verified statement type")
	}
	var subjects []map[string]json.RawMessage
	if err := json.Unmarshal(statement["subject"], &subjects); err != nil || len(subjects) == 0 || len(subjects) > MaxArtifacts {
		return errors.New("invalid verified subject inventory")
	}
	matched := 0
	for _, subject := range subjects {
		if !textEquals(subject, "name", a.SubjectName) {
			continue
		}
		digests, err := member(subject, "digest")
		if err != nil || !textEquals(digests, a.DigestAlgorithm, expectedDigest) {
			return errors.New("verified subject digest does not match selected bytes")
		}
		matched++
	}
	if matched != 1 {
		return errors.New("selected subject is missing or duplicated")
	}
	predicate, err := member(statement, "predicate")
	if err != nil {
		return err
	}
	definition, err := member(predicate, "buildDefinition")
	if err != nil {
		return err
	}
	external, err := member(definition, "externalParameters")
	if err != nil {
		return err
	}
	invocation, err := member(external, "workflow")
	if err != nil {
		return err
	}
	if !textEquals(definition, "buildType", githubBuildType) || !textEquals(invocation, "repository", sourceURI) ||
		!textEquals(invocation, "path", p.Build.WorkflowPath) || !textEquals(invocation, "ref", v.SourceRef) {
		return errors.New("workflow statement does not match selected build")
	}
	var dependencies []map[string]json.RawMessage
	if err := json.Unmarshal(definition["resolvedDependencies"], &dependencies); err != nil || len(dependencies) == 0 || len(dependencies) > 64 {
		return errors.New("source dependency assertion is absent")
	}
	matched = 0
	for _, dependency := range dependencies {
		if !textEquals(dependency, "uri", "git+"+sourceURI+"@"+v.SourceRef) {
			continue
		}
		digests, err := member(dependency, "digest")
		if err != nil || !textEquals(digests, "gitCommit", p.Release.Source.Commit) {
			return errors.New("statement source commit does not match")
		}
		matched++
	}
	if matched != 1 {
		return errors.New("statement source is missing or duplicated")
	}
	run, err := member(predicate, "runDetails")
	if err != nil {
		return err
	}
	builder, err := member(run, "builder")
	if err != nil || !textEquals(builder, "id", githubBuilder) {
		return errors.New("unexpected workflow builder assertion")
	}
	// The authenticated workflow made these predicate assertions. They do not
	// independently prove recipe/material completeness, platform or reproduction.
	return nil
}
