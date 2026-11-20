package release

import (
	"context"
	"errors"
	"path/filepath"
)

type Receipt struct {
	ManifestSHA256         string `json:"manifestSha256"`
	EpochSHA256            string `json:"epochSha256"`
	TrustedSignatures      int    `json:"trustedSignatures"`
	VerifiedRepositories   int    `json:"verifiedRepositories"`
	VerifiedFiles          int    `json:"verifiedFiles"`
	VerifiedL1Genesis      bool   `json:"verifiedL1Genesis"`
	VerifiedContractBuilds int    `json:"verifiedContractBuilds"`
	CompilerExecuted       bool   `json:"compilerExecuted"`
	Scope                  string `json:"scope"`
	RuntimeObserved        bool   `json:"runtimeObserved"`
}

// Verify authenticates the declared inventory before reading files or running
// bounded, read-only Git commands. A receipt covers offline inputs only.
func (m Manifest) Verify(ctx context.Context, p Policy, s Signatures, k TrustedKeys, filesRoot, sourcesRoot string) (Receipt, error) {
	return m.verify(ctx, p, s, k, filesRoot, sourcesRoot, "")
}

// VerifyWithL1Genesis also reconstructs the signed NoM genesis using an
// independently provisioned local verifier. The manifest cannot select it.
func (m Manifest) VerifyWithL1Genesis(ctx context.Context, p Policy, s Signatures, k TrustedKeys, filesRoot, sourcesRoot, verifier string) (Receipt, error) {
	if !filepath.IsAbs(verifier) {
		return Receipt{}, errors.New("an absolute path to a trusted NoM genesis verifier is required")
	}
	return m.verify(ctx, p, s, k, filesRoot, sourcesRoot, verifier)
}

func (m Manifest) verify(ctx context.Context, p Policy, s Signatures, k TrustedKeys, filesRoot, sourcesRoot, l1Verifier string) (Receipt, error) {
	var r Receipt
	count, err := m.VerifySignatures(p, s, k)
	if err != nil {
		return r, err
	}
	files, err := m.VerifyFiles(filesRoot)
	if err != nil {
		return r, err
	}
	if err := m.verifyEpochFiles(ctx, filesRoot, l1Verifier); err != nil {
		return r, err
	}
	repos, err := m.VerifySources(ctx, sourcesRoot)
	if err != nil {
		return r, err
	}
	builds, err := m.VerifyContractBuilds(filesRoot, sourcesRoot)
	if err != nil {
		return r, err
	}
	manifest, err := m.Fingerprint()
	if err != nil {
		return r, err
	}
	epoch, err := m.EpochFingerprint()
	if err != nil {
		return r, err
	}
	genesis := "L2 construction"
	if l1Verifier != "" {
		genesis = "L2 construction and NoM genesis momentum reconstruction"
	}
	return Receipt{
		ManifestSHA256: manifest, EpochSHA256: epoch, TrustedSignatures: count,
		VerifiedRepositories: repos, VerifiedFiles: files, VerifiedL1Genesis: l1Verifier != "",
		VerifiedContractBuilds: builds,
		Scope:                  "offline signed inventory, file bytes, " + genesis + ", Git snapshots and declared saved build consistency",
	}, nil
}
