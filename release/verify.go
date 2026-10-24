package release

import "context"

type Receipt struct {
	ManifestSHA256         string `json:"manifestSha256"`
	EpochSHA256            string `json:"epochSha256"`
	TrustedSignatures      int    `json:"trustedSignatures"`
	VerifiedRepositories   int    `json:"verifiedRepositories"`
	VerifiedFiles          int    `json:"verifiedFiles"`
	VerifiedContractBuilds int    `json:"verifiedContractBuilds"`
	CompilerExecuted       bool   `json:"compilerExecuted"`
	Scope                  string `json:"scope"`
	RuntimeObserved        bool   `json:"runtimeObserved"`
}

// Verify authenticates the declared inventory before reading files or running
// bounded, read-only Git commands. A receipt covers offline inputs only.
func (m Manifest) Verify(ctx context.Context, p Policy, s Signatures, k TrustedKeys, filesRoot, sourcesRoot string) (Receipt, error) {
	var r Receipt
	count, err := m.VerifySignatures(p, s, k)
	if err != nil {
		return r, err
	}
	files, err := m.VerifyFiles(filesRoot)
	if err != nil {
		return r, err
	}
	if err := m.VerifyEpochFiles(filesRoot); err != nil {
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
	return Receipt{ManifestSHA256: manifest, EpochSHA256: epoch, TrustedSignatures: count, VerifiedRepositories: repos, VerifiedFiles: files, VerifiedContractBuilds: builds, CompilerExecuted: false, Scope: "offline signed inventory, file bytes, L2 construction, Git snapshots and declared saved build consistency", RuntimeObserved: false}, nil
}
