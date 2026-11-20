package release

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

// CandidateTargets supplies independently chosen source, Docker and chain
// inputs. Services.FilesRoot is the shared signed file inventory root.
type CandidateTargets struct {
	SourcesRoot       string
	L1GenesisVerifier string
	Services          ServicesTarget
	Chain             ChainTargets
}

// CandidateObservation records the verified offline inputs and the Docker and
// chain observations made in one attempt.
type CandidateObservation struct {
	Offline  Receipt             `json:"offline"`
	Services ServicesObservation `json:"services"`
	Chain    ChainObservation    `json:"chain"`
}

// VerifyCandidate authenticates one manifest, verifies its offline inputs,
// then checks the chain while observing the signed Docker service inventory.
func (m Manifest) VerifyCandidate(ctx context.Context, p Policy, s Signatures, k TrustedKeys, targets CandidateTargets) (CandidateObservation, error) {
	count, err := m.VerifySignatures(p, s, k)
	if err != nil {
		return CandidateObservation{}, err
	}
	if targets.SourcesRoot == "" || !filepath.IsAbs(targets.L1GenesisVerifier) {
		return CandidateObservation{}, errors.New("candidate verification requires sources and an absolute NoM genesis verifier path")
	}
	if err := targets.Services.validate(); err != nil {
		return CandidateObservation{}, err
	}
	filesRoot := targets.Services.FilesRoot
	if targets.Chain.FilesRoot != "" && targets.Chain.FilesRoot != filesRoot {
		return CandidateObservation{}, errors.New("candidate verification requires one shared signed files root")
	}
	targets.Chain.FilesRoot = filesRoot
	if err := targets.Chain.validate(); err != nil {
		return CandidateObservation{}, err
	}
	offline, cfg, err := m.verifyInputs(ctx, count, filesRoot, targets.SourcesRoot, targets.L1GenesisVerifier)
	if err != nil {
		return CandidateObservation{}, fmt.Errorf("offline verification: %w", err)
	}
	expected, err := m.nodeEpochForConfiguration(cfg)
	if err != nil {
		return CandidateObservation{}, err
	}
	var chain ChainObservation
	services, err := m.observeServices(ctx, count, targets.Services, func(ctx context.Context) error {
		got, err := m.observeChain(ctx, count, targets.Chain, expected)
		if err != nil {
			return fmt.Errorf("chain observation: %w", err)
		}
		chain = got
		return nil
	})
	if err != nil {
		return CandidateObservation{}, err
	}
	if offline.ManifestSHA256 != services.ManifestSHA256 || offline.ManifestSHA256 != chain.ManifestSHA256 ||
		offline.EpochSHA256 != services.EpochSHA256 || offline.EpochSHA256 != chain.EpochSHA256 {
		return CandidateObservation{}, errors.New("candidate observations do not identify the same signed release")
	}
	return CandidateObservation{Offline: offline, Services: services, Chain: chain}, nil
}
