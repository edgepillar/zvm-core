# Selected artifact, signature and SBOM composition

`CheckContents` verifies the complete selected byte inventory and every explicitly
selected Go SBOM profile inside the same observed artifact directory. `CheckBundle`
additionally invokes the real independently pinned signature verifier in that
observation. Failure at any stage returns no partial success receipt.

```sh
./zvm-artifact-check -manifest manifest.json -policy policy.json -directory selected \
  -contents-policy contents-policy.json -content-inputs content-controls
```

Add the four provenance options from the [provenance guide](README.md) to require
both checks. Supplying only part of either option group fails. The default
byte-only command and provenance-only command retain their previous meanings.

## Independent content expectations

Contents policy schema 1 requires `schema`, `selectionPolicySha256` and a sorted
`artifacts` array that exactly covers every artifact ID in the selection policy.
`selectionPolicySha256` hashes `CanonicalPolicy` of that independent selection
policy, binding the source/build/release expectations before any file is read.
Each requirement has exactly these members:

```json
{
  "id": "darwin-arm64",
  "profile": "spdx-2.3-go-buildinfo-v1",
  "policy": {"path": "darwin-arm64.json", "bytes": 1234, "sha256": "<exact Go policy SHA-256>"},
  "goMod": {"path": "source/go.mod", "bytes": 123, "sha256": "<exact go.mod SHA-256>"},
  "goSum": {"path": "source/go.sum", "bytes": 456, "sha256": "<exact go.sum SHA-256>"}
}
```

Replace the illustrative byte counts and placeholders with independently
qualified pins. Keep the contents policy outside `content-controls`. That
dedicated directory must contain exactly the named control files and necessary
directories. Shared controls are permitted only when their role and entire file
pin agree. Extra/missing entries, unsafe paths, aliases, links and nonregular
files fail. Documents are at most 1 MiB each, the unique input set is at most
32 MiB, and the existing artifact/control count limits apply. No dependency
tree, source checkout, input archive or executable is copied into this directory.

Every selected artifact currently requires the explicit
[`spdx-2.3-go-buildinfo-v1` profile](SBOM.md) and `kind: binary`. Other formats and
coverage profiles are refused. Local replacements, other languages, containers
and complete standard-library/OS/native/asset coverage remain separate work.

The Go policy must match the artifact's exact relative path, bytes and SHA-256,
source repository/commit/tree/Gitlink inventory, qualification reference and
GOOS/GOARCH platform. Its module/checksum hashes must equal the control pins.
The actual selected SBOM is checked against that independently supplied policy
and the actual Go executable. Copying expected modules from the executable or
expectations from an untrusted archive does not establish independent authority.

All selected SBOM files must pass. After the signature stage, the control-file
inventory and identities are checked again; the selected artifact inventory is
also checked at completion. Observed substitutions and late extra files fail.
This is a bounded identity/byte observation on a trusted local host, not an OS
sandbox or a lock against a hostile concurrent owner.

## Result scope

In contents mode, `sbomContentsVerified: true` means every named SBOM matched its
explicitly selected Go profile and cross-policy bindings. `sbomProfileScope`,
profile/module counts and control-file count make that scope explicit.
`provenanceSignaturesVerified` remains false unless signature mode was actually
required and passed. Combined mode reports both checks only after all stages pass.

`completeRuntimeInventoryEstablished`, `licenseCoverageEstablished`,
`sourceCommitAuthenticated`, `toolchainIdentityAuthenticated`, build reproduction
and `releaseAccepted` remain false. Signed certificate/workflow identities and
profile assertions do not independently prove complete runtime/license coverage,
source/toolchain honesty, owner trust, a deployed system or publication authority.

## Qualification boundaries

The opt-in actual Go-subject controls exercise real binary metadata and actual
generated SBOM documents. Composition protocol controls use explicitly synthetic
verifier results to test callback ordering, output fields, cross-policy refusal,
late control mutation and failure atomicity. They are not actual signature
verification. The existing genuine signed public fixture retains its separate
subject/trust policy and cryptographic qualification.

A real ZVM Go artifact signed under an accepted production workflow/root policy
is still required before claiming an actual joint project release verification.
These APIs do not create that policy, sign an artifact or publish a release.
