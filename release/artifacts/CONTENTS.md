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

Schema 1 requires the explicit
[`spdx-2.3-go-buildinfo-v1` profile](SBOM.md) and `kind: binary`. Other formats and
coverage profiles are refused by that schema. Schema 2 additionally supports the
explicit [local source profile](LOCAL-SOURCES.md), as described below. Other
languages, containers and complete standard-library/OS/native/asset coverage
remain separate work.

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

## Explicit local source composition

`SourceContentsPolicy` uses `schema: 2` with the same top-level selection digest
and exact sorted artifact inventory. Every requirement has the five schema 1
members above and a required `commitObjects` array. For a remote-module profile
this array is empty. For `spdx-2.3-go-local-source-v1` it contains the sorted,
unique `File` pins for every distinct raw commit control named by that source
policy. Missing, extra, changed or differently assigned controls fail. Mixed
remote/local profiles can share controls only with identical roles and pins.
An empty, correctly pinned `goSum` is allowed only for the local-source profile;
its source-policy semantics still require zero remote modules.

The exact `content-inputs` directory includes those commit controls together
with all selected policies and parent module/checksum inputs. It excludes source
trees. The independent contents-policy digest binds this complete control set.
Schema 1 retains its exact JSON shape, receipt fields and original profile.

Local-source composition also requires a separate private mapping:

```json
{
  "schema": 1,
  "artifacts": [
    {"id": "darwin-arm64", "sources": [
      {"path": "zvm-core", "directory": "/path/to/qualified/core"}
    ]}
  ]
}
```

Artifact IDs and logical source paths are sorted and unique. The mapping covers
exactly the artifacts selecting local-source profiles and exactly their logical
Gitlink paths. No mapping is accepted for a remote-only profile. Physical
directories remain runtime inputs; policies, SBOMs and receipts contain no such
paths. Mapping documents are bounded, strict JSON, with no unknown or duplicate
members. They do not select trusted source authority.

```sh
./zvm-artifact-check -manifest manifest.json -policy policy.json -directory selected \
  -contents-policy contents-policy-v2.json -content-inputs content-controls \
  -content-sources private-source-directories.json
```

The corresponding APIs are `CheckContentsWithOptions` and
`CheckBundleWithOptions`, with `ContentsOptions.SourceDirectories` keyed first
by artifact ID, then logical source path. `CanonicalSourceContentsPolicy`
validates and serializes schema 2. The old APIs require no new options and cannot
infer a local source location. The four provenance options compose the actual
signature verifier with schema 2 in the same command.

Every selected local tree stays open after SBOM validation through signature
verification and final artifact/control checks. Late source bytes, extra files,
replaced identities or commit/control changes fail the whole operation.
`SourceContentsResult` and `SourceBundleResult` add local tree/file/byte/commit
counts and explicit false compiler-use/parent-tree assertions. Counts are per
verified artifact profile; shared inputs can be checked for several artifacts.
`sbomProfileScope` lists the sorted distinct selected profiles, comma-separated.
No local-source or signature result survives a later failure.

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

Opt-in local-Core controls also exercise the schema 2 API, complete commit
inventory, explicit runtime mapping, late source/commit changes and zero partial
receipts. Their successful signature-composition protocol is synthetic; the
unsigned actual Core qualification subject fails the actual combined verifier.

A real ZVM Go artifact signed under an accepted production workflow/root policy
is still required before claiming an actual joint project release verification.
These APIs do not create that policy, sign an artifact or publish a release.
