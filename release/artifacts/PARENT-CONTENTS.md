# Parent source, artifact contents and provenance binding

`zvm-artifact-check -parent-sources FILE` adds complete parent-source observation
to an independently selected contents check. Every selected artifact requires
one parent policy, its independently selected SHA-256, a complete regular-file
export and dedicated raw commit controls. This opt-in consumer binds the
[source preflight](SOURCE-TREES.md) to the selected artifact, SPDX profile and
optional provenance observation.

```sh
go build ./cmd/zvm-artifact-check
./zvm-artifact-check -manifest manifest.json -policy selection-policy.json \
  -directory artifacts -contents-policy contents-policy.json \
  -content-inputs sbom-controls -content-sources local-sources.json \
  -parent-sources parent-inputs.json
```

`-content-sources` is required only when the selected contents profile includes
local replacements. `-parent-sources` requires contents controls. To include
signatures, additionally supply the existing complete provenance option set:
`-provenance-policy`, `-verifier`, `-trusted-root`, `-temporary-directory`.

## Independent input selection

The parent mapping is private runtime configuration, not an artifact, manifest
field or source of trust. For example, with illustrative absolute locations:

```json
{
  "schema": 1,
  "artifacts": [
    {
      "id": "darwin-arm64",
      "policy": "/qualification/parent-policy.json",
      "policySha256": "INDEPENDENTLY_SELECTED_PARENT_POLICY_SHA256",
      "directory": "/qualification/parent-export",
      "controls": "/qualification/parent-commit-controls"
    }
  ]
}
```

Replace the digest placeholder with the lowercase 64-character SHA-256 obtained
from independent input selection. Calculating a digest from an untrusted
replacement policy does not choose accepted source. Artifact IDs must be sorted,
unique and match the complete selected artifact set. Policy, source and control
locations must be absolute. Unknown/duplicate fields and trailing documents fail.
Physical locations are not emitted in result receipts.

Each parent policy uses `git-go-source-tree-v1`. Its repository label, commit,
tree and complete Gitlink list must exactly equal the independent selection
policy's release source. Its `go.mod` pin must match the selected contents input;
its tracked `go.sum` pin must match the selected checksum input. A missing
tracked `go.sum` is permitted only for an independently selected empty lock;
the contents control still exists and is checked. A valid parent export for
another release fails even if its files and Git objects are self-consistent.

Parent controls contain only their selected raw commit and required directories.
They are distinct from the SBOM control directory. Parent Gitlink directories
must be absent; local replacement contents use the existing separate private
mapping and source controls. The selected SBOM policy still binds the executable,
module inventory, lock inputs, release source, platform and qualification hash.

No existing contents format is extended. Schemas 1 and 2 retain their exact
shape and behavior. A standalone source receipt or a caller-created success
flag cannot enable parent binding in an older contents API.

## One retained observation

The new consumer keeps the parent source/control observations open while
checking artifact bytes, selected SPDX contents, local replacement sources and,
when requested, provenance signatures. Final inventory and identity checks cover
parents, child sources, contents controls, selected artifacts and the pinned
verifier. A late parent file, extra entry, replaced identity or commit/control
change refuses the whole result. Errors return no partial success receipt.

The API entry points are `CheckContentsWithParentSources` and
`CheckBundleWithParentSources`. `ParentContentsOptions` supplies the existing
`ContentsOptions` and a complete map of artifact IDs to `GoParentSourceInput`.
Each input contains immutable policy bytes, the independent policy SHA-256 and
explicit source/control locations. `ReadParentSourceInputs` is the CLI mapping
reader; applications may instead provision input bytes directly.

Successful receipts add profile `git-go-parent-contents-v1`, counts for parent
policies/trees/files/bytes/commit controls/Gitlinks and
`parentSourcePolicySetSha256`. The latter hashes compact JSON for the sorted
artifact list, with each object encoded as `{"id":ID,"policySha256":DIGEST}` in
that field order. This commits the receipt to the independently supplied parent
policy set without exporting physical paths. Counts cover each selected
artifact's observation; reused source directories can be counted more than once.

Only these new opt-in results can report `parentSourceTreeVerified: true`.
Existing local-source counts retain their separate scope. Without provenance
options, `provenanceSignaturesVerified` remains false. A signature-protocol test
using a synthetic callback is not an actual cryptographic or project release
verification.

The consumer does not prove compiler use of those trees, source/toolchain
authority, complete child/runtime/license coverage, independent build
reproduction or accepted release policy. `compilerUseOfTreesProven`,
`sourceCommitAuthenticated`, `toolchainIdentityAuthenticated`,
`completeRuntimeInventoryEstablished`, `licenseCoverageEstablished` and
`releaseAccepted` remain false. Hosts and independent input selection must be
trusted, and hostile writers excluded; observations are not operating-system
locks or hardware durability proof.

The explicit parent layer supports at most 16 selected artifacts per call.
Each parent retains the source preflight's 1 MiB policy/commit limits,
256-file/64-Gitlink inventory, 16 MiB per file and 64 MiB total file limits.
The aggregate parent policy input is also bounded. Native file verification
currently supports Linux and macOS.

Full positive source/SPDX composition tests need independently provisioned parent
and local-Core subject fixtures. Ordinary hosted source CI cannot establish
that fixture qualification through skipped tests. Actual service/platform
outputs, accepted recipes/images/toolchains, project attestations, distribution,
reproduction and maintainer/owner release acceptance remain separate D02 gates.
