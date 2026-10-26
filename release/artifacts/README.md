# Offline release artifact selection

`zvm-artifact-check` checks the byte closure of an explicitly selected release
package against an independently supplied policy. Its default mode checks bytes.
An optional mode adds actual signature and exact source/workflow verification
through a pinned local GitHub CLI and local trust root. Neither mode builds or
executes subjects, unpacks archives, analyzes SBOM contents, authenticates a tag
or accepts a release.

```sh
go build -o zvm-artifact-check ./cmd/zvm-artifact-check
./zvm-artifact-check -manifest manifest.json -policy policy.json -directory selected
```

Keep the two documents outside `selected`. The dedicated directory must contain
exactly the declared payload and sidecar files and their necessary directories.
The synthetic [manifest](testdata/synthetic/manifest.json),
[policy](testdata/synthetic/policy.json) and [selected files](testdata/synthetic/payloads)
are a runnable shape/byte vector. Its subject is plain fixture text, its
provenance is unsigned and its SBOM is intentionally incomplete. Selection
success for that vector proves none of those assertions.

A successful default receipt reports `selectionVerified: true` with exact counts and
document digests. `provenanceSignaturesVerified`, `sbomContentsVerified` and
`releaseAccepted` remain false. Errors return no partial success receipt. Local
input paths are excluded from command errors. Manifest SHA-256 hashes the exact
supplied bytes; policy SHA-256 hashes the fixed-field schema serialization, not
arbitrary input whitespace. This is not a general JSON canonicalization scheme.

## Independent expectations

Policy schema 1 fixes the repository commit/tree and explicit Gitlink inventory,
release/epoch/qualification references, observed tag commit, workflow source,
build recipe/environment policy, ordered flags and sorted toolchain/image/material
digests. These are compared exactly with the manifest. The caller must obtain and
authenticate that policy independently. Copying expectations from the untrusted
manifest does not establish authority. The checker does not inspect a Git checkout,
validate CI evidence or authenticate a supplied source/recipe/qualification hash.

Each sorted artifact requirement selects its kind, platform, subject filename,
SBOM filename and provenance filename. Every required filename must appear once
in the manifest's sorted file pins. Shared sidecars of one role are permitted;
subjects and different roles cannot alias. Release notes and checksums have
separate roles. Missing or additional artifacts, platform changes, duplicate IDs,
case and file/directory aliases and unsupported filenames are refused.

The exact checksums text contains one `<lowercase SHA-256>  <relative path>` line
with LF for every selected file except the checksums file itself, in bytewise path
order. The manifest pins the checksum file, avoiding a self-hash cycle. This checks
the actual checksums content rather than only hashing an unrelated text file.

## Bounds and filesystem scope

- Documents are valid UTF-8 JSON, at most 1 MiB, with exact case-sensitive required
  members. Unknown, missing, duplicate and escaped duplicate members, null arrays,
  wrong types and trailing data fail. Lists, strings and numeric values are bounded.
- At most 64 artifacts and 256 unique selected files are accepted. Each file is
  nonempty and at most 1 GiB; the complete file set is at most 4 GiB. Payloads are
  streamed through SHA-256; neither contents nor archives are retained in memory.
- Paths use a portable ASCII grammar, at most 256 bytes, eight components and
  64 bytes per component. Traversal, absolute paths, reserved device names,
  trailing-dot aliases, control/space characters and `.git` components fail.
- Native file checks currently support Linux and macOS hosts. Other hosts compile
  but return an explicit unsupported error. Platform labels in policy are claims
  to be matched, not proof that the artifact runs on that platform.
- A rooted directory confines lookups. Symlink ancestors/final entries, hard-linked
  files, nonregular entries and extra directories are refused. Final opens use
  no-follow/nonblocking flags, so substitution with a FIFO cannot block a regular
  read. File and directory identities, byte counts, modes and modification times
  are compared around enumeration/streaming and checked again at completion.

This is a bounded read/identity observation of a dedicated directory, not an
operating-system sandbox or a lock against a hostile concurrent owner. Cryptographic
hash equality identifies the consumed bytes. It does not certify future paths,
contents inside an archive or OCI layers, source honesty, license inventory,
supported platforms, reproducible builds, signer authority or chain deployment.

## Selected GitHub provenance verification

Use all four additional options to enable `CheckProvenance`:

```sh
./zvm-artifact-check -manifest manifest.json -policy policy.json -directory selected \
  -provenance-policy provenance-policy.json -verifier "$VERIFIER_PATH" \
  -trusted-root trusted-root.jsonl -temporary-directory "$OWNED_SCRATCH"
```

The verifier path must be absolute, regular, executable and bounded, with exactly
one filesystem link.
Its exact SHA-256 and the local trust-root bytes must match the separately selected
provenance policy. Tool paths are runtime inputs and never appear in receipts.
The root must be one complete JSON record with a final LF. The process receives
only explicit local bundle/root arguments and an isolated configuration/cache
directory, with no inherited credentials or home configuration. It does not ask
for authentication, run `trusted-root`, update TUF or acquire a bundle through the
API. The caller must provision and authenticate both inputs and enforce runner
network/host isolation independently. The implementation is not an OS sandbox.

Provenance policy schema 1 has exactly these required members:

```json
{
  "schema": 1,
  "verifierSha256": "<independent verifier SHA-256>",
  "trustedRootSha256": "<independent local root SHA-256>",
  "sourceRef": "refs/tags/v0.1.0",
  "signer": {
    "repository": "Example/builders",
    "workflowPath": ".github/workflows/release.yml",
    "ref": "refs/heads/main",
    "commit": "<exact signer commit>"
  },
  "artifacts": [{
    "id": "linux-amd64",
    "subjectName": "zvm-linux-amd64",
    "digestAlgorithm": "sha256"
  }]
}
```

Replace every angle-bracket placeholder with an independently reviewed pin.
The sorted artifact IDs must exactly cover the selection policy. SHA-256 and
SHA-512 subjects are supported; SHA-512 is streamed together with SHA-256 to
preserve the manifest binding. Each required sidecar must be exactly one JSON
DSSE bundle. Concatenated records and collections are refused before invocation:
an external verifier's success for a filtered subset cannot accept the package.
Bundle and result JSON reject duplicate, escaped duplicate and case aliases.

The verifier enforces the selected source repository/commit/ref, exact signer
workflow SAN/commit, GitHub OIDC issuer, SLSA v1 predicate and hosted-runner policy.
Its authenticated certificate must additionally match the source build-config
URI and commit. A reusable signer's identity remains separate from the caller's
source/config identity. The sole returned result must contain verified timestamp
evidence, the exact subject name/digest and matching source/workflow/builder
predicate assertions. Every required artifact must pass. The original observed
file inventory is checked again after all invocations; no partial receipt survives
a later failure or changed file set.

Each child is bounded to 30 seconds, 1 MiB stdout and 64 KiB stderr. Output and
diagnostics remain private; errors do not echo certificate contents or paths.
Only small sidecars and the root are copied into the owned temporary directory.
Subjects are not copied or extracted. The tool is hashed once, and its observed
identity is held and checked through completion. As with selection, the caller
must trust the local host and exclude hostile concurrent ownership changes.

A successful provenance receipt sets `provenanceSignaturesVerified` and
`workflowIdentityVerified` true and reports exact policy/tool/root hashes and an
artifact count. It keeps `buildRecipeReproduced`, `sbomContentsVerified` and
`releaseAccepted` false. Certificate extensions authenticate workflow/source
identities; signed predicate fields remain assertions by that workflow. This
does not independently verify tree/Gitlink/material completeness, recipe inputs,
build flags, platform capability, SLSA level, reproducibility, current owner
approval or the authority to publish a release.

## Actual offline signature control

Unit protocol controls use explicitly synthetic results and prove no cryptography.
The opt-in `TestActualOfflineGitHubSignatureFixture` executes the real provisioned
verifier against the public `sigstore-js-2.1.0` fixture, including source/ref/signer,
changed subject and changed signature refusals. Without its inputs it is explicitly
skipped. Ordinary source CI must not be presented as that external integration.

Provision these files without extracting the subject, from
[`cli/cli@55dbb4dc`](https://github.com/cli/cli/tree/55dbb4dc6b7edb10b48e3d7fc5bccd32318d1b55/pkg/cmd/attestation/test/data):

| Local fixture name | Upstream fixture | SHA-256 |
| --- | --- | --- |
| `subject.tgz` | `sigstore-js-2.1.0.tgz` | `f0c641fce0310cb43208f4272dc1423153630e44ba8cdc0b5ce8466f724e0eed` |
| `bundle.json` | `sigstore-js-2.1.0-bundle.json` | `cfadddd579b9fb45947530cd0e860986ec610a28f7fa6de3ef31cc051f07f761` |
| `trusted-root.json` | `trusted_root.json` | `455b3fe53e2678889f093d66ebbfda5f12ebb9d682b146c3535fa04e97689787` |

Set `ZVM_ATTESTATION_VERIFIER`, `ZVM_ATTESTATION_VERIFIER_SHA256` and
`ZVM_ATTESTATION_FIXTURE_DIRECTORY` explicitly, then run `go test ./release/artifacts`.
Tests perform no transport and require the fixed subject/bundle/root hashes before
using them. The historical fixture trust policy applies only to this public
control; it is neither a ZVM release nor an adopted ZVM signer/trust policy. Source
interfaces were reviewed at GitHub CLI 2.97.0. A new verifier version or platform
requires independently selected executable pins and fresh qualification.

## Remaining release work

Adopt an independently reviewed production verifier/root/workflow policy and
qualify actual project bundles on supported verifier hosts. Validate the selected SBOM
schema, generator inputs and subject/dependency coverage separately. Generate
qualified platform outputs, immutable checksums/provenance/SBOMs and release
notes from the selected candidate; independently verify the actual distribution.
Protected tag/publication policy, owner signatures and chain-epoch/operator
acceptance remain external gates. Neither mode makes publication changes or
grants those decisions.

## Actual Relayer output qualification

The [initial Darwin arm64 Relayer result](qualification/relayer-output-darwin-arm64.json)
records one actual trimpath build, its selected Go/source SPDX check and three
refusals using retained qualified tools. The profile counts 80 remote modules
and one local Core module. That output/profile snapshot preserves its initial
caller-count failure, metadata-only reconciliation and original scope.

The [parent/source contents follow-up](qualification/relayer-parent-contents-darwin-arm64.json)
reuses the same executable and SPDX bytes. It checks 23 Relayer files, the exact
Core Gitlink, 112 Core files and 81 module records together. Repeat receipts
match; four actual selection/content refusals emit no success output. The same
88,730-byte SPDX document separately passes its pinned official schema and six
malformed controls. No native rebuild or dependency download is needed.

The follow-up uses an explicitly synthetic release/epoch/tag/workflow envelope.
It establishes local byte/source consistency, with project provenance,
independent reproduction, complete runtime/license coverage and release
acceptance still open. Neither record distributes a binary or SPDX payload.
