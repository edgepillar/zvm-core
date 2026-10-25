# Offline release artifact selection

`zvm-artifact-check` checks the byte closure of an explicitly selected release
package against an independently supplied policy. It does not build or execute
the subjects, unpack archives, fetch inputs, verify signatures, analyze SBOM
contents, authenticate a tag or accept a release.

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

A successful receipt reports `selectionVerified: true` with exact counts and
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

## Remaining release work

Connect a pinned supported provenance verifier to actual signed bundles and an
independent workflow/repository/ref trust policy. Validate the selected SBOM
schema, generator inputs and subject/dependency coverage separately. Generate
qualified platform outputs, immutable checksums/provenance/SBOMs and release
notes from the selected candidate; independently verify the actual distribution.
Protected tag/publication policy, owner signatures and chain-epoch/operator
acceptance remain external gates. The current checker makes no network calls or
publication changes and cannot grant those decisions.
