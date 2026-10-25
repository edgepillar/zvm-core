# Deterministic selected-file ZIP package

`zvm-artifact-pack` streams a canonical `zip-store-v1` package from an independently
selected manifest, selection policy and dedicated file directory. It uses the
explicit manifest inventory, never recursive filesystem packaging. A separate
consumer checks an independently size/SHA-256-pinned archive without extraction.

```sh
go build -o zvm-artifact-pack ./cmd/zvm-artifact-pack
./zvm-artifact-pack -manifest manifest.json -policy policy.json \
  -archive-policy archive-policy.json -directory selected > candidate.zip
./zvm-artifact-pack -manifest manifest.json -policy policy.json \
  -archive-policy archive-policy.json -check candidate.zip -archive-pin candidate-pin.json
```

Binary ZIP output is streamed directly to the caller's output. A nonzero exit,
incomplete transport or failed writer leaves output unverified; retain the actual
failure and never publish those bytes as successful. Production callers must own
their output/spool, allocation limit and retention/promotion process. The command
does not choose or clean arbitrary output paths.

## Independent archive expectations

Archive policy schema 1 requires exactly `schema`, `format`, `manifestSha256`,
`selectionPolicySha256` and `sourceDateEpoch`. Format is `zip-store-v1`.
`manifestSha256` hashes the exact independently qualified manifest bytes;
`selectionPolicySha256` hashes `CanonicalPolicy` of the independent selection
policy. The epoch is an explicit even UTC Unix second between 1980 and the end
of 2105. It is not sampled from the clock or copied from host file metadata.

Archive pin schema is the existing exact `File` object: portable logical `path`,
exact `bytes`, and lowercase `sha256`. Obtain this pin independently of the
untrusted archive. The copied `manifest.json` and `policy.json` inside the ZIP
are compared with external expectations and never adopted as trust inputs.

Entries are exactly `manifest.json`, canonical `policy.json` and
`payloads/<selected path>` for each manifest file, sorted bytewise by entry name.
There are no implicit directory entries, source trees, caches or additional files.
Metadata entries and sidecars use mode 0644; subjects explicitly selected as
`binary` use 0755. Host modes, ownership, times, extended attributes and names
outside the declared inventory do not influence package bytes.

The profile uses uncompressed ZIP Store, fixed UTF-8 flags, Unix regular-file
modes, explicit UTC timestamp data, no comments, one disk and ZIP32 offsets/counts.
This avoids compressor-version changes. The archive is at most 4 GiB minus one
byte; selected payloads leave a bounded metadata margin. Existing file/manifest
bounds still apply. Larger/other archive formats require another explicit profile.

## Stream and consumer checks

Before and during production, exact byte/checksum closure and regular no-follow
file identities are checked. Each payload is streamed through SHA-256 while it
is written. Observed substitution, changed bytes, late extra files and short or
failed output fail without a success receipt. ZIP finalization occurs before the
final selected-directory identity observation. Subjects are not executed.

Consumption first checks the independent whole-archive size/SHA-256, then bounded
single-disk EOCD metadata before constructing the standard-library ZIP reader.
Every entry name, order, method, flag, mode, timestamp, extra field, size and
payload digest/CRC must match. Canonical reconstruction is streamed only into a
hash sink and must equal the consumed archive's exact size/hash. No reconstructed
archive file or extracted dependency tree is created. Prefix/suffix padding,
alternate local headers, duplicate/extra entries and altered physical layouts
cannot pass merely because central-directory payload names look right.

The archive API reports byte selection and deterministic metadata only.
`provenanceSignaturesVerified`, `sbomContentsVerified` and `releaseAccepted` remain
false. Verify actual signature and SBOM content policy through the
[contents composition](CONTENTS.md) and independently provisioned controls.
Reproducible ZIP bytes do not establish reproducible compilation, all-platform
execution, source/toolchain honesty, a trusted owner or an accepted release.

Local qualification must bind actual produced bytes and retain outputs before
later checks. A repeat packaging control compares actual bytes for the same
inputs; a second build or another host's reproduction is separate evidence.
Original D02 still requires qualified supported-platform project outputs,
actual signed project sidecars, complete chosen inventories, independent
download/reproduction and owner/operator/epoch publication acceptance.
