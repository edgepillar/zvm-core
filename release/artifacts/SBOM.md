# Selected SPDX 2.3 Go build inventory

`zvm-sbom` generates or checks the bounded `spdx-2.3-go-buildinfo-v1` profile.
It reads an independently selected, qualified Go executable and its exact
source-side expected module inventory, `go.mod` and `go.sum`. The executable is
never run, extracted or used to infer its own expected module list. There are no
module resolution, download or installation operations in this command.

```sh
go build -o zvm-sbom ./cmd/zvm-sbom
./zvm-sbom -policy go-sbom-policy.json -go-mod go.mod -go-sum go.sum \
  -subject selected-tool > selected-tool.spdx.json
./zvm-sbom -policy go-sbom-policy.json -go-mod go.mod -go-sum go.sum \
  -subject selected-tool -check selected-tool.spdx.json
```

Select the expected module inventory independently from the exact qualified
source/package graph and lock inputs. A policy copied from the executable's own
embedded records does not establish completeness. A source-side `go list -deps`
observation must retain its source, target, compiler, lock/cache identities and
actual exit/completeness evidence. It does not establish native OS/container,
embedded asset or other-language dependency coverage.

## Policy and inputs

Policy schema 1 requires every member in `GoSBOMPolicy`: profile, subject relative
path/size/SHA-256, source repository/commit/tree/Gitlink inventory, independent
qualification reference, exact `go.mod`/`go.sum` hashes, main package/module/version,
Go version, sorted exact build settings, sorted complete expected Go module
records, document name, independently selected HTTPS namespace and canonical UTC
creation time. The namespace must be globally unique for that document; its URI
does not publish it or prove ownership. Creation time is explicit, never sampled
from the local clock. Identical pinned inputs produce identical SPDX bytes.

Each module record preserves `path`, `version`, `replacement`, `effectivePath`,
`effectiveVersion` and `sum`. Replacement is `none` or `versioned`. For example:

```json
{
  "path": "example.invalid/original",
  "version": "v1.2.3",
  "replacement": "versioned",
  "effectivePath": "example.invalid/replacement",
  "effectiveVersion": "v1.3.0",
  "sum": "<independently locked Go h1 checksum>"
}
```

The effective module must match the actual embedded replacement and the selected
`go.sum` content checksum record. A `/go.mod` checksum alone does not satisfy the
content record. Local filesystem replacements need a separate independently
qualified source/tree profile and are refused here. Their raw paths are never
copied into a document or diagnostic. No replacement source is downloaded.

The selected profile currently requires an `exe` built by `gc`, `-trimpath=true`,
`CGO_ENABLED=0`, explicit GOOS/GOARCH and exact remaining embedded build settings.
All expected module records must be present exactly once, including transitively
recorded modules; extra, missing or changed records fail. Metadata is an observation
of the selected bytes, not authentication of an honest compiler or source tree.

Documents/lock inputs are at most 1 MiB. There are at most 254 expected modules
and 32 build settings. Subject bytes are streamed through SHA-256 before the
build metadata is decoded. Metadata reads retain a 1 MiB per-read
and 16 MiB cumulative budget. Thin little-endian Mach-O executables for amd64
and arm64 use a bounded explicit `__go_buildinfo` section reader for Go 1.18+
inline metadata. Load commands/section spans, unique section selection, framing
and CPU/settings agreement are checked before reading at most 1 MiB of metadata.
Unrelated symbol/string/relocation tables are never loaded. Other executable
formats retain the bounded standard-library reader. This is build-inventory
parsing, not complete executable-format or OS-loader validation. Rooted no-follow regular-file opens and observed
identity/size/mode/time/link checks preserve the existing filesystem scope. Native
file operations support Linux and macOS; reading a platform label does not qualify
execution on that platform. The caller must trust the local host and prevent
hostile concurrent ownership changes.

## SPDX content and checks

The document uses SPDX 2.3 JSON, CC0-1.0 metadata and a tool-only creator. Packages
represent the selected executable, independently supplied source reference,
reported Go toolchain version and effective dependency modules. SPDX IDs and
relationships are deterministic and sorted. The document describes the artifact;
source is `GENERATED_FROM`, the compiler is `BUILD_TOOL_OF`, and the flat embedded
module records are `BUILD_DEPENDENCY_OF`. No direct/transitive dependency graph
edges are invented from the flat build-info list.

The executable package's SHA-256 identifies its complete distributed bytes. Go
`h1` sums identify canonical module file trees. They are retained as Go-specific
external references and are never mislabeled as file/archive SHA-256 checksums.
There is no file-analysis verification code, source-file inventory, package file
list or claim that `filesAnalyzed` is true.

Licenses, copyright and download locations are `NOASSERTION`. The standard
library's individual files, OS/native libraries, embedded assets, container
packages and license/copyright coverage remain unqualified. `CGO_ENABLED=0`
does not certify the absence of operating-system dependencies. The reported Go
version does not authenticate toolchain bytes. Source/qualification references
are independently supplied expectations and are not proven by embedded metadata.

`CheckGoSBOM` accepts this exact profile against independently regenerated expected
content. It rejects changed subjects/checksums, module omissions/additions,
duplicate or dangling IDs/relationships, unsupported schema/profile, changed
coverage claims, unknown members and duplicate/escaped/case-aliased JSON. Object
member order and whitespace may vary; canonical array order and all content must
match. This is a strict profile consumer, not a general SPDX document validator.

A successful receipt reports `spdxProfileVerified`, `subjectBytesVerified`,
`goBuildInfoMatched` and `lockedModulesMatched`. `sourceCommitAuthenticated`,
`toolchainIdentityAuthenticated`, `completeRuntimeInventoryEstablished`,
`licenseCoverageEstablished` and `releaseAccepted` remain false. The existing
default artifact-selection result's `sbomContentsVerified` is unchanged. Optional
[contents composition](CONTENTS.md) verifies every explicitly selected Go profile
and cross-policy binding inside the closed file observation; that scoped mode
can report content verification while retaining false runtime/license/release
acceptance. A valid profile or schema is not a production acceptance decision.

## Qualification

Unit controls distinguish synthetic metadata from actual executable parsing.
The opt-in actual subject tests require `ZVM_GO_SBOM_FIXTURE_DIRECTORY` containing
`policy.json`, `go.mod`, `go.sum` and the independently pinned `subject`. They
generate twice, verify exact bytes and check altered subject/module/schema/
relationship and coverage records. Without provisioned inputs those tests are
explicitly skipped; ordinary source CI is not actual external-input qualification.

Validate generated content separately against the official
[`spdx/spdx-spec@6f2cb47d`](https://github.com/spdx/spdx-spec/blob/6f2cb47d13db19b12c23885573b22ef32ec1ada5/schemas/spdx-schema.json)
JSON schema (47,602 bytes, SHA-256
`4126dc29f15e92feec92e9622f4939131ad58b125d6f578aa93e980a6e6f3212`).
That specification/schema is maintained by the SPDX contributors under its
[CC BY 3.0 license](https://github.com/spdx/spdx-spec/blob/6f2cb47d13db19b12c23885573b22ef32ec1ada5/LICENSE).
The repository does not vendor the schema or install a validator. Schema-engine
qualification and negative schema controls retain their exact tool/source pins
and actual results separately; no library-generated receipt claims a general
schema-engine execution.

Original D02 still needs other Go/local-source profiles, Node/web and container
inventories, supported platform packages, actual signed project sidecars,
independent distribution/reproduction and owner/operator release acceptance.

The additional opt-in `ZVM_CORE_CLI_FIXTURE_DIRECTORY` uses the same four-file
input layout for an independently qualified real `cmd/zvm` subject. It exercises
the actual source-side transitive module inventory and versioned op-geth
replacement, rather than assuming a one-module tool fixture. This control reads
the subject without execution; fixture provisioning retains its original source,
build and qualification receipts. It does not relabel an older retained build as
a newly compiled current-head output.
