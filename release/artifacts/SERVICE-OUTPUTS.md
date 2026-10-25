# Current service source and output qualification

The [source cohort snapshot](qualification/service-source-darwin-arm64.json)
records independent pre-build expectations for the current Node, Relayer and
Bridge sources. It accompanies the [local-source profile](LOCAL-SOURCES.md)
and [contents schema 2](CONTENTS.md). It is qualification data, not a release
manifest or a policy automatically accepted by either command.

## Source cohort

All three repositories select Core commit
`29e6d9b30be94de3772c850c7a1e9811585a8833`, tree
`86f8c8cb55fb298674a73242a928141eebc1dee6`.
The complete Core snapshot has 112 regular files and 1,155,787 source bytes.
Every parent regular file, executable mode and Core Gitlink was included when
independently reproducing each parent Git tree and commit binding.

| Service | Selected parent commit | Parent files | Parent bytes |
| --- | --- | ---: | ---: |
| Bridge | `3f8f1197a91e530590f9e1c21ae55d358f62296d` | 33 | 214,717 |
| Relayer | `5a72a223dd60d1ae4e974d420cadd85e6f9ee929` | 23 | 170,231 |
| Node | `ae90b945b0ea95887c31cfb2f19e0b88504186d8` | 110 | 2,062,637 |

Sources were read once from retained public Git objects. No new repository,
checkout or dependency download was needed. Explicit file/member references
allow the same inputs to be reused without duplicating entire dependency trees.
Raw Git author/message data and physical runtime directories are excluded from
the public snapshot.

## Actual package observations

The recorded source graphs used Go 1.25.14 with `GOOS=darwin`, `GOARCH=arm64`,
`GOARM64=v8.0` and `CGO_ENABLED=0`, with network access denied. Exact parent and
Core exports contained no Git metadata. The Go commands used read-only module
inputs and a read-only compiler cache. All source exports, cache observations
and module inputs matched after the commands; parent cache growth was zero.

| Service | Packages | Remote modules | Local modules | Selected parent files | Selected Core files | Selected standard-library files |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Bridge | 664 | 89 | 1 | 15 | 36 | 1,250 |
| Relayer | 620 | 80 | 1 | 6 | 36 | 1,250 |
| Node | 674 | 88 | 1 | 61 | 38 | 1,264 |

Each native `go list -e -deps` observation completed with exit 0 and zero
incomplete packages, package errors or dependency errors. `-e` alone is not a
success criterion: every error-bearing package must be inspected. Counts cover
the selected command package and its dependencies, without test packages.

The snapshot includes every expected remote module coordinate, original and
effective replacement identity, and source-lock Go h1 sum. The single local
Core record keeps its requested version and selected commit/tree; no h1 sum is
invented for local source. These expectations came from source/package inputs,
before any new executable was built, rather than from binary build information.

The 1,264 distinct selected standard-library source files were content-hashed
against the retained SDK distribution manifest. The snapshot reports each
cohort's selected-file count and manifest digest. These digests cover a JSON
object mapping SDK-relative filenames to SHA-256, serialized as UTF-8 with keys
sorted, no whitespace and no trailing newline. They are source-input evidence;
the whole current SDK, compiler use and complete runtime inventory are not
established by that selected-file check.

To repeat the source observation with independently qualified inputs, select the
exact commits and Core Gitlink, use the recorded Go tool/version and target, and
run the relevant command package:

```sh
go list -p=1 -mod=readonly -trimpath -buildvcs=false -e -deps \
  -json=Dir,ImportPath,Name,Module,Standard,GoFiles,CgoFiles,CFiles,CXXFiles,HFiles,SFiles,SysoFiles,EmbedFiles,EmbedPatterns,Imports,DefaultGODEBUG,Incomplete,Error,DepsErrors \
  ./cmd/zvm-relayer
```

Use the corresponding `./cmd/zvm-node` or `./cmd/zvm-bridge` package for the
other cohorts. Keep Go environment/toolchain configuration fixed, disable
network/module resolution and inspect errors. Raw graph output contains runtime
directories and requires privacy review before sharing.

## Docker and release boundaries

The selected Dockerfiles use `golang:1.25-alpine` and `alpine:3.22` tags,
`CGO_ENABLED=0`, `-trimpath` and linker flags `-s -w`. The command package and
exact Dockerfile, ignore-file, module, checksum, workflow and Gitlink-file pins
are in the snapshot. The image tags and runtime package resolution remain
mutable. A Darwin source graph does not qualify a Linux image or resolve its
target architecture, toolchain, OS packages, runtime assets or licenses.

The captured five-repository inventory had no tags or releases. The `.github`
repository had no default branch. This records the observation, not release
policy or maintainer approval. All five original D02 adopters remain in scope:
`.github`, Core, Node, Relayer and Bridge.

The next output cohort needs a retained actual service executable from the
independently selected source/recipe/platform, followed by subject-bound SPDX
generation/check and complete contents verification. Reuse these source-side
module expectations; do not reconstruct expectations from the resulting binary.
Record any extra qualification flags and their difference from the Docker recipe.
Keep prior qualification fixtures and older project builds bound to their own
sources.

Accepted image/toolchain/build recipes, real project attestations and trusted
roots, immutable tags/checksums/notes/SBOM/package sets, supported-platform
outputs, independent distribution/reproduction and runtime/license coverage
remain open. Source and package closure does not run the services, signers,
wallets or a chain. D01/V02/epoch and maintainer/owner/operator release gates
remain separate. `releaseAccepted` stays false.
