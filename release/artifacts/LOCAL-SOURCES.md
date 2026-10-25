# Go SBOM profile for independently pinned local source

Node, Relayer and Bridge select Core through a local `./zvm-core` replacement.
Those bytes have no versioned-module Go h1 checksum. The separate
`spdx-2.3-go-local-source-v1` profile binds each local replacement to independent
source-file and Git-object expectations, alongside the complete expected remote
module inventory. It does not infer expectations from the executable or invent
a module checksum for local source.

```sh
./zvm-sbom -policy source-policy.json -go-mod go.mod -go-sum go.sum \
  -subject selected-program -source-inputs private-directories.json \
  -source-controls commit-controls > selected-program.spdx.json
./zvm-sbom -policy source-policy.json -go-mod go.mod -go-sum go.sum \
  -subject selected-program -source-inputs private-directories.json \
  -source-controls commit-controls -check selected-program.spdx.json
```

These two source options are required together only for this explicit profile.
The original `spdx-2.3-go-buildinfo-v1` mode retains its previous behavior and
continues to refuse local replacements. Artifact contents/bundle schema 1 also
retains that original profile. Explicit [contents schema 2](CONTENTS.md) selects
local-source envelopes with a complete commit-control inventory and a private
per-artifact directory mapping; observations remain open through signatures.

## Independent policy and private locations

The top-level policy has exactly `schema: 1`, `profile`, `go` and `localSources`.
`go` is the complete original `GoSBOMPolicy`, retaining its original profile name.
Its `modules` array covers all expected remote modules, including effective
versioned replacements and exact content h1 sums from the selected lock.
`localSources` covers every remaining local module, sorted by module path.
The expected package/module graph must come independently from qualified source,
target and build inputs before the selected executable is inspected.

Each local requirement has exactly:

- `module` and requested `version`, matching the original dependency coordinate.
- `path`, the portable parent Gitlink path. Embedded replacement metadata must
  use exactly `./<path>`, development version `(devel)` and no h1 sum. Absolute,
  parent-relative, versioned or nested replacements do not satisfy this binding.
- `source`, the complete repository/commit/tree/Gitlink object. Repository and
  commit must match that exact path in the parent `go.source.gitlinks` inventory.
  This version requires flat local repository trees with an empty Gitlink array;
  nested local source trees need another explicit coverage profile.
- `goModSha256`, matching the selected tree's `go.mod` file pin.
- `commitObject`, a regular bounded `File` pin for the raw Git commit object bytes
  in the dedicated commit-controls directory. This is uncompressed object content,
  without a loose-object header or transport wrapper. Its fields are `path`,
  exact `bytes` and lowercase `sha256`.
- `files`, the entire selected tracked regular-file inventory, sorted by portable
  path. Every entry has `path`, exact `bytes`, lowercase `sha256` and Git `mode`
  string `100644` or `100755`. Empty files are allowed; symlinks are refused.

Every commit control must be independently provisioned. Its raw content is hashed
with Git's object header, checked against the selected commit ID and required to
start with the selected tree declaration. Each actual source file is streamed
through SHA-256 and its Git blob hash. Recursive tree objects preserve Git modes
and directory sorting and must reproduce the selected tree ID. SHA-1 and SHA-256
Git object formats remain distinct from artifact SHA-256 and Go h1 tree sums.
Git object identity is a content binding, not a signature or maintainer authority.

The private directory mapping has this complete shape:

```json
{
  "schema": 1,
  "sources": [
    {"path": "zvm-core", "directory": "/path/to/qualified/core"}
  ]
}
```

Mapping paths are sorted, unique and exactly match the policy's local sources.
Directories are explicit absolute runtime locations, excluded from policy hashes,
SPDX content and result/error text. The source controls directory contains exactly
the named commit files and necessary directories. Distinct local sources cannot
alias the same physical directory. Runtime paths do not choose source authority.

Source directories contain exactly the named files and necessary directories.
Only their root `.git` metadata entry may be excluded: its contents are never
read, followed or used to authenticate the selected source. Unsafe metadata entry
types, extra/missing files, empty extra directories, case/path aliases, linked
ancestors, symlinks, hard links and observed substitutions fail. An exported
source tree without Git metadata is supported. No repository initialization,
checkout, Git process, module download, extraction or source execution occurs in
this API. Native file/source operations currently support Linux and macOS;
reading another target label does not qualify execution on that target.
Source and control observations remain open and are checked again
before producing a result. Callers must trust the host and prevent hostile writers;
this is an observation, not an operating-system source lock.

Limits are 16 local trees, 256 files per tree, 16 MiB per source file and 64 MiB
for all selected source bytes. Each source `go.mod` and commit object is at most
1 MiB; policies/documents and checksum inputs retain the 1 MiB bound. At most 254
total remote/local module records and 32 exact build settings are allowed. The
SPDX consumer has a bounded 32-level/32,768-node structure check for this profile;
existing provenance and original-profile structure bounds remain unchanged.
An empty `go.sum` is permitted only when there are no expected remote modules
and its empty SHA-256 matches policy. No dummy checksum record is required.

## Document and result scope

Remote modules keep their versioned coordinates and Go h1 external references.
A local source package identifies its requested module, selected repository,
commit and tree, with Git object external references. It reports no invented h1
sum, package archive checksum, file-analysis verification code or inferred
transitive edges. Physical source paths and raw commit author/message data are
never copied into the document. Source files are verified internally, while
`filesAnalyzed` remains false for SPDX license/file-analysis purposes.

Receipts count all verified module records, local source trees, regular files,
source bytes and distinct commit controls. `sourceCommitAuthenticated`,
`toolchainIdentityAuthenticated`, `compilerUseOfTreesProven`,
`parentSourceTreeVerified`, complete runtime/license coverage and `releaseAccepted`
remain false. Matching local bytes to selected Git object IDs does not prove that
an honest compiler used them, authenticate the parent tree/owner, qualify all
platforms or authorize publication. Parent source, actual build recipes and
accepted provenance still need independent qualification.

The optional `ZVM_GO_SOURCE_FIXTURE_DIRECTORY` control uses a qualified subject,
`policy.json`, source-side `go.mod`/`go.sum`, `directories.json` and `controls/`.
It exercises actual local Core metadata, full independent source-tree binding,
deterministic generation and semantic refusal. Ordinary source CI skips this
external-input qualification when inputs are absent. The local qualification
parent module is explicit fixture scaffolding; it is not a Node, Relayer or
Bridge service execution. Original D02 adoption, source/recipe/platform output,
other-language/container/runtime/license, distribution/reproduction and accepted
project signing/owner/operator gates remain open.
