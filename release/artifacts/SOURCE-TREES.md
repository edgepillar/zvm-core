# Complete Go source tree preflight

`zvm-source-check` checks a complete regular-file Go repository export against
an independently selected source policy. It reproduces Git blob/tree identities,
including declared Gitlink entries, and binds the tree to selected raw commit
bytes. It uses no Git process, checkout, module resolution or source execution.

```sh
go build ./cmd/zvm-source-check
./zvm-source-check -policy parent-source-policy.json \
  -policy-sha256 INDEPENDENTLY_SELECTED_POLICY_SHA256 \
  -directory parent-export -controls parent-commit-controls
```

Obtain the expected policy SHA-256 from the independent input-selection record.
Do not calculate it from an untrusted replacement policy and treat that as
acceptance. A self-consistent replacement export/policy is a different input
selection; the checker does not choose trusted source authority.

## Policy and inputs

The policy has exactly these fields:

- `schema`: `1`.
- `profile`: `git-go-source-tree-v1`.
- `source`: repository label, commit ID, tree ID and sorted `gitlinks` array.
  Each Gitlink declares its portable path, repository label and commit ID.
  The array is required even when empty. A repository label is caller-selected
  context; Git object identity does not authenticate a remote repository.
- `goModSha256`: the lowercase SHA-256 of the exported `go.mod`.
- `commitObject`: a `path`, exact `bytes` and lowercase `sha256` pin for the
  selected raw commit content in the dedicated controls directory. Supply
  uncompressed content without a loose-object header or transport wrapper.
- `files`: every selected tracked regular file, sorted by portable path.
  Each entry has `path`, exact `bytes`, lowercase `sha256` and Git mode
  `100644` or `100755`. Empty files are supported.

The source directory contains exactly those files and necessary directories.
Gitlink directories must be absent from this export. Their `160000` entries
are reconstructed from the selected path and commit ID. The child repository's
files are not substituted for that parent-tree entry. See Git's
[submodule model](https://git-scm.com/docs/gitsubmodules).

Only a root `.git` metadata entry may be excluded; it is never read or used to
authenticate the source. Extra or missing files, extra empty directories,
checked-out child directories, symlinks, hard links, case/path aliases,
executable-mode mismatches and observed substitutions fail. A flat export with
no Git metadata is supported. Linked ancestors are refused.

The controls directory contains exactly the selected commit file and its
necessary directories. The checker verifies the file's SHA-256 and size, then
computes its Git commit identity and checks the leading tree declaration.
Raw author, message and signature content is not emitted in the receipt.
This is content binding, not commit-signature or full Git-history validation.

Source files are streamed through SHA-256 and Git blob hashing. Recursive Git
trees preserve executable modes and Git directory ordering. SHA-1 and SHA-256
Git object formats are supported; the selected commit, tree and Gitlinks must
use one object-ID width. Git object IDs remain distinct from artifact SHA-256
checksums and Go module h1 sums.

Limits are one tree per call, 256 regular files, 64 Gitlinks, 16 MiB per source
file and 64 MiB total source bytes. The policy, raw commit control and `go.mod`
are each bounded to 1 MiB. Duplicate/unknown JSON fields and trailing documents
are refused. Policies and receipts use logical paths; physical source/control
locations occur only in runtime arguments.

## Receipt and acceptance boundaries

After successful verification, the JSON receipt includes the selected policy
SHA-256, repository label, commit/tree IDs, regular-file byte/count coverage,
Gitlink count and one verified commit control. `sourceTreeVerified` is true only
after final source/control inventory and identity checks. Invalid inputs emit no
success receipt; incomplete result writes fail the command.

These result fields remain false:

- `childSourceTreesVerified`: Gitlink identity does not inspect child contents.
- `sourceCommitAuthenticated`: object content does not establish source authority.
- `compilerUseOfTreeProven`: this command neither builds nor observes a compiler.
- `releaseAccepted`: source content is only one release input.

Source and control observations remain open until the final check. The host and
input-selection process must be trusted and hostile writers excluded. This is
an observation, not an operating-system lock or hardware durability proof.
Native file verification currently supports Linux and macOS.

The existing Go CI job includes a selected race step for the artifact library
and four standalone commands. It reuses the preceding build's SDK/module inputs,
disables implicit module/toolchain resolution, uses one package worker and is
bounded to five minutes. The original build, vet and test steps are preserved.
External-fixture tests still require their independently provisioned inputs;
their skips are not current project output, signature or source qualification.
An authored CI step is not evidence that a hosted run has completed.

This standalone preflight is separate from the [Go SBOM profiles](SBOM.md),
[local Core profile](LOCAL-SOURCES.md) and [contents composition](CONTENTS.md).
Their formats and receipts retain their existing behavior. In particular, a
separate source receipt does not change their `parentSourceTreeVerified` field
or create a joint source/artifact/signature observation. The separate opt-in
[parent contents consumer](PARENT-CONTENTS.md) binds independent parent policies
to contents and optional provenance while keeping source observations open.
Its adoption and release policy still require independent review.

For the [recorded service cohorts](SERVICE-OUTPUTS.md), select each complete
parent export and its exact Core Gitlink. Check Core's complete export separately
when child content is required. Preserve every policy/receipt with its own
selected bytes and source context. Source and package closure still leave
actual service outputs, accepted recipes/images/toolchains, project signatures,
distribution, independent reproduction, runtime/license coverage and maintainer
or owner/operator release acceptance open.
