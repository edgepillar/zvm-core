# Dependency and distribution review

The CI action implementations are pinned to full commit IDs. The adjacent
version comments describe their selected releases. Weekly Dependabot
configuration proposes updates for Actions, Go modules, Docker inputs and the
shared web package, with at most two open ordinary version-update pull requests per
ecosystem. Review and qualification are required before accepting an update.

This configuration does not establish that Dependabot has run, that an advisory
scan is clean, that a dependency is unreachable, or that a distribution has
completed license review.

## Review an update

For an action, resolve the intended release in its official repository and
inspect the old-to-new commit diff, action metadata, bundled implementation and
dependency changes. Review requested permissions, credentials, subprocesses,
network destinations and artifact handling. Keep the full commit pin and its
readable version comment together. A matching tag alone is not an independent
review of the implementation.

For Go, review `go.mod` and `go.sum` together. Include the
`github.com/ethereum/go-ethereum` replacement by
`github.com/ethereum-optimism/op-geth` in the effective dependency inventory;
checking only the replaced module's nominal version misses the code that is
actually built. Record the selected Go toolchain and platform separately.
Run build, vet, relevant behavior tests and module-integrity verification in a
bounded qualification environment. Lock or checksum agreement establishes
input consistency, not absence of vulnerabilities.

For `web/package.json`, review peer dependency compatibility in the consuming
application and its committed lock. This shared package has peer ranges and no
standalone application lock at this source revision. Resolve and retain the
consumer's actual versions, integrity records, install-script decisions and
build/test results rather than reporting a range as an installed version.

Record advisory triage against the exact resolved dependency or replacement,
advisory revision and affected versions. State whether the path is used at
runtime, during builds/tests, or only in a non-shipped tool. Link the relevant
call site or build step and a bounded reproducer/check when available. Preserve
unknown reachability explicitly; a scanner match or a missing scanner match is
not a reachability decision. Keep sensitive findings in the repository's private
reporting channel until coordinated disclosure.

## Review the distribution inventory

Start with [`NOTICE.md`](../NOTICE.md) and [`LICENSE`](../LICENSE). The project's
own license does not describe every third-party bytecode or dependency input.
For each shipped binary, web bundle and predeploy bytecode, retain the exact
source revision, input and output digests, build/compiler settings, applicable
upstream license/notice files and the distribution's corresponding material.
Include copied, linked and transitive material that actually reaches the output.
Have the appropriate distribution and license reviewers assess that inventory;
the existing notice table is not a completed review record.

An SBOM and provenance statement must describe a particular built output and
its resolved inputs. A manifest-only dependency list cannot substitute for
that output-bound record. Release signing, complete notices, immutable runner
and image provenance, supported-platform builds and independent verification
remain separate release work.

## Preserve the evidence boundary

The current `ubuntu-latest` runner label is mutable. Pinning actions does not pin
the runner image, downloaded Go toolchain, module proxy responses or a complete
build environment. Record their actual identities in qualification evidence.
Successful CI qualifies only its exact source, inputs, platform and executed
checks; it does not qualify deployment, live-chain behavior or release approval.

Keep public review records in English and omit private paths, personal identity,
credentials, wallet material and raw private diagnostics. Preserve source pins,
actual exit/completeness results and explicit skipped or unknown checks without
copying those private details into a pull request.

References: [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
and [Dependabot options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference).

## Bounded source vulnerability review

The `Dependency review` workflow runs the pinned govulncheck v1.9.0 source
scanner against the exact selected commit, including test packages. The scanner
is built with Go 1.27.4 in a separate tool module/cache, then analysis uses
Go 1.26.11 with CGO disabled. The source scan includes this module's test
packages; other platforms, build tags and CGO configurations need separate
review. The scanned source is this workflow's exact checkout; its findings
are not an analysis of historical retained binaries. The selected SDK does not
choose an accepted release toolchain or qualify other platforms. The Go job
uses the same exact SDK, verifies module checksums and tidy locks, and runs
build, vet, tests and race tests with automatic toolchain switching disabled.
Its twenty-minute deadline includes those additional checks.

The wrapper checks the complete regular-file Git tree, tracked modes and module
locks before and after analysis. Gitlinks, links, untracked/ignored files and
changed inputs require a separately supported profile. A ten-minute process
deadline, process-group termination on budget refusal, an 8 MiB stdout cap and a
256 KiB stderr cap bound collection. GOMAXPROCS and GOMEMLIMIT are workload
controls; GOMEMLIMIT is not an operating-system hard memory limit. The hosted
job has a separate fifteen-minute deadline. Local protocol tests do not claim
the hosted process controls or actual scanner execution.

The producer's actual exit, stream completeness, hashes, scanner digest and
source pins are retained in `execution.json`. `govulncheck.json` and stderr are
kept even on failure. A valid JSON prefix, an absent report or exit zero alone
cannot establish success: govulncheck's JSON mode exits zero even when it emits
findings. A recognized complete protocol, expected scanner/database/Go/mode,
scan inventory and matching advisory references are required. Incomplete,
malformed, mismatched, timed-out or capped scans exit 2. Any finding, including
module-only and package-only reports, exits 1 and requires review. A complete
scan without findings exits 0 with `NO_FINDINGS_REPORTED_IN_THIS_SCAN`.

`review.json` separates module, package and source-call reports, retains missing
fix versions as unknown and counts repeated findings separately from distinct
advisories. The parser also labels binary symbols separately from source call
traces; this workflow executes source mode only. Source locations and advisory
prose are omitted from the summary. The raw report remains necessary for call
site and runtime/build/test classification. Review public artifacts for privacy
before using these tools on any private source.

A source call reported by static analysis is not exercised exploitability.
Reflection, unsafe code, excluded build configurations and unknown module
versions require separate review. An unreported advisory does not establish an
unaffected dependency. In particular, the effective op-geth replacement needs
explicit upstream/fork advisory mapping; checking only one namespace is not
complete fork coverage. Database modification time and retained OSV digests
identify observations, not an authenticated or complete database snapshot.
Actual updater operation, remediation, distribution notices and all D04 release
and owner acceptance requirements remain open. No waivers are generated.

Reports are uploaded for the exact automatic workflow attempt, including failed
attempts. They are review evidence, not accepted project provenance, a release
SBOM, a deployment authorization or a clean-security claim. No manual CI
trigger, retry, signing or release path is added.

Protocol and limits: [govulncheck v1.9.0](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck@v1.9.0),
[stream protocol](https://github.com/golang/vuln/blob/e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5/internal/govulncheck/govulncheck.go),
and [Go vulnerability database](https://go.dev/doc/security/vuln/database).

## Selected CLI and test import graphs

After a successful source scan, the same analysis SDK/cache records the complete
`go list -deps -test` import graph for Linux/amd64 with CGO disabled. A fixed Go
template emits only package identifiers, import edges, test context and selected
nominal/effective module identities. Absolute source/cache paths and generated
filenames are not requested. `go list -json=Fields` specifies required fields,
so it is not used as a field-exclusion guarantee. See the
[Go list contract](https://pkg.go.dev/cmd/go#hdr-List_packages_or_modules).

The observer disables toolchain switching and module downloads, uses the populated
analysis cache, and preserves read-only module selection. Each metadata command
has a 120-second deadline; package output is capped at 4 MiB and stderr at 64 KiB.
The consumer requires exact SDK/profile/source/tree/lock observations, complete
producer streams, a closed acyclic graph, coherent test contexts and versioned
replacement identities. Missing or incomplete records fail the graph step.
Repeated identical import IDs are counted as raw occurrences separately from
distinct graph edges; different test variants retain their full identities.
Data-only controls exercise these refusal boundaries; actual Go execution needs
the exact hosted workflow attempt.

`import-graph/graph.json` separates the CLI entry's transitive package import
closure from test graphs and retains nominal module paths alongside replacements.
Package presence is build-profile evidence, not proof that a vulnerable function
executes. Package absence covers only this selected profile. Function-level
reachability, reflection/dynamic behavior, upstream/fork advisory mapping, other
entrypoints, platforms, build tags, CGO profiles and release review remain open.
No advisory finding is suppressed and no waiver is generated. Projected producer
output and actual process/source receipts remain in the same attempt's report
archive, including failures. Review privacy before using this profile elsewhere.

## Repeated effective module identities

Test-package scans and replacement resolution can report the same effective
module path/version more than once. The consumer records the raw occurrence
count and counts distinct path/version pairs separately. Different versions
remain separate records. This normalization applies only to the scan inventory;
it does not remove findings, collapse their levels or merge advisory revisions.
An initial complete producer stream that exercised this case remains retained
under its original source/attempt; consumer replay is separate from a new scan.

## Maintained SDK and dependency remediation

The module requires Go 1.26.11. The minimum includes the patch level so an
older SDK is rejected with GOTOOLCHAIN=local. Other SDK branches require
their own advisory review; a higher version alone is not patch qualification.
Normal CI and source analysis both select that exact maintained SDK; the scanner is
still built separately with Go 1.27.4. This source change does not rebuild or
qualify previously retained binaries.

The candidate locks select these fixes from the public Go advisory reports:

| Input | Previous version | Selected version | Review basis |
| --- | --- | --- | --- |
| Go SDK | Analysis: 1.25.14; minimum: 1.25.0 | 1.26.11 | [Go downloads](https://go.dev/dl/) and [GO-2026-6859](https://pkg.go.dev/vuln/GO-2026-6859) |
| brotli | 1.2.4 | 1.2.7 | [GO-2026-6888](https://pkg.go.dev/vuln/GO-2026-6888) |
| gorilla/websocket | 1.4.2 | 1.5.3 | [GO-2026-6278](https://pkg.go.dev/vuln/GO-2026-6278), an unreviewed database report; upstream's mask-key change was also inspected |
| klauspost/compress | 1.17.8 | 1.20.2 | [GO-2026-6865](https://pkg.go.dev/vuln/GO-2026-6865) and [GO-2026-5841](https://pkg.go.dev/vuln/GO-2026-5841) |
| OpenTelemetry root, metric and trace | 1.40.0 | 1.44.0 | [GO-2026-5506](https://pkg.go.dev/vuln/GO-2026-5506) and [GO-2026-5158](https://pkg.go.dev/vuln/GO-2026-5158) |
| x/crypto | 0.44.0 | 0.59.0 | Includes the reported [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) fix and earlier matched fixes |
| x/text | 0.31.0 | 0.44.0 | [GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970) and [GO-2026-6629](https://pkg.go.dev/vuln/GO-2026-6629) |

OpenTelemetry 1.44.0 also avoids the baggage-length regression ranges in
GO-2026-5158. The scanner continues to review the complete selected module
configuration; passing an earlier advisory's fixed version is not enough.

The op-geth replacement stays at v1.101702.2. Engine HTTP authentication now
uses the existing JWT library directly instead of importing op-geth's node
server solely for its authentication callback. Each request signs an HS256
token containing only a fresh issued-at claim with the selected 32-byte secret,
as required by the [Engine API authentication scheme](https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md).
The public Engine client API and payload methods are unchanged.
The JWT dependency remains at v4.5.2; only its use becomes direct. Downstream
consumers adopting these locks must also select a reviewed compatible SDK.

The regression controls independently verify the wire token with HMAC-SHA256,
check issued-at renewal using virtual time, exercise concurrent callbacks and
use a loopback JSON-RPC server to check that DialEngine attaches authentication
to actual requests. Their current execution results belong to the exact CI
revision and attempt, rather than this description.

[GO-2026-4479](https://pkg.go.dev/vuln/GO-2026-4479) has no known fixed DTLS v2
release. Removing an unnecessary node-server import is not a fix to DTLS v2 or
a major-version migration. Module/test dependency records and other consumers
still require their own review. No advisory is suppressed: any finding in the
current source/test scan continues to fail the review gate. The effective
op-geth namespace, fork advisory coverage, distribution licenses, supported
platforms, continued action/runtime maintenance and release acceptance remain separate work.

The Docker builder selects the official Go 1.26.11 Alpine 3.24 image by its
full multi-platform index digest and checks the actual SDK version before
downloading and verifying modules. A separate fifteen-minute CI job builds the
Linux CLI image and exercises its usage exit with networking disabled. It does
not start the faucet, contact an engine or publish an image. Other platforms,
image provenance, APK repository inputs and complete transitive package locks
remain separate review and reproducibility work. Weekly Docker update
proposals do not establish that any update has been executed or accepted.

## Reviewed action runtime and container inputs

The selected action releases are
[checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1),
[setup-go v7.0.0](https://github.com/actions/setup-go/releases/tag/v7.0.0) and
[upload-artifact v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2).
Their full commit pins select Node 24 implementations. Old and new source
trees, action inputs, bundled code and resolved dependency locks were compared;
the bundles were not independently rebuilt and upstream action test suites
were not executed. Actual action execution requires the exact hosted CI attempt.
Self-hosted runners need their own compatibility and runner-version review.

Each job checks the exact selected source revision and verifies that matching
repository-local authentication config keys are absent without printing their
values. Checkout keeps credential persistence disabled and unsafe PR checkout
disabled. This control does not audit global config or every credential source.
Setup-go retains explicit SDK versions, automatic switching disabled and the
ordinary upstream download path. Enabled Go caches explicitly include both
`go.mod` and `go.sum`; the scanner-build SDK cache remains disabled. Artifact
uploads explicitly retain ZIP archives, refuse overwrite, exclude hidden files
and keep the existing fourteen-day retention policy. No additional token
permissions, privileged trigger, custom download mirror or manual retry is added.

The Dockerfile frontend uses the stable major-1 channel at a full index digest.
The runtime base selects Alpine 3.22.8 at a full index digest and pins the
requested ca-certificates and wget package versions. The Go builder's digest
and exact SDK check remain in place. Registry content digests identify selected
bytes; they do not independently authenticate image origin or provenance.
Alpine 3.22's main branch is supported through May 1, 2027 according to the
[upstream release table](https://alpinelinux.org/releases/). Continued maintenance
is required; this patch does not migrate every supported platform.

The container job retains a bounded observation of its exact local image ID,
OS/architecture, entrypoint/user, installed package versions and CLI binary
SHA-256. The package and binary commands use that immutable local image ID with
networking disabled, a read-only filesystem and UID/GID 65534. Actual process
exits, output completeness and stream digests accompany the record; failures
are retained. The image configuration query selects only these fields rather
than exporting host paths or environment values. This is an installed-package
observation, not a complete SBOM, image vulnerability scan, license acceptance,
independent origin proof or release approval. APK repositories, signing keys
and transitive package selection still require separate review and locking.

## CLI image source notices

The CLI Docker build collects Go source notices after building the binary in
the same builder. The collector uses the verified module cache with network
module resolution disabled. Its package selection uses the CLI's non-test
imports under the Linux build profile and checks the nominal and effective
module identities against the built binary's metadata. The Go SDK notice and
the project's own license and notice are included.

The image carries the selected notice bytes under
`/usr/share/doc/zvm/notices`. The manifest records the SHA-256 of each
source notice and embedded input. Identical notice payloads use one object.
The collector comes from the reviewed zvm-node source. The pinned bloomfilter
supplement matches the effective module and selected source bytes before it adds
the original upstream notice.
[Original collector source](https://github.com/Zenoglyphs-VM/zvm-node/tree/07c6edeedc1e4493da241868aa3a64f5313396cf/tools/noticebundle)

CI reads the manifest from the exact built image. It compares the binary
digest, Go lock digests and each notice object's size and digest. It also
compares the embedded project files with the checked source. The image commands
return manifest and digest metadata, so the report reuses the built binary and
keeps the notice payloads in the image. The review of compiler intermediates
and Alpine notice text remains open.

## Embedded predeploy source and license catalog

The catalog binds all ten third-party predeploy paths in the CLI to the exact
embedded bytes. Eight paths match the outputs recorded in the pinned Node
compiler lock. The EntryPoint and Permit2 records use the lock's independently
recorded immutable context, and the other six record full runtime equality.
Two additional paths match the runtime literals published in the pinned EIPs.
The two factory paths share a byte digest and retain their distinct upstream
attribution. [Predeploy source and license catalog](../LICENSES/predeploys/sources.json)

The original license texts cover the named source groups, including the
AGPL-3.0-only declarations on the two Solmate inputs to Permit2 and the
LGPL-3.0-only declaration on `Exec.sol` in the EntryPoint group. The Node compiler
lock records the complete source-unit paths, archive integrity pins, compiler
versions and build settings. [Solmate source](https://github.com/transmissions11/solmate/blob/8d910d876f51c3b2585c9109409d601f600e68e1/src/utils/SafeTransferLib.sol) ·
[EntryPoint group source](https://github.com/eth-infinitism/account-abstraction/blob/7af70c8993a6f42973f520ae0752386a5032abe7/contracts/utils/Exec.sol) ·
[Locked compiler inputs](https://github.com/Zenoglyphs-VM/zvm-node/blob/9fb7cddc819d935e052069d7cb563eca0c89f6f2/contracts/upstream-predeploy-build.lock.json)

CI compares the catalog and every referenced original text with the notice
objects in the exact CLI image. The corresponding-source distribution method
and license obligations for the combined outputs remain open for review by the
release maintainers. [GNU GPL version 3](https://www.gnu.org/licenses/gpl-3.0.html)

The image metadata projection handles Docker Engine API 1.52's optional
`Config.User` field and records whether the engine reported it. The observation
processes run with the explicit UID/GID recorded by the container job.
[Docker Engine API changes](https://docs.docker.com/reference/api/engine/version-history/#v152-api-changes)
