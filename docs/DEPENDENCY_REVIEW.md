# Dependency and distribution review

The CI action implementations are pinned to full commit IDs. The adjacent
version comments describe their existing major versions. Weekly Dependabot
configuration proposes updates for Actions, Go modules and the shared web
package, with at most two open ordinary version-update pull requests per
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
