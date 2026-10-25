# Documentation evidence

This page separates source inspection, retained results and proposed work. The
[offline checker](../tools/doc-check/README.md) binds selected bytes and structured
records. It does not establish semantic conformance, execution or deployment.

## Current implementation

The selected encoding source is Core
`29e6d9b30be94de3772c850c7a1e9811585a8833`. The
[committed vectors](../vectors/vectors.json), [generator](../vectors/vectors.go)
and [test](../vectors/vectors_test.go) are local inputs with exact size and SHA-256
pins in the [manifest](../tools/doc-check/manifest.json). The selected
[specification](https://github.com/Zenoglyphs-VM/zvm-docs/blob/35c5be8a59059a9e1f3aab40c980ef6cd18cf0be/spec/SPEC.md#11-vectors)
is a separately pinned external input. The checker verifies its bytes and the
selected heading; it cannot infer that every rule in the specification matches
the implementation. Intentional encoding or specification changes require review
of both pins and meaning.

Checking these references does not run `zvm vectors -check`, Go tests, a browser,
a benchmark or a node. A successful documentation job establishes this checker's
selected documentation checks at its recorded source, not those other results.

## Historical results

No retained runtime result is introduced by this package. A committed result
record must be labelled `historical`, name its full source revision, identify
local or hosted execution, retain complete output/result evidence separately,
and state its scope and limitations. Structured record validation does not
authenticate a hosted run or replay the result. A new CI run is separate evidence.

## Performance evidence

This package contains no performance measurement. It cannot support throughput,
latency, storage or production capacity claims. Historical benchmark adoption
requires a pinned raw manifest, retained raw samples, source/runtime/platform and
command information, complete successful runs and explicit evidence limits.
Missing raw evidence remains unavailable. A summary table alone is insufficient.

## Planned work

The G02 roadmap also covers `zvm-docs` and `zvm-fleet`. Their source inventories,
historical benchmark material and CI adoption require separate qualification.
This Core change does not complete those repository tasks or any production gate.

Every publication still requires English and privacy review. The automated guards
cover selected private path, credential, email and language markers; they cannot
recognize every identity, secret, language or identifying aggregate.
