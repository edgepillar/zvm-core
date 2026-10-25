# zvm-core

The part of the ZVM that every process has to agree on, as one Go module.

The node, the relayer and the bridge are separate programs. If each carried its
own copy of `derive`, two of them could read the same momentum and disagree
about what block it is. One copy, one chain.

| Package | |
|---|---|
| `derive` | momentum in, EVM block out: the consensus |
| `znn` | the NoM client: addresses, account blocks, plasma |
| `rollup`, `l2` | chain parameters and genesis |
| `store` | the SQLite schema the node and the bridge share |
| `orderbook` | the NFT order's EIP-712 encoding |
| `vectors` | the golden encodings, in `vectors/vectors.json` |
| `cli` | flags shared by every binary, including the endpoint ones |
| `cmd/zvm` | the CLI: genesis, dev-key transactions, faucet, vectors |
| `web/` | `@zvm/web`, the shared browser code for the front ends |
| `chains/` | the committed chain definitions: chains 70, 71 and 69 |

## Build and test

```sh
go build ./...
go test ./...
docker build -t zvm-core .     # the zvm CLI, which also runs the devnet faucet
```

The genesis tests check `chains/` and the encoding test checks
`vectors/vectors.json`, both in this repository. A missing file fails the test
rather than skipping it.

## Configure

No node is built in. Every command reads its endpoints from flags that default
to environment variables: `NOM_NODE` (a NoM node), `ZVM_RPC` (the ZVM's
JSON-RPC), `ZVM_NODE` (a node's read API), `ZVM_RELAYER`. `.env.example` has
a local [zvm-devnet](https://github.com/Zenoglyphs-VM/zvm-devnet)'s.

A change to `derive` changes what block a momentum means: it is a hard fork,
whether or not anyone calls it one.

Used by [zvm-node](https://github.com/Zenoglyphs-VM/zvm-node),
[zvm-relayer](https://github.com/Zenoglyphs-VM/zvm-relayer),
[zvm-bridge](https://github.com/Zenoglyphs-VM/zvm-bridge) and the front ends,
each as a git submodule at `./zvm-core`.

MIT licence; third-party bytecode is listed in [NOTICE.md](NOTICE.md). The
full guide, with how it works and why: [docs/GUIDE.md](docs/GUIDE.md).

## Offline release verification

The optional `zvm release-message` and `zvm release-verify` commands bind signed
release inventories to source, artifact, genesis and saved contract build inputs.
See [the release verification guide](release/README.md) for the independent policy
and trust inputs, supported material formats and acceptance limits. These commands
do not publish a release or establish a running deployment.

The standalone `go build ./cmd/zvm-artifact-check` command checks a dedicated
artifact directory against an independent byte-selection policy. See the
[artifact verification guide](release/artifacts/README.md) for its optional
provenance mode, which adds a pinned local verifier/root and exact source/workflow
policy. SBOM content, build reproduction and release acceptance remain unverified.

The standalone `go build ./cmd/zvm-sbom` command produces or checks a selected
SPDX 2.3 Go build inventory against independent artifact/source/module inputs.
See the [Go SBOM profile](release/artifacts/SBOM.md) for its exact checksum,
replacement, metadata and coverage boundaries. Full runtime/license coverage,
source authority and release acceptance remain unqualified.
