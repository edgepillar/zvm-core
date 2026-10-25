# Complete account-state balance witnesses

`stateaudit` is an offline building block for native ZNN accounting. It collects
a complete account Merkle Patricia Trie (MPT), reconstructs that trie from its
witness and sums every consensus account balance in exact wei. The caller must
provide the expected state root from a separately accepted source.

This sum includes bridge locks, fee accounts, contract balances and sink
addresses. It is not circulating supply, user liability, reserve verification or
chain acceptance. The existing bridge native `totalBackingState` remains
`not_established`. This package does not change derivation, genesis, payout state,
economic exclusions or any execution rule.

## Collection and verification

`Collect(ctx, expectedRoot, iterator, limits)` accepts the read-only node-iterator
subset implemented by the configured geth account trie. Start the iterator before
its first node. Collection traverses all children, checks node hashes and retains
one blob per hash. It then reconstructs the entire trie in a separate read-only
witness database and verifies the aggregate before returning a witness.

`Verify(ctx, expectedRoot, witness, limits)` refuses a root mismatch, missing or
unreachable nodes, duplicate or unordered blobs, noncanonical node shapes,
incorrect account-key lengths and malformed consensus account RLP. It requires
the full four-field account representation and counts zero-balance accounts that
remain in state. The sum uses arbitrary-precision integers and may exceed one
account's uint256 range.

A repeated subtree hash is stored once but traversed at every distinct key path.
Deduplicating witness storage must not deduplicate account balances. Storage-trie
contents, bytecode and address preimages are unnecessary for this aggregate:
their roots/hashes remain committed in each account value. Their correctness and
the authority of the expected root are separate acceptance requirements.

Partial traversal, source errors, I/O failure, cancellation and resource refusals
return no successful aggregate. No reported total in the input is trusted; the
verifier computes the total itself. It performs no RPC, signing or publication.

## Binary format, version 1

Integers use unsigned big-endian encoding. The stream contains exactly:

| Field | Encoding |
| --- | --- |
| Magic and version | Eight bytes: `5a 56 4d 42 41 4c 00 01` |
| Account state root | 32 bytes |
| Unique node count | uint64 |
| Each node | uint32 RLP byte length, followed by those RLP bytes |

Nodes are sorted strictly by their Keccak-256 hash. Zero-length nodes, node blobs
over 1024 bytes, duplicate hashes, unknown versions, truncated input and trailing
data are refused. The empty account root has zero nodes. The format is for the
classic account MPT and four-field consensus account RLP; a different state-tree
or account representation requires a separately reviewed format version.

`Encode` and `Decode` are bounded codecs. Encoding checks wire order and limits;
decoding does not establish Merkle validity or select the accepted root. Always
call `Verify` against a root accepted independently of the witness. A partial
encoded stream is not a verified artifact.

## Standalone verifier

```sh
go build -o zvm-state-sum ./cmd/zvm-state-sum
./zvm-state-sum -state-root 0x<accepted-64-hex-digit-root> -input snapshot.witness
```

Use `-input -` for a bounded standard-input stream. File input must be a regular
file. Success prints one JSON summary containing the root, account count, exact
`nativeBalanceWei`, unique node count and encoded witness bytes. Refused evidence
prints no success summary. The command never fetches or automatically accepts a
root, opens an engine database, enumerates a public RPC or alters local state.

Default resource limits are 32 MiB encoded input, 250,000 unique nodes, 250,000
accounts and 1,000,000 verification steps. The corresponding flags are
`-max-bytes`, `-max-nodes`, `-max-accounts` and `-max-steps`. Limits must be positive;
they are resource bounds, not monetary or governance policy. A larger snapshot
requires an explicit budget and retained completion evidence.

Cancellation is checked between synchronous iterator/I/O operations. Owners must
provide an external process or I/O deadline for a source that can block inside an
operation. Do not put a whole-state scan in the public bridge HTTP collector.
Retain one verified witness object and a small manifest binding its digest and
completion to the accepted source; stream its encoding without a second full
payload buffer or recursive evidence archive.

## Qualification and adoption gates

The dedicated workflow builds the actual standalone verifier and runs the
library/command suites in normal and race modes. Set `ZVM_STATE_SUM_BINARY` to
that built binary when running the command integration suite locally. Without
it, the standalone-command test explicitly skips; this is not command execution
proof. No private keys, signed transactions, real funds or network readers are
needed for the owned synthetic state/EVM fixtures.

Before adopting this sum in a native-liability monitor, independently accept the
exact chain/genesis/configuration/epoch, canonical block and state root, supported
full execution client and fork profile, and complete checkpoint/reorg history.
Economic policy must separately classify bridge locks, pending NoM payouts,
relayer claims, retained fees and local/mirrored burns without double counting.
Preserve exact wei quantities and explicit NoM reserve rounding. A verified MPT
sum alone closes none of those economic, custody, operator or deployment gates.

MPT representation reference: [Ethereum's Merkle Patricia Trie documentation](https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/).
