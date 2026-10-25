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

## Bound snapshots and retained checkpoints

`NewSnapshot` and `VerifySnapshot` bind the binary witness to a small context
document. The independently provisioned policy pins chain ID, genesis hash,
the exact release rollup-file SHA-256, epoch fingerprint, one to eight accepted
release manifest digests, and a specific canonical block number/hash. The rollup
file digest is distinct from the bridge provider's typed-configuration digest.

The snapshot carries the existing release signing message, canonical RLP headers
and the SHA-256 of the separate canonical binary witness. Verification checks
the existing `ZVM release manifest v1` message domain and accepted body digest,
then recomputes the existing `ZVM chain epoch v1` fingerprint over epoch/contracts.
It compares the required chain/genesis/rollup fields with independent pins.
It does not approve a release or verify a new owner-signature policy: an existing
release verifier must supply accepted manifest/cohort pins beforehand. Test
inputs reuse the existing public Go/browser release-message vector without keys.

The final RLP header must have the independently accepted number/hash. Its state
root must match the complete MPT witness, whose canonical encoded digest is
recomputed without embedding another copy of that payload in JSON. Header links
establish ancestry from the retained checkpoint; they do not independently
select the canonical chain or prove a running client/profile.

Bootstrap must be explicit and accepts one independently pinned point with no
previous record. Otherwise the policy must pin the latest previous checkpoint
digest and the caller must supply that exact record. Advancement requires every
consecutive header from the previous point through the accepted target. Missing,
reordered, repeated, reorged or retreating headers are refused. Same-height
verification must retain the same hash/root/balance and original first-observed
time. Compatible release/cohort replacement within the same epoch preserves
history, including when the previous release is retired.

Header age is checked against the policy's explicit maximum and the caller's
trusted current time. Fresh collection cannot hide an old header. A backwards
clock or changed checkpoint identity is refused. The command uses its current
clock; library callers must qualify their time source separately.

```sh
./zvm-state-sum -input snapshot.witness \
  -snapshot snapshot-context.json -snapshot-policy independently-accepted.json \
  -checkpoint previous-checkpoint.json
```

Omit `-checkpoint` only for an explicitly provisioned bootstrap policy. Bound
mode refuses a separate `-state-root` override. It reads regular local JSON files
with exact required field names, no aliases, duplicates, unknown fields, nulls or
trailing data. The policy, snapshot and checkpoint types in `stateaudit` define
their version-1 schemas; all fields are required, including explicit bootstrap
and previous-digest fields. No trust keys, URLs or signing material are inputs.

Bound success prints the verified sum, next checkpoint and its domain-separated
SHA-256 fingerprint. It does not write or replace any checkpoint or policy file.
The owner must atomically retain the successful record and independently retain
its latest accepted digest before advancing. A self-consistent old file/policy
is not rollback authority, and this utility cannot manufacture external storage
freshness, policy approval, independent consensus or hardware durability.

Default context bounds are 8 MiB per JSON document, 256 linked headers and 8192
bytes per RLP header, controlled by `-max-context-bytes`, `-max-headers` and
`-max-header-bytes`. JSON also has fixed nesting/token/array bounds. Whole native
liability accounting and economic exclusions remain separate adoption gates;
the bound sum still includes every account balance.
