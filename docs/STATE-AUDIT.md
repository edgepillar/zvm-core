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

For a local consumer that already holds accepted policy/checkpoint data,
`-bundle-stdin` verifies one streamed input without temporary context files.
It cannot be combined with root or context-file overrides. The frame starts with
`5a 56 4d 53 4e 50 00 01`, a uint32 big-endian JSON byte length, then exactly one
JSON object with required `schema`, `policy`, `snapshot` and `checkpoint` fields.
`schema` is 1; `checkpoint` is null only for explicit bootstrap. The existing
binary witness follows immediately and must end at EOF. The same context and
witness limits apply. `EncodeInput` streams this format; `VerifyInput` validates
it through the existing complete snapshot verifier. A frame supplies inputs,
not independent authority, and a refused stream emits no successful record.

## Disjoint balance measurements

An optional independently provisioned partition policy measures selected address
groups and the exact remainder while verifying the entire account trie. It
supplies no default bridge, fee, sink or exclusion membership. A group name is a
measurement label; it establishes no contract code/storage, withdrawal lock,
burn authority, economic exclusion or circulating liability.

The exact policy schema is `schema: 1` and `groups`, an array of objects with
required `id` and `addresses`. IDs match `[a-z][a-z0-9-]{0,31}` and are strictly
sorted. Every group has at least one address. Addresses are exact lowercase
`0x` plus forty hexadecimal digits, strictly sorted within a group and disjoint
across all groups. The zero address is a valid measurement target. Policy and
resource bounds are explicit: at most 64 groups and 4096 selected addresses.
Unknown, aliased, duplicate, missing and null JSON fields are rejected.

`PartitionPolicy.Fingerprint` is SHA-256 of `ZVM native balance partition v1\n`
followed by canonical typed JSON, with no trailing newline. Its accepted digest
must be independently provisioned by the caller, separately from snapshot input.
The digest binds the address selection; it neither approves the selection nor
conceals a predictable address inventory. Keep inventories and meaningful private
labels outside public status output.

`VerifyPartition`, `VerifySnapshotPartition` and `VerifyInputPartition` return
the complete aggregate, pinned group digest, aggregate balance and selected/
present account counts for each group, plus remainder balance/account count.
No individual addresses are output. Groups and remainder exactly conserve the
full account total, including amounts above uint256. A zero-balance account
retained by nonce is present; an absent selected address is counted separately.
Absence becomes a proved zero only after complete state verification succeeds.
Missing selected or unselected trie nodes cannot become a successful sample.
Failure returns no partial group measurements or checkpoint.

The original verifier and partition verifier share the same complete traversal;
there is no extra state scan per address or group. Lookups and accumulators are
bounded by the explicit partition limits. The witness, framed-input and
checkpoint formats remain unchanged. Context-bound measurements retain the
existing accepted header, release, epoch, freshness and checkpoint checks.
Retain both the latest checkpoint pin and partition-policy pin externally.

The command accepts `-partition-policy accepted-groups.json` together with
`-partition-policy-sha256 <independently-accepted-digest>` in raw-root, bound-file
and `-bundle-stdin` modes. Both flags are required together. In framed mode the
group policy remains outside the producer's frame; that frame cannot select a
different group policy. `-max-partition-groups` and `-max-partition-addresses`
can lower the measurement bounds. Success prints aggregate group measurements;
it does not subtract any group from liability, add pending withdrawals or
declare native backing. Complete storage/code proofs, cross-chain reserve
binding, explicit unit/rounding rules and accepted economic policy remain
separate requirements.


## Same-root code and storage measurements

A separately accepted `StoragePolicy` measures fixed raw storage keys for
selected accounts. Its exact schema is `schema: 1` and `accounts`. Each account
requires `id`, canonical lowercase `address`, accepted `codeHash` and nonempty
`slots`; every slot requires `id` and a canonical lowercase 32-byte `key`.
Account IDs and slot IDs match the group-ID grammar and are strictly sorted.
Account addresses cannot repeat; keys cannot repeat within an account. A slot
key may be zero. The owner accepts this layout and code identity independently,
then retains `StoragePolicy.Fingerprint`: SHA-256 of
`ZVM account storage measurement policy v1\n` plus canonical typed JSON.
The policy has no default protocol addresses, code hashes, slot maps or units.

Code hashes are Keccak-256 runtime-bytecode commitments from authenticated
account leaves. A matching hash identifies bytes, not review approval or upgrade
safety. Proxy bytecode alone does not establish implementation identity or
layout semantics. A label such as pending, paid, fees or burned supplies no
policy authority. Packed slots remain raw uint256 values; the utility performs
no unpacking, NoM conversion, reserve rounding or economic interpretation.

The selected account must be present in the verified complete account trie,
with the accepted code hash and a nonzero storage-root commitment. Missing
accounts are unavailable, never implicit zero contracts. Fixed keys are hashed
with Keccak-256 and proved against each account's authenticated storage root.
An exact empty storage root, or a verified non-membership path under a nonempty
root, establishes zero. A stored leaf must encode a canonical nonzero uint256:
leading zeros, oversized integers, malformed RLP and noncanonical trie shapes
are refused. Unseen off-path storage is not claimed as complete storage coverage.

`StorageWitness` is separate JSON with exactly `schema: 1` and `nodes`, a non-null
array of lowercase hex RLP blobs. Nodes form the unique Keccak-sorted union of
all selected proof paths. No roots, account addresses, keys or measurement labels
are learned from it. Every supplied node must be used by a selected proof; a
missing, altered, duplicated, out-of-order or unused node makes the complete
measurement unavailable. Missing selected or unselected account-state nodes also
fail complete account verification. The sparse proof is not an engine database.

`StorageProofCollector` implements the writer for an owner's bounded local
`trie.Prove` calls. It copies source blobs once, deduplicates by digest and
finalizes once. Check every source error and bound synchronous prover calls
externally. Collector output is an unverified artifact until the complete
measurement verifier accepts it. It neither opens a live database nor contacts
RPC. Do not treat a partial producer result as completed qualification.

A proof fingerprint hashes `ZVM storage witness v1\n`, an unsigned 64-bit
big-endian node count, then an unsigned 32-bit big-endian length and raw bytes
for every sorted node. Hashing streams the raw nodes without another whole JSON
encoding. This content fingerprint differs from the SHA-256 of a JSON file;
retain exact file/transport identity separately when needed.

`VerifyMeasurements`, `VerifySnapshotMeasurements` and `VerifyInputMeasurements`
combine complete balances, optional independently pinned disjoint groups and
selected account code/storage roots in the same full account traversal. They
then verify all fixed storage paths. The result binds the complete state root,
measurement policy digest, proof digest, raw values and presence flags. It
contains account/slot IDs and account code/storage-root commitments, without an
address/key inventory. Keep private inventories and meaningful private labels
outside public status output. Any failure returns no partial measurement or
checkpoint. Bound and framed modes preserve the existing accepted header,
release, epoch, freshness and prior-checkpoint rules. Original witness, frame
and checkpoint formats are unchanged; retain measurement pins separately.

The command requires all three of `-storage-policy accepted-slots.json`,
`-storage-policy-sha256 <independently-accepted-digest>` and
`-storage-witness selected-storage-proof.json`. These are separate from the
producer's snapshot frame. Raw-root, bound-file and `-bundle-stdin` modes are
supported; an optional partition policy can be measured in the same operation.
Only a fully verified result is printed. The command writes no checkpoint,
signs no operation, executes no contract and changes no payout state.

Defaults are 64 accounts, 1024 slots, 8192 unique proof nodes, 2 MiB raw node
bytes and 65536 proof-node reads. The `-max-storage-accounts`,
`-max-storage-slots`, `-max-storage-nodes`, `-max-storage-bytes` and
`-max-storage-steps` flags set explicit bounds. Hard ceilings are 64 accounts,
1024 slots, 65536 nodes, 16 MiB node bytes and 131072 reads. The existing context
JSON byte/nesting/token/array limits additionally bound sidecar documents.

Qualification uses committed bridge and fee runtime bytes in owned unsigned
EVM fixtures, then compares proof measurements with committed geth StateDB
lookups across pending, paid, settlement, withdrawal and mirror transitions.
These are local raw-value/identity checks. Full supported-client and artifact
provenance acceptance, real code/layout/upgrade authority, independently accepted
NoM vault/frontier/reserve binding and economic liability/exclusion policy remain
separate adoption gates. The native total-backing claim stays not_established.


## NoM reserve boundary at the reviewed source

This section reviews Core `0e897c1dc5117beafbe59a960b0a49c2c44be2c2` and the Bridge observation provider
`edb38e664c5b6436d4bfd8f1eb5b9d2b635ad6e1`. It describes the selected ZVM data flow; it makes no claim about
all other NoM implementations or network activation.

| Source-bound fact | Evidence and limit |
| --- | --- |
| The L2 height maps to a configured NoM momentum height. | [`MomentumForL2Block`](https://github.com/Zenoglyphs-VM/zvm-core/blob/0e897c1dc5117beafbe59a960b0a49c2c44be2c2/rollup/params.go#L371) is a configuration mapping; a height alone does not authenticate a NoM branch. |
| Derivation carries a momentum height, hash and timestamp into L1 attributes. | [`L1InfoData`](https://github.com/Zenoglyphs-VM/zvm-core/blob/0e897c1dc5117beafbe59a960b0a49c2c44be2c2/l2/deposit.go#L43) encodes the supplied momentum; [`Attributes`](https://github.com/Zenoglyphs-VM/zvm-core/blob/0e897c1dc5117beafbe59a960b0a49c2c44be2c2/derive/plan.go#L1176) also supplies its hash as randomness/beacon-root input. An accepted L2 header commits the resulting values without independently proving a NoM balance. |
| The vault reader checks a confirmed account frontier and a stable reader sample. | [`observationFrontier` and `observePeg`](https://github.com/Zenoglyphs-VM/zvm-bridge/blob/edb38e664c5b6436d4bfd8f1eb5b9d2b635ad6e1/bridge/observations.go#L263) check configured identity, reported confirmation, account height, empty queues and rechecks. These checks remain reader observations. |
| The balance interface carries address, account height and token amounts. | [`AccountInfo`](https://github.com/Zenoglyphs-VM/zvm-core/blob/0e897c1dc5117beafbe59a960b0a49c2c44be2c2/znn/client.go#L156) and the provider carry no authenticated state/value proof. An omitted token entry is a reader zero convention, not a proved absent state key. |
| Confirmation details are RPC decorations in the inspected account-block model. | [`AccountBlock` and `ComputeHash`](https://github.com/Zenoglyphs-VM/zvm-core/blob/0e897c1dc5117beafbe59a960b0a49c2c44be2c2/znn/block.go#L81) do not turn those decorations or `ChangesHash` into an adopted typed reserve commitment. A separate verified protocol rule is required. |

The local complete account witness and code/storage proofs authenticate L2
measurements under the caller's accepted L2 point. Attaching an unsigned NoM
balance declaration cannot extend that proof to the vault. The current native
`totalBackingState` therefore remains `not_established`; missing reserve
proof is unavailable, never a zero reserve or a zero deficit. Preserve the
existing pending-liquidity observation as its separately labelled reader sample.

A future reserve consumer needs an independently accepted NoM chain/genesis and
version/profile, canonical momentum hash and height, plus authenticated vault
address/token/value at that exact retained state point. This may be an accepted
state/value proof or a complete independently validated snapshot/replay under
an explicit supported profile. Account-block content/signature/linkage evidence
must not be relabelled as a balance proof. Derive keys locally from the accepted
profile, rather than accepting an arbitrary key or root from the producer.

The join must bind that NoM point to the momentum declared by the accepted L2
derivation and retain the exact vault account frontier and confirmation anchor.
Do not substitute height equality, a fresh collection time or agreement among
unqualified readers for the accepted authority. Reorgs, missing history, epoch
changes, rollback, lost checkpoints and an ahead-of-derivation vault point
require explicit verified reconciliation. Keep original account/payout hashes;
this consumer must never sign, settle, replace, broadcast or reset history.

Before adoption, exercise wrong address/token/key/root, wrong same-height hash,
stored zero versus absent key, missing/partial proof, stale source, changed
frontier, restored old checkpoint, cancellation and resource bounds. These NoM
reserve cases are acceptance requirements, not tests executed by this review.
Code/layout/upgrade authority, exact wei/base-unit conversion and ceiling
reserves, retained fees, pending/paid payouts, burn mirroring and sink exclusions
still require their separately accepted economic contract.

Measurement output omits selector inventories, but arbitrary raw storage values
or meaningful labels can themselves identify accounts. Review every selected
counter and exported aggregate before publication; omission of selector addresses
is not anonymization of arbitrary contract storage.

The NoM review executes no client, VM, signing, chain RPC, wallet or recipient
operation. The existing L2 implementation tests are retained only when every
executable, test, fixture, dependency and workflow file is unchanged. A new
source-only note is not new native execution, NoM proof qualification, independent
economic acceptance or production readiness.
