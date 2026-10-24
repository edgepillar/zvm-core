# Offline release and chain-epoch verification

This package is a local foundation for the release manifest. It does not publish
a release, provision trust keys, sign with a real maintainer key, pull images,
contact a chain, or attest a running service. Those acceptance gates remain open.

Every release has two independently reviewed inputs:

- A schema-1 policy lists the exact repositories, gitlinks, toolchains, images,
  compilers, file requirements and contract IDs, plus a signature quorum of 1..16. Each
  file requirement fixes its ID, kind, repository and relative path. Empty
  inventories are refused except for gitlinks. A gitlink policy key has the form
  `repository:relative/path`.
- A schema-1 manifest binds the canonical policy SHA-256, complete source
  commits/gitlinks, platform-specific tool/compiler artifact bytes, digest-only
  OCI image references, locks, genesis/configuration/deployment files, contract
  addresses and runtime-code hashes. Empty repositories are explicit and must
  verify as clean, unborn Git worktrees with no refs.

The policy is not generated from the manifest being checked. The release owner
must review its complete organization inventory, nested dependencies, supported
platforms, compiler versions, image set, locks and contracts before approving it.
The current organization includes an empty `.github` repository; an omitted repo
and a verified empty repo are different inputs.

`files` contains `id`, `kind`, `repository`, `path`, `bytes` and `sha256`. Exactly
one `rollup`, `l1-genesis`, `l2-genesis` and `deployments` pin is required. Other
kinds are `lock`, `artifact`, `config` and `runtime-code`. Files are read beneath
`files-root/repository/path`, with no link ancestors. Each file is at most 1 GiB;
the declared set is at most 4 GiB. Byte counts and hashes are streamed. A
toolchain/compiler's `fileId` must bind the same SHA-256 in an `artifact` pin.

Contract entries contain `id`, lowercase `address`, `runtimeFile` and
`runtimeCodeHash`. A runtime-code file contains hexadecimal deployed bytecode,
with an optional lowercase `0x` prefix and surrounding whitespace. Its decoded
EVM keccak256 must match `runtimeCodeHash`; raw file bytes are separately pinned
with SHA-256. Genesis predeploy code must also agree with the L2 allocation.
The pinned deployment bindings file is `{schema: 1, contracts: [...]}` with the
same contract records. It records expected code and does not prove live code.

The epoch includes an explicit nonzero 32-byte `id`, canonical decimal L1/L2 chain IDs, nonzero genesis block
hashes, raw rollup/deployment file SHA-256 values, and `isthmus` or `karst` EVM
rules. The verifier uses the normal strict rollup decoder, reconstructs the
supported L2 genesis, and checks its execution rules and block hash. The L1
genesis file's bytes are verified; deriving its declared momentum hash still
requires an independently qualified NoM implementation and runtime observation.
The operator must rotate the epoch ID on every chain reset, including a reset
that deliberately reuses identical genesis files and chain IDs. A running node
must expose the independently accepted epoch identity before an application can
resume signing. This offline tool cannot detect an undeclared reset.

An epoch fingerprint hashes `ZVM chain epoch v1\n` followed by compact JSON of
the epoch and the contract records sorted by ID. Applications must retain it
with account and operation identity; changing a genesis, configuration,
deployment, address or code hash invalidates the old signing context even if a
chain ID is reused. This package alone does not implement application recovery.

## Canonical messages and signatures

Documents reject duplicate keys, case aliases, unknown nested fields, trailing
values, unsupported schemas and inputs over 1 MiB. Inventories are bounded to
1,024 entries per array. Repository/gitlink/artifact/file/contract collections
are sorted by their name, path or ID. Nil gitlink arrays normalize to `[]`.
Canonical JSON uses Go's compact `encoding/json` representation and the declared
schema field order; it is not an assertion of RFC-8785 conformance.

`release-message` emits the exact bytes to sign:

```sh
zvm release-message -manifest manifest.json -policy policy.json
```

The signing message is `ZVM release manifest v1\n` followed by canonical manifest
JSON, with no added trailing newline. Ed25519 signatures are detached. The
signature envelope is `{schema: 1, signatures: [...]}`; each signature has
`algorithm: "ed25519"`, `keySha256` (SHA-256 of the 32-byte public key) and `value`
(standard padded base64 of the 64-byte signature). Trust keys are supplied
independently as `{schema: 1, keys: [...]}`, containing standard base64 public
keys. No names, email addresses, private keys or machine paths belong in these
public documents. Keys supplied by a manifest are never accepted as trust roots.
Duplicate keys/signatures cannot satisfy a quorum.

```sh
zvm release-verify \
  -manifest manifest.json -policy policy.json \
  -signatures signatures.json -trusted-keys trusted-keys.json \
  -files-root release-inputs -sources-root source-checkouts
```

Verification authenticates signatures before reading the input set or running
Git. Git reads are bounded and do not fetch, initialize, reset or modify source
trees. Git must support `--no-lazy-fetch` and `--no-replace-objects`; an unsupported
Git fails rather than falling back to network access or replacement objects.
Hooks, fsmonitor, global configuration and credential prompts are disabled.
Only builtins inspect repositories and recursive gitlinks; locally configured
submodule commands are not invoked. Every repository must be clean at its
declared HEAD, including initialized recursive dependencies. The source walk is
bounded to 1,024 worktrees, depth eight, one minute total, ten seconds per Git
read and 2 MiB per output stream.
Receipts contain digests/counts and `runtimeObserved: false`, without local paths.
Image references, declared platform/version labels, running binary/image identity,
L1 genesis calculation, independent node agreement and production behavior require
separate qualification. A valid offline receipt cannot turn those gates green.

Tests use synthetic tool/image labels, ephemeral signing keys and throwaway Git
repositories. The shipped L2 configuration/genesis supply the actual supported
construction fixture. No wallet, container or live chain is started.

## Saved contract build material

A release can declare an additional file with `id: "contract-build-policy"`,
`kind: "config"`. Both the manifest and the independently reviewed policy must
inventory this file. `release-verify` checks it after signatures, files, genesis
construction and clean Git snapshots. An absent file returns
`verifiedContractBuilds: 0`; it establishes no reconstruction coverage. A complete
release acceptance policy must require the file explicitly.

The schema-1 document contains `epochId`, `rollupSha256`, `l2GenesisHash` and
`builds`. These identity fields must equal the signed release epoch. Each build
has `id`, `compiler`, `bundleFile`, `inputSha256`, `sources` and `contracts`:

- `compiler` references an inventoried compiler with platform
  `emscripten/wasm32`, version such as `0.8.30+commit.73712a01`, and an artifact
  pin no larger than 16 MiB. Its SHA-256 remains bound by the signed manifest.
- `bundleFile` references an `artifact` pin containing the exact
  `{schema: 1, compilerVersion, input, output}` document from a Standard JSON
  compilation. `compilerVersion` must equal the compiler version followed by
  `.Emscripten.clang`. `inputSha256` hashes the exact UTF-8 JSON bytes inside
  `input`, including its formatting. Each bundle is at most 16 MiB; at most 64
  builds and 64 MiB of bundles are accepted.
- A source is `{unit, file}`. Each relative `unit` names one input source with
  literal `content`, never `urls`. `file` references an `artifact` pin whose
  bytes, for an ordinary Git source, must match both that content and the same
  repository-relative file in the declared clean source checkout. A locked npm
  source uses the explicit archive/member binding below. Source files are at
  most 1 MiB each and 16 MiB per build. The input's complete source set must match
  this inventory.
- A contract target contains `contract`, `unit`, `name`, `creationSha256`,
  `storageLayoutSha256` and `metadataSha256`. `contract` references its release
  contract ID. The creation hash covers decoded creation bytes; the metadata
  hash covers the compiler's metadata string. The layout hash covers compact
  UTF-8 JSON with recursively sorted object keys and no HTML escaping. Array
  order is preserved. Source IDs, metadata compiler/target/source hashes and
  compiler diagnostics are checked. A compiler JSON error is a refusal.

Build targets must cover every release contract exactly once, and the release
must contain every predeploy embedded by the supported genesis constructor.
Omitting a predeploy from both inventories cannot turn partial reconstruction
into complete coverage. Invalid, duplicate, linked or immutable references are
refused. Runtime bytes must match in full, including metadata; there is no
metadata stripping, wildcard replacement or on-chain substitution. Typed policy
documents reject unknown fields and aliases. Compiler documents also reject
duplicate keys throughout dynamic/ignored objects, invalid UTF-8, trailing data,
nesting beyond 64 levels and excessive structure.

Receipts report the number of verified saved contract targets and always
`compilerExecuted: false`, `runtimeObserved: false`. A saved compiler output can
be authored without running its compiler. Authenticating that output establishes
consistency of declared bytes, not an execution witness. Retain separate bounded,
exact-source fresh-compiler command evidence and qualify its runtime. The node
repository's `contracts/rebuild-predeploys.cjs` supplies fresh reconstruction for
ZVMBridge and WrappedQSR only. Its locked layout vectors also bind the genesis
fee slots in this package's regression suite. Ten other predeploys, application
and benchmark artifacts, immutable/constructor witnesses, hosted build CI and
independent release acceptance remain open. This format deliberately cannot
accept their missing evidence as a completed reconstruction.

### Locked external package sources

An npm source adds `member`, `lockFile`, `packageKey`, `packageName` and
`packageVersion` to its `{unit, file}` record. All five fields are required
together. `file` pins the compressed distribution archive as an `artifact`;
`member` is its complete `package/.../*.sol` path. The unit must equal
`packageName + "/" + member-without-"package/"`. The archive is a release input,
not a file invented inside the source Git tree.

`lockFile` references a `lock` pin in the same owning repository. Its exact bytes
must agree in both the release file root and the declared clean source checkout.
The verifier supports npm lock versions 2 and 3 and looks up the exact
`packageKey`, such as `node_modules/@openzeppelin/contracts`. Its locked version
must equal `packageVersion`, its canonical single SHA-512 integrity must match
the entire SHA-256-pinned archive, and its distribution label must be HTTPS with
no credentials or fragment. The URL is never contacted. Linked/workspace and
ambiguous package entries are refused. The archive's own `package/package.json`
must independently agree with the declared name and exact version.

Archives are read in memory without extraction, installation, lifecycle scripts
or compiler execution. The accepted format is the pinned USTAR subset with gzip
checksum validation. All headers are checked, including unselected members;
links, PAX/GNU extensions, unsafe paths, case aliases, missing members, extra
nonzero trailing data and inconsistent identities are refused. A build admits
at most 16 distinct archive pins, 16 MiB per compressed archive, 32 MiB compressed
in total, 64 MiB expanded in total and 4,096 archive members in total. Parsing and
byte/member budgets are cached across source units rather than restarted for
each import. Cached content cannot be rebound to a different lock integrity.
Selected source and package identity files are limited to 1 MiB each.

The literal member bytes must equal the compiler input, and existing metadata
source hashes still have to agree. Ordinary Git-source checks and complete
genesis/release coverage remain required. Package integrity is a declared,
commit-bound supply input; it does not execute a compiler, establish constructor
or immutable behavior, or replace independent release acceptance.

## Service assertions

`Manifest.NewAssertion` checks the configured policy, independent trust keys and
signature quorum, then binds the exact rollup bytes used to start a service.
`DecodeAssertionInputs` provides the same operation for bounded input documents.
The public assertion contains the base64 signing message, detached signatures,
manifest and epoch fingerprints, and `runtimeObserved: false`. It contains no
trust-key list, credentials or local paths. This startup check does not inspect
the release's other files or source checkouts; qualify those separately with
`release-verify` before accepting a release.

The deterministic assertion vector is fixture-only and is checked by the Go
assertion tests. Its keys must never be used as operator trust keys. Browser
verification and application integration require separate implementation and checks.

## Typed saved contract material (schema 2)

The same signed `contract-build-policy` file may explicitly select schema 2.
It retains `epochId`, `rollupSha256`, `l2GenesisHash` and `builds`. Each build is
`{id, kind, definition}`. The complete release contract inventory and all twelve
supported genesis predeploys remain mandatory. Partial EIP or factory packages
cannot satisfy this gate. Schema 1 retains its original fields and rejects every
immutable substitution and every new typed definition.

The supported kinds have separate definitions:

| Kind | Definition |
| --- | --- |
| `solidity` | `{build, runtimeContexts}`; `build` has the schema-1 Solidity fields and the same ID as its enclosing typed build. |
| `solc-yul-fixed-return-v1` | `{compiler, bundleFile, inputSha256, sources, contracts}` for the reviewed solc 0.5.8 deterministic factory creation program. |
| `eip-evm-assembly-v1` | `{source, contracts}` for one final EIP-4788 or EIP-2935 document and its canonical system address. |

Every Solidity target must have one `runtimeContexts` entry keyed by its release
contract ID. All contexts include `kind` and `runtimeTemplateSha256`, the SHA-256
of the complete unfilled compiler runtime. Only these contexts are accepted:

- `exact` has no additional fields and requires an empty immutable map.
- `permit2-domain-cache` additionally declares `chainId`, `chainIdImmutable` and
  `domainImmutable`. It applies only to Permit2 at its supported canonical
  address. The two words are derived from the canonical decimal chain identity
  and `keccak256(abi.encode(typeHash, keccak256("Permit2"), chainId, address))`,
  with the fixed domain type
  `EIP712Domain(string name,uint256 chainId,address verifyingContract)`.
- `entrypoint-sender-creator` additionally declares `immutable`, `childContract`
  and `childNonce`. It applies only to the canonical EntryPoint. The nonce must
  be the explicit decimal string `"1"`; the child must be the release's canonical
  SenderCreator and equal `CREATE(entryPointAddress, 1)`.

- `collection-factory-implementation` declares `immutable` and
  `implementationContract`. It supports `apps/ZVMCollectionFactory.sol` and
  `ZVMCollectionFactory`. The same build must include the named counterpart as
  `apps/ZVMCollection.sol:ZVMCollection` with an `exact` runtime context. Its
  nonzero release address supplies the complete address word. The saved compiler
  output must retain the factory source AST under the exact `sources`/`ast`
  fields. The AST must bind the public immutable address declaration to the
  sole address constructor parameter through one direct assignment, without a
  base constructor or modifier. Declaration IDs, scopes and source identities
  must agree; arbitrary words and other constructor expressions are refused.

The collection context checks saved material. It does not execute its
constructor, initialize a clone or attest live implementation code. Qualify
source-bound constructor/storage/clone behavior separately and provision real
release authority independently.

- `farm-reward-token` declares `rewardTokenContract`. The reward token word is
  the canonical address of that separately inventoried release contract.
- `uniswap-v2-router02` declares `factoryContract` and `wethContract`. The
  factory must be a declared `contracts/UniswapV2Factory.sol:UniswapV2Factory`
  target with an `exact` context. Both addresses come from the complete release
  inventory; the Router02 constructor does not call either counterpart.
- `farm-fee-strategy` declares `farmContract`, `routerContract`,
  `factoryContract`, and `wethContract`. The farm must have a
  `farm-reward-token` context and the router must have a `uniswap-v2-router02`
  context, with their exact source-unit/contract roles. Router and strategy
  factory/WETH identity fields must agree. The strategy reward token is derived
  from the farm's declared reward identity, matching the reviewed constructor's
  `farm_.rewardToken()` call. No independent returned word is accepted. These
  subjects may belong to different Solidity builds; every subject is verified
  before the complete policy can succeed.
- `exchange-eip712-domain` has only the common `kind` and
  `runtimeTemplateSha256` fields. It derives the seven OpenZeppelin EIP-712
  cached domain/chain/address, hashed name/version, and ShortString words from
  the release epoch chain ID, the exchange release address, and the reviewed
  `ZVM Exchange` / `1` literals. A caller cannot override the chain or words.

These four contexts require the exact reviewed application/Router02 source
digests in `contractbuild_application.go`; the exchange also requires the
reviewed EIP712 and ShortStrings sources. Saved compiler AST declarations must
bind immutable IDs to the matching contract scopes, source file IDs, bounded
byte spans and declaration text. IDs are derived from those declarations,
rather than supplied by the policy. A source-version change needs a separately
reviewed derivation. The source fingerprints establish the supported literal
algorithm; the verifier does not evaluate arbitrary constructor expressions.

The source and AST checks operate on saved compiler material and do not execute
the compiler or a constructor. Constructor/storage witnesses remain separate.
Counterpart identity consistency is not acceptance of ERC-20 behavior, DEX
operations, funding, operator policy or an actual deployment. The exchange
context describes construction in the declared release epoch; a different
historical cached chain requires a separate reviewed witness.

The complete compiler reference map must equal the declared binding inventory.
Every range is exactly 32 bytes, non-overlapping and zero in the original
template. IDs and range fields are canonical and case-sensitive; at most 256
ranges are accepted. The verifier derives the declared words independently and
compares every resulting byte, including metadata, with the signed release code.
It accepts no observed runtime word or general-purpose masking expression.
Historical construction context is explicit: Permit2's chain-10 cached words do
not assert construction on the current ZVM chain. Ordinary fresh-copy constructor
and current-genesis behavior proofs retain their own contexts. Other application
immutable and library witnesses require a separate supported format.

The Yul kind requires one exact literal Git source and the pinned
`0.5.8+commit.23d335f2` WASM compiler identity. Its targets contain `contract`,
`unit`, `name`, `creationSha256` and `runtimeSha256`. Both factory release
addresses may reference the same `Proxy` output. The complete 83-byte creation
program must retain the exact 14-byte copy/return prefix followed by its 69-byte
runtime. This creation-only compiler output must not invent Solidity ABI,
metadata, storage layout or a deployed-output object. Library and immutable
references remain refused.

The EIP kind requires one ordinary signed Git source, bounded at 64 KiB. Its
target contains `contract`, `eip`, `assemblySha256`, `creationSha256` and
`runtimeSha256`. The document must have one matching EIP identity, one `Final`
status, one literal `caller` assembly section and one creation input. A finite
assembler accepts the reviewed instructions and exact-width lowercase PUSH
operands, with no macros, labels, expressions or callbacks. The complete source
program, nine-byte creation prefix and runtime must match all declared pins and
the release contract code. No Solidity compiler, ABI or layout is claimed.

Typed definitions reject omissions, unknown fields, duplicate keys, case aliases
and null required values. Compiler bundles remain individually bounded at
16 MiB, unique per build, and collectively bounded at 64 MiB across at most 64
builds. The bounded npm archive reader and its cumulative compressed, expanded,
archive/member and digest authority are shared across the typed policy.

These checks run after signatures, independent inventories, file/genesis checks
and clean source snapshots. The receipt still reports `compilerExecuted: false`
and `runtimeObserved: false`. Saved material consistency and deterministic source
assembly do not establish fresh compiler provenance, actual constructor state,
canonical deployment, system-call/block processing, supported-platform or
independent operator/release acceptance. No real policy, key or release is shipped.
