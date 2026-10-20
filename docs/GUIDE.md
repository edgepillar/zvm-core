# zvm-core guide

The part of the ZVM that every process has to agree on, as one Go module.

The ZVM is a based EVM on Zenon's Network of Momentum: NoM orders and stores
every transaction, and a derivation node turns each momentum into exactly one
EVM block. There is no sequencer, so *any* node with the same NoM history must
rebuild the same chain — which is the reason this module exists. The node, the
relayer and the bridge are separate programs in separate repositories, and if
they carried their own copies of `derive`, two of them could read the same
momentum and disagree about what block it is. One copy, one chain.

```
znn       the NoM client: addresses, account blocks, plasma, token standards
rollup    the chain's parameters — fork heights, gas rules, fee schedule
l2        the genesis: predeploys, the alloc, the deposit transaction
derive    momentum in, EVM block out. This is the consensus.
store     the SQLite schema and the migrations both the node and the bridge use
devnet    the dev mnemonic and the indices each role signs from
ethrpc    the sliver of the Ethereum JSON-RPC shape used outside an ethclient
service   stop on a signal; wait for a dependency that is not up yet
cli       flags, amounts and JSON replies, spelled the same way in every binary
orderbook the NFT order: EIP-712 hashing, the bulk Merkle tree, signing
faucet    devnet ZNN and QSR, with the plasma to spend it
vectors   every encoding above, computed and written to zvm-docs/spec
```

`orderbook` holds only the order's encoding, not the book: an order is hashed in
three places — here, the browser, and `ZVMExchange.sol` — and a browser that
hashed one differently from the node would collect signatures nothing can fill.
Storage and matching need a database and the compiled contract, so they stay in
[`zvm-node/orderbook`](https://github.com/Zenoglyphs-VM/zvm-node/tree/main/orderbook), which aliases these names.

`web/` is the same idea for the browser: an npm package, **@zvm/web**, holding
the bech32 encoding, the number formatting, the viem chain definition, the
dollar-price store and the relayer's fee floor that `zvm-explorer`, `zvm-nft`
and `zvm-glyphswap` were each carrying their own copy of. See
[web/README.md](../web/README.md).

## `zvm`, the tool

`cmd/zvm` is every ZVM command that is not a service: the two genesis
generators, the dev-key transactions, the faucet, the fee splitter, the vectors
and the two repair commands.

```
l1-genesis   write a NoM L1 genesis and node configs
l2-genesis   write op-geth's genesis, the rollup config and the Engine API secret
call         send a native call, or a contract deploy, from a dev key
deposit      move ZNN or QSR into the ZVM through the vault
balance      an address's balances on both layers
evm-send     sign and send EVM transactions as MetaMask would
evm-key      a dev secp256k1 key and its addresses, for importing into a wallet
sign         sign a message the way the Syrius extension does
fund         ZNN, QSR and plasma onto an L1 account of a running chain
faucet       hand out devnet ZNN/QSR on NoM, and ZNN on the ZVM
fees         the relayed lane's fee splitter: where it lands and what it holds
constants    protocol addresses, chain ids and token bytes
vectors      write or check zvm-docs/spec/vectors.json
compare      check that two ZVM nodes derived the same chain
rebid        unwedge an account whose oldest block missed a congested momentum
```

They are here and not in a service because none of them is part of running one:
they need the encodings, the dev mnemonic and the chain parameters, and nothing
a node, a relayer or a bridge owns. Putting one in a service would mean building
a node to write a genesis file.

Two commands are **not** here. `dex` and `verify-tokens` are in
[`zvm-node`](https://github.com/Zenoglyphs-VM/zvm-node), because both need the compiled Solidity and half a
contract tree verifies nothing.

## Who uses it

| | |
|---|---|
| [`zvm-node`](https://github.com/Zenoglyphs-VM/zvm-node) | derives the chain, indexes it, serves the read API |
| [`zvm-relayer`](https://github.com/Zenoglyphs-VM/zvm-relayer) | the batch lane: signed EVM transactions → NoM |
| [`zvm-bridge`](https://github.com/Zenoglyphs-VM/zvm-bridge) | the peg, and the FROST committee that signs payouts |
| [`zvm-explorer`](https://github.com/Zenoglyphs-VM/zvm-explorer), [`zvm-nft`](https://github.com/Zenoglyphs-VM/zvm-nft), [`zvm-glyphswap`](https://github.com/Zenoglyphs-VM/zvm-glyphswap) | static front ends, sharing `web/` |
| [`zvm-fleet`](https://github.com/Zenoglyphs-VM/zvm-fleet) | the whole-system benchmark, and a local devnet stack in `devnet/` |
| [`zvm-docs`](https://github.com/Zenoglyphs-VM/zvm-docs) | the spec, the decisions, operations and benchmarks |

Each carries this module as a git submodule at `./zvm-core`, pinned to a commit,
and a `replace github.com/Zenoglyphs-VM/zvm-core => ./zvm-core` builds against
that checkout rather than a published version. Moving a dependent to a newer
core is a submodule bump, made on purpose.

## Building and testing

```sh
go build ./...
go test ./...
```

`l2`'s genesis tests check `BuildGenesis` against the *committed* `rollup.json`
and `genesis.json` of every chain, because a drift between them either refuses
to start a node or — worse — starts one against a genesis nobody meant. Those
files are in `chains/`, one directory per chain (`l2` is chain 70, `l2-dp` chain
71, `l2-69` chain 69, and `nom`, `nom-dp` their L1s); `ZVM_CHAINS` points the
tests at another set:

```sh
ZVM_CHAINS=/path/to/chains go test ./l2/
```

A missing chain directory fails the test rather than skipping it. A skipped
genesis check is how the op-geth/op-reth `withdrawalsRoot` split (D2) comes
back.

`vectors` sits beside the code that computes the golden encodings:
`vectors/vectors.json` is what zvm-docs' `spec/SPEC.md` is pinned by. `ZVM_SPEC`
points the test at another copy, and a missing file fails.

```sh
go run ./cmd/zvm vectors -check      # the committed file still matches the code
go run ./cmd/zvm vectors -write      # after a deliberate encoding change
```

## The one rule

`derive` is consensus. A change to it changes what block a momentum means, so
it is a hard fork whether or not anyone calls it one, and every node has to
take the same change at the same height. Everything else here is ordinary code.
