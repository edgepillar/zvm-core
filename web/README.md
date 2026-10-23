# @zvm/web

Address input policy: NoM strings use BIP-173 checksums and may be uniformly
lowercase or uppercase; mixed case is rejected. Hex inputs must contain exactly
40 ASCII hexadecimal digits, with an optional `0x`/`0X` prefix for `hexToNom`.
`toEvmAddress` trims surrounding whitespace and accepts prefixed hex or NoM.
`isNomUser` requires a complete prefixed hex address with the user type byte.
Hex syntax validation does not verify an EIP-55 checksum.

Run `npm --prefix web test` from the repository root with Node.js 22.6 or newer.
The tests use Node's built-in type stripping and need no installed dependencies.
They share `vectors/address-vectors.json` with the Go client.

The parts of a ZVM web app that must not differ between apps.

The ZVM's front ends (`zvm-explorer`, `zvm-glyphswap`, `zvm-nft`, `zvm-karum`,
`zvm-mozaic`, `zvm-zns` and the status page) are separate static bundles with
no backend, which is the right shape for them — but they were each carrying
their own copy of bech32, of `units()`, of the viem chain definition and of the
relayer's fee floor. Copies of arithmetic drift, and the ways they drift here
are not cosmetic: an address that decodes to different bytes in two apps sends money to
the wrong place, and a tip floor that is right in one and stale in the other
produces a transaction one app can land and the other cannot.

So this is the shared half, in the repo that already holds what every ZVM
process has to agree on:

```
config.ts      the four things an app tells this package about itself
address.ts     bech32 (BIP-173): a NoM z1 address ↔ the 20 bytes the EVM sees
format.ts      units, amounts, times, sizes — every number a person reads
evm.ts         the viem chain, the clients, wallet discovery, the fee policy
url.ts         what counts as a loopback, and what a browser will refuse to call
prices.ts      dollars: the node's /api/prices, and what an amount is worth
names.ts       .znn names through ZNS's resolver, and links to the ZNS page
components/    the marks and chrome every app draws identically
```

`prices.ts` is a store rather than a module of functions, because each app
reaches its node differently. `createPrices(() => apiBase)` is handed a getter,
called on every refresh: the explorer and the NFT market always have an API
base, glyphswap may be pointed at a bare op-reth that has none, and all three
let a person change node mid-session. A null base is not an error — nothing is
fetched, and every price is simply unknown.

Unknown is also how an unpriced token reads. `usdOf` and `usdValue` return
`null`, never 0, and each app leaves the line out rather than printing $0.00
for a balance nobody can value.

## Using it

Each app carries zvm-core as a git submodule and resolves `@zvm/web` into it
through a Vite alias and a tsconfig path, the same arrangement as the Go
modules' `replace github.com/Zenoglyphs-VM/zvm-core => ./zvm-core`:

```ts
// vite.config.ts
resolve: {alias: {'@zvm/web': resolve(__dirname, 'zvm-core/web/src')}}
```

`vue` and `viem` are peer dependencies, pinned in the same config to the app's
own copies so there is one Vue instance. `names.ts` links to the ZNS page under
the app's `VITE_GATEWAY`, and to none when the app has no gateway set.

Then, once, at startup:

```ts
import {configure} from '@zvm/web'

configure({
  empty: '-',                       // what a formatter prints for nothing
  appUrl: () => location.origin,    // a wallet's "view on explorer" link
  rpcUrl: () => `${base()}/rpc`,    // where reads go
  chainName: id => `ZVM ${id}`,
})
```

`empty` is the one that looks trivial and is not. The explorer prints `-` for a
value it does not have, and the swap interface prints `0`, because a dash in a
trade field reads as a broken input. Both are right; what would be wrong is one
of them changing because the other did.

Then, for dollars, one store per app:

```ts
import {prices} from '@zvm/web'

const store = prices.createPrices(() => endpoint.apiBase)   // may return null
store.start()                                               // refreshes every 30s
```

## What is deliberately not here

The endpoint store, the wallet store and the chain heartbeat stay in each app.
They look similar and they are not the same thing: the explorer's endpoint is a
node's API base with the RPC hanging off it, and glyphswap's is a bare JSON-RPC
URL with presets, chosen so it works against an op-reth with no node in front.
Merging those would mean one app pretending to be the other. The pure helpers
underneath them — `isLoopback`, `mixedContentBlocked` — are shared, because
those are facts about browsers, not choices about apps.
