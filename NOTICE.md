# Third-party material

zvm-core is MIT-licensed (LICENSE). These files come from other projects and
keep the licence their upstream gives them.

| Path | What | Upstream |
|---|---|---|
| `l2/predeploys/EntryPoint_v07.hex`, `SenderCreator_v07.hex` | ERC-4337 EntryPoint v0.7 runtime bytecode | eth-infinitism/account-abstraction (GPL-3.0 and LGPL-3.0-only declarations) and OpenZeppelin (MIT) sources in the build group |
| `l2/predeploys/Permit2.hex` | Permit2 runtime bytecode | Uniswap/permit2 (MIT) and Solmate (AGPL-3.0-only) sources in the build group |
| `l2/predeploys/Multicall3.hex` | Multicall3 runtime bytecode | mds1/multicall (MIT) |
| `l2/predeploys/SafeSingletonFactory.hex` | Safe singleton factory | safe-fndn/safe-singleton-factory (MIT) |
| `l2/predeploys/Create2Deployer_Arachnid.hex` | deterministic deployment proxy | Arachnid/deterministic-deployment-proxy (Unlicense) |
| `l2/predeploys/BeaconRoots_4788.hex`, `HistoryStorage_2935.hex` | EIP-4788 and EIP-2935 system contracts | the EIPs (CC0-1.0) |
| `l2/predeploys/L1Block.hex`, `L2ToL1MessagePasser.hex` | OP Stack predeploys | ethereum-optimism/optimism (MIT) |
| `tools/noticebundle/` | CLI source notice collector adapted from zvm-node | [MIT notice](tools/noticebundle/LICENSE.zvm-node) |

`WrappedQSR.hex` and `ZVMBridge.hex` are this project's own.

The CLI image includes the selected Go dependency and SDK notices under
`/usr/share/doc/zvm/notices`. The manifest records their source scopes, object
digests, linked module identities and the CLI binary digest.

The same image contains the license texts for the listed predeploys and their
compiler input groups. The project entries in its manifest locate the original
texts and the catalog by digest. [Predeploy source and license catalog](LICENSES/predeploys/sources.json)

The Linux amd64 Alpine catalog identifies the installed APKs, their build
recipe commits and selected original notices and reference texts. The
project entries in the image manifest locate the catalog and its objects by
digest. The APK declaration reader is adapted from zvm-node.
[Alpine source and notice catalog](LICENSES/alpine/sources.json) ·
[MIT notice](tools/noticebundle/LICENSE.zvm-node)
