# Third-party material

zvm-core is MIT-licensed (LICENSE). These files come from other projects and
keep the licence their upstream gives them.

| Path | What | Upstream |
|---|---|---|
| `l2/predeploys/EntryPoint_v07.hex`, `SenderCreator_v07.hex` | ERC-4337 EntryPoint v0.7 runtime bytecode | eth-infinitism/account-abstraction (GPL-3.0) |
| `l2/predeploys/Permit2.hex` | Permit2 runtime bytecode | Uniswap/permit2 (MIT) |
| `l2/predeploys/Multicall3.hex` | Multicall3 runtime bytecode | mds1/multicall (MIT) |
| `l2/predeploys/SafeSingletonFactory.hex` | Safe singleton factory | safe-global/safe-singleton-factory |
| `l2/predeploys/Create2Deployer_Arachnid.hex` | deterministic deployment proxy | Arachnid/deterministic-deployment-proxy |
| `l2/predeploys/BeaconRoots_4788.hex`, `HistoryStorage_2935.hex` | EIP-4788 and EIP-2935 system contracts | the EIPs (CC0) |
| `l2/predeploys/L1Block.hex`, `L2ToL1MessagePasser.hex` | OP Stack predeploys | ethereum-optimism/optimism (MIT) |
| `tools/noticebundle/` | CLI source notice collector adapted from zvm-node | [MIT notice](tools/noticebundle/LICENSE.zvm-node) |

`WrappedQSR.hex` and `ZVMBridge.hex` are this project's own.

The CLI image includes the selected Go dependency and SDK notices under
`/usr/share/doc/zvm/notices`. The manifest records their source scopes, object
digests, linked module identities and the CLI binary digest.
