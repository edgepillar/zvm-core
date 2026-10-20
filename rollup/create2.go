package rollup

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Deterministic deployment (DECISIONS.md D32).
//
// A contract this chain's rules or its explorer must agree on cannot live at
// "wherever the operator's deploy script put it" — two explorers configured
// with different files would show two different marketplaces, and nothing on
// chain would say which is real. The industry answer for *application*
// contracts is a deterministic proxy: Safe, Uniswap and `forge create
// --create2` all deploy through one, so an address is a pure function of
// (factory, salt, init code) and anyone can recompute it. Genesis predeploys
// are what OP uses for *system* contracts, which these are not.
//
// This chain's genesis already carries Arachnid's deployer at the address every
// EVM chain has it, so nothing needs to be added to genesis: a deployment is a
// transaction to it whose calldata is `salt ‖ initCode`.

// Create2Deployer is Arachnid's deterministic deployment proxy
// (https://github.com/Arachnid/deterministic-deployment-proxy), a genesis
// predeploy here and on every other EVM chain. Calldata is `salt ‖ initCode`;
// it returns the 20-byte address.
var Create2Deployer = common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")

// Salt is this project's published salt for a named contract:
// keccak256("zvm/<name>/v<version>"). Publishing the rule rather than 32
// opaque bytes is what lets someone else recompute an address from the name
// alone.
func Salt(name string, version int) common.Hash {
	return crypto.Keccak256Hash([]byte(fmt.Sprintf("zvm/%s/v%d", name, version)))
}

// Create2Address is EIP-1014's address: the low 20 bytes of
// keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(initCode)).
func Create2Address(deployer common.Address, salt common.Hash, initCode []byte) common.Address {
	return crypto.CreateAddress2(deployer, salt, crypto.Keccak256(initCode))
}

// DeployCalldata is what the deterministic deployer is called with.
func DeployCalldata(salt common.Hash, initCode []byte) []byte {
	return append(append([]byte{}, salt[:]...), initCode...)
}

// Artifact is a compiled contract as the repository keeps it: the creation
// code the address is computed from, and enough provenance to recompile it.
type Artifact struct {
	Contract string          `json:"contract"`
	Source   string          `json:"source"`
	Compiler string          `json:"compiler"`
	Settings json.RawMessage `json:"settings"`
	ABI      json.RawMessage `json:"abi"`
	Bin      string          `json:"bin"`
	Runtime  string          `json:"runtime"`
}

// InitCode is the creation code the deployment sends.
func (a *Artifact) InitCode() []byte { return common.FromHex(a.Bin) }

// RuntimeCode is what ends up on chain, which is what a verifier compares.
func (a *Artifact) RuntimeCode() []byte { return common.FromHex(a.Runtime) }

// AddressWithSalt is where this artifact lands through the deterministic
// deployer with the given salt.
func (a *Artifact) AddressWithSalt(salt common.Hash) common.Address {
	return Create2Address(Create2Deployer, salt, a.InitCode())
}
