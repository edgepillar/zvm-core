package rollup

import (
	_ "embed"
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// The relayed lane's fee split (DECISIONS.md D9, "the relayed lane's fee").
//
// From the gas fork, a block's `coinbase` is the ZVMFees contract rather than
// the sequencer fee vault, so every relayed transaction's priority fee arrives
// there. After the user transactions, derivation appends one system call to
// `settle`, carrying the per-author weights it computed from that block's own
// messages: half of each author's share is credited to it, the rest is sent to
// the burn address.
//
// The contract is not a predeploy. It is deployed through the deterministic
// deployer that is already in genesis (D32), so turning this on costs no
// genesis change — the address is a pure function of the published salt and
// the creation code committed beside this file.

//go:embed artifacts/ZVMFees.json
var feesArtifactJSON []byte

// FeesArtifact is the compiled ZVMFees, as committed.
var FeesArtifact = mustArtifact(feesArtifactJSON)

// FeesSalt is the published salt ZVMFees is deployed with.
var FeesSalt = Salt("fees", 1)

// FeeSplitterAddr is where ZVMFees lands: CREATE2 from the deterministic
// deployer with FeesSalt and the committed creation code. Pinned by a test
// against the literal below, so recompiling with different settings fails
// loudly instead of moving a consensus address.
var FeeSplitterAddr = FeesArtifact.AddressWithSalt(FeesSalt)

// BurnAddr is where the burned half of a relayed fee goes on the ZVM: no code,
// no key, and a balance anyone can read as the chain's burned supply.
var BurnAddr = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

// BurnMagic prefixes the data of a vault send to the inbox that destroys, on
// NoM, ZNN the fee splitter has burned here: "ZVMB" then the 32-byte cumulative
// total the committee believes it has now matched.
var BurnMagic = []byte("ZVMB")

const (
	// FeeSettleBaseGas is the settle call's fixed cost, and FeeSettleAuthorGas
	// what each author adds (a cold SSTORE, an event, and the arithmetic).
	FeeSettleBaseGas   = 80_000
	FeeSettleAuthorGas = 45_000
	// MaxFeeSplitAuthors bounds one settle. A block with more relayers than
	// this pays the largest MaxFeeSplitAuthors of them and burns the rest,
	// which keeps the derived transaction's gas bounded.
	MaxFeeSplitAuthors = 32
)

// FeeSettleGas is the gas reserved for one settle call.
func FeeSettleGas(authors int) uint64 {
	if authors > MaxFeeSplitAuthors {
		authors = MaxFeeSplitAuthors
	}
	return FeeSettleBaseGas + uint64(authors)*FeeSettleAuthorGas
}

func mustArtifact(raw []byte) *Artifact {
	var a Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		panic(err)
	}
	if len(a.InitCode()) == 0 {
		panic("rollup: " + a.Contract + " artifact has no creation code")
	}
	return &a
}

// WeiPerBaseUnit is ZNNScale as a big.Int, for the burn mirror's arithmetic.
func WeiPerBaseUnit() *big.Int { return new(big.Int).Set(ZNNScale) }
