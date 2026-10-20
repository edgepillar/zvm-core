package derive

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Calls the derivation makes into ZVMBridge. Encoded by hand: two static
// signatures do not justify the ABI package, and a test pins them against the
// compiled contract's ABI.

var (
	selectorMarkPaid   = crypto.Keccak256([]byte("markPaid(uint256,bytes32,address,bytes10,uint256)"))[:4]
	selectorDepositQSR = crypto.Keccak256([]byte("depositQSR(bytes32,address,uint256)"))[:4]
	selectorSettle     = crypto.Keccak256([]byte("settle(uint256,address[],uint256[])"))[:4]
	selectorMarkBurned = crypto.Keccak256([]byte("markBurnedOnNoM(bytes32,uint256)"))[:4]
	selectorMarkFused  = crypto.Keccak256([]byte("markFused(bytes32,address,uint256)"))[:4]

	// PlasmaFuseSelector is NoM's plasma.Fuse(address). Embedded-contract
	// selectors are SHA3-256, not Keccak.
	PlasmaFuseSelector = func() []byte { h := znn.Sha3([]byte("Fuse(address)")); return h[:4] }()
)

// PlasmaContract is NoM's embedded plasma contract.
var PlasmaContract = znn.MustParseAddress("z1qxemdeddedxplasmaxxxxxxxxxxxxxxxxsctrp")

// EncodePlasmaFuse is the data of a NoM send that fuses QSR to beneficiary.
func EncodePlasmaFuse(beneficiary znn.Address) []byte {
	return append(append([]byte{}, PlasmaFuseSelector...), word(beneficiary[:])...)
}

// EncodeMarkFused encodes ZVMBridge.markFused(nomBlock, beneficiary, amount).
func EncodeMarkFused(nomBlock znn.Hash, beneficiary common.Address, amount *big.Int) []byte {
	out := append([]byte{}, selectorMarkFused...)
	out = append(out, nomBlock[:]...)
	out = append(out, word(beneficiary.Bytes())...)
	out = append(out, uintWord(amount)...)
	return out
}

func word(b []byte) []byte { return common.LeftPadBytes(b, 32) }

func uintWord(x *big.Int) []byte {
	if x == nil {
		return make([]byte, 32)
	}
	return word(x.Bytes())
}

// bytesNWord right-pads a fixed-size byte string, as the ABI does for bytesN.
func bytesNWord(b []byte) []byte {
	out := make([]byte, 32)
	copy(out, b)
	return out
}

// EncodeMarkPaid encodes markPaid(id, nomBlock, to, zts, amount).
func EncodeMarkPaid(id *big.Int, nomBlock znn.Hash, to common.Address, zts znn.TokenStandard, amount *big.Int) []byte {
	out := append([]byte{}, selectorMarkPaid...)
	out = append(out, uintWord(id)...)
	out = append(out, nomBlock[:]...)
	out = append(out, word(to.Bytes())...)
	out = append(out, bytesNWord(zts[:])...)
	out = append(out, uintWord(amount)...)
	return out
}

// EncodeDepositQSR encodes depositQSR(nomBlock, to, amount).
func EncodeDepositQSR(nomBlock znn.Hash, to common.Address, amount *big.Int) []byte {
	out := append([]byte{}, selectorDepositQSR...)
	out = append(out, nomBlock[:]...)
	out = append(out, word(to.Bytes())...)
	out = append(out, uintWord(amount)...)
	return out
}

// EncodeSettle encodes ZVMFees.settle(momentum, relayers, weights): the
// per-author split of one block's priority fees. Two dynamic arrays, so the
// head carries their offsets and the tail their lengths and contents.
func EncodeSettle(momentum uint64, relayers []common.Address, weights []uint64) []byte {
	n := len(relayers)
	const headWords = 3
	relOffset := uint64(headWords * 32)
	wOffset := relOffset + 32 + uint64(n)*32

	out := append([]byte{}, selectorSettle...)
	out = append(out, uintWord(new(big.Int).SetUint64(momentum))...)
	out = append(out, uintWord(new(big.Int).SetUint64(relOffset))...)
	out = append(out, uintWord(new(big.Int).SetUint64(wOffset))...)
	out = append(out, uintWord(new(big.Int).SetUint64(uint64(n)))...)
	for _, a := range relayers {
		out = append(out, word(a.Bytes())...)
	}
	out = append(out, uintWord(new(big.Int).SetUint64(uint64(len(weights))))...)
	for _, w := range weights {
		out = append(out, uintWord(new(big.Int).SetUint64(w))...)
	}
	return out
}

// EncodeMarkBurned encodes ZVMFees.markBurnedOnNoM(nomBlock, amount): the
// committee destroying, on NoM, ZNN the splitter burned here. The amount is in
// wei, so a NoM base unit is scaled up on the way in.
func EncodeMarkBurned(nomBlock znn.Hash, amountWei *big.Int) []byte {
	out := append([]byte{}, selectorMarkBurned...)
	out = append(out, nomBlock[:]...)
	out = append(out, uintWord(amountWei)...)
	return out
}
