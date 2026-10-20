package l2

import (
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Source-hash domains. 0 and 1 are OP Stack's (user deposit, L1 info); 3 is
// the ZVM's derived bridge calls and 4 its derived fee split. OP uses 2 for
// network upgrades.
const (
	DomainUserDeposit = 0
	DomainL1Info      = 1
	DomainSystem      = 3
	DomainFees        = 4
)

// SourceHash is OP Stack's construction: keccak256(domain ‖ keccak256(l1Hash ‖
// index)), with the NoM momentum or account block hash as the L1 hash. It is
// what makes two deposits with identical fields distinct transactions.
func SourceHash(domain uint64, l1Hash [32]byte, index uint64) common.Hash {
	var d, idx [32]byte
	binary.BigEndian.PutUint64(d[24:], domain)
	binary.BigEndian.PutUint64(idx[24:], index)
	inner := crypto.Keccak256(l1Hash[:], idx[:])
	return common.BytesToHash(crypto.Keccak256(d[:], inner))
}

// L1 attributes selectors: setL1BlockValuesIsthmus() and its Jovian
// successor, which Karst carries.
var (
	IsthmusL1InfoSelector = []byte{0x09, 0x89, 0x99, 0xbe}
	JovianL1InfoSelector  = []byte{0x3d, 0xb6, 0xbe, 0x2b}
)

// L1InfoData encodes a momentum as the L1 attributes calldata of every block's
// first transaction: 176 bytes on Isthmus, 178 on Karst, where Jovian appends
// the DA-footprint gas scalar. The engine derives receipt fields from this
// exact layout, and the L1Block predeploy stores it, which is how ZVM
// contracts read NoM: L1Block.number() is the momentum height, hash() its
// hash, timestamp() its time.
//
// The fee fields are zero — the ZVM posts no data to Ethereum and charges no
// L1 data fee — and batcherHash carries the inbox address. **The DA-footprint
// scalar is zero too**, which is what makes Jovian's second metering rule
// inert here: the footprint is priced against a data layer this chain does not
// use.
func L1InfoData(cfg *rollup.Config, m *znn.Momentum) []byte {
	buf := make([]byte, 0, 178)
	if cfg.IsKarst() {
		buf = append(buf, JovianL1InfoSelector...)
	} else {
		buf = append(buf, IsthmusL1InfoSelector...)
	}
	buf = binary.BigEndian.AppendUint32(buf, 0) // baseFeeScalar
	buf = binary.BigEndian.AppendUint32(buf, 0) // blobBaseFeeScalar
	buf = binary.BigEndian.AppendUint64(buf, 0) // sequenceNumber: one L2 block per momentum
	buf = binary.BigEndian.AppendUint64(buf, m.Timestamp)
	buf = binary.BigEndian.AppendUint64(buf, m.Height)
	buf = append(buf, make([]byte, 32)...) // basefee
	buf = append(buf, make([]byte, 32)...) // blobBaseFee
	buf = append(buf, m.Hash[:]...)
	// The protocol inbox, not this rollup's tagged one: nothing reads the
	// field, and changing it would move every block hash on a chain that has
	// already derived with it.
	buf = append(buf, common.LeftPadBytes(rollup.Inbox[:], 32)...)
	buf = binary.BigEndian.AppendUint32(buf, 0) // operatorFeeScalar
	buf = binary.BigEndian.AppendUint64(buf, 0) // operatorFeeConstant
	if cfg.IsKarst() {
		buf = binary.BigEndian.AppendUint16(buf, 0) // daFootprintGasScalar
	}
	return buf
}

// L1InfoTx is the first transaction of the L2 block derived from m.
func L1InfoTx(cfg *rollup.Config, m *znn.Momentum) *types.Transaction {
	to := rollup.L1BlockAddr
	return types.NewTx(&types.DepositTx{
		SourceHash: SourceHash(DomainL1Info, m.Hash, 0),
		From:       rollup.L1InfoDepositor,
		To:         &to,
		Value:      new(big.Int),
		Gas:        rollup.L1InfoGas,
		Data:       L1InfoData(cfg, m),
	})
}

// EthAddress is the EVM spelling of a NoM address: the same 20 bytes.
func EthAddress(a znn.Address) common.Address { return common.Address(a) }

// NomAddress is the NoM spelling of an EVM address.
func NomAddress(a common.Address) znn.Address { return znn.Address(a) }
