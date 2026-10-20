// Package orderbook is the NFT market's order: an EIP-712 signature rather
// than a transaction (DECISIONS.md D28), the way OpenSea's and Blur's are.
//
// Only the encoding lives here — hashing, the Merkle tree a bulk listing is
// signed over, signing and recovery. Storage, matching and the live re-check
// against the exchange are zvm-node's, because they need a database and the
// compiled contract; this half needs neither.
//
// It is in zvm-core for the reason cli is: an order is hashed in three places
// — this package, the browser, and ZVMExchange.sol — and a browser that hashed
// one differently from the node would collect signatures nothing can fill.
// spec/vectors.json pins the agreement, and vectors computes it from here.
package orderbook

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Sides and signature kinds, as the exchange numbers them.
const (
	SideSell uint8 = 0
	SideBuy  uint8 = 1

	KindSingle  uint8 = 0 // an EIP-712 signature over the order
	KindBulk    uint8 = 1 // an EIP-712 signature over a Merkle root of orders
	KindOnChain uint8 = 2 // approveOrders, sent by the trader
)

// Check codes returned by ZVMExchange.checkOrder.
const (
	CodeOK           uint8 = 0
	CodeBadSignature uint8 = 1
	CodeCancelled    uint8 = 2
	CodeStaleNonce   uint8 = 3
	CodeNotStarted   uint8 = 4
	CodeExpired      uint8 = 5
	CodeFilled       uint8 = 6
	CodeNotHeld      uint8 = 7
	CodeNotFunded    uint8 = 8
	CodeMalformed    uint8 = 9
)

// CodeText is what a check code means, for a person.
func CodeText(code uint8) string {
	switch code {
	case CodeOK:
		return "fillable"
	case CodeBadSignature:
		return "the signature does not match the order"
	case CodeCancelled:
		return "cancelled"
	case CodeStaleNonce:
		return "cancelled: the trader has bumped their nonce since signing"
	case CodeNotStarted:
		return "not open yet"
	case CodeExpired:
		return "expired"
	case CodeFilled:
		return "filled"
	case CodeNotHeld:
		return "the seller no longer holds the token, or no longer lets the exchange move it"
	case CodeNotFunded:
		return "the bidder lacks the balance or the allowance to pay"
	case CodeMalformed:
		return "malformed"
	}
	return fmt.Sprintf("code %d", code)
}

var (
	OrderTypeHash = crypto.Keccak256Hash([]byte("Order(address trader,uint8 side,address collection,uint256 tokenId,bool anyToken,uint256 amount,address paymentToken,uint256 price,uint64 listingTime,uint64 expirationTime,uint256 nonce,uint256 salt)"))
	RootTypeHash  = crypto.Keccak256Hash([]byte("OrderRoot(bytes32 root)"))
	domainType    = crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
)

// DomainName and DomainVersion are the exchange's EIP-712 domain.
const (
	DomainName    = "ZVM Exchange"
	DomainVersion = "1"
)

// Order is ZVMExchange.Order. Amounts are decimal strings in JSON, which is
// what a wallet's typed-data prompt shows and what JavaScript can hold.
type Order struct {
	Trader         common.Address `json:"trader"`
	Side           uint8          `json:"side"`
	Collection     common.Address `json:"collection"`
	TokenID        *znn.BigInt    `json:"tokenId"`
	AnyToken       bool           `json:"anyToken"`
	Amount         *znn.BigInt    `json:"amount"`
	PaymentToken   common.Address `json:"paymentToken"`
	Price          *znn.BigInt    `json:"price"`
	ListingTime    uint64         `json:"listingTime"`
	ExpirationTime uint64         `json:"expirationTime"`
	Nonce          *znn.BigInt    `json:"nonce"`
	Salt           *znn.BigInt    `json:"salt"`
}

// Input is ZVMExchange.Input: an order and how its trader agreed to it.
type Input struct {
	Order     Order         `json:"order"`
	Kind      uint8         `json:"kind"`
	Signature hexutil.Bytes `json:"signature"`
	Proof     []common.Hash `json:"proof"`
	Root      *common.Hash  `json:"root,omitempty"`
}

func word(b []byte) []byte { return common.LeftPadBytes(b, 32) }

func uintWord(x *znn.BigInt) []byte { return word(x.Big().Bytes()) }

func boolWord(b bool) []byte {
	if b {
		return word([]byte{1})
	}
	return make([]byte, 32)
}

// Hash is the order's EIP-712 struct hash, which is also its identity: the
// exchange records fills and cancellations under it.
func (o *Order) Hash() common.Hash {
	var buf bytes.Buffer
	buf.Write(OrderTypeHash[:])
	buf.Write(word(o.Trader[:]))
	buf.Write(word([]byte{o.Side}))
	buf.Write(word(o.Collection[:]))
	buf.Write(uintWord(o.TokenID))
	buf.Write(boolWord(o.AnyToken))
	buf.Write(uintWord(o.Amount))
	buf.Write(word(o.PaymentToken[:]))
	buf.Write(uintWord(o.Price))
	buf.Write(word(new(big.Int).SetUint64(o.ListingTime).Bytes()))
	buf.Write(word(new(big.Int).SetUint64(o.ExpirationTime).Bytes()))
	buf.Write(uintWord(o.Nonce))
	buf.Write(uintWord(o.Salt))
	return crypto.Keccak256Hash(buf.Bytes())
}

// Check refuses an order the exchange would call malformed, before anyone
// spends an eth_call on it.
func (o *Order) Check() error {
	for name, v := range map[string]*znn.BigInt{"tokenId": o.TokenID, "amount": o.Amount, "price": o.Price, "nonce": o.Nonce, "salt": o.Salt} {
		if v == nil {
			return fmt.Errorf("order has no %s", name)
		}
		if v.Sign() < 0 || v.BitLen() > 256 {
			return fmt.Errorf("order %s is out of range", name)
		}
	}
	switch {
	case o.Trader == (common.Address{}):
		return errors.New("order has no trader")
	case o.Side > SideBuy:
		return errors.New("order side must be 0 (sell) or 1 (buy)")
	case o.Collection == (common.Address{}):
		return errors.New("order has no collection")
	case o.Amount.Sign() == 0 || o.Price.Sign() == 0:
		return errors.New("an order needs an amount and a price")
	case o.Side == SideSell && (o.Amount.Big().Cmp(big.NewInt(1)) != 0 || o.AnyToken):
		return errors.New("a listing sells exactly one named token")
	case o.Side == SideBuy && o.PaymentToken == (common.Address{}):
		return errors.New("a bid is paid in an ERC-20, since nothing is escrowed")
	case o.ExpirationTime <= o.ListingTime:
		return errors.New("an order must expire after it opens")
	}
	return nil
}

// Domain is the exchange's EIP-712 domain separator on one chain.
func Domain(chainID uint64, exchange common.Address) common.Hash {
	return crypto.Keccak256Hash(
		domainType[:],
		crypto.Keccak256([]byte(DomainName)),
		crypto.Keccak256([]byte(DomainVersion)),
		word(new(big.Int).SetUint64(chainID).Bytes()),
		word(exchange[:]),
	)
}

func typedDigest(domain, structHash common.Hash) common.Hash {
	return crypto.Keccak256Hash([]byte{0x19, 0x01}, domain[:], structHash[:])
}

// OrderDigest is what a wallet signs for one order.
func OrderDigest(domain, orderHash common.Hash) common.Hash {
	return typedDigest(domain, orderHash)
}

// RootDigest is what a wallet signs for a Merkle root of orders.
func RootDigest(domain, root common.Hash) common.Hash {
	return typedDigest(domain, crypto.Keccak256Hash(RootTypeHash[:], root[:]))
}

// hashPair is OpenZeppelin's commutative Keccak: the pair is sorted first, so a
// proof needs no left/right flags.
func hashPair(a, b common.Hash) common.Hash {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	return crypto.Keccak256Hash(a[:], b[:])
}

// Tree builds the Merkle tree a bulk signature covers, and a proof for every
// leaf, in leaf order. An odd node is carried up a level unhashed, which
// MerkleProof.processProof accepts because it only folds what it is given.
func Tree(leaves []common.Hash) (common.Hash, [][]common.Hash) {
	if len(leaves) == 0 {
		return common.Hash{}, nil
	}
	proofs := make([][]common.Hash, len(leaves))
	pos := make([]int, len(leaves))
	for i := range pos {
		pos[i] = i
	}
	level := append([]common.Hash(nil), leaves...)
	for len(level) > 1 {
		next := make([]common.Hash, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, hashPair(level[i], level[i+1]))
		}
		for leaf, p := range pos {
			sibling := p ^ 1
			if sibling < len(level) {
				proofs[leaf] = append(proofs[leaf], level[sibling])
			}
			pos[leaf] = p / 2
		}
		level = next
	}
	return level[0], proofs
}

// ProcessProof folds a proof into the root it implies, as the exchange does.
func ProcessProof(leaf common.Hash, proof []common.Hash) common.Hash {
	h := leaf
	for _, p := range proof {
		h = hashPair(h, p)
	}
	return h
}

// Sign signs one order with an EVM key, as eth_signTypedData_v4 would.
func Sign(key *ecdsa.PrivateKey, domain common.Hash, o *Order) (*Input, error) {
	sig, err := signDigest(key, OrderDigest(domain, o.Hash()))
	if err != nil {
		return nil, err
	}
	return &Input{Order: *o, Kind: KindSingle, Signature: sig, Proof: []common.Hash{}}, nil
}

// SignBulk signs many orders with one signature over their Merkle root —
// Blur's bulk listing — and returns one fillable input per order.
func SignBulk(key *ecdsa.PrivateKey, domain common.Hash, orders []*Order) ([]*Input, error) {
	leaves := make([]common.Hash, len(orders))
	for i, o := range orders {
		leaves[i] = o.Hash()
	}
	root, proofs := Tree(leaves)
	sig, err := signDigest(key, RootDigest(domain, root))
	if err != nil {
		return nil, err
	}
	out := make([]*Input, len(orders))
	for i, o := range orders {
		r := root
		out[i] = &Input{Order: *o, Kind: KindBulk, Signature: sig, Proof: append([]common.Hash{}, proofs[i]...), Root: &r}
	}
	return out, nil
}

func signDigest(key *ecdsa.PrivateKey, digest common.Hash) ([]byte, error) {
	sig, err := crypto.Sign(digest[:], key)
	if err != nil {
		return nil, err
	}
	sig[64] += 27
	return sig, nil
}

// Recover returns the EOA that signed an input, or false for an input whose
// signature is not a plain 65-byte ECDSA one (an ERC-1271 wallet's, or an
// on-chain approval); those only the exchange can check.
func Recover(domain common.Hash, in *Input) (common.Address, bool) {
	if in.Kind == KindOnChain || len(in.Signature) != 65 {
		return common.Address{}, false
	}
	digest := OrderDigest(domain, in.Order.Hash())
	if in.Kind == KindBulk {
		digest = RootDigest(domain, ProcessProof(in.Order.Hash(), in.Proof))
	}
	sig := append([]byte(nil), in.Signature...)
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	pub, err := crypto.SigToPub(digest[:], sig)
	if err != nil {
		return common.Address{}, false
	}
	return crypto.PubkeyToAddress(*pub), true
}

// ABIOrder and ABIInput are the same values with the field names the ABI
// package matches tuple components against.
type ABIOrder struct {
	Trader         common.Address
	Side           uint8
	Collection     common.Address
	TokenId        *big.Int
	AnyToken       bool
	Amount         *big.Int
	PaymentToken   common.Address
	Price          *big.Int
	ListingTime    uint64
	ExpirationTime uint64
	Nonce          *big.Int
	Salt           *big.Int
}

type ABIInput struct {
	Order     ABIOrder
	Kind      uint8
	Signature []byte
	Proof     [][32]byte
}

// ABI returns the order in the shape go-ethereum's ABI encoder packs.
func (o *Order) ABI() ABIOrder {
	return ABIOrder{
		Trader: o.Trader, Side: o.Side, Collection: o.Collection, TokenId: o.TokenID.Big(), AnyToken: o.AnyToken,
		Amount: o.Amount.Big(), PaymentToken: o.PaymentToken, Price: o.Price.Big(),
		ListingTime: o.ListingTime, ExpirationTime: o.ExpirationTime, Nonce: o.Nonce.Big(), Salt: o.Salt.Big(),
	}
}

// ABI returns the input in the shape go-ethereum's ABI encoder packs.
func (in *Input) ABI() ABIInput {
	proof := make([][32]byte, len(in.Proof))
	for i, p := range in.Proof {
		proof[i] = p
	}
	sig := []byte(in.Signature)
	if sig == nil {
		sig = []byte{}
	}
	return ABIInput{Order: in.Order.ABI(), Kind: in.Kind, Signature: sig, Proof: proof}
}

// ABIOrders packs a list of orders for approveOrders and cancelOrders.
func ABIOrders(orders []*Order) any {
	out := make([]ABIOrder, len(orders))
	for i, o := range orders {
		out[i] = o.ABI()
	}
	return out
}

// FromABI converts an order decoded from a log or a call back into an Order.
func FromABI(v ABIOrder) Order {
	return Order{
		Trader: v.Trader, Side: v.Side, Collection: v.Collection, TokenID: znn.NewBigInt(v.TokenId), AnyToken: v.AnyToken,
		Amount: znn.NewBigInt(v.Amount), PaymentToken: v.PaymentToken, Price: znn.NewBigInt(v.Price),
		ListingTime: v.ListingTime, ExpirationTime: v.ExpirationTime, Nonce: znn.NewBigInt(v.Nonce), Salt: znn.NewBigInt(v.Salt),
	}
}

// U builds a *znn.BigInt from an int64, for callers building orders.
func U(v int64) *znn.BigInt { return znn.NewBigInt(big.NewInt(v)) }

// B wraps a *big.Int.
func B(v *big.Int) *znn.BigInt { return znn.NewBigInt(v) }
