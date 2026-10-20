package znn

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

const (
	AddressHRP = "z"
	TokenHRP   = "zts"

	// UserAddressByte and ContractAddressByte are the only type bytes a NoM
	// key or embedded contract can produce. Every other leading byte names an
	// address no keypair can reach, which is what the ZVM inbox relies on.
	UserAddressByte     = 0x00
	ContractAddressByte = 0x01
)

// Address is a 20-byte NoM address: a type byte and 19 bytes of hash. On the
// ZVM the same 20 bytes are the EVM address, so a `z1…` string and a `0x…`
// string are two spellings of one account.
type Address [20]byte

var ZeroAddress Address

func ParseAddress(s string) (Address, error) {
	hrp, data, err := DecodeBech32(s)
	if err != nil {
		return Address{}, fmt.Errorf("address %q: %w", s, err)
	}
	if hrp != AddressHRP {
		return Address{}, fmt.Errorf("address %q: prefix %q, want %q", s, hrp, AddressHRP)
	}
	if len(data) != len(Address{}) {
		return Address{}, fmt.Errorf("address %q: %d bytes, want 20", s, len(data))
	}
	var a Address
	copy(a[:], data)
	return a, nil
}

func MustParseAddress(s string) Address {
	a, err := ParseAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

// AddressFromBody builds an address from its 32 bech32 data characters, the
// part between "z1" and the checksum. A body that does not start with 'q'
// sets a type byte that no key (0x00) and no embedded contract (0x01) can
// have, so the address is reachable by sends and spendable by nobody.
func AddressFromBody(body string) (Address, error) {
	if len(body) != 32 {
		return Address{}, fmt.Errorf("address body must be 32 characters, got %d", len(body))
	}
	five := make([]byte, len(body))
	for i := 0; i < len(body); i++ {
		idx := strings.IndexByte(bech32Charset, body[i])
		if idx < 0 {
			return Address{}, fmt.Errorf("address body: %q is not a bech32 character", body[i])
		}
		five[i] = byte(idx)
	}
	eight, err := convertBits(five, 5, 8, false)
	if err != nil {
		return Address{}, err
	}
	var a Address
	copy(a[:], eight)
	return a, nil
}

func MustAddressFromBody(body string) Address {
	a, err := AddressFromBody(body)
	if err != nil {
		panic(err)
	}
	return a
}

// PubKeyToAddress mirrors go-zenon types.PubKeyToAddress: a zero type byte
// then the first 19 bytes of sha3-256(publicKey).
func PubKeyToAddress(pub []byte) Address {
	h := sha3.Sum256(pub)
	var a Address
	a[0] = UserAddressByte
	copy(a[1:], h[:19])
	return a
}

func (a Address) String() string {
	s, err := EncodeBech32(AddressHRP, a[:])
	if err != nil {
		panic(err)
	}
	return s
}

func (a Address) Bytes() []byte        { return a[:] }
func (a Address) IsZero() bool         { return a == ZeroAddress }
func (a Address) IsUser() bool         { return a[0] == UserAddressByte }
func (a Address) IsEmbedded() bool     { return a[0] == ContractAddressByte }
func (a Address) Hex() string          { return "0x" + hex.EncodeToString(a[:]) }
func (a Address) Equal(b Address) bool { return a == b }

func (a Address) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

func (a *Address) UnmarshalText(b []byte) error {
	v, err := ParseAddress(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// TokenStandard is a 10-byte ZTS identifier, spelled `zts1…`.
type TokenStandard [10]byte

var (
	ZeroTokenStandard TokenStandard
	ZNN               = MustParseZTS("zts1znnxxxxxxxxxxxxx9z4ulx")
	QSR               = MustParseZTS("zts1qsrxxxxxxxxxxxxxmrhjll")
)

func ParseZTS(s string) (TokenStandard, error) {
	hrp, data, err := DecodeBech32(s)
	if err != nil {
		return TokenStandard{}, fmt.Errorf("token standard %q: %w", s, err)
	}
	if hrp != TokenHRP {
		return TokenStandard{}, fmt.Errorf("token standard %q: prefix %q, want %q", s, hrp, TokenHRP)
	}
	if len(data) != len(TokenStandard{}) {
		return TokenStandard{}, fmt.Errorf("token standard %q: %d bytes, want 10", s, len(data))
	}
	var t TokenStandard
	copy(t[:], data)
	return t, nil
}

func MustParseZTS(s string) TokenStandard {
	t, err := ParseZTS(s)
	if err != nil {
		panic(err)
	}
	return t
}

func (t TokenStandard) String() string {
	s, err := EncodeBech32(TokenHRP, t[:])
	if err != nil {
		panic(err)
	}
	return s
}

func (t TokenStandard) Bytes() []byte { return t[:] }

func (t TokenStandard) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

func (t *TokenStandard) UnmarshalText(b []byte) error {
	v, err := ParseZTS(string(b))
	if err != nil {
		return err
	}
	*t = v
	return nil
}

// Hash is a 32-byte sha3-256 digest, hex without a prefix on the wire.
type Hash [32]byte

var ZeroHash Hash

func Sha3(parts ...[]byte) Hash {
	if len(parts) == 1 {
		return sha3.Sum256(parts[0])
	}
	return sha3.Sum256(bytes.Join(parts, nil))
}

func ParseHash(s string) (Hash, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	raw, err := hex.DecodeString(s)
	if err != nil {
		return Hash{}, fmt.Errorf("hash %q: %w", s, err)
	}
	if len(raw) != 32 {
		return Hash{}, fmt.Errorf("hash %q: %d bytes, want 32", s, len(raw))
	}
	var h Hash
	copy(h[:], raw)
	return h, nil
}

func (h Hash) String() string { return hex.EncodeToString(h[:]) }
func (h Hash) Bytes() []byte  { return h[:] }
func (h Hash) IsZero() bool   { return h == ZeroHash }

func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

func (h *Hash) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*h = ZeroHash
		return nil
	}
	v, err := ParseHash(string(b))
	if err != nil {
		return err
	}
	*h = v
	return nil
}

// HashHeight names a block by hash and height; its byte form is hash ‖ height.
type HashHeight struct {
	Hash   Hash   `json:"hash"`
	Height uint64 `json:"height"`
}

func (hh HashHeight) Bytes() []byte {
	return binary.BigEndian.AppendUint64(append([]byte(nil), hh.Hash[:]...), hh.Height)
}

// BigInt carries amounts, which go-zenon's RPC writes as JSON strings. A plain
// *big.Int field fails to decode them, and because the failure is at the field
// level the whole momentum fails to parse with it.
type BigInt struct{ big.Int }

func NewBigInt(x *big.Int) *BigInt {
	b := new(BigInt)
	if x != nil {
		b.Set(x)
	}
	return b
}

func BigIntFromUint64(x uint64) *BigInt {
	b := new(BigInt)
	b.SetUint64(x)
	return b
}

func (b *BigInt) Big() *big.Int {
	if b == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(&b.Int)
}

func (b BigInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.Int.String())
}

func (b *BigInt) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		b.SetInt64(0)
		return nil
	}
	if _, ok := b.SetString(s, 10); !ok {
		return fmt.Errorf("amount %q is not a decimal integer", s)
	}
	return nil
}

// Nonce is the 8-byte proof-of-work nonce, hex on the wire.
type Nonce [8]byte

func (n Nonce) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(n[:])), nil }

func (n *Nonce) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*n = Nonce{}
		return nil
	}
	raw, err := hex.DecodeString(string(b))
	if err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	if len(raw) != 8 {
		return fmt.Errorf("nonce: %d bytes, want 8", len(raw))
	}
	copy(n[:], raw)
	return nil
}
