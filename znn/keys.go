package znn

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"github.com/tyler-smith/go-bip39"
)

// DevMnemonic is go-zenon's committed devnet mnemonic. It is public: every key
// derived from it is a devnet key and nothing else. The ZVM reuses it so that
// one wallet import reaches every dev account on both layers.
const DevMnemonic = "abstract affair idle position alien fluid board ordinary exist afraid chapter wood wood guide sun walnut crew perfect place firm poverty model side million"

const hardened = uint32(0x80000000)

// KeyPair is one NoM account key.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	Address Address
}

func KeyFromSeed(seed []byte) *KeyPair {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{Private: priv, Public: pub, Address: PubKeyToAddress(pub)}
}

func (k *KeyPair) Sign(msg []byte) []byte { return ed25519.Sign(k.Private, msg) }

// Wallet derives NoM account keys from a BIP-39 mnemonic the way go-zenon does
// (wallet/derivation.go): an empty BIP-39 passphrase, then SLIP-0010 ed25519
// along m/44'/73404'/i'. The Zenon "password" protects the keystore file and
// plays no part in the seed.
type Wallet struct {
	seed []byte
}

func NewWallet(mnemonic string) (*Wallet, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid BIP-39 mnemonic")
	}
	return &Wallet{seed: bip39.NewSeed(mnemonic, "")}, nil
}

func MustDevWallet() *Wallet {
	w, err := NewWallet(DevMnemonic)
	if err != nil {
		panic(err)
	}
	return w
}

// Key returns the key at m/44'/73404'/index'.
func (w *Wallet) Key(index uint32) *KeyPair {
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(w.seed)
	sum := mac.Sum(nil)
	key, chain := sum[:32], sum[32:]
	for _, segment := range []uint32{44, 73404, index} {
		data := make([]byte, 0, 1+32+4)
		data = append(data, 0x00)
		data = append(data, key...)
		data = binary.BigEndian.AppendUint32(data, segment|hardened)
		mac = hmac.New(sha512.New, chain)
		mac.Write(data)
		sum = mac.Sum(nil)
		key, chain = sum[:32], sum[32:]
	}
	return KeyFromSeed(key)
}
