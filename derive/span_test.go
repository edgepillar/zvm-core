package derive

import (
	"bytes"
	"crypto/ecdsa"
	"io"
	"math/big"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// wallets makes n deterministic keys, so the numbers below are reproducible.
func wallets(t *testing.T, n int) []*ecdsa.PrivateKey {
	t.Helper()
	out := make([]*ecdsa.PrivateKey, n)
	for i := range out {
		k, err := crypto.ToECDSA(crypto.Keccak256([]byte{byte(i), byte(i >> 8), 'z', 'v', 'm'}))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = k
	}
	return out
}

func transfers(t *testing.T, keys []*ecdsa.PrivateKey, chainID uint64) [][]byte {
	t.Helper()
	signer := types.LatestSignerForChainID(new(big.Int).SetUint64(chainID))
	var out [][]byte
	for i, k := range keys {
		to := common.BigToAddress(big.NewInt(int64(1_000 + i)))
		tx := types.MustSignNewTx(k, signer, &types.DynamicFeeTx{
			ChainID: new(big.Int).SetUint64(chainID), Nonce: uint64(i % 7), GasTipCap: big.NewInt(1_000_000),
			GasFeeCap: big.NewInt(2_000_000_000), Gas: 21_000, To: &to, Value: big.NewInt(1_000_000_000_000_000),
		})
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

// Every transaction shape the batch lane accepts must come back byte for byte,
// or the encoder must refuse to use the span format at all.
func TestSpanRoundTripsEveryShape(t *testing.T) {
	keys := wallets(t, 4)
	chainID := big.NewInt(7_340_470)
	legacySigner := types.HomesteadSigner{}
	eip155 := types.NewEIP155Signer(chainID)
	latest := types.LatestSignerForChainID(chainID)
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	list := types.AccessList{{Address: to, StorageKeys: []common.Hash{{1}, {2}}}}

	var raws [][]byte
	for _, tx := range []*types.Transaction{
		types.MustSignNewTx(keys[0], legacySigner, &types.LegacyTx{
			Nonce: 3, GasPrice: big.NewInt(1e9), Gas: 21_000, To: &to, Value: big.NewInt(7)}),
		types.MustSignNewTx(keys[1], eip155, &types.LegacyTx{
			Nonce: 0, GasPrice: big.NewInt(1e9), Gas: 90_000, Value: big.NewInt(0), Data: []byte{0x60, 0x80}}),
		types.MustSignNewTx(keys[2], latest, &types.AccessListTx{
			ChainID: chainID, Nonce: 9, GasPrice: big.NewInt(2e9), Gas: 50_000, To: &to,
			Value: big.NewInt(1), AccessList: list}),
		types.MustSignNewTx(keys[3], latest, &types.DynamicFeeTx{
			ChainID: chainID, Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(3e9),
			Gas: 120_000, Value: big.NewInt(5), Data: bytes.Repeat([]byte{0xab}, 40), AccessList: list}),
	} {
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}

	enc, err := EncodeBatch(raws, BatchSpan)
	if err != nil {
		t.Fatal(err)
	}
	if enc[1] != BatchSpan {
		t.Fatalf("the encoder fell back to flag %d", enc[1])
	}
	got, err := DecodeBatch(enc[1:], 1<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(raws) {
		t.Fatalf("%d transactions back, %d in", len(got), len(raws))
	}
	for i := range raws {
		if !bytes.Equal(got[i], raws[i]) {
			t.Fatalf("transaction %d did not survive the span", i)
		}
	}
}

// A shape the span cannot carry must fall back rather than lose bytes.
func TestSpanFallsBackForSetCode(t *testing.T) {
	key := wallets(t, 1)[0]
	chainID := big.NewInt(7_340_470)
	auth, err := types.SignSetCode(key, types.SetCodeAuthorization{
		ChainID: *uint256FromBig(chainID), Address: common.HexToAddress("0x01"), Nonce: 0})
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	tx := types.MustSignNewTx(key, types.LatestSignerForChainID(chainID), &types.SetCodeTx{
		ChainID: uint256FromBig(chainID), Nonce: 0, GasTipCap: uint256FromBig(big.NewInt(1)),
		GasFeeCap: uint256FromBig(big.NewInt(1e9)), Gas: 100_000, To: to,
		AuthList: []types.SetCodeAuthorization{auth}})
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncodeBatch([][]byte{raw}, BatchSpan)
	if err != nil {
		t.Fatal(err)
	}
	if enc[1] != BatchBrotli {
		t.Fatalf("want a fall back to brotli, got flag %d", enc[1])
	}
	got, err := DecodeBatch(enc[1:], 1<<20, true)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0], raw) {
		t.Fatalf("the fallback lost the transaction: %v", err)
	}
}

// A span from before the wire fork is not a message at all.
func TestSpanNeedsTheWireFork(t *testing.T) {
	raws := transfers(t, wallets(t, 4), 7_340_470)
	enc, err := EncodeBatch(raws, BatchSpan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBatch(enc[1:], 1<<20, false); err == nil {
		t.Fatal("a span decoded before the wire fork")
	}
}

// What the columnar layout is for: the same transactions, smaller.
func TestSpanIsSmallerThanZlib(t *testing.T) {
	raws := transfers(t, wallets(t, 200), 7_340_470)
	var raw int
	for _, r := range raws {
		raw += len(r)
	}
	sizes := map[string]int{}
	for name, codec := range map[string]byte{"zlib-9": BatchZlib, "brotli-6": BatchBrotli, "span": BatchSpan} {
		enc, err := EncodeBatch(raws, codec)
		if err != nil {
			t.Fatal(err)
		}
		sizes[name] = len(enc)
	}
	t.Logf("200 transfers, %d raw bytes: zlib %d (%.3f), brotli %d (%.3f), span %d (%.3f)",
		raw, sizes["zlib-9"], float64(sizes["zlib-9"])/float64(raw),
		sizes["brotli-6"], float64(sizes["brotli-6"])/float64(raw),
		sizes["span"], float64(sizes["span"])/float64(raw))
	if sizes["span"] >= sizes["zlib-9"] {
		t.Fatalf("the span layout should beat zlib: %d against %d", sizes["span"], sizes["zlib-9"])
	}
	if sizes["brotli-6"] >= sizes["zlib-9"] {
		t.Fatalf("brotli should beat zlib: %d against %d", sizes["brotli-6"], sizes["zlib-9"])
	}
}

// A malformed span must be refused rather than trusted: every column length is
// checked against the number of transactions.
func TestSpanRejectsMismatchedColumns(t *testing.T) {
	raws := transfers(t, wallets(t, 3), 7_340_470)
	enc, err := encodeSpanBatch(raws)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decompressBrotli(enc[2:])
	if err != nil {
		t.Fatal(err)
	}
	var s spanBatch
	if err := rlpDecode(payload, &s); err != nil {
		t.Fatal(err)
	}
	s.Nonces = s.Nonces[:2]
	if _, err := decodeSpan(rlpEncode(t, &s)); err == nil {
		t.Fatal("a short column was accepted")
	}
	if err := rlpDecode(payload, &s); err != nil {
		t.Fatal(err)
	}
	s.Rs = s.Rs[:len(s.Rs)-1]
	if _, err := decodeSpan(rlpEncode(t, &s)); err == nil {
		t.Fatal("a short signature column was accepted")
	}
}

func uint256FromBig(x *big.Int) *uint256.Int {
	v, _ := uint256.FromBig(x)
	return v
}

func decompressBrotli(b []byte) ([]byte, error) {
	return io.ReadAll(brotli.NewReader(bytes.NewReader(b)))
}

func rlpDecode(raw []byte, v any) error { return rlp.DecodeBytes(raw, v) }

func rlpEncode(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := rlp.EncodeToBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
