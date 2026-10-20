package derive

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func TestCallRoundTrip(t *testing.T) {
	to := common.HexToAddress("0x4200000000000000000000000000000000000100")
	for _, c := range []Call{
		{To: &to, Value: big.NewInt(1_000_000), Gas: 60_000, Data: []byte{0xa9, 0x05, 0x9c, 0xbb}},
		{To: nil, Value: new(big.Int), Gas: 0, Data: bytes.Repeat([]byte{0x60}, 300)},
	} {
		enc := EncodeCall(c)
		if enc[0] != MsgCall {
			t.Fatalf("type byte %x", enc[0])
		}
		got, err := DecodeCall(enc[1:], false)
		if err != nil {
			t.Fatal(err)
		}
		if (got.To == nil) != (c.To == nil) || (got.To != nil && *got.To != *c.To) ||
			got.Value.Cmp(c.Value) != 0 || got.Gas != c.Gas || !bytes.Equal(got.Data, c.Data) {
			t.Fatalf("round trip: got %+v want %+v", got, c)
		}
	}
}

func TestCallRejectsTrailingBytes(t *testing.T) {
	enc := EncodeCall(Call{Value: big.NewInt(1)})
	if _, err := DecodeCall(append(enc[1:], 0x00), false); err == nil {
		t.Fatal("trailing byte accepted")
	}
}

// An ERC-20 transfer as a native call: the plan's 89-byte figure is the type
// byte, the target and 68 bytes of calldata, before RLP framing.
func TestERC20TransferSize(t *testing.T) {
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	data := make([]byte, 68)
	enc := EncodeCall(Call{To: &to, Value: new(big.Int), Gas: 60_000, Data: data})
	if len(enc) > 100 {
		t.Fatalf("native ERC-20 transfer is %d bytes", len(enc))
	}
	t.Logf("native ERC-20 transfer message: %d bytes, %d base plasma", len(enc), znn.BaseSendPlasma(len(enc)))
}

func TestBatchRoundTripAndBound(t *testing.T) {
	txs := [][]byte{bytes.Repeat([]byte{1}, 120), bytes.Repeat([]byte{2}, 150)}
	for _, codec := range []byte{BatchRaw, BatchZlib, BatchBrotli} {
		enc, err := EncodeBatch(txs, codec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeBatch(enc[1:], 1<<20, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || !bytes.Equal(got[1], txs[1]) {
			t.Fatal("batch round trip")
		}
	}
	bomb, err := EncodeBatch([][]byte{make([]byte, 100_000)}, BatchZlib)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBatch(bomb[1:], 10_000, true); err == nil {
		t.Fatal("decompression bound not enforced")
	}
}

func TestAssembleAndChunk(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 40_000)
	chunks := SplitChunks(payload)
	if len(chunks) != 3 {
		t.Fatalf("%d chunks", len(chunks))
	}
	var joined []byte
	for _, c := range chunks {
		if len(c) > znn.MaxDataLength || c[0] != MsgChunk {
			t.Fatal("chunk does not fit a block")
		}
		joined = append(joined, c[1:]...)
	}
	if !bytes.Equal(joined, payload) {
		t.Fatal("chunks do not reassemble")
	}
	hashes := []znn.Hash{znn.Sha3([]byte("a")), znn.Sha3([]byte("b"))}
	got, err := DecodeAssemble(EncodeAssemble(hashes)[1:])
	if err != nil || len(got) != 2 || got[1] != hashes[1] {
		t.Fatalf("assemble round trip: %v", err)
	}
}
