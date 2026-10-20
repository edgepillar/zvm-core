// Package derive turns NoM momentums into ZVM blocks. Everything in it that
// decides what goes into a block is a pure function of NoM data, so any two
// nodes that run it over the same momentums build the same chain.
package derive

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Message types: the first data byte of a NoM send to the inbox.
const (
	MsgCall     = 0x01 // a call authored by the NoM account itself
	MsgBatch    = 0x02 // signed EVM transactions posted by a relayer
	MsgChunk    = 0x03 // raw bytes, assembled later
	MsgAssemble = 0x04 // concatenates chunks into one message
)

// Batch compression flags. 0x02 and 0x03 arrive with the wire fork; before it
// they are unknown flags and the message is invalid, which is what keeps a node
// that has upgraded early from building a block its peers will not.
const (
	BatchRaw    = 0x00
	BatchZlib   = 0x01
	BatchBrotli = 0x02 // brotli, quality 6: 3 % smaller than zlib-9 at zlib's speed (D19)
	BatchSpan   = 0x03 // span.go's columnar layout, then brotli
)

// BrotliQuality is the level every encoder here uses. Measured (D19):
// quality 11 is 50× slower than zlib for 0.1 % more, and 6 matches zlib-9's
// speed at the same size.
const BrotliQuality = 6

// BestCodec is the compression a publisher should use for a batch that will
// be derived at this momentum height: the best one every node can decode
// there. A publisher that guesses high produces a message the chain rejects,
// so this is the only place the choice is made.
func BestCodec(forks *rollup.Forks, momentum uint64) byte {
	if forks.WireActive(momentum) {
		return BatchSpan
	}
	return BatchZlib
}

// MaxAssembleChunks bounds how many chunks one assemble may name.
const MaxAssembleChunks = 64

var (
	ErrEmpty       = errors.New("empty message")
	ErrUnknownType = errors.New("unknown message type")
)

// Call is a native transaction: no signature, because the NoM block that
// carries it is already signed by its author, and the author is msg.sender.
// NoM's account height is the replay protection.
type Call struct {
	To    *common.Address // nil creates a contract
	Value *big.Int
	Gas   uint64 // 0 means "whatever the block's plasma buys"
	Data  []byte

	// Boost is the part of the block's burn that buys admission priority
	// rather than gas (DECISIONS.md D7, after Facet's mine_boost). It is a
	// fifth RLP item, so it exists only from the gas fork, and it must be
	// omitted rather than written as zero. nil and zero are the same thing.
	Boost *big.Int
}

// HasBoost reports whether this call carries a fifth item.
func (c Call) HasBoost() bool { return c.Boost != nil && c.Boost.Sign() > 0 }

type callRLP struct {
	To    []byte
	Value *big.Int
	Gas   uint64
	Data  []byte
}

type callBoostRLP struct {
	To    []byte
	Value *big.Int
	Gas   uint64
	Data  []byte
	Boost *big.Int
}

func EncodeCall(c Call) []byte {
	value := c.Value
	if value == nil {
		value = new(big.Int)
	}
	var to []byte
	if c.To != nil {
		to = c.To.Bytes()
	}
	var payload []byte
	var err error
	if c.HasBoost() {
		payload, err = rlp.EncodeToBytes(callBoostRLP{To: to, Value: value, Gas: c.Gas, Data: c.Data, Boost: c.Boost})
	} else {
		payload, err = rlp.EncodeToBytes(callRLP{To: to, Value: value, Gas: c.Gas, Data: c.Data})
	}
	if err != nil {
		panic(err) // only unencodable types fail, and these are not
	}
	return append([]byte{MsgCall}, payload...)
}

// DecodeCall decodes the payload after the type byte. RLP decoding is strict:
// trailing bytes and non-canonical integers are rejected.
//
// boost says whether this chain's gas fork covers the momentum being derived.
// Before it, a five-item list is not a call at all; after it, a five-item list
// carries the boost and a zero boost must be written as four items, so that
// one message has one encoding.
func DecodeCall(payload []byte, boost bool) (Call, error) {
	kind, content, rest, err := rlp.Split(payload)
	if err != nil {
		return Call{}, fmt.Errorf("call: %w", err)
	}
	if kind != rlp.List {
		return Call{}, errors.New("call: not a list")
	}
	if len(rest) != 0 {
		return Call{}, fmt.Errorf("call: %d trailing bytes", len(rest))
	}
	items, err := rlp.CountValues(content)
	if err != nil {
		return Call{}, fmt.Errorf("call: %w", err)
	}

	var c Call
	switch {
	case items == 4:
		var v callRLP
		if err := rlp.DecodeBytes(payload, &v); err != nil {
			return Call{}, fmt.Errorf("call: %w", err)
		}
		c = Call{Value: v.Value, Gas: v.Gas, Data: v.Data}
		if err := setTo(&c, v.To); err != nil {
			return Call{}, err
		}
	case items == 5 && boost:
		var v callBoostRLP
		if err := rlp.DecodeBytes(payload, &v); err != nil {
			return Call{}, fmt.Errorf("call: %w", err)
		}
		if v.Boost == nil || v.Boost.Sign() == 0 {
			return Call{}, errors.New("call: a zero boost must be omitted, not written")
		}
		c = Call{Value: v.Value, Gas: v.Gas, Data: v.Data, Boost: v.Boost}
		if err := setTo(&c, v.To); err != nil {
			return Call{}, err
		}
	case items == 5:
		return Call{}, errors.New("call: five items, but this chain's gas fork is not active")
	default:
		return Call{}, fmt.Errorf("call: %d items, want 4 or 5", items)
	}
	if c.Value == nil {
		c.Value = new(big.Int)
	}
	return c, nil
}

func setTo(c *Call, to []byte) error {
	switch len(to) {
	case 0:
		return nil
	case common.AddressLength:
		a := common.BytesToAddress(to)
		c.To = &a
		return nil
	default:
		return fmt.Errorf("call: 'to' is %d bytes", len(to))
	}
}

// EncodeBatch wraps EIP-2718 encoded transactions
// (types.Transaction.MarshalBinary) with the named compression flag.
//
// BatchSpan re-encodes the transactions column by column (span.go) and falls
// back to BatchBrotli for a set it cannot represent exactly, so a caller may
// always ask for the best codec and take what it gets. The flag in the
// returned bytes says which was used.
func EncodeBatch(txs [][]byte, codec byte) ([]byte, error) {
	if codec == BatchSpan {
		out, err := encodeSpanBatch(txs)
		if err == nil {
			return out, nil
		}
		codec = BatchBrotli
	}
	payload, err := rlp.EncodeToBytes(txs)
	if err != nil {
		return nil, err
	}
	switch codec {
	case BatchRaw:
		return append([]byte{MsgBatch, BatchRaw}, payload...), nil
	case BatchZlib:
		var buf bytes.Buffer
		buf.Write([]byte{MsgBatch, BatchZlib})
		zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
		if err != nil {
			return nil, err
		}
		if _, err := zw.Write(payload); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case BatchBrotli:
		var buf bytes.Buffer
		buf.Write([]byte{MsgBatch, BatchBrotli})
		bw := brotli.NewWriterLevel(&buf, BrotliQuality)
		if _, err := bw.Write(payload); err != nil {
			return nil, err
		}
		if err := bw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("batch: unknown compression flag %d", codec)
	}
}

// DecodeBatch decodes the payload after the type byte. Decompression is
// bounded by maxBytes, so a small block cannot expand without limit.
//
// wire says whether this chain's wire fork covers the momentum: before it,
// flags 0x02 and 0x03 are unknown and the message is invalid.
func DecodeBatch(payload []byte, maxBytes int, wire bool) ([][]byte, error) {
	if len(payload) < 1 {
		return nil, errors.New("batch: missing compression flag")
	}
	flag, raw := payload[0], payload[1:]
	if (flag == BatchBrotli || flag == BatchSpan) && !wire {
		return nil, fmt.Errorf("batch: compression flag %d needs this chain's wire fork", flag)
	}
	switch flag {
	case BatchRaw:
	case BatchZlib:
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("batch: %w", err)
		}
		out, err := io.ReadAll(io.LimitReader(zr, int64(maxBytes)+1))
		if err != nil {
			return nil, fmt.Errorf("batch: %w", err)
		}
		raw = out
	case BatchBrotli, BatchSpan:
		out, err := io.ReadAll(io.LimitReader(brotli.NewReader(bytes.NewReader(raw)), int64(maxBytes)+1))
		if err != nil {
			return nil, fmt.Errorf("batch: %w", err)
		}
		raw = out
	default:
		return nil, fmt.Errorf("batch: unknown compression flag %d", flag)
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("batch: decompresses past %d bytes", maxBytes)
	}
	if flag == BatchSpan {
		return decodeSpan(raw)
	}
	var txs [][]byte
	if err := rlp.DecodeBytes(raw, &txs); err != nil {
		return nil, fmt.Errorf("batch: %w", err)
	}
	return txs, nil
}

func EncodeAssemble(chunks []znn.Hash) []byte {
	list := make([][]byte, len(chunks))
	for i := range chunks {
		list[i] = chunks[i][:]
	}
	payload, err := rlp.EncodeToBytes(list)
	if err != nil {
		panic(err)
	}
	return append([]byte{MsgAssemble}, payload...)
}

func DecodeAssemble(payload []byte) ([]znn.Hash, error) {
	var list [][]byte
	if err := rlp.DecodeBytes(payload, &list); err != nil {
		return nil, fmt.Errorf("assemble: %w", err)
	}
	if len(list) == 0 || len(list) > MaxAssembleChunks {
		return nil, fmt.Errorf("assemble: %d chunks, want 1..%d", len(list), MaxAssembleChunks)
	}
	out := make([]znn.Hash, len(list))
	for i, h := range list {
		if len(h) != 32 {
			return nil, fmt.Errorf("assemble: chunk %d hash is %d bytes", i, len(h))
		}
		copy(out[i][:], h)
	}
	return out, nil
}

// SplitChunks splits a payload into chunk messages that each fit one NoM block.
func SplitChunks(payload []byte) [][]byte {
	return SplitChunksRoom(payload, znn.MaxDataLength)
}

// SplitChunksRoom splits into chunks of at most room bytes each, which is what
// a publisher can afford on a priced network rather than what a block could
// hold at the minimum price.
func SplitChunksRoom(payload []byte, room int) [][]byte {
	if room > znn.MaxDataLength {
		room = znn.MaxDataLength
	}
	if room < 2 {
		room = 2
	}
	space := room - 1
	var out [][]byte
	for i := 0; i < len(payload); i += space {
		end := min(i+space, len(payload))
		chunk := make([]byte, 0, end-i+1)
		chunk = append(chunk, MsgChunk)
		out = append(out, append(chunk, payload[i:end]...))
	}
	return out
}
