package derive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// Span batches: compression flag 0x03 (DECISIONS.md D19).
//
// A batch is a list of whole signed transactions, one after another, so every
// field that repeats across a batch — the chain id, the gas price a wallet
// picked, the gas limit, the recipient of a token transfer — is separated from
// its next occurrence by a 65-byte signature, which is random. Storing the
// fields **column by column** puts the repeats next to each other, where both
// the match finder and the entropy coder can see them. The OP Stack's span
// batches do exactly this, for the same reason, and it is worth more than
// changing the codec.
//
// The rule that keeps it safe: the decoder rebuilds each transaction and
// re-encodes it, and **the encoder refuses to use this format unless every
// transaction round-trips byte for byte**. A batch it cannot represent — a
// SetCode transaction, an encoding go-ethereum does not reproduce exactly —
// falls back to flag 0x02. So a span batch can only ever carry transactions
// whose bytes are recoverable exactly; anything else never becomes one.

// Transaction kinds inside a span. They are not EIP-2718 type bytes: legacy
// splits in two, because a protected transaction carries a chain id in its v
// and an unprotected one does not.
const (
	spanLegacy          = 0x00
	spanLegacyProtected = 0x01
	spanAccessList      = 0x02
	spanDynamicFee      = 0x03
)

// spanBatch is the columnar form. Every column is parallel to Kinds except
// those that only some kinds have, which appear once per transaction that has
// them, in transaction order.
type spanBatch struct {
	Kinds       []byte   // one per transaction
	ChainIDs    [][]byte // protected legacy, access-list and dynamic-fee
	Nonces      []uint64
	Gases       []uint64
	FeeCaps     [][]byte // gasPrice, or maxFeePerGas for dynamic-fee
	TipCaps     [][]byte // dynamic-fee only
	Creates     []byte   // 1 where `to` is empty
	Tos         []byte   // 20 bytes per non-creating transaction
	Values      [][]byte
	Datas       [][]byte
	AccessLists [][]byte // access-list and dynamic-fee, each rlp(types.AccessList)
	Parities    []byte   // the signature's y parity, one per transaction
	Rs          []byte   // 32 bytes per transaction
	Ss          []byte   // 32 bytes per transaction
}

var errNotSpannable = errors.New("batch: not representable as a span")

// encodeSpanBatch builds flag 0x03, or returns errNotSpannable.
func encodeSpanBatch(raws [][]byte) ([]byte, error) {
	if len(raws) == 0 {
		return nil, errNotSpannable
	}
	var s spanBatch
	for _, raw := range raws {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			return nil, errNotSpannable
		}
		v, r, sig := tx.RawSignatureValues()
		var kind byte
		switch tx.Type() {
		case types.LegacyTxType:
			if tx.Protected() {
				kind = spanLegacyProtected
				s.ChainIDs = append(s.ChainIDs, tx.ChainId().Bytes())
			} else {
				kind = spanLegacy
			}
			s.FeeCaps = append(s.FeeCaps, tx.GasPrice().Bytes())
		case types.AccessListTxType:
			kind = spanAccessList
			s.ChainIDs = append(s.ChainIDs, tx.ChainId().Bytes())
			s.FeeCaps = append(s.FeeCaps, tx.GasPrice().Bytes())
			s.AccessLists = append(s.AccessLists, mustRLP(tx.AccessList()))
		case types.DynamicFeeTxType:
			kind = spanDynamicFee
			s.ChainIDs = append(s.ChainIDs, tx.ChainId().Bytes())
			s.FeeCaps = append(s.FeeCaps, tx.GasFeeCap().Bytes())
			s.TipCaps = append(s.TipCaps, tx.GasTipCap().Bytes())
			s.AccessLists = append(s.AccessLists, mustRLP(tx.AccessList()))
		default:
			return nil, errNotSpannable
		}
		s.Kinds = append(s.Kinds, kind)
		s.Nonces = append(s.Nonces, tx.Nonce())
		s.Gases = append(s.Gases, tx.Gas())
		if to := tx.To(); to == nil {
			s.Creates = append(s.Creates, 1)
		} else {
			s.Creates = append(s.Creates, 0)
			s.Tos = append(s.Tos, to[:]...)
		}
		s.Values = append(s.Values, tx.Value().Bytes())
		s.Datas = append(s.Datas, tx.Data())
		parity, err := spanParity(kind, v, tx.ChainId())
		if err != nil {
			return nil, errNotSpannable
		}
		s.Parities = append(s.Parities, parity)
		if len(r.Bytes()) > 32 || len(sig.Bytes()) > 32 {
			return nil, errNotSpannable
		}
		s.Rs = append(s.Rs, common.LeftPadBytes(r.Bytes(), 32)...)
		s.Ss = append(s.Ss, common.LeftPadBytes(sig.Bytes(), 32)...)
	}

	payload, err := rlp.EncodeToBytes(&s)
	if err != nil {
		return nil, errNotSpannable
	}
	// The safety rule: what this decodes to must be what went in.
	back, err := decodeSpan(payload)
	if err != nil || len(back) != len(raws) {
		return nil, errNotSpannable
	}
	for i := range raws {
		if !bytes.Equal(back[i], raws[i]) {
			return nil, errNotSpannable
		}
	}

	var buf bytes.Buffer
	buf.Write([]byte{MsgBatch, BatchSpan})
	bw := brotli.NewWriterLevel(&buf, BrotliQuality)
	if _, err := bw.Write(payload); err != nil {
		return nil, err
	}
	if err := bw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// spanParity reduces a signature's v to one bit, given what the kind says
// about how v was built.
func spanParity(kind byte, v, chainID *big.Int) (byte, error) {
	switch kind {
	case spanLegacy:
		switch v.Uint64() {
		case 27:
			return 0, nil
		case 28:
			return 1, nil
		}
		return 0, errNotSpannable
	case spanLegacyProtected:
		// v = 35 + 2·chainID + parity
		base := new(big.Int).Mul(chainID, big.NewInt(2))
		base.Add(base, big.NewInt(35))
		d := new(big.Int).Sub(v, base)
		if d.Sign() < 0 || d.Cmp(big.NewInt(1)) > 0 {
			return 0, errNotSpannable
		}
		return byte(d.Uint64()), nil
	default:
		if !v.IsUint64() || v.Uint64() > 1 {
			return 0, errNotSpannable
		}
		return byte(v.Uint64()), nil
	}
}

// decodeSpan rebuilds the EIP-2718 encodings from the columnar payload. Every
// length is checked against the transaction count: the payload is a stranger's.
func decodeSpan(payload []byte) ([][]byte, error) {
	var s spanBatch
	if err := rlp.DecodeBytes(payload, &s); err != nil {
		return nil, fmt.Errorf("span: %w", err)
	}
	n := len(s.Kinds)
	if n == 0 {
		return nil, errors.New("span: no transactions")
	}
	var chained, tipped, listed, creates int
	for _, k := range s.Kinds {
		switch k {
		case spanLegacy:
		case spanLegacyProtected:
			chained++
		case spanAccessList:
			chained++
			listed++
		case spanDynamicFee:
			chained++
			listed++
			tipped++
		default:
			return nil, fmt.Errorf("span: unknown kind %d", k)
		}
	}
	for _, c := range s.Creates {
		if c > 1 {
			return nil, errors.New("span: creation flag is not 0 or 1")
		}
		creates += int(c)
	}
	switch {
	case len(s.Nonces) != n, len(s.Gases) != n, len(s.FeeCaps) != n,
		len(s.Values) != n, len(s.Datas) != n, len(s.Parities) != n, len(s.Creates) != n:
		return nil, errors.New("span: a per-transaction column has the wrong length")
	case len(s.ChainIDs) != chained, len(s.TipCaps) != tipped, len(s.AccessLists) != listed:
		return nil, errors.New("span: a per-kind column has the wrong length")
	case len(s.Tos) != 20*(n-creates):
		return nil, errors.New("span: the recipient column has the wrong length")
	case len(s.Rs) != 32*n, len(s.Ss) != 32*n:
		return nil, errors.New("span: the signature columns have the wrong length")
	}

	out := make([][]byte, n)
	var ci, ti, li, toi int
	for i, kind := range s.Kinds {
		if s.Parities[i] > 1 {
			return nil, errors.New("span: parity is not 0 or 1")
		}
		var to *common.Address
		if s.Creates[i] == 0 {
			a := common.BytesToAddress(s.Tos[toi : toi+20])
			to = &a
			toi += 20
		}
		var chainID *big.Int
		if kind != spanLegacy {
			chainID = new(big.Int).SetBytes(s.ChainIDs[ci])
			ci++
		}
		var list types.AccessList
		if kind == spanAccessList || kind == spanDynamicFee {
			if err := rlp.DecodeBytes(s.AccessLists[li], &list); err != nil {
				return nil, fmt.Errorf("span: access list %d: %w", li, err)
			}
			li++
		}
		r := new(big.Int).SetBytes(s.Rs[32*i : 32*i+32])
		sv := new(big.Int).SetBytes(s.Ss[32*i : 32*i+32])
		parity := big.NewInt(int64(s.Parities[i]))

		var inner types.TxData
		switch kind {
		case spanLegacy, spanLegacyProtected:
			v := new(big.Int).Add(big.NewInt(27), parity)
			if kind == spanLegacyProtected {
				v = new(big.Int).Mul(chainID, big.NewInt(2))
				v.Add(v, big.NewInt(35))
				v.Add(v, parity)
			}
			inner = &types.LegacyTx{
				Nonce: s.Nonces[i], GasPrice: new(big.Int).SetBytes(s.FeeCaps[i]), Gas: s.Gases[i],
				To: to, Value: new(big.Int).SetBytes(s.Values[i]), Data: s.Datas[i], V: v, R: r, S: sv,
			}
		case spanAccessList:
			inner = &types.AccessListTx{
				ChainID: chainID, Nonce: s.Nonces[i], GasPrice: new(big.Int).SetBytes(s.FeeCaps[i]),
				Gas: s.Gases[i], To: to, Value: new(big.Int).SetBytes(s.Values[i]), Data: s.Datas[i],
				AccessList: list, V: parity, R: r, S: sv,
			}
		default:
			tip := new(big.Int).SetBytes(s.TipCaps[ti])
			ti++
			inner = &types.DynamicFeeTx{
				ChainID: chainID, Nonce: s.Nonces[i], GasTipCap: tip,
				GasFeeCap: new(big.Int).SetBytes(s.FeeCaps[i]), Gas: s.Gases[i], To: to,
				Value: new(big.Int).SetBytes(s.Values[i]), Data: s.Datas[i],
				AccessList: list, V: parity, R: r, S: sv,
			}
		}
		raw, err := types.NewTx(inner).MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("span: transaction %d: %w", i, err)
		}
		out[i] = raw
	}
	return out, nil
}

// SpanVector is the columnar payload for a set of transactions, before
// compression, and what a decoder must produce from it. The golden vectors pin
// this rather than the compressed message: brotli is a standard, and an
// implementation's obligation is the layout inside it.
func SpanVector(raws [][]byte) (payload []byte, decoded [][]byte, err error) {
	msg, err := encodeSpanBatch(raws)
	if err != nil {
		return nil, nil, err
	}
	payload, err = io.ReadAll(brotli.NewReader(bytes.NewReader(msg[2:])))
	if err != nil {
		return nil, nil, err
	}
	decoded, err = decodeSpan(payload)
	if err != nil {
		return nil, nil, err
	}
	return payload, decoded, nil
}

func mustRLP(v any) []byte {
	raw, err := rlp.EncodeToBytes(v)
	if err != nil {
		panic(err)
	}
	return raw
}
