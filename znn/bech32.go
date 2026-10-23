package znn

import (
	"errors"
	"fmt"
	"strings"
)

// Bech32 as BIP-173 defines it (not bech32m), which is what go-zenon uses for
// both `z1…` addresses and `zts1…` token standards. It lives here rather than
// behind a dependency because the whole of it is sixty lines and the checksum
// must be *checked* on decode: zenoglyphs' first decoder stripped it, so a
// mistyped recipient decoded silently to different bytes.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Gen = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= bech32Gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// convertBits regroups a byte slice between bit widths. With pad false it
// rejects non-zero padding, which is what makes a decode canonical.
func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	acc, bits := uint32(0), uint(0)
	maxv := uint32(1)<<to - 1
	out := make([]byte, 0, len(data)*int(from)/int(to)+1)
	for _, b := range data {
		if uint32(b)>>from != 0 {
			return nil, fmt.Errorf("bech32: value %d wider than %d bits", b, from)
		}
		acc = acc<<from | uint32(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("bech32: non-zero padding")
	}
	return out, nil
}

// EncodeBech32 encodes 8-bit data under a human-readable prefix.
func EncodeBech32(hrp string, data []byte) (string, error) {
	five, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	values := append(bech32HRPExpand(hrp), five...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1
	var sb strings.Builder
	sb.Grow(len(hrp) + 1 + len(five) + 6)
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range five {
		sb.WriteByte(bech32Charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(bech32Charset[(mod>>uint(5*(5-i)))&31])
	}
	return sb.String(), nil
}

// DecodeBech32 decodes and verifies a bech32 string, returning the prefix and
// the 8-bit payload.
func DecodeBech32(s string) (string, []byte, error) {
	if len(s) > 90 {
		return "", nil, errors.New("bech32: string longer than 90 characters")
	}
	// Reject non-ASCII before case folding: a Unicode lookalike must not
	// normalize into a valid address or checksum character.
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return "", nil, errors.New("bech32: invalid character")
		}
	}
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("bech32: mixed case")
	}
	s = strings.ToLower(s)
	sep := strings.LastIndexByte(s, '1')
	if sep < 1 || sep+7 > len(s) {
		return "", nil, errors.New("bech32: separator missing or checksum too short")
	}
	hrp := s[:sep]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, errors.New("bech32: invalid prefix character")
		}
	}
	values := make([]byte, 0, len(s)-sep-1)
	for i := sep + 1; i < len(s); i++ {
		idx := strings.IndexByte(bech32Charset, s[i])
		if idx < 0 {
			return "", nil, fmt.Errorf("bech32: invalid character %q", s[i])
		}
		values = append(values, byte(idx))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("bech32: checksum mismatch")
	}
	data, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}
