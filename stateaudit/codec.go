package stateaudit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var magic = [8]byte{'Z', 'V', 'M', 'B', 'A', 'L', 0, 1}

// Encode writes the versioned binary format without copying the witness into a
// second whole buffer. It checks wire order and resource bounds, not chain or
// Merkle validity; Collect or Verify must establish completeness separately.
// On a writer/cancellation error the owner must preserve or discard the partial
// stream explicitly. It is not a verified complete artifact.
func Encode(ctx context.Context, writer io.Writer, witness Witness, limits Limits) error {
	if writer == nil {
		return errors.New("state witness writer unavailable")
	}
	if _, err := wireSize(ctx, witness, limits); err != nil {
		return err
	}
	var header [headerBytes]byte
	copy(header[:8], magic[:])
	copy(header[8:40], witness.StateRoot[:])
	binary.BigEndian.PutUint64(header[40:], uint64(len(witness.Nodes)))
	write := func(raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := writer.Write(raw)
		if err != nil {
			return errors.New("state witness output incomplete")
		}
		if n != len(raw) {
			return io.ErrShortWrite
		}
		return ctx.Err()
	}
	if err := write(header[:]); err != nil {
		return err
	}
	for _, blob := range witness.Nodes {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(blob)))
		if err := write(size[:]); err != nil {
			return err
		}
		if err := write(blob); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Decode reads one exact bounded stream. It rejects duplicate/unordered nodes,
// invalid lengths and trailing data. The caller must still Verify against a
// separately accepted expected root. Cancellation is checked between reads;
// synchronous I/O needs an owner-supplied deadline when it can block.
func Decode(ctx context.Context, reader io.Reader, limits Limits) (Witness, error) {
	if err := check(ctx, limits); err != nil {
		return Witness{}, err
	}
	if reader == nil {
		return Witness{}, errors.New("state witness input unavailable")
	}
	read := func(raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := io.ReadFull(reader, raw); err != nil {
			return errors.New("state witness input incomplete")
		}
		return ctx.Err()
	}
	var header [headerBytes]byte
	if err := read(header[:]); err != nil {
		return Witness{}, err
	}
	if !bytes.Equal(header[:8], magic[:]) {
		return Witness{}, errors.New("unsupported state witness format")
	}
	witness := Witness{StateRoot: common.BytesToHash(header[8:40])}
	count := binary.BigEndian.Uint64(header[40:])
	if witness.StateRoot == (common.Hash{}) || count > limits.MaxNodes {
		return Witness{}, errors.New("invalid state witness root or node count")
	}
	size := uint64(headerBytes)
	var previous common.Hash
	for i := uint64(0); i < count; i++ {
		var length [4]byte
		if size > limits.MaxEncodedBytes-4 {
			return Witness{}, errors.New("state witness size limit")
		}
		if err := read(length[:]); err != nil {
			return Witness{}, err
		}
		size += 4
		n := binary.BigEndian.Uint32(length[:])
		if n == 0 || n > maxNodeBytes || uint64(n) > limits.MaxEncodedBytes-size {
			return Witness{}, errors.New("state witness node size limit")
		}
		blob := make([]byte, int(n))
		if err := read(blob); err != nil {
			return Witness{}, err
		}
		size += uint64(n)
		hash := crypto.Keccak256Hash(blob)
		if i > 0 && bytes.Compare(previous[:], hash[:]) >= 0 {
			return Witness{}, errors.New("state witness nodes are duplicated or unordered")
		}
		previous = hash
		witness.Nodes = append(witness.Nodes, blob)
	}
	if err := ctx.Err(); err != nil {
		return Witness{}, err
	}
	var tail [1]byte
	n, err := io.ReadFull(reader, tail[:])
	if n != 0 || err != io.EOF {
		return Witness{}, errors.New("state witness trailing or unreadable data")
	}
	if err := ctx.Err(); err != nil {
		return Witness{}, err
	}
	return witness, nil
}
