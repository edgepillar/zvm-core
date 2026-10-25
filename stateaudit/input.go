package stateaudit

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
)

var inputMagic = [8]byte{'Z', 'V', 'M', 'S', 'N', 'P', 0, 1}

// EncodeInput streams one framed context and the separate canonical witness.
// It is a codec, not policy/canonicality approval. A partial output is not a
// verified artifact. The small JSON context never embeds the binary witness.
func EncodeInput(ctx context.Context, writer io.Writer, policy SnapshotPolicy, snapshot Snapshot, previous *Checkpoint, witness Witness, limits Limits, bounds BindingLimits) error {
	if err := check(ctx, limits); err != nil {
		return err
	}
	if writer == nil || bounds.MaxDocumentBytes == 0 || bounds.MaxDocumentBytes > math.MaxUint32 {
		return errors.New("snapshot input writer or context bound unavailable")
	}
	raw, err := json.Marshal(struct {
		Schema     int            `json:"schema"`
		Policy     SnapshotPolicy `json:"policy"`
		Snapshot   Snapshot       `json:"snapshot"`
		Checkpoint *Checkpoint    `json:"checkpoint"`
	}{1, policy, snapshot, previous})
	if err != nil || uint64(len(raw)) > bounds.MaxDocumentBytes {
		return errors.New("snapshot input context exceeds bounds")
	}
	var header [12]byte
	copy(header[:8], inputMagic[:])
	binary.BigEndian.PutUint32(header[8:], uint32(len(raw)))
	for _, part := range [][]byte{header[:], raw} {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := writer.Write(part)
		if err != nil {
			return errors.New("snapshot input output incomplete")
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return Encode(ctx, writer, witness, limits)
}

// VerifyInput consumes exactly one bounded frame followed by the existing
// version-1 witness stream. Accepted policy and previous-record authority must
// come from the caller; the frame supplies no trust keys or network source.
func VerifyInput(ctx context.Context, reader io.Reader, now int64, limits Limits, bounds BindingLimits) (BoundSummary, error) {
	input, err := decodeInput(ctx, reader, limits, bounds)
	if err != nil {
		return BoundSummary{}, err
	}
	return VerifySnapshot(ctx, input.policy, input.snapshot, input.witness, input.checkpoint, now, limits, bounds)
}

type framedInput struct {
	policy     SnapshotPolicy
	snapshot   Snapshot
	checkpoint *Checkpoint
	witness    Witness
}

func decodeInput(ctx context.Context, reader io.Reader, limits Limits, bounds BindingLimits) (framedInput, error) {
	if err := check(ctx, limits); err != nil {
		return framedInput{}, err
	}
	if reader == nil || bounds.MaxDocumentBytes == 0 || bounds.MaxDocumentBytes > math.MaxUint32 {
		return framedInput{}, errors.New("snapshot input reader or context bound unavailable")
	}
	var header [12]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil || !bytes.Equal(header[:8], inputMagic[:]) {
		return framedInput{}, errors.New("snapshot input frame unavailable")
	}
	n := binary.BigEndian.Uint32(header[8:])
	if n == 0 || uint64(n) > bounds.MaxDocumentBytes {
		return framedInput{}, errors.New("snapshot input context size limit")
	}
	if err := ctx.Err(); err != nil {
		return framedInput{}, err
	}
	raw := make([]byte, int(n))
	if _, err := io.ReadFull(reader, raw); err != nil {
		return framedInput{}, errors.New("snapshot input context incomplete")
	}
	fields, err := contextObject(raw, bounds.MaxDocumentBytes)
	if err != nil || len(fields) != 4 || requiredContextFields(fields, "schema", "policy", "snapshot") != nil || fields["checkpoint"] == nil {
		return framedInput{}, errors.New("snapshot input fields must match the exact schema")
	}
	var schema int
	if json.Unmarshal(fields["schema"], &schema) != nil || schema != 1 {
		return framedInput{}, errors.New("snapshot input schema unavailable")
	}
	policy, err := DecodeSnapshotPolicy(fields["policy"], bounds.MaxDocumentBytes)
	if err != nil {
		return framedInput{}, err
	}
	snapshot, err := DecodeSnapshot(fields["snapshot"], bounds.MaxDocumentBytes)
	if err != nil {
		return framedInput{}, err
	}
	var previous *Checkpoint
	if !bytes.Equal(bytes.TrimSpace(fields["checkpoint"]), []byte("null")) {
		checkpoint, err := DecodeCheckpoint(fields["checkpoint"], bounds.MaxDocumentBytes)
		if err != nil {
			return framedInput{}, err
		}
		previous = &checkpoint
	}
	witness, err := Decode(ctx, reader, limits)
	if err != nil {
		return framedInput{}, err
	}
	return framedInput{policy: policy, snapshot: snapshot, checkpoint: previous, witness: witness}, nil
}
