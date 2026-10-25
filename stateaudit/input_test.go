package stateaudit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFramedContextAndWitnessRoundTripWithoutPayloadEmbedding(t *testing.T) {
	f := snapshotFixture(t)
	var stream bytes.Buffer
	if err := EncodeInput(context.Background(), &stream, f.policy, f.snapshot, nil, f.witness, testLimits, bindingLimits); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyInput(context.Background(), bytes.NewReader(stream.Bytes()), fixtureNow, testLimits, bindingLimits)
	if err != nil || got.CheckpointSHA256 != f.result.CheckpointSHA256 {
		t.Fatalf("framed source did not preserve context: %v", err)
	}
	var resume bytes.Buffer
	if err := EncodeInput(context.Background(), &resume, resumePolicy(f), f.snapshot, &f.result.Checkpoint, f.witness, testLimits, bindingLimits); err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyInput(context.Background(), bytes.NewReader(resume.Bytes()), fixtureNow+1, testLimits, bindingLimits); err != nil || got.Checkpoint.FirstObservedAt != fixtureNow {
		t.Fatal("framed restart lost history")
	}
	meta := binary.BigEndian.Uint32(stream.Bytes()[8:12])
	if meta == 0 || int(meta) >= stream.Len()-12 {
		t.Fatal("binary witness was not kept separate from its small context")
	}
}

func TestFramedInputRejectsVersionLengthsTruncationAndModeAmbiguity(t *testing.T) {
	f := snapshotFixture(t)
	var stream bytes.Buffer
	if err := EncodeInput(context.Background(), &stream, f.policy, f.snapshot, nil, f.witness, testLimits, bindingLimits); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"version", "zero-size", "huge-size", "metadata-truncated", "witness-truncated", "trailing", "wrong-root", "alias-frame", "duplicate-frame", "missing-checkpoint", "context-cap"} {
		t.Run(kind, func(t *testing.T) {
			raw := bytes.Clone(stream.Bytes())
			bounds := bindingLimits
			switch kind {
			case "version":
				raw[7]++
			case "zero-size":
				clear(raw[8:12])
			case "huge-size":
				binary.BigEndian.PutUint32(raw[8:12], ^uint32(0))
			case "metadata-truncated":
				raw = raw[:20]
			case "witness-truncated":
				raw = raw[:len(raw)-1]
			case "trailing":
				raw = append(raw, 0)
			case "wrong-root":
				p := f.policy
				p.BlockHash = "0x" + string(bytes.Repeat([]byte("3"), 64))
				var b bytes.Buffer
				EncodeInput(context.Background(), &b, p, f.snapshot, nil, f.witness, testLimits, bindingLimits)
				raw = b.Bytes()
			case "alias-frame", "duplicate-frame", "missing-checkpoint":
				n := int(binary.BigEndian.Uint32(raw[8:12]))
				meta := bytes.Clone(raw[12 : 12+n])
				tail := bytes.Clone(raw[12+n:])
				if kind == "alias-frame" {
					meta = bytes.Replace(meta, []byte("\"schema\":1"), []byte("\"Schema\":1"), 1)
				}
				if kind == "duplicate-frame" {
					meta = bytes.Replace(meta, []byte("\"schema\":1"), []byte("\"schema\":1,\"schema\":1"), 1)
				}
				if kind == "missing-checkpoint" {
					meta = bytes.Replace(meta, []byte(",\"checkpoint\":null"), nil, 1)
				}
				raw = append(raw[:12], meta...)
				binary.BigEndian.PutUint32(raw[8:12], uint32(len(meta)))
				raw = append(raw, tail...)
			case "context-cap":
				bounds.MaxDocumentBytes = 1
			}
			if got, err := VerifyInput(context.Background(), bytes.NewReader(raw), fixtureNow, testLimits, bounds); err == nil || got.CheckpointSHA256 != "" {
				t.Fatal("bad frame produced a successful record")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyInput(ctx, bytes.NewReader(stream.Bytes()), fixtureNow, testLimits, bindingLimits); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := EncodeInput(context.Background(), shortWriter{}, f.policy, f.snapshot, nil, f.witness, testLimits, bindingLimits); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}
