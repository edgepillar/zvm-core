package stateaudit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

var bindingLimits = BindingLimits{MaxDocumentBytes: 8 << 20, MaxHeaders: 256, MaxHeaderBytes: 8192}

const fixtureNow int64 = 2000000000

func releaseFixture(version string) (ChainContext, string, string) {
	raw, err := os.ReadFile("testdata/release-context.json")
	if err != nil {
		panic(err)
	}
	var golden struct {
		FixtureOnly    bool   `json:"fixtureOnly"`
		SigningMessage string `json:"signingMessage"`
		Manifest       string `json:"manifestSha256"`
		Epoch          string `json:"epochSha256"`
	}
	if json.Unmarshal(raw, &golden) != nil || !golden.FixtureOnly {
		panic("public release context fixture unavailable")
	}
	message, err := base64.StdEncoding.Strict().DecodeString(golden.SigningMessage)
	if err != nil || !bytes.HasPrefix(message, []byte("ZVM release manifest v1\n")) {
		panic("release vector domain changed")
	}
	body := message[len("ZVM release manifest v1\n"):]
	if digestBytes(body) != golden.Manifest {
		panic("public release vector digest changed")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		panic("release vector body changed")
	}
	var epoch struct {
		Chain   string `json:"l2ChainId"`
		Genesis string `json:"l2GenesisHash"`
		Rollup  string `json:"rollupSha256"`
	}
	if json.Unmarshal(fields["epoch"], &epoch) != nil {
		panic("release vector epoch changed")
	}
	epochBody := encJSON(struct {
		Epoch     json.RawMessage `json:"epoch"`
		Contracts json.RawMessage `json:"contracts"`
	}{fields["epoch"], fields["contracts"]})
	if digestBytes(append([]byte("ZVM chain epoch v1\n"), epochBody...)) != golden.Epoch {
		panic("public Go/browser epoch vector changed")
	}
	if version != "first" {
		var repositories []struct {
			Commit string `json:"commit"`
		}
		if json.Unmarshal(fields["repositories"], &repositories) != nil || len(repositories) == 0 {
			panic("release vector source missing")
		}
		replacement := strings.Repeat("a", 40)
		if replacement == repositories[0].Commit {
			replacement = strings.Repeat("b", 40)
		}
		old := append([]byte(`"commit":`), encJSON(repositories[0].Commit)...)
		next := append([]byte(`"commit":`), encJSON(replacement)...)
		body = bytes.Replace(body, old, next, 1)
		if digestBytes(body) == golden.Manifest {
			panic("compatible cohort fixture did not change source")
		}
	}
	identity := ChainContext{ChainID: epoch.Chain, GenesisHash: epoch.Genesis, RollupSHA256: epoch.Rollup, EpochSHA256: golden.Epoch}
	return identity, digestBytes(body), base64.StdEncoding.EncodeToString(append([]byte("ZVM release manifest v1\n"), body...))
}
func encJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

type bindingFixture struct {
	policy   SnapshotPolicy
	snapshot Snapshot
	witness  Witness
	header   *types.Header
	result   BoundSummary
}

func snapshotFixture(t *testing.T) bindingFixture {
	t.Helper()
	f := fixture(t, 8, true)
	w := collected(t, f)
	header := &types.Header{ParentHash: common.HexToHash("0x11"), UncleHash: types.EmptyUncleHash, Root: f.root, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Number: big.NewInt(40), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: uint64(fixtureNow - 30)}
	identity, manifest, message := releaseFixture("first")
	policy := SnapshotPolicy{Schema: 1, Expected: identity, ManifestSHA256: []string{manifest}, BlockNumber: 40, BlockHash: header.Hash().Hex(), MaxHeaderAgeSeconds: 60, Bootstrap: true}
	raw, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, result, err := NewSnapshot(context.Background(), policy, message, []hexutil.Bytes{raw}, w, nil, fixtureNow, testLimits, bindingLimits)
	if err != nil {
		t.Fatal(err)
	}
	return bindingFixture{policy: policy, snapshot: snapshot, witness: w, header: header, result: result}
}
func resumePolicy(f bindingFixture) SnapshotPolicy {
	p := f.policy
	p.ManifestSHA256 = append([]string(nil), p.ManifestSHA256...)
	p.Bootstrap = false
	p.PreviousCheckpointSHA256 = f.result.CheckpointSHA256
	return p
}

func TestSnapshotBindsActualWitnessToHeaderAndExistingReleaseEpochDomains(t *testing.T) {
	f := snapshotFixture(t)
	if f.result.Summary.StateRoot != f.header.Root || f.result.Checkpoint.BlockHash != f.header.Hash().Hex() || f.result.Checkpoint.NativeBalanceWei != f.result.Summary.NativeBalanceWei {
		t.Fatal("verified state root and source context were separated")
	}
	policy, err := DecodeSnapshotPolicy(encJSON(f.policy), bindingLimits.MaxDocumentBytes)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := DecodeSnapshot(encJSON(f.snapshot), bindingLimits.MaxDocumentBytes)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := DecodeCheckpoint(encJSON(f.result.Checkpoint), bindingLimits.MaxDocumentBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(policy, f.policy) || !reflect.DeepEqual(snapshot, f.snapshot) || checkpoint != f.result.Checkpoint {
		t.Fatal("context round trip changed accepted values")
	}
	resume := resumePolicy(f)
	protected := func() []byte {
		return encJSON(struct {
			Policy     SnapshotPolicy
			Snapshot   Snapshot
			Witness    Witness
			Checkpoint Checkpoint
		}{resume, snapshot, f.witness, checkpoint})
	}
	before := protected()
	result, err := VerifySnapshot(context.Background(), resume, snapshot, f.witness, &checkpoint, fixtureNow+1, testLimits, bindingLimits)
	if err != nil || result.Checkpoint.FirstObservedAt != fixtureNow || result.Checkpoint.LastVerifiedAt != fixtureNow+1 {
		t.Fatalf("resume refreshed source age: %+v %v", result, err)
	}
	if !bytes.Equal(before, protected()) || checkpoint != f.result.Checkpoint {
		t.Fatal("verification mutated a previous source or checkpoint")
	}
	if _, err := VerifySnapshot(context.Background(), resumePolicy(f), snapshot, f.witness, &checkpoint, fixtureNow+100, testLimits, bindingLimits); err == nil {
		t.Fatal("fresh collection time hid an old accepted header")
	}
}

func TestCompatibleReleaseRetirementDoesNotResetSameEpochCheckpoint(t *testing.T) {
	f := snapshotFixture(t)
	identity, newManifest, message := releaseFixture("second")
	if identity != f.policy.Expected {
		t.Fatal("fixture changed its epoch")
	}
	p := resumePolicy(f)
	p.ManifestSHA256 = []string{newManifest} // Previous cohort has been retired.
	snapshot := f.snapshot
	snapshot.SigningMessage = message
	got, err := VerifySnapshot(context.Background(), p, snapshot, f.witness, &f.result.Checkpoint, fixtureNow+2, testLimits, bindingLimits)
	if err != nil || got.Checkpoint.ManifestSHA256 != newManifest || got.Checkpoint.FirstObservedAt != f.result.Checkpoint.FirstObservedAt {
		t.Fatalf("compatible source rollout reset history: %+v %v", got, err)
	}
	p.ManifestSHA256 = []string{f.policy.ManifestSHA256[0], newManifest}
	if _, err := VerifySnapshot(context.Background(), p, snapshot, f.witness, &f.result.Checkpoint, fixtureNow+2, testLimits, bindingLimits); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedHeaderSegmentAdvancesAndRefusesMissingReorderedOrChangedHistory(t *testing.T) {
	f := snapshotFixture(t)
	p := resumePolicy(f)
	first := types.CopyHeader(f.header)
	first.Number = new(big.Int).Add(first.Number, big.NewInt(1))
	first.ParentHash = f.header.Hash()
	first.Time++
	last := types.CopyHeader(first)
	last.Number = new(big.Int).Add(last.Number, big.NewInt(1))
	last.ParentHash = first.Hash()
	last.Time++
	p.BlockNumber = last.Number.Uint64()
	p.BlockHash = last.Hash().Hex()
	s := f.snapshot
	s.Headers = []hexutil.Bytes{enc(first), enc(last)}
	got, err := VerifySnapshot(context.Background(), p, s, f.witness, &f.result.Checkpoint, fixtureNow+1, testLimits, bindingLimits)
	if err != nil || got.Checkpoint.BlockNumber != 42 || got.Checkpoint.FirstObservedAt != fixtureNow+1 {
		t.Fatalf("complete header segment refused: %+v %v", got, err)
	}
	for _, kind := range []string{"gap", "reorder", "duplicate", "parent", "time-retreat", "same-height-reorg", "height-retreat", "old-pin", "changed-checkpoint", "clock-retreat", "missing-previous", "context-reset"} {
		t.Run(kind, func(t *testing.T) {
			policy := p
			policy.ManifestSHA256 = append([]string(nil), p.ManifestSHA256...)
			snapshot := s
			snapshot.Headers = append([]hexutil.Bytes(nil), s.Headers...)
			previous := f.result.Checkpoint
			prior := &previous
			now := fixtureNow + 1
			switch kind {
			case "gap":
				snapshot.Headers = snapshot.Headers[1:]
			case "reorder":
				snapshot.Headers[0], snapshot.Headers[1] = snapshot.Headers[1], snapshot.Headers[0]
			case "duplicate":
				snapshot.Headers[1] = snapshot.Headers[0]
			case "parent":
				h := types.CopyHeader(first)
				h.ParentHash = common.HexToHash("0x12")
				snapshot.Headers[0] = enc(h)
			case "time-retreat":
				h := types.CopyHeader(first)
				h.Time = f.header.Time - 1
				snapshot.Headers[0] = enc(h)
			case "same-height-reorg":
				policy = resumePolicy(f)
				h := types.CopyHeader(f.header)
				h.Extra = []byte{1}
				policy.BlockHash = h.Hash().Hex()
				snapshot.Headers = []hexutil.Bytes{enc(h)}
			case "height-retreat":
				policy.BlockNumber = 39
			case "old-pin":
				policy.PreviousCheckpointSHA256 = strings.Repeat("3", 64)
			case "changed-checkpoint":
				previous.NativeBalanceWei = "0"
			case "clock-retreat":
				now = fixtureNow - 1
			case "missing-previous":
				prior = nil
			case "context-reset":
				previous.Context.EpochSHA256 = strings.Repeat("4", 64)
				policy.PreviousCheckpointSHA256, _ = previous.Fingerprint()
			}
			if got, err := VerifySnapshot(context.Background(), policy, snapshot, f.witness, prior, now, testLimits, bindingLimits); err == nil || got.CheckpointSHA256 != "" {
				t.Fatal("changed or incomplete history produced a checkpoint")
			}
		})
	}
}

func TestSnapshotIdentityPointAndResourceRefusalsHaveNoSuccessResult(t *testing.T) {
	f := snapshotFixture(t)
	for _, kind := range []string{"policy-schema", "snapshot-schema", "zero-chain", "alias-chain", "genesis", "rollup", "epoch", "empty-releases", "duplicate-release", "unknown-release", "release-domain", "noncanonical-base64", "witness-digest", "witness-root", "block-hash", "block-number", "future-header", "stale-header", "empty-headers", "trailing-header", "bad-header", "header-count", "header-bytes", "context-bytes", "zero-age", "bootstrap-previous", "missing-anchor", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			p := f.policy
			p.ManifestSHA256 = append([]string(nil), p.ManifestSHA256...)
			s := f.snapshot
			s.Headers = append([]hexutil.Bytes(nil), s.Headers...)
			w := f.witness
			bounds := bindingLimits
			now := fixtureNow
			ctx := context.Background()
			var previous *Checkpoint
			switch kind {
			case "policy-schema":
				p.Schema = 2
			case "snapshot-schema":
				s.Schema = 2
			case "zero-chain":
				p.Expected.ChainID = "0"
			case "alias-chain":
				p.Expected.ChainID = "070"
			case "genesis":
				p.Expected.GenesisHash = "0x" + strings.Repeat("3", 64)
			case "rollup":
				p.Expected.RollupSHA256 = strings.Repeat("3", 64)
			case "epoch":
				p.Expected.EpochSHA256 = strings.Repeat("3", 64)
			case "empty-releases":
				p.ManifestSHA256 = nil
			case "duplicate-release":
				p.ManifestSHA256 = append(p.ManifestSHA256, p.ManifestSHA256[0])
			case "unknown-release":
				p.ManifestSHA256[0] = strings.Repeat("3", 64)
			case "release-domain":
				raw, _ := base64.StdEncoding.DecodeString(s.SigningMessage)
				s.SigningMessage = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte("v1\n"), []byte("v2\n"), 1))
			case "noncanonical-base64":
				s.SigningMessage += "\n"
			case "witness-digest":
				s.WitnessSHA256 = strings.Repeat("3", 64)
			case "witness-root":
				w.StateRoot = common.HexToHash("0x01")
			case "block-hash":
				p.BlockHash = "0x" + strings.Repeat("3", 64)
			case "block-number":
				p.BlockNumber++
			case "future-header":
				h := types.CopyHeader(f.header)
				h.Time = uint64(now + 1)
				s.Headers[0] = enc(h)
				p.BlockHash = h.Hash().Hex()
			case "stale-header":
				p.MaxHeaderAgeSeconds = 1
			case "empty-headers":
				s.Headers = nil
			case "trailing-header":
				s.Headers[0] = append(bytes.Clone(s.Headers[0]), 0)
			case "bad-header":
				s.Headers[0] = []byte{0xff}
			case "header-count":
				bounds.MaxHeaders = 0
			case "header-bytes":
				bounds.MaxHeaderBytes = 1
			case "context-bytes":
				bounds.MaxDocumentBytes = 300
			case "zero-age":
				p.MaxHeaderAgeSeconds = 0
			case "bootstrap-previous":
				previous = &f.result.Checkpoint
			case "missing-anchor":
				p.Bootstrap = false
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if got, err := VerifySnapshot(ctx, p, s, w, previous, now, testLimits, bounds); err == nil || got.CheckpointSHA256 != "" {
				t.Fatal("refused snapshot returned a new accepted record")
			}
		})
	}
}

func TestEvenPinnedReleaseMessagesRequireExactNonambiguousIdentityFields(t *testing.T) {
	f := snapshotFixture(t)
	raw, _ := base64.StdEncoding.DecodeString(f.snapshot.SigningMessage)
	body := raw[len("ZVM release manifest v1\n"):]
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		t.Fatal("fixture release fields unavailable")
	}
	field := func(name string, value []byte) []byte { return append(append(encJSON(name), ':'), value...) }
	chainField := field("l2ChainId", encJSON(f.policy.Expected.ChainID))
	contractsField := field("contracts", fields["contracts"])
	for _, kind := range []string{"duplicate-schema", "alias-schema", "duplicate-epoch-field", "alias-epoch-field", "null-contracts", "missing-contracts", "wrong-chain", "wrong-epoch", "trailing", "deep"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(body)
			switch kind {
			case "duplicate-schema":
				bad = bytes.Replace(bad, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
			case "alias-schema":
				bad = bytes.Replace(bad, []byte(`"schema":1`), []byte(`"Schema":1`), 1)
			case "duplicate-epoch-field":
				bad = bytes.Replace(bad, chainField, append(append(bytes.Clone(chainField), ','), chainField...), 1)
			case "alias-epoch-field":
				bad = bytes.Replace(bad, []byte(`"l2ChainId"`), []byte(`"L2ChainId"`), 1)
			case "null-contracts":
				bad = bytes.Replace(bad, contractsField, field("contracts", []byte("null")), 1)
			case "missing-contracts":
				bad = bytes.Replace(bad, append([]byte{','}, contractsField...), nil, 1)
			case "wrong-chain":
				bad = bytes.Replace(bad, chainField, field("l2ChainId", encJSON("71")), 1)
			case "wrong-epoch":
				bad = bytes.Replace(bad, contractsField, field("contracts", []byte("[]")), 1)
			case "trailing":
				bad = append(bad, []byte(` {}`)...)
			case "deep":
				bad = []byte(`{"schema":1,"epoch":` + strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34) + `,"contracts":[]}`)
			}
			p := f.policy
			p.ManifestSHA256 = []string{digestBytes(bad)}
			s := f.snapshot
			s.SigningMessage = base64.StdEncoding.EncodeToString(append([]byte("ZVM release manifest v1\n"), bad...))
			if got, err := VerifySnapshot(context.Background(), p, s, f.witness, nil, fixtureNow, testLimits, bindingLimits); err == nil || got.CheckpointSHA256 != "" {
				t.Fatal("ambiguous pinned message selected an identity")
			}
		})
	}
}

func TestContextDocumentsRefuseMissingAliasedDuplicateUnknownAndNullFields(t *testing.T) {
	f := snapshotFixture(t)
	for _, document := range []struct {
		name   string
		raw    []byte
		decode func([]byte) error
	}{
		{"policy", encJSON(f.policy), func(raw []byte) error { _, e := DecodeSnapshotPolicy(raw, bindingLimits.MaxDocumentBytes); return e }},
		{"snapshot", encJSON(f.snapshot), func(raw []byte) error { _, e := DecodeSnapshot(raw, bindingLimits.MaxDocumentBytes); return e }},
		{"checkpoint", encJSON(f.result.Checkpoint), func(raw []byte) error { _, e := DecodeCheckpoint(raw, bindingLimits.MaxDocumentBytes); return e }},
	} {
		t.Run(document.name, func(t *testing.T) {
			for _, kind := range []string{"missing", "alias", "duplicate", "unknown", "null", "fraction", "trailing", "oversized"} {
				t.Run(kind, func(t *testing.T) {
					raw := bytes.Clone(document.raw)
					switch kind {
					case "missing":
						raw = bytes.Replace(raw, []byte(`"schema":1,`), nil, 1)
					case "alias":
						raw = bytes.Replace(raw, []byte(`"schema":1`), []byte(`"Schema":1`), 1)
					case "duplicate":
						raw = bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
					case "unknown":
						raw = append([]byte(`{"unexpected":1,`), raw[1:]...)
					case "null":
						raw = bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":null`), 1)
					case "fraction":
						raw = bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1.0`), 1)
					case "trailing":
						raw = append(raw, []byte(`{}`)...)
					case "oversized":
						raw = bytes.Repeat([]byte(" "), int(bindingLimits.MaxDocumentBytes)+1)
					}
					if document.decode(raw) == nil {
						t.Fatal("malformed context document accepted")
					}
				})
			}
		})
	}
}

func TestSnapshotProducerCopiesHeadersAndReturnsNothingAfterRefusal(t *testing.T) {
	f := snapshotFixture(t)
	headers := []hexutil.Bytes{bytes.Clone(f.snapshot.Headers[0])}
	s, _, err := NewSnapshot(context.Background(), f.policy, f.snapshot.SigningMessage, headers, f.witness, nil, fixtureNow, testLimits, bindingLimits)
	if err != nil {
		t.Fatal(err)
	}
	headers[0][0] ^= 1
	if bytes.Equal(headers[0], s.Headers[0]) {
		t.Fatal("producer retained mutable caller header storage")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, result, err := NewSnapshot(ctx, f.policy, f.snapshot.SigningMessage, f.snapshot.Headers, f.witness, nil, fixtureNow, testLimits, bindingLimits)
	if !errors.Is(err, context.Canceled) || s.Schema != 0 || result.CheckpointSHA256 != "" {
		t.Fatal("cancelled producer returned an artifact")
	}
	p := f.policy
	p.BlockHash = "0x" + strings.Repeat("3", 64)
	if s, result, err := NewSnapshot(context.Background(), p, f.snapshot.SigningMessage, f.snapshot.Headers, f.witness, nil, fixtureNow, testLimits, bindingLimits); err == nil || s.Schema != 0 || result.CheckpointSHA256 != "" {
		t.Fatal("unaccepted point produced a snapshot")
	}
}
