package stateaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// ChainContext uses the existing independently pinned agreement identity.
// RollupSHA256 is the exact release configuration-file digest, not the bridge
// provider's separately defined typed-configuration digest.
type ChainContext struct {
	ChainID      string `json:"chainId"`
	GenesisHash  string `json:"genesisHash"`
	RollupSHA256 string `json:"rollupSha256"`
	EpochSHA256  string `json:"epochSha256"`
}

// SnapshotPolicy must be provisioned independently of the snapshot. Accepted
// manifest pins come from the existing release/signature acceptance process;
// BlockHash/Number come from an independently accepted canonical observation.
// This package does not create that authority or verify a new signing policy.
type SnapshotPolicy struct {
	Schema                   int          `json:"schema"`
	Expected                 ChainContext `json:"expected"`
	ManifestSHA256           []string     `json:"manifestSha256"`
	BlockNumber              uint64       `json:"blockNumber"`
	BlockHash                string       `json:"blockHash"`
	MaxHeaderAgeSeconds      uint64       `json:"maxHeaderAgeSeconds"`
	Bootstrap                bool         `json:"bootstrap"`
	PreviousCheckpointSHA256 string       `json:"previousCheckpointSha256"`
}

type Snapshot struct {
	Schema         int             `json:"schema"`
	SigningMessage string          `json:"signingMessage"`
	WitnessSHA256  string          `json:"witnessSha256"`
	Headers        []hexutil.Bytes `json:"headers"`
}

// BindingLimits are resource bounds. Freshness is explicitly supplied by the
// independently accepted SnapshotPolicy, never inferred from collection time.
type BindingLimits struct {
	MaxDocumentBytes uint64
	MaxHeaders       uint64
	MaxHeaderBytes   uint64
}

type Checkpoint struct {
	Schema           int          `json:"schema"`
	Context          ChainContext `json:"context"`
	ManifestSHA256   string       `json:"manifestSha256"`
	BlockNumber      uint64       `json:"blockNumber"`
	BlockHash        string       `json:"blockHash"`
	StateRoot        string       `json:"stateRoot"`
	HeaderTimestamp  uint64       `json:"headerTimestamp"`
	NativeBalanceWei string       `json:"nativeBalanceWei"`
	Accounts         uint64       `json:"accounts"`
	WitnessSHA256    string       `json:"witnessSha256"`
	FirstObservedAt  int64        `json:"firstObservedAt"`
	LastVerifiedAt   int64        `json:"lastVerifiedAt"`
}

type BoundSummary struct {
	Summary          Summary    `json:"summary"`
	Checkpoint       Checkpoint `json:"checkpoint"`
	CheckpointSHA256 string     `json:"checkpointSha256"`
}

func snapshotBudget(snapshot Snapshot, bounds BindingLimits) bool {
	if bounds.MaxDocumentBytes <= 256 || bounds.MaxDocumentBytes >= math.MaxInt64 || bounds.MaxHeaders == 0 || bounds.MaxHeaderBytes == 0 || bounds.MaxHeaderBytes >= math.MaxInt64 || uint64(len(snapshot.Headers)) > bounds.MaxHeaders {
		return false
	}
	remaining := bounds.MaxDocumentBytes - 256
	if uint64(len(snapshot.SigningMessage)) > remaining {
		return false
	}
	remaining -= uint64(len(snapshot.SigningMessage))
	for _, raw := range snapshot.Headers {
		if uint64(len(raw)) > bounds.MaxHeaderBytes || remaining < 8 || uint64(len(raw)) > (remaining-8)/2 {
			return false
		}
		remaining -= uint64(2*len(raw) + 8)
	}
	return true
}

func digestBytes(raw []byte) string {
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}

func contextDigest(value string) bool {
	if len(value) != 64 || value == strings.Repeat("0", 64) || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func contextHash(value string) bool {
	return len(value) == 66 && strings.HasPrefix(value, "0x") && contextDigest(value[2:])
}

func validChainContext(value ChainContext) bool {
	id, err := strconv.ParseUint(value.ChainID, 10, 64)
	return err == nil && id > 0 && strconv.FormatUint(id, 10) == value.ChainID && contextHash(value.GenesisHash) && contextDigest(value.RollupSHA256) && contextDigest(value.EpochSHA256)
}

func (policy SnapshotPolicy) validate() error {
	if policy.Schema != 1 || !validChainContext(policy.Expected) || !contextHash(policy.BlockHash) || policy.MaxHeaderAgeSeconds == 0 || policy.MaxHeaderAgeSeconds > math.MaxInt64 || len(policy.ManifestSHA256) == 0 || len(policy.ManifestSHA256) > 8 {
		return errors.New("invalid independently pinned snapshot policy")
	}
	seen := map[string]bool{}
	for _, pin := range policy.ManifestSHA256 {
		if !contextDigest(pin) || seen[pin] {
			return errors.New("invalid or repeated snapshot release pin")
		}
		seen[pin] = true
	}
	if (policy.Bootstrap && policy.PreviousCheckpointSHA256 != "") || (!policy.Bootstrap && !contextDigest(policy.PreviousCheckpointSHA256)) {
		return errors.New("explicit bootstrap or independently pinned previous checkpoint required")
	}
	return nil
}

func (checkpoint Checkpoint) validate() error {
	if len(checkpoint.NativeBalanceWei) == 0 || len(checkpoint.NativeBalanceWei) > 100 {
		return errors.New("checkpoint native balance exceeds bounds")
	}
	value, ok := new(big.Int).SetString(checkpoint.NativeBalanceWei, 10)
	if checkpoint.Schema != 1 || !validChainContext(checkpoint.Context) || !contextDigest(checkpoint.ManifestSHA256) || !contextHash(checkpoint.BlockHash) || !contextHash(checkpoint.StateRoot) || !contextDigest(checkpoint.WitnessSHA256) || checkpoint.FirstObservedAt <= 0 || checkpoint.LastVerifiedAt < checkpoint.FirstObservedAt || !ok || value.Sign() < 0 || value.BitLen() > 320 || value.String() != checkpoint.NativeBalanceWei {
		return errors.New("invalid native balance checkpoint")
	}
	if (checkpoint.Accounts == 0) != (checkpoint.StateRoot == types.EmptyRootHash.Hex()) || (checkpoint.Accounts == 0 && value.Sign() != 0) || (checkpoint.BlockNumber == 0 && checkpoint.BlockHash != checkpoint.Context.GenesisHash) {
		return errors.New("checkpoint account/root disagreement")
	}
	return nil
}

// Fingerprint detects changed checkpoint bytes under the declared canonical
// representation. The caller must independently retain the latest accepted pin;
// a self-consistent old file and hash do not establish anti-rollback authority.
func (checkpoint Checkpoint) Fingerprint() (string, error) {
	if err := checkpoint.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		return "", errors.New("checkpoint encoding unavailable")
	}
	return digestBytes(append([]byte("ZVM native balance checkpoint v1\n"), raw...)), nil
}

func releaseContext(message string, policy SnapshotPolicy, limits BindingLimits) (string, error) {
	if len(message) == 0 || uint64(len(message)) > limits.MaxDocumentBytes {
		return "", errors.New("snapshot release message unavailable")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(message)
	const domain = "ZVM release manifest v1\n"
	if err != nil || base64.StdEncoding.EncodeToString(raw) != message || !bytes.HasPrefix(raw, []byte(domain)) {
		return "", errors.New("snapshot release message domain unavailable")
	}
	body := raw[len(domain):]
	manifest := digestBytes(body)
	accepted := false
	for _, pin := range policy.ManifestSHA256 {
		accepted = accepted || pin == manifest
	}
	if !accepted {
		return "", errors.New("snapshot release is outside accepted cohorts")
	}
	fields, err := contextObject(body, limits.MaxDocumentBytes)
	if err != nil || requiredContextFields(fields, "schema", "epoch", "contracts") != nil || string(fields["schema"]) != "1" {
		return "", errors.New("snapshot release identity fields unavailable")
	}
	epoch, err := contextObject(fields["epoch"], limits.MaxDocumentBytes)
	if err != nil || requiredContextFields(epoch, "l2ChainId", "l2GenesisHash", "rollupSha256") != nil {
		return "", errors.New("snapshot release epoch unavailable")
	}
	var chain, genesis, rollup string
	if json.Unmarshal(epoch["l2ChainId"], &chain) != nil || json.Unmarshal(epoch["l2GenesisHash"], &genesis) != nil || json.Unmarshal(epoch["rollupSha256"], &rollup) != nil || chain != policy.Expected.ChainID || genesis != policy.Expected.GenesisHash || rollup != policy.Expected.RollupSHA256 {
		return "", errors.New("snapshot release context disagrees with independent pins")
	}
	var contracts []json.RawMessage
	if json.Unmarshal(fields["contracts"], &contracts) != nil || contracts == nil {
		return "", errors.New("snapshot release contract inventory unavailable")
	}
	epochBody, err := json.Marshal(struct {
		Epoch     json.RawMessage `json:"epoch"`
		Contracts json.RawMessage `json:"contracts"`
	}{fields["epoch"], fields["contracts"]})
	if err != nil || digestBytes(append([]byte("ZVM chain epoch v1\n"), epochBody...)) != policy.Expected.EpochSHA256 {
		return "", errors.New("snapshot epoch fingerprint disagrees with independent pins")
	}
	return manifest, nil
}

func decodeSnapshotHeader(raw []byte, limit uint64) (*types.Header, error) {
	var header types.Header
	if len(raw) == 0 || uint64(len(raw)) > limit || rlp.DecodeBytes(raw, &header) != nil || header.Number == nil || !header.Number.IsUint64() || header.Root == (common.Hash{}) {
		return nil, errors.New("snapshot header unavailable")
	}
	canonical, err := rlp.EncodeToBytes(&header)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errors.New("snapshot header is not canonical RLP")
	}
	return &header, nil
}

// VerifySnapshot binds a complete MPT sum to a caller-accepted canonical point,
// accepted release/epoch pins and an explicitly retained checkpoint. Header
// links prove continuity with that checkpoint, not independent canonicality.
// It never changes inputs, writes a checkpoint, selects trust or resets history.
func VerifySnapshot(ctx context.Context, policy SnapshotPolicy, snapshot Snapshot, witness Witness, previous *Checkpoint, now int64, limits Limits, bounds BindingLimits) (BoundSummary, error) {
	return verifySnapshot(ctx, policy, snapshot, witness, previous, now, limits, bounds, nil)
}

func verifySnapshot(ctx context.Context, policy SnapshotPolicy, snapshot Snapshot, witness Witness, previous *Checkpoint, now int64, limits Limits, bounds BindingLimits, observe func([]byte, *big.Int) error) (BoundSummary, error) {
	if err := check(ctx, limits); err != nil {
		return BoundSummary{}, err
	}
	if policy.validate() != nil || snapshot.Schema != 1 || now <= 0 || !snapshotBudget(snapshot, bounds) || len(snapshot.Headers) == 0 || !contextDigest(snapshot.WitnessSHA256) {
		return BoundSummary{}, errors.New("snapshot context or bounds unavailable")
	}
	manifest, err := releaseContext(snapshot.SigningMessage, policy, bounds)
	if err != nil {
		return BoundSummary{}, err
	}
	if policy.Bootstrap {
		if previous != nil || len(snapshot.Headers) != 1 {
			return BoundSummary{}, errors.New("bootstrap requires one independently accepted point and no previous record")
		}
	} else {
		if previous == nil {
			return BoundSummary{}, errors.New("previous checkpoint required")
		}
		pin, err := previous.Fingerprint()
		if err != nil || pin != policy.PreviousCheckpointSHA256 || previous.Context != policy.Expected || now < previous.LastVerifiedAt || policy.BlockNumber < previous.BlockNumber {
			return BoundSummary{}, errors.New("checkpoint identity, clock or accepted point retreated")
		}
	}
	var last *types.Header
	for i, raw := range snapshot.Headers {
		if err := ctx.Err(); err != nil {
			return BoundSummary{}, err
		}
		header, err := decodeSnapshotHeader(raw, bounds.MaxHeaderBytes)
		if err != nil {
			return BoundSummary{}, err
		}
		height := header.Number.Uint64()
		if i == 0 && previous != nil {
			if policy.BlockNumber == previous.BlockNumber {
				if len(snapshot.Headers) != 1 || height != previous.BlockNumber || header.Hash().Hex() != previous.BlockHash || header.Root.Hex() != previous.StateRoot || header.Time != previous.HeaderTimestamp {
					return BoundSummary{}, errors.New("same-height snapshot changed its accepted state")
				}
			} else if previous.BlockNumber == math.MaxUint64 || height != previous.BlockNumber+1 || header.ParentHash.Hex() != previous.BlockHash || header.Time < previous.HeaderTimestamp {
				return BoundSummary{}, errors.New("snapshot cannot bridge a checkpoint gap or reorg")
			}
		}
		if last != nil && (last.Number.Uint64() == math.MaxUint64 || height != last.Number.Uint64()+1 || header.ParentHash != last.Hash() || header.Time < last.Time) {
			return BoundSummary{}, errors.New("snapshot header segment is incomplete or changed")
		}
		last = header
	}
	if last.Number.Uint64() != policy.BlockNumber || last.Hash().Hex() != policy.BlockHash || last.Time > uint64(now) || uint64(now)-last.Time > policy.MaxHeaderAgeSeconds || (policy.BlockNumber == 0 && policy.BlockHash != policy.Expected.GenesisHash) {
		return BoundSummary{}, errors.New("snapshot does not match the accepted fresh block")
	}
	summary, err := verifyAccounts(ctx, last.Root, witness, limits, observe)
	if err != nil {
		return BoundSummary{}, err
	}
	hash := sha256.New()
	if err := Encode(ctx, hash, witness, limits); err != nil {
		return BoundSummary{}, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != snapshot.WitnessSHA256 {
		return BoundSummary{}, errors.New("snapshot witness digest disagrees with its canonical artifact")
	}
	firstObserved := now
	if previous != nil && policy.BlockNumber == previous.BlockNumber {
		if summary.NativeBalanceWei != previous.NativeBalanceWei || summary.Accounts != previous.Accounts || snapshot.WitnessSHA256 != previous.WitnessSHA256 {
			return BoundSummary{}, errors.New("same-height snapshot changed its native balance record")
		}
		firstObserved = previous.FirstObservedAt
	}
	checkpoint := Checkpoint{Schema: 1, Context: policy.Expected, ManifestSHA256: manifest, BlockNumber: policy.BlockNumber,
		BlockHash: policy.BlockHash, StateRoot: last.Root.Hex(), HeaderTimestamp: last.Time, NativeBalanceWei: summary.NativeBalanceWei,
		Accounts: summary.Accounts, WitnessSHA256: snapshot.WitnessSHA256, FirstObservedAt: firstObserved, LastVerifiedAt: now}
	pin, err := checkpoint.Fingerprint()
	if err != nil {
		return BoundSummary{}, err
	}
	return BoundSummary{Summary: summary, Checkpoint: checkpoint, CheckpointSHA256: pin}, nil
}

// NewSnapshot produces a small verified context document, retaining the witness
// as a separate binary artifact. A refused policy/point/previous record returns
// no document or checkpoint. Headers are copied; witness bytes are streamed into
// their digest rather than copied into the context document.
func NewSnapshot(ctx context.Context, policy SnapshotPolicy, signingMessage string, headers []hexutil.Bytes, witness Witness, previous *Checkpoint, now int64, limits Limits, bounds BindingLimits) (Snapshot, BoundSummary, error) {
	if err := check(ctx, limits); err != nil {
		return Snapshot{}, BoundSummary{}, err
	}
	if len(headers) == 0 || !snapshotBudget(Snapshot{SigningMessage: signingMessage, Headers: headers}, bounds) {
		return Snapshot{}, BoundSummary{}, errors.New("snapshot source exceeds context bounds")
	}
	snapshot := Snapshot{Schema: 1, SigningMessage: signingMessage}
	for _, raw := range headers {
		if uint64(len(raw)) > bounds.MaxHeaderBytes {
			return Snapshot{}, BoundSummary{}, errors.New("snapshot header exceeds bounds")
		}
		snapshot.Headers = append(snapshot.Headers, bytes.Clone(raw))
	}
	hash := sha256.New()
	if err := Encode(ctx, hash, witness, limits); err != nil {
		return Snapshot{}, BoundSummary{}, err
	}
	snapshot.WitnessSHA256 = hex.EncodeToString(hash.Sum(nil))
	result, err := VerifySnapshot(ctx, policy, snapshot, witness, previous, now, limits, bounds)
	if err != nil {
		return Snapshot{}, BoundSummary{}, err
	}
	return snapshot, result, nil
}
