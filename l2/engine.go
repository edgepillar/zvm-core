// Package l2 talks to op-geth: the Engine API that builds blocks, and the
// genesis and deposit encodings those blocks are made of.
package l2

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
)

// Engine is an authenticated Engine API client. The ZVM targets Isthmus
// (Prague) payloads: forkchoiceUpdatedV3, getPayloadV4, newPayloadV4.
type Engine struct {
	c *rpc.Client
}

func ReadJWTSecret(path string) ([32]byte, error) {
	var secret [32]byte
	raw, err := os.ReadFile(path)
	if err != nil {
		return secret, err
	}
	s := strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return secret, fmt.Errorf("%s: want 32 hex bytes", path)
	}
	copy(secret[:], b)
	return secret, nil
}

func DialEngine(ctx context.Context, url string, secret [32]byte) (*Engine, error) {
	c, err := rpc.DialOptions(ctx, url, rpc.WithHTTPAuth(node.NewJWTAuth(secret)))
	if err != nil {
		return nil, err
	}
	return &Engine{c: c}, nil
}

func (e *Engine) Close() { e.c.Close() }

func (e *Engine) ForkchoiceUpdated(ctx context.Context, state engine.ForkchoiceStateV1, attrs *engine.PayloadAttributes) (*engine.ForkChoiceResponse, error) {
	var res engine.ForkChoiceResponse
	if err := e.c.CallContext(ctx, &res, "engine_forkchoiceUpdatedV3", state, attrs); err != nil {
		return nil, err
	}
	return &res, nil
}

func (e *Engine) GetPayload(ctx context.Context, id engine.PayloadID) (*engine.ExecutionPayloadEnvelope, error) {
	var res engine.ExecutionPayloadEnvelope
	if err := e.c.CallContext(ctx, &res, "engine_getPayloadV4", id); err != nil {
		return nil, err
	}
	return &res, nil
}

func (e *Engine) NewPayload(ctx context.Context, payload *engine.ExecutableData, beaconRoot common.Hash) (*engine.PayloadStatusV1, error) {
	var res engine.PayloadStatusV1
	if err := e.c.CallContext(ctx, &res, "engine_newPayloadV4", payload, []common.Hash{}, beaconRoot, []hexutil.Bytes{}); err != nil {
		return nil, err
	}
	return &res, nil
}

// How an engine names the transaction it refused (DECISIONS.md D12).
//
// op-geth aborts the whole block on the first forced transaction it cannot
// apply and names it — in the JSON-RPC error's *data*, under a generic
// "Invalid payload attributes" message (eth/catalyst/api.go:
// engine.InvalidPayloadAttributes.With(err)). That sentence is op-geth's own
// wording, and the rule that reads it is the one place derivation depends on
// a client's prose.
//
// So it is read three ways, most specific first:
//
//  1. the patterns below, which are the wordings we have seen;
//  2. failing those, any 32-byte hash anywhere in the error, checked by the
//     caller against the transactions it actually planned — a hash that is not
//     in the plan is ignored, so a block hash or a parent hash in the message
//     costs nothing;
//  3. failing that, the payload itself: whatever the engine built without is
//     what it refused (Plan.Missing), which needs no error text at all and is
//     what a client that silently skips a transaction leaves behind.
//
// (3) is the one that does not have to be re-established when the client
// changes; (1) and (2) only make the common case one round trip cheaper.
var refusalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`failed to force-include tx: (0x[0-9a-fA-F]{64})`), // op-geth
	regexp.MustCompile(`(?i)invalid (?:sequencer |deposit )?transaction[^0-9a-fA-F]+(0x[0-9a-fA-F]{64})`),
	regexp.MustCompile(`(?i)transaction (0x[0-9a-fA-F]{64})[^.]*?(?:rejected|invalid|could not be applied)`),
}

var anyHashRe = regexp.MustCompile(`0x[0-9a-fA-F]{64}`)

// RefusedTransactions lists the transaction hashes an engine error names, most
// likely first, with a reason to record. The caller must check each against
// its own plan before acting on it.
func RefusedTransactions(err error) ([]common.Hash, string) {
	if err == nil {
		return nil, ""
	}
	text := err.Error()
	var de rpc.DataError
	if errors.As(err, &de) {
		if raw, jerr := json.Marshal(de.ErrorData()); jerr == nil {
			text += " " + string(raw)
		}
	}
	reason := text
	if i := strings.LastIndex(reason, "err: "); i >= 0 {
		reason = strings.TrimRight(reason[i+len("err: "):], `"}`)
	}

	var out []common.Hash
	seen := map[common.Hash]bool{}
	appendHash := func(s string) {
		h := common.HexToHash(s)
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, re := range refusalPatterns {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			appendHash(m[1])
		}
	}
	for _, s := range anyHashRe.FindAllString(text, -1) {
		appendHash(s)
	}
	return out, reason
}

// ForceIncludeFailure is RefusedTransactions for a caller that wants only the
// first candidate. Kept for the CLI and tests; the deriver uses the list.
func ForceIncludeFailure(err error) (common.Hash, string, bool) {
	hashes, reason := RefusedTransactions(err)
	if len(hashes) == 0 {
		return common.Hash{}, "", false
	}
	return hashes[0], reason, true
}
