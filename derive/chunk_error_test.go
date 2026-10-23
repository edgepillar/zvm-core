package derive

import (
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

type chunkLookup func(znn.Hash) (*Chunk, bool, error)

func (f chunkLookup) Chunk(h znn.Hash) (*Chunk, bool, error) { return f(h) }

func TestChunkReadFailureStopsThePlanAndCanBeRetried(t *testing.T) {
	for _, active := range []bool{false, true} {
		name := "before gas fork"
		if active {
			name = "after gas fork"
		}
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			if active {
				cfg = gasForkConfig(t)
			}
			author := znn.Address{19: 9}
			target := common.Address{19: 7}
			payload := EncodeCall(Call{To: &target, Gas: 50_000, Data: []byte{1, 2, 3}})
			first, second := znn.Hash{0: 1}, znn.Hash{0: 2}
			chunks := fakeChunks{
				first:  {Hash: first, Author: author, Height: 11, Data: payload[:3]},
				second: {Hash: second, Author: author, Height: 11, Data: payload[3:]},
			}
			mb := newMomentum(12)
			mb.send(author, cfg.Inbox, znn.ZNN, 100_000, EncodeAssemble([]znn.Hash{first, second}))
			failure := errors.New("fixture chunk storage unavailable")
			failing := chunkLookup(func(h znn.Hash) (*Chunk, bool, error) {
				if h == second {
					return nil, false, failure
				}
				return chunks.Chunk(h)
			})
			plan, err := BuildPlan(cfg, mb.dm, failing)
			if plan != nil || !errors.Is(err, failure) || !strings.Contains(err.Error(), "momentum 12") || !strings.Contains(err.Error(), second.String()) {
				t.Fatalf("read error became an executable or invalid-message plan: plan=%v err=%v", plan, err)
			}
			// Neither partial assembly nor the failed attempt consumed a chunk.
			plan, err = BuildPlan(cfg, mb.dm, chunks)
			if err != nil || len(plan.Messages) != 1 || plan.Messages[0].Status != StatusIncluded {
				t.Fatalf("retry lost a valid assembly: plan=%+v err=%v", plan, err)
			}
			if active && len(plan.UsedChunks) != 2 {
				t.Fatalf("retry did not consume the two chunks exactly once: %+v", plan.UsedChunks)
			}
		})
	}
}

func TestMissingChunkRemainsAnInvalidMessage(t *testing.T) {
	cfg := testConfig()
	mb := newMomentum(12)
	mb.send(znn.Address{19: 9}, cfg.Inbox, znn.ZeroTokenStandard, 0, EncodeAssemble([]znn.Hash{{0: 1}}))
	plan, err := BuildPlan(cfg, mb.dm, fakeChunks{})
	if err != nil || plan == nil || plan.Messages[0].Status != StatusInvalid || !strings.Contains(plan.Messages[0].Reason, "unknown chunk") {
		t.Fatalf("genuine absence changed consensus handling: plan=%+v err=%v", plan, err)
	}
	plan, err = BuildPlan(cfg, mb.dm, chunkLookup(func(znn.Hash) (*Chunk, bool, error) { return nil, true, nil }))
	if err == nil || plan != nil {
		t.Fatal("an inconsistent stored-chunk result was accepted")
	}
}
