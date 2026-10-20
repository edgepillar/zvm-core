package znn

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
)

// Account publishes blocks for one key.
//
// It chains locally: after a publish it remembers the block it just made and
// builds the next one on top of it, so a burst of blocks does not wait a
// momentum per link. The node accepts blocks on top of unconfirmed ones (up to
// 500 per account). If a publish is refused the local chain is forgotten and
// re-read from the node on the next call, because the refused block's height
// was never taken.
type Account struct {
	Key *KeyPair
	// Signer, when set, signs instead of Key: a committee quorum holds the
	// account and no process holds its private key.
	Signer  BlockSigner
	Client  *Client
	ChainID uint64

	// AssumeFused skips the node's plasma quote for sends to non-embedded
	// addresses: fused plasma is set to the base plasma computed locally.
	// Only correct for accounts with plasma to spare, which is every service
	// account the ZVM runs.
	AssumeFused bool

	// AutoRebid re-bids a wedged block automatically: when the network's price
	// has risen above what this account last paid, the next publish first
	// replaces the oldest unconfirmed block at the current price. Defaults on,
	// because the failure it prevents is silent — a wedged account's blocks are
	// accepted by the node and simply never confirm.
	AutoRebid bool

	mu        sync.Mutex
	loaded    bool
	prev      HashHeight
	paidPrice uint64 // the price the last block this account published met
	rebidAt   uint64 // the momentum a rebid was last attempted at
}

// BlockSigner signs a fully built account block: it sets Hash, PublicKey and
// Signature. It receives the whole block, not a hash, so that a signer can
// check what it is being asked to authorise.
type BlockSigner interface {
	Address() Address
	SignBlock(ctx context.Context, b *AccountBlock) error
}

func NewAccount(key *KeyPair, client *Client, chainID uint64) *Account {
	return &Account{Key: key, Client: client, ChainID: chainID, AutoRebid: true}
}

func NewSignerAccount(signer BlockSigner, client *Client, chainID uint64) *Account {
	return &Account{Signer: signer, Client: client, ChainID: chainID, AutoRebid: true}
}

func (a *Account) Address() Address {
	if a.Signer != nil {
		return a.Signer.Address()
	}
	return a.Key.Address
}

// Reset forgets the locally chained frontier.
func (a *Account) Reset() {
	a.mu.Lock()
	a.loaded = false
	a.mu.Unlock()
}

// FeeFunc decides the value a send carries, after its plasma is known and
// before it is signed. It is how a native call pays the burned fee: the amount
// is part of the block hash, and the fee depends on the plasma the block
// actually pays, so this is the only point at which both are settled. A nil or
// zero amount leaves the block unchanged.
type FeeFunc func(b *AccountBlock, frontier *Momentum) (*big.Int, TokenStandard)

// Send publishes a user send.
func (a *Account) Send(ctx context.Context, to Address, zts TokenStandard, amount *big.Int, data []byte) (*AccountBlock, error) {
	return a.SendFee(ctx, to, zts, amount, data, nil)
}

// SendFee publishes a user send whose value a fee function decides.
func (a *Account) SendFee(ctx context.Context, to Address, zts TokenStandard, amount *big.Int, data []byte, fee FeeFunc) (*AccountBlock, error) {
	if len(data) > MaxDataLength {
		return nil, fmt.Errorf("data is %d bytes, the limit is %d", len(data), MaxDataLength)
	}
	return a.publish(ctx, &AccountBlock{
		BlockType:     BlockTypeUserSend,
		ToAddress:     to,
		TokenStandard: zts,
		Amount:        NewBigInt(amount),
		Data:          data,
	}, fee)
}

// Receive publishes a receive for an unreceived send.
func (a *Account) Receive(ctx context.Context, fromBlock Hash) (*AccountBlock, error) {
	return a.publish(ctx, &AccountBlock{
		BlockType:     BlockTypeUserReceive,
		FromBlockHash: fromBlock,
		Amount:        BigIntFromUint64(0),
	}, nil)
}

func (a *Account) publish(ctx context.Context, b *AccountBlock, fee FeeFunc) (*AccountBlock, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.publishLocked(ctx, b, fee)
}

// publishLocked is publish with a.mu already held.
//
// It is split out for one reason: the re-bid path below rebuilds the block and
// has to try again, and calling publish for that would take a.mu a second time
// on the same goroutine. **sync.Mutex is not reentrant**, so that deadlocked
// the account permanently — and a mutex deadlock is not cancellable, so the
// context deadline the caller set could not break it either.
//
// It only ever fired on a chain with dynamic plasma, because the branch needs
// the price to have risen above what this account last paid, and only under
// enough load to move the price. That is why it hid: chain 70 cannot reach it,
// and on chain 71 it took offering the native lane more than it could carry.
// Measured before the fix: a native run at 15 tx/s hung indefinitely, while the
// same run at 5 tx/s finished in 40 s.
func (a *Account) publishLocked(ctx context.Context, b *AccountBlock, fee FeeFunc) (*AccountBlock, error) {
	if !a.loaded {
		fb, err := a.Client.FrontierAccountBlock(ctx, a.Address())
		if err != nil {
			return nil, err
		}
		a.prev = HashHeight{}
		if fb != nil {
			a.prev = HashHeight{Hash: fb.Hash, Height: fb.Height}
		}
		a.loaded = true
	}
	m, err := a.Client.FrontierMomentum(ctx)
	if err != nil {
		return nil, err
	}
	b.Version = 1
	b.ChainIdentifier = a.ChainID
	b.Address = a.Address()
	b.PreviousHash = a.prev.Hash
	b.Height = a.prev.Height + 1
	b.MomentumAcknowledged = HashHeight{Hash: m.Hash, Height: m.Height}
	if b.DescendantBlocks == nil {
		b.DescendantBlocks = []*AccountBlock{}
	}
	if b.Amount == nil {
		b.Amount = BigIntFromUint64(0)
	}

	// What a block must pay is its base plasma times the network's current
	// price. On a network without dynamic plasma the price is the minimum, so
	// this is base plasma and nothing changes; on one with it, paying base
	// plasma alone is what wedges an account.
	price := m.FusionPrice()
	// A block signed at yesterday's price is not refused, it is stranded, and
	// every block after it on this account with it. If the price has moved past
	// what this account last paid, clear the wedge before adding to the queue.
	if a.AutoRebid && a.paidPrice != 0 && price > a.paidPrice && m.Height != a.rebidAt {
		a.rebidAt = m.Height
		if bid, err := a.rebidLocked(ctx, m); err != nil {
			return nil, err
		} else if bid != nil {
			// The chain was rebuilt under us; this block must be rebuilt too.
			// publishLocked, not publish: we already hold a.mu.
			return a.publishLocked(ctx, b, fee)
		}
	}
	if a.AssumeFused && b.BlockType == BlockTypeUserSend && !b.ToAddress.IsEmbedded() {
		b.BasePlasma = BaseSendPlasma(len(b.Data))
		b.FusedPlasma = RequiredFusedPlasma(b.BasePlasma, price)
	} else {
		q, err := a.Client.RequiredPoW(ctx, RequiredPoWParam{
			Address:   b.Address,
			BlockType: b.BlockType,
			ToAddress: b.ToAddress,
			Data:      b.Data,
		})
		if err != nil {
			return nil, err
		}
		b.BasePlasma = q.BasePlasma
		if q.RequiredDifficulty == 0 {
			b.FusedPlasma = RequiredFusedPlasma(q.BasePlasma, price)
		} else {
			b.FusedPlasma = q.AvailablePlasma
			b.Difficulty = q.RequiredDifficulty
			nonce, err := GeneratePoW(ctx, b.Difficulty, PoWDataHash(b.Address, b.PreviousHash))
			if err != nil {
				return nil, err
			}
			b.Nonce = nonce
		}
	}
	b.UsedPlasma = b.BasePlasma
	if fee != nil && b.BlockType == BlockTypeUserSend && b.AmountBig().Sign() == 0 {
		if amount, zts := fee(b, m); amount != nil && amount.Sign() > 0 {
			b.Amount, b.TokenStandard = NewBigInt(amount), zts
		}
	}
	if a.Signer != nil {
		if err := a.Signer.SignBlock(ctx, b); err != nil {
			a.loaded = false
			return nil, err
		}
	} else {
		b.Sign(a.Key)
	}

	if err := a.Client.Publish(ctx, b); err != nil {
		a.loaded = false
		return nil, err
	}
	a.prev = HashHeight{Hash: b.Hash, Height: b.Height}
	a.paidPrice = price
	return b, nil
}

// ErrNotConfirmed is returned by WaitConfirmed when the context ends first.
var ErrNotConfirmed = errors.New("account block not confirmed")

// Rebid re-publishes this account's oldest unconfirmed block at the price the
// network is asking now.
//
// It exists because of how dynamic plasma fails. A block commits to the price
// it was signed at; if the momentum it was meant for filled up, the price rises
// and go-zenon's ValidPrice then refuses it — but it is not dropped. It sits
// unconfirmed, every later block on the account builds on it, and the account
// is frozen until the price decays back down, which under sustained load it
// never does (zenon-docs/protocol/facts/plasma-wedging.md). go-zenon's account
// pool accepts a replacement at an occupied height if it pays more, and that is
// the only way out.
//
// Everything queued behind the wedged block is re-chained onto it, at the same
// price: a replacement changes the block's hash, so every later block on the
// account — which committed to the old hash as its parent — would otherwise be
// dropped with it. Measured on a v2 devnet before this re-chained: rebidding
// the oldest of 24 queued blocks left the account with one.
//
// Two things a caller must still know. **Every hash changes**, so anything that
// remembered one — a derived L2 transaction hash, a payout record — has to be
// re-read from what this returns. And a replacement is per node: the pillar may
// still commit the original, so both bids have to be watched.
//
// Returns the new first block, or nil when nothing is unconfirmed or the oldest
// unconfirmed block already meets the current price.
func (a *Account) Rebid(ctx context.Context) (*AccountBlock, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := a.Client.FrontierMomentum(ctx)
	if err != nil {
		return nil, err
	}
	return a.rebidLocked(ctx, m)
}

func (a *Account) rebidLocked(ctx context.Context, m *Momentum) (*AccountBlock, error) {
	unconfirmed, err := a.Client.UnconfirmedBlocks(ctx, a.Address(), 0, 50)
	if err != nil {
		return nil, err
	}
	if unconfirmed == nil || len(unconfirmed.List) == 0 {
		return nil, nil
	}
	oldest := unconfirmed.List[0]
	for _, b := range unconfirmed.List {
		if b.Height < oldest.Height {
			oldest = b
		}
	}
	base := oldest.BasePlasma
	if base == 0 {
		base = BaseSendPlasma(len(oldest.Data))
	}
	if oldest.FusedPlasma+DifficultyToPlasma(oldest.Difficulty) >= RequiredFusedPlasma(base, m.FusionPrice()) {
		return nil, nil // not wedged: it already pays what the network asks
	}

	// The wedged block and everything queued behind it, re-signed at the
	// current price and re-chained: each block's parent hash changes, so the
	// whole tail has to be rebuilt or the node drops it.
	queue := make([]*AccountBlock, 0, len(unconfirmed.List))
	for _, b := range unconfirmed.List {
		if b.Height >= oldest.Height {
			queue = append(queue, b)
		}
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].Height < queue[j].Height })

	var first *AccountBlock
	prev := oldest.PreviousHash
	for _, old := range queue {
		obase := old.BasePlasma
		if obase == 0 {
			obase = BaseSendPlasma(len(old.Data))
		}
		bid := &AccountBlock{
			Version:              1,
			ChainIdentifier:      a.ChainID,
			BlockType:            old.BlockType,
			PreviousHash:         prev,
			Height:               old.Height,
			MomentumAcknowledged: HashHeight{Hash: m.Hash, Height: m.Height},
			Address:              old.Address,
			ToAddress:            old.ToAddress,
			Amount:               old.Amount,
			TokenStandard:        old.TokenStandard,
			FromBlockHash:        old.FromBlockHash,
			DescendantBlocks:     []*AccountBlock{},
			Data:                 old.Data,
			BasePlasma:           obase,
			FusedPlasma:          RequiredFusedPlasma(obase, m.FusionPrice()),
			UsedPlasma:           obase,
		}
		if bid.Amount == nil {
			bid.Amount = BigIntFromUint64(0)
		}
		if a.Signer != nil {
			if err := a.Signer.SignBlock(ctx, bid); err != nil {
				return first, err
			}
		} else {
			bid.Sign(a.Key)
		}
		if err := a.Client.Publish(ctx, bid); err != nil {
			a.loaded = false
			return first, fmt.Errorf("rebidding height %d at price %d: %w", bid.Height, m.FusionPrice(), err)
		}
		prev = bid.Hash
		if first == nil {
			first = bid
		}
		a.prev = HashHeight{Hash: bid.Hash, Height: bid.Height}
	}
	bid := first
	a.loaded = true
	a.paidPrice = m.FusionPrice()
	return bid, nil
}
