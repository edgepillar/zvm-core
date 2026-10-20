package znn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync/atomic"
	"time"
)

// Client is a minimal go-zenon JSON-RPC client over HTTP. It carries only the
// calls the ZVM uses, typed against the node's own JSON shapes.
type Client struct {
	url  string
	http *http.Client
	id   atomic.Uint64
}

func NewClient(url string) *Client {
	return &Client{
		url: url,
		http: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{MaxIdleConnsPerHost: 128, MaxConnsPerHost: 256},
		},
	}
}

func (c *Client) URL() string { return c.url }

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// Call invokes method and decodes the result into out (which may be nil).
func (c *Client) Call(ctx context.Context, out any, method string, params ...any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      c.id.Add(1),
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return fmt.Errorf("%s: encoding request: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	defer resp.Body.Close()
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("%s: decoding response (HTTP %d): %w", method, resp.StatusCode, err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("%s: %w", method, envelope.Error)
	}
	if out == nil || len(envelope.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, out); err != nil {
		return fmt.Errorf("%s: decoding result: %w", method, err)
	}
	return nil
}

func (c *Client) FrontierMomentum(ctx context.Context) (*Momentum, error) {
	var m *Momentum
	if err := c.Call(ctx, &m, "ledger.getFrontierMomentum"); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("ledger.getFrontierMomentum: empty result")
	}
	return m, nil
}

// DetailedMomentums returns up to count momentums (count ≤ 1024) from height,
// each with its account blocks.
func (c *Client) DetailedMomentums(ctx context.Context, height, count uint64) ([]*DetailedMomentum, error) {
	var res struct {
		Count uint64              `json:"count"`
		List  []*DetailedMomentum `json:"list"`
	}
	if err := c.Call(ctx, &res, "ledger.getDetailedMomentumsByHeight", height, count); err != nil {
		return nil, err
	}
	return res.List, nil
}

// FrontierAccountBlock returns the account's latest block, or nil for an
// account that has never published.
func (c *Client) FrontierAccountBlock(ctx context.Context, addr Address) (*AccountBlock, error) {
	var b *AccountBlock
	if err := c.Call(ctx, &b, "ledger.getFrontierAccountBlock", addr); err != nil {
		return nil, err
	}
	return b, nil
}

func (c *Client) AccountBlockByHash(ctx context.Context, h Hash) (*AccountBlock, error) {
	var b *AccountBlock
	if err := c.Call(ctx, &b, "ledger.getAccountBlockByHash", h); err != nil {
		return nil, err
	}
	return b, nil
}

type BlockList struct {
	Count uint64          `json:"count"`
	List  []*AccountBlock `json:"list"`
	More  bool            `json:"more"`
}

func (c *Client) AccountBlocksByHeight(ctx context.Context, addr Address, height, count uint64) (*BlockList, error) {
	var res BlockList
	if err := c.Call(ctx, &res, "ledger.getAccountBlocksByHeight", addr, height, count); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) UnreceivedBlocks(ctx context.Context, addr Address, page, size uint32) (*BlockList, error) {
	var res BlockList
	if err := c.Call(ctx, &res, "ledger.getUnreceivedBlocksByAddress", addr, page, size); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) UnconfirmedBlocks(ctx context.Context, addr Address, page, size uint32) (*BlockList, error) {
	var res BlockList
	if err := c.Call(ctx, &res, "ledger.getUnconfirmedBlocksByAddress", addr, page, size); err != nil {
		return nil, err
	}
	return &res, nil
}

type BalanceInfo struct {
	Balance *BigInt `json:"balance"`
}

type AccountInfo struct {
	Address        Address                `json:"address"`
	AccountHeight  uint64                 `json:"accountHeight"`
	BalanceInfoMap map[string]BalanceInfo `json:"balanceInfoMap"`
}

func (i *AccountInfo) Balance(zts TokenStandard) *big.Int {
	if i == nil {
		return new(big.Int)
	}
	if b, ok := i.BalanceInfoMap[zts.String()]; ok {
		return b.Balance.Big()
	}
	return new(big.Int)
}

func (c *Client) AccountInfo(ctx context.Context, addr Address) (*AccountInfo, error) {
	var res AccountInfo
	if err := c.Call(ctx, &res, "ledger.getAccountInfoByAddress", addr); err != nil {
		return nil, err
	}
	return &res, nil
}

type RequiredPoWParam struct {
	Address   Address `json:"address"`
	BlockType uint64  `json:"blockType"`
	ToAddress Address `json:"toAddress"`
	Data      []byte  `json:"data"`
}

type RequiredPoW struct {
	AvailablePlasma    uint64 `json:"availablePlasma"`
	BasePlasma         uint64 `json:"basePlasma"`
	RequiredDifficulty uint64 `json:"requiredDifficulty"`
}

func (c *Client) RequiredPoW(ctx context.Context, p RequiredPoWParam) (*RequiredPoW, error) {
	var res RequiredPoW
	if err := c.Call(ctx, &res, "embedded.plasma.getRequiredPoWForAccountBlock", p); err != nil {
		return nil, err
	}
	return &res, nil
}

type PlasmaInfo struct {
	CurrentPlasma uint64  `json:"currentPlasma"`
	MaxPlasma     uint64  `json:"maxPlasma"`
	QsrAmount     *BigInt `json:"qsrAmount"`
}

func (c *Client) PlasmaInfo(ctx context.Context, addr Address) (*PlasmaInfo, error) {
	var res PlasmaInfo
	if err := c.Call(ctx, &res, "embedded.plasma.get", addr); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) Publish(ctx context.Context, b *AccountBlock) error {
	return c.Call(ctx, nil, "ledger.publishRawTransaction", b)
}

type SyncInfo struct {
	State         uint64 `json:"state"`
	CurrentHeight uint64 `json:"currentHeight"`
	TargetHeight  uint64 `json:"targetHeight"`
}

func (c *Client) SyncInfo(ctx context.Context) (*SyncInfo, error) {
	var res SyncInfo
	if err := c.Call(ctx, &res, "stats.syncInfo"); err != nil {
		return nil, err
	}
	return &res, nil
}

// TokenInfo is embedded.token.getByZts, for the fields the fee schedule needs.
type TokenInfo struct {
	Name          string        `json:"name"`
	Symbol        string        `json:"symbol"`
	Decimals      uint64        `json:"decimals"`
	TotalSupply   *BigInt       `json:"totalSupply"`
	MaxSupply     *BigInt       `json:"maxSupply"`
	TokenStandard TokenStandard `json:"tokenStandard"`
}

func (c *Client) TokenInfo(ctx context.Context, zts TokenStandard) (*TokenInfo, error) {
	var res TokenInfo
	if err := c.Call(ctx, &res, "embedded.token.getByZts", zts.String()); err != nil {
		return nil, err
	}
	return &res, nil
}

// MomentumsByHeight returns up to count momentum headers from height upwards.
func (c *Client) MomentumsByHeight(ctx context.Context, height, count uint64) ([]*Momentum, error) {
	var res struct {
		List []*Momentum `json:"list"`
	}
	if err := c.Call(ctx, &res, "ledger.getMomentumsByHeight", height, count); err != nil {
		return nil, err
	}
	return res.List, nil
}

// MomentumByHeight returns one momentum's header.
func (c *Client) MomentumByHeight(ctx context.Context, height uint64) (*Momentum, error) {
	var res struct {
		List []*Momentum `json:"list"`
	}
	if err := c.Call(ctx, &res, "ledger.getMomentumsByHeight", height, 1); err != nil {
		return nil, err
	}
	if len(res.List) != 1 {
		return nil, fmt.Errorf("momentum %d not found", height)
	}
	return res.List[0], nil
}
