// Package ethrpc dials the ZVM's JSON-RPC over a connection pool.
//
// Go's default transport keeps two idle connections per host, so a service
// making a few hundred concurrent calls opens and closes a socket for each one
// and runs its container out of ephemeral ports. The load generator was given
// a pool for that reason; the long-running services were not, and the relayer
// then hit the same wall from the other side — 513 submissions refused with
// "cannot assign requested address" at 600 tx/s from 100,000 wallets, measured
// on chain 70 on 2026-09-17. Everything that talks to an execution client for
// a living dials through here.
package ethrpc

import (
	"context"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// PooledTransport keeps enough idle connections for load.
func PooledTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 4096
	t.MaxIdleConnsPerHost = 1024
	t.IdleConnTimeout = 90 * time.Second
	return t
}

// PooledHTTP is an HTTP client over PooledTransport.
func PooledHTTP(timeout time.Duration) *http.Client {
	return &http.Client{Transport: PooledTransport(), Timeout: timeout}
}

// Dial connects to a JSON-RPC endpoint over a pooled HTTP client. A ws:// or
// ipc:// endpoint has no such pool to configure, so it is dialled as it comes.
func Dial(ctx context.Context, url string) (*ethclient.Client, error) {
	if len(url) >= 4 && (url[:4] == "http") {
		c, err := rpc.DialOptions(ctx, url, rpc.WithHTTPClient(PooledHTTP(2*time.Minute)))
		if err != nil {
			return nil, err
		}
		return ethclient.NewClient(c), nil
	}
	return ethclient.DialContext(ctx, url)
}
