package release

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// ChainTargets supplies the primary and independently selected witness for each
// layer and the heights to compare. Endpoints are provisioned by the observer.
type ChainTargets struct {
	L1, L2             [2]string
	L1Height, L2Height uint64
}

type ObservedBlock struct {
	Height uint64 `json:"height"`
	Hash   string `json:"hash"`
}

// ChainObservation records agreement at specific heights, bound to the signed
// manifest. Image, process and finality acceptance use separate evidence.
type ChainObservation struct {
	ManifestSHA256    string        `json:"manifestSha256"`
	EpochSHA256       string        `json:"epochSha256"`
	TrustedSignatures int           `json:"trustedSignatures"`
	L1                ObservedBlock `json:"l1"`
	L2                ObservedBlock `json:"l2"`
	VerifiedContracts int           `json:"verifiedContracts"`
}

type chainTransport struct {
	*http.Transport
}

func (t chainTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.Transport.RoundTrip(req)
	if err == nil {
		response.Body = http.MaxBytesReader(nil, response.Body, 8<<20)
	}
	return response, err
}

func observerEndpoints(endpoints [2]string) error {
	var authorities [2]string
	for i, endpoint := range endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" ||
			u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("chain observers require explicit HTTP or HTTPS endpoints without URL credentials, queries or fragments")
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		authorities[i] = strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")) + "/" + port
	}
	if authorities[0] == authorities[1] {
		return errors.New("chain observer and witness must use distinct endpoint authorities")
	}
	return nil
}

func readNoMMomentum(ctx context.Context, client *rpc.Client, chain string, height uint64) (string, error) {
	var result struct {
		List []*struct {
			Hash            znn.Hash `json:"hash"`
			Height          uint64   `json:"height"`
			ChainIdentifier uint64   `json:"chainIdentifier"`
		} `json:"list"`
	}
	err := client.CallContext(ctx, &result, "ledger.getMomentumsByHeight", height, uint64(1))
	if err != nil || len(result.List) != 1 || result.List[0] == nil {
		return "", errors.New("NoM momentum observation was unavailable")
	}
	momentum := result.List[0]
	if momentum.Height != height || strconv.FormatUint(momentum.ChainIdentifier, 10) != chain || momentum.Hash == (znn.Hash{}) {
		return "", errors.New("NoM momentum has an unexpected chain, height or hash")
	}
	return "0x" + momentum.Hash.String(), nil
}

func readL2Block(ctx context.Context, client *ethclient.Client, height uint64) (common.Hash, error) {
	header, err := client.HeaderByNumber(ctx, new(big.Int).SetUint64(height))
	if err != nil || header == nil || header.Number == nil || !header.Number.IsUint64() || header.Number.Uint64() != height {
		return common.Hash{}, errors.New("execution block observation was unavailable at the requested height")
	}
	return header.Hash(), nil
}

func (m Manifest) observeNoM(ctx context.Context, clients [2]*rpc.Client, height uint64) (ObservedBlock, error) {
	var commonHash string
	for i, client := range clients {
		genesis, err := readNoMMomentum(ctx, client, m.Epoch.L1ChainID, 1)
		if err != nil || genesis != m.Epoch.L1GenesisHash {
			return ObservedBlock{}, fmt.Errorf("L1 endpoint %d did not establish the signed genesis", i+1)
		}
		hash, err := readNoMMomentum(ctx, client, m.Epoch.L1ChainID, height)
		if err != nil {
			return ObservedBlock{}, fmt.Errorf("L1 endpoint %d did not establish the requested momentum", i+1)
		}
		if i > 0 && hash != commonHash {
			return ObservedBlock{}, errors.New("L1 endpoints disagree at the requested height")
		}
		commonHash = hash
	}
	return ObservedBlock{Height: height, Hash: commonHash}, nil
}

func (m Manifest) observeExecution(ctx context.Context, clients [2]*rpc.Client, height uint64) (ObservedBlock, error) {
	var block common.Hash
	for i, client := range clients {
		eth := ethclient.NewClient(client)
		chain, err := eth.ChainID(ctx)
		if err != nil || chain == nil || chain.String() != m.Epoch.L2ChainID {
			return ObservedBlock{}, fmt.Errorf("L2 endpoint %d did not establish the signed chain ID", i+1)
		}
		genesis, err := readL2Block(ctx, eth, 0)
		if err != nil || genesis.Hex() != m.Epoch.L2GenesisHash {
			return ObservedBlock{}, fmt.Errorf("L2 endpoint %d did not establish the signed genesis", i+1)
		}
		observed, err := readL2Block(ctx, eth, height)
		if err != nil {
			return ObservedBlock{}, fmt.Errorf("L2 endpoint %d did not establish the requested block", i+1)
		}
		if i > 0 && observed != block {
			return ObservedBlock{}, errors.New("L2 endpoints disagree at the requested height")
		}
		block = observed
	}
	at := rpc.BlockNumberOrHashWithHash(block, true)
	for i, client := range clients {
		for _, contract := range m.Contracts {
			var code hexutil.Bytes
			err := client.CallContext(ctx, &code, "eth_getCode", common.HexToAddress(contract.Address), at)
			if err != nil || len(code) == 0 || crypto.Keccak256Hash(code).Hex() != contract.RuntimeCodeHash {
				return ObservedBlock{}, fmt.Errorf("L2 endpoint %d did not establish the signed runtime code for %s", i+1, contract.ID)
			}
		}
	}
	for i, client := range clients {
		end, err := readL2Block(ctx, ethclient.NewClient(client), height)
		if err != nil || end != block {
			return ObservedBlock{}, fmt.Errorf("L2 endpoint %d changed the observed block during verification", i+1)
		}
	}
	return ObservedBlock{Height: height, Hash: block.Hex()}, nil
}

// ObserveChain verifies the release signature quorum before contacting the
// operator-selected RPC endpoints. Only chain identity and state reads are used.
func (m Manifest) ObserveChain(parent context.Context, p Policy, s Signatures, k TrustedKeys, targets ChainTargets) (ChainObservation, error) {
	var result ChainObservation
	count, err := m.VerifySignatures(p, s, k)
	if err != nil {
		return result, err
	}
	if targets.L1Height < 2 || targets.L2Height == 0 {
		return result, errors.New("chain observation requires a post-genesis height on both layers")
	}
	if err := observerEndpoints(targets.L1); err != nil {
		return result, err
	}
	if err := observerEndpoints(targets.L2); err != nil {
		return result, err
	}
	manifest, err := m.Fingerprint()
	if err != nil {
		return result, err
	}
	epoch, err := m.EpochFingerprint()
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	transport := chainTransport{&http.Transport{MaxResponseHeaderBytes: 64 << 10}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	dial := func(endpoints [2]string) ([2]*rpc.Client, error) {
		var clients [2]*rpc.Client
		for i, endpoint := range endpoints {
			client, err := rpc.DialOptions(ctx, endpoint, rpc.WithHTTPClient(httpClient))
			if err != nil {
				return clients, errors.New("could not open a chain observer endpoint")
			}
			clients[i] = client
			// HTTP clients share the transport closed by ObserveChain.
		}
		return clients, nil
	}
	l1, err := dial(targets.L1)
	if err != nil {
		return result, err
	}
	l2, err := dial(targets.L2)
	if err != nil {
		return result, err
	}
	for _, client := range append(l1[:], l2[:]...) {
		defer client.Close()
	}
	before, err := m.observeNoM(ctx, l1, targets.L1Height)
	if err != nil {
		return result, err
	}
	execution, err := m.observeExecution(ctx, l2, targets.L2Height)
	if err != nil {
		return result, err
	}
	after, err := m.observeNoM(ctx, l1, targets.L1Height)
	if err != nil {
		return result, err
	}
	if before != after {
		return result, errors.New("L1 endpoints changed the observed momentum during verification")
	}
	return ChainObservation{
		ManifestSHA256: manifest, EpochSHA256: epoch, TrustedSignatures: count,
		L1: before, L2: execution, VerifiedContracts: len(m.Contracts),
	}, nil
}
