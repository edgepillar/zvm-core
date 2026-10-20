package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("l1-genesis", "write a NoM L1 genesis and node configs (chain 69 with dynamic plasma by default; -dynamic-plasma=false for the deprecated v1 ruleset)", runL1Genesis)
}

// The L1 is go-zenon's devnet shape cut down to one pillar and one RPC node,
// on its own subnet. It reuses the devnet's committed producer keystore and p2p
// keys (they are public), so the only new material is the genesis itself.
const (
	// zvm-fleet's devnet runs the deprecated version 1 network on 172.28.0.0/24
	// and the dynamic-plasma one on 172.27.0.0/24, so both rulesets can run at
	// once (DECISIONS.md D4). -subnet places the pillar anywhere else.
	v1Subnet   = "172.28.0"
	dpSubnet   = "172.27.0"
	pillarPeer = "16Uiu2HAmRe2RazMPxYEV1A8Vs7LbVfNVMqBdiw7zgSkBLB3E2vQv"
	pillarNode = "c0e8b1c4cffe16c4aa8d394655fd11a0548cab01281d2838c868cd3a12284717d1e66b410bde0d8aa76cb149fdb4dc252e932f4f92394d651e425628e8761971"
)

type genesisPillar struct {
	Name                         string   `json:"Name"`
	BlockProducingAddress        string   `json:"BlockProducingAddress"`
	RewardWithdrawAddress        string   `json:"RewardWithdrawAddress"`
	StakeAddress                 string   `json:"StakeAddress"`
	Amount                       *big.Int `json:"Amount"`
	RegistrationTime             int64    `json:"RegistrationTime"`
	RevokeTime                   int64    `json:"RevokeTime"`
	GiveBlockRewardPercentage    int      `json:"GiveBlockRewardPercentage"`
	GiveDelegateRewardPercentage int      `json:"GiveDelegateRewardPercentage"`
	PillarType                   int      `json:"PillarType"`
}

type genesisToken struct {
	Owner         string   `json:"owner"`
	TokenName     string   `json:"tokenName"`
	TokenSymbol   string   `json:"tokenSymbol"`
	TokenDomain   string   `json:"tokenDomain"`
	TotalSupply   *big.Int `json:"totalSupply"`
	MaxSupply     *big.Int `json:"maxSupply"`
	Decimals      int      `json:"decimals"`
	IsMintable    bool     `json:"isMintable"`
	IsBurnable    bool     `json:"isBurnable"`
	IsUtility     bool     `json:"isUtility"`
	TokenStandard string   `json:"tokenStandard"`
}

type genesisFusion struct {
	Owner              string   `json:"owner"`
	ID                 string   `json:"id"`
	Amount             *big.Int `json:"amount"`
	WithdrawHeight     uint64   `json:"withdrawHeight"`
	BeneficiaryAddress string   `json:"beneficiaryAddress"`
}

type genesisSpork struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Activated         bool   `json:"activated"`
	EnforcementHeight uint64 `json:"enforcementHeight"`
}

type genesisBlock struct {
	Address     string              `json:"Address"`
	BalanceList map[string]*big.Int `json:"BalanceList"`
}

type l1GenesisFile struct {
	ChainIdentifier     uint64 `json:"ChainIdentifier"`
	ExtraData           string `json:"ExtraData"`
	GenesisTimestampSec int64  `json:"GenesisTimestampSec"`
	SporkAddress        string `json:"SporkAddress"`
	PillarConfig        struct {
		Pillars       []genesisPillar `json:"Pillars"`
		Delegations   []any           `json:"Delegations"`
		LegacyEntries []any           `json:"LegacyEntries"`
	} `json:"PillarConfig"`
	TokenConfig struct {
		Tokens []genesisToken `json:"Tokens"`
	} `json:"TokenConfig"`
	PlasmaConfig struct {
		Fusions []genesisFusion `json:"Fusions"`
	} `json:"PlasmaConfig"`
	SwapConfig struct {
		Entries []any `json:"Entries"`
	} `json:"SwapConfig"`
	SporkConfig struct {
		Sporks []genesisSpork `json:"Sporks"`
	} `json:"SporkConfig"`
	GenesisBlocks struct {
		Blocks []genesisBlock `json:"Blocks"`
	} `json:"GenesisBlocks"`
}

var (
	pillarContract = "z1qxemdeddedxpyllarxxxxxxxxxxxxxxxsy3fmg"
	plasmaContract = "z1qxemdeddedxplasmaxxxxxxxxxxxxxxxxsctrp"
	tokenContract  = "z1qxemdeddedxt0kenxxxxxxxxxxxxxxxxh9amk0"
)

func buildL1Genesis(chainID uint64, dynamicPlasma bool, timestamp int64) (*l1GenesisFile, error) {
	extra := "ZVM L1 DEV-NET"
	if dynamicPlasma {
		extra = "ZVM L1 DEV-NET (dynamic plasma)"
	}
	g := &l1GenesisFile{
		ChainIdentifier:     chainID,
		ExtraData:           extra,
		GenesisTimestampSec: timestamp,
	}
	producer := devnet.Key(devnet.PillarProducer).Address.String()
	owner := devnet.Key(devnet.DevOwner).Address.String()
	g.SporkAddress = producer

	stake := devnet.Units(15_000)
	g.PillarConfig.Pillars = []genesisPillar{{
		Name: "zvm1", BlockProducingAddress: producer, RewardWithdrawAddress: owner, StakeAddress: owner,
		Amount: stake, GiveDelegateRewardPercentage: 100, PillarType: 1,
	}}
	g.PillarConfig.Delegations = []any{}
	g.PillarConfig.LegacyEntries = []any{}
	g.SwapConfig.Entries = []any{}

	// Sporks as the devnet has them. Dynamic plasma is the whole difference
	// between a v1 network (mainnet's rules, momentum version 1) and a v2 one:
	// activated at genesis, every momentum this network produces is v2 and
	// priced by the fee market, which is the second ruleset everything here
	// has to work under.
	dpDescription := "Dynamic Plasma, deliberately inactive: this network runs mainnet's rules"
	if dynamicPlasma {
		dpDescription = "Dynamic Plasma, active from genesis"
	}
	g.SporkConfig.Sporks = []genesisSpork{
		{"6d2b1e6cb4025f2f45533f0fe22e9b7ce2014d91cc960471045fa64eee5a6ba3", "az", "az", true, 0},
		{"ceb7e3808ef17ea910adda2f3ab547be4cdfb54de8400ce3683258d06be1354b", "htlc", "htlc", true, 0},
		{"ddd43466769461c5b5d109c639da0f50a7eeb96ad6e7274b1928a35c431d7b1b", "bridge-liq", "bridge-liq", false, 0},
		{"0000000000000000000000000000000000000000000000000000000000000001", "libp2p", "Activates the libp2p networking stack", true, 20},
		{"0000000000000000000000000000000000000000000000000000000000000002", "dynamic-plasma", dpDescription, dynamicPlasma, 0},
	}

	znnTotal, qsrTotal, fusedTotal := new(big.Int), new(big.Int), new(big.Int)
	for _, a := range devnet.L1Accounts() {
		addr := devnet.Key(a.Index).Address.String()
		bal := map[string]*big.Int{}
		if a.ZNN > 0 {
			bal[znn.ZNN.String()] = devnet.Units(a.ZNN)
			znnTotal.Add(znnTotal, bal[znn.ZNN.String()])
		}
		if a.QSR > 0 {
			bal[znn.QSR.String()] = devnet.Units(a.QSR)
			qsrTotal.Add(qsrTotal, bal[znn.QSR.String()])
		}
		if len(bal) > 0 {
			g.GenesisBlocks.Blocks = append(g.GenesisBlocks.Blocks, genesisBlock{Address: addr, BalanceList: bal})
		}
		if a.FuseQSR > 0 {
			amt := devnet.Units(a.FuseQSR)
			fusedTotal.Add(fusedTotal, amt)
			id := znn.Sha3([]byte("zvm-l1-fusion"), []byte(addr))
			g.PlasmaConfig.Fusions = append(g.PlasmaConfig.Fusions, genesisFusion{
				Owner: addr, ID: id.String(), Amount: amt, WithdrawHeight: 1, BeneficiaryAddress: addr,
			})
		}
	}
	g.GenesisBlocks.Blocks = append(g.GenesisBlocks.Blocks,
		genesisBlock{Address: pillarContract, BalanceList: map[string]*big.Int{znn.ZNN.String(): stake}},
		genesisBlock{Address: plasmaContract, BalanceList: map[string]*big.Int{znn.QSR.String(): fusedTotal}},
	)
	znnTotal.Add(znnTotal, stake)
	qsrTotal.Add(qsrTotal, fusedTotal)

	maxSupply := big.NewInt(9007199254740991)
	g.TokenConfig.Tokens = []genesisToken{
		{tokenContract, "ZNN", "ZNN", "zenon.devnet", znnTotal, maxSupply, 8, true, true, true, znn.ZNN.String()},
		{tokenContract, "QSR", "QSR", "zenon.devnet", qsrTotal, maxSupply, 8, true, true, true, znn.QSR.String()},
	}
	return g, nil
}

func nodeConfig(name string, producer bool, minPeers int, seeders, bootstrap []string) map[string]any {
	cfg := map[string]any{
		"DataPath":    "/root/.znn",
		"WalletPath":  "/root/.znn/wallet",
		"GenesisFile": "/root/.znn/genesis.json",
		"Name":        name,
		"LogLevel":    "info",
		"RPC": map[string]any{
			"EnableHTTP": true, "EnableWS": true,
			"HTTPHost": "0.0.0.0", "HTTPPort": 35997,
			"WSHost": "0.0.0.0", "WSPort": 35998,
			"Endpoints": []string{}, "HTTPVirtualHosts": []string{"*"},
			"HTTPCors": []string{"*"}, "WSOrigins": []string{"*"},
		},
		"Net": map[string]any{
			"ListenHost": "0.0.0.0", "ListenPort": 35995,
			"MinPeers": minPeers, "MinConnectedPeers": 1,
			"Seeders": seeders, "BootstrapPeers": bootstrap,
		},
	}
	if producer {
		addr := devnet.Key(devnet.PillarProducer).Address.String()
		cfg["Producer"] = map[string]any{"Address": addr, "Index": devnet.PillarProducer, "KeyFilePath": addr, "Password": "devnet"}
	}
	return cfg
}

// parseGenesisTimestamp reads -timestamp: empty is the committed constant,
// "now" is this moment rounded down to a momentum tick, and anything else is
// unix seconds.
func parseGenesisTimestamp(v string) (int64, error) {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "":
		return devnet.GenesisTimestampSec, nil
	case "now":
		return time.Now().Unix() / 10 * 10, nil
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("-timestamp %q: want unix seconds or \"now\"", v)
	}
	return ts, nil
}

func writeJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func runL1Genesis(args []string) error {
	fs := flag.NewFlagSet("l1-genesis", flag.ExitOnError)
	out := fs.String("out", "nom", "directory to write genesis.json and role directories into")
	devnetDir := fs.String("devnet", os.Getenv("GO_ZENON_DEVNET"), "go-zenon's docker/devnet, to take the producer keystore and p2p keys from (default $GO_ZENON_DEVNET)")
	chainID := fs.Uint64("chain-id", devnet.L1ChainID, "NoM chain identifier")
	dynamicPlasma := fs.Bool("dynamic-plasma", true, "activate the dynamic-plasma spork at genesis: every momentum is version 2 and priced (false: the deprecated version 1 ruleset)")
	name := fs.String("name", "zvm-l1", "container name prefix, used in the node configs")
	timestamp := fs.String("timestamp", "", "genesis timestamp: unix seconds, or `now` (default: the committed devnet constant). A genesis far in the past costs momentum cadence — see internal/devnet")
	subnet := fs.String("subnet", "", "the first three octets of the network the pillar is .10 on, e.g. 10.70.0 (default 172.27.0, or 172.28.0 with -dynamic-plasma=false)")
	fs.Parse(args)
	if *devnetDir == "" {
		return fmt.Errorf("-devnet: point it (or GO_ZENON_DEVNET) at a go-zenon checkout's docker/devnet")
	}

	ts, err := parseGenesisTimestamp(*timestamp)
	if err != nil {
		return err
	}

	if *subnet == "" {
		*subnet = dpSubnet
		if !*dynamicPlasma {
			*subnet = v1Subnet
		}
	}
	pillarIP := *subnet + ".10"

	g, err := buildL1Genesis(*chainID, *dynamicPlasma, ts)
	if err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(*out, "genesis.json"), g); err != nil {
		return err
	}

	producer := devnet.Key(devnet.PillarProducer).Address.String()
	for _, f := range [][2]string{
		{filepath.Join(*devnetDir, "pillar", "wallet", producer), filepath.Join(*out, "pillar", "wallet", producer)},
		{filepath.Join(*devnetDir, "pillar", "network-private-key"), filepath.Join(*out, "pillar", "network-private-key")},
		{filepath.Join(*devnetDir, "rpc", "network-private-key"), filepath.Join(*out, "rpc", "network-private-key")},
	} {
		if err := copyFile(f[0], f[1]); err != nil {
			return fmt.Errorf("copying %s: %w", f[0], err)
		}
	}

	pillarEnode := fmt.Sprintf("enode://%s@%s:35995", pillarNode, pillarIP)
	pillarAddr := fmt.Sprintf("/ip4/%s/tcp/35995/p2p/%s", pillarIP, pillarPeer)
	if err := writeJSONFile(filepath.Join(*out, "pillar", "config.json"),
		nodeConfig(*name+"-pillar", true, 0, []string{}, []string{})); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(*out, "rpc", "config.json"),
		nodeConfig(*name+"-rpc", false, 1, []string{pillarEnode}, []string{pillarAddr})); err != nil {
		return err
	}

	var fused int64
	for _, f := range g.PlasmaConfig.Fusions {
		fused += new(big.Int).Div(f.Amount, znn.OneQSR).Int64()
	}
	fmt.Printf("genesis timestamp %d (%s)\n", ts, time.Unix(ts, 0).UTC().Format(time.RFC3339))
	fmt.Printf("wrote %s: chain %d, dynamic plasma %t, %d allocations, %d fusions (%d QSR), ZNN supply %s, QSR supply %s\n",
		*out, g.ChainIdentifier, *dynamicPlasma, len(g.GenesisBlocks.Blocks), len(g.PlasmaConfig.Fusions), fused,
		strings.TrimSuffix(new(big.Int).Div(g.TokenConfig.Tokens[0].TotalSupply, znn.OneZNN).String(), ""),
		new(big.Int).Div(g.TokenConfig.Tokens[1].TotalSupply, znn.OneQSR).String())
	return nil
}
