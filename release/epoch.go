package release

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Zenoglyphs-VM/zvm-core/l2"
)

type DeploymentBindings struct {
	Schema    int        `json:"schema"`
	Contracts []Contract `json:"contracts"`
}

func readPin(root *os.Root, pin File, limit int64) ([]byte, error) {
	if pin.Bytes > limit {
		return nil, errors.New("epoch input exceeds its byte limit")
	}
	f, err := openFile(root, pin.Repository+"/"+pin.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, pin.Bytes+1))
	if err != nil || int64(len(raw)) != pin.Bytes || digest(raw) != pin.SHA256 {
		return nil, errors.New("epoch input changed or has the wrong digest")
	}
	return raw, nil
}

func genesisHash(g *core.Genesis) (hash common.Hash, err error) {
	defer func() {
		if recover() != nil {
			hash = common.Hash{}
			err = errors.New("invalid L2 genesis")
		}
	}()
	return g.ToBlock().Hash(), nil
}

// VerifyEpochFiles binds configuration, the L2 genesis construction and
// declared runtime bytecode. The L1 genesis block hash still requires an
// independently qualified NoM implementation/runtime observation.
func (m Manifest) VerifyEpochFiles(directory string) error {
	if err := m.validate(); err != nil {
		return err
	}
	root, err := openDirectory(directory)
	if err != nil {
		return errors.New("epoch file root could not be opened")
	}
	defer root.Close()
	byID, byKind := map[string]File{}, map[string]File{}
	for _, f := range m.Files {
		byID[f.ID] = f
		byKind[f.Kind] = f
	}
	raw, err := readPin(root, byKind["rollup"], MaxDocumentBytes)
	if err != nil {
		return err
	}
	cfg, err := m.BindConfiguration(raw)
	if err != nil {
		return err
	}
	raw, err = readPin(root, byKind["l2-genesis"], 16<<20)
	if err != nil {
		return err
	}
	var g core.Genesis
	if json.Unmarshal(raw, &g) != nil || g.Config == nil || !reflect.DeepEqual(g.Config, l2.ChainConfig(cfg)) {
		return errors.New("L2 genesis execution rules disagree with the rollup")
	}
	expected, err := l2.BuildGenesis(cfg, cfg.L2GenesisTimestamp)
	if err != nil {
		return errors.New("supported genesis construction failed")
	}
	actualHash, err := genesisHash(&g)
	if err != nil {
		return err
	}
	if actualHash != cfg.L2GenesisHash || actualHash != expected.ToBlock().Hash() {
		return errors.New("L2 genesis block hash disagrees with the rollup or supported construction")
	}
	raw, err = readPin(root, byKind["deployments"], MaxDocumentBytes)
	if err != nil {
		return err
	}
	var deployment DeploymentBindings
	if decode(raw, &deployment) != nil || deployment.Schema != Schema {
		return errors.New("invalid pinned deployment bindings")
	}
	declared := slices.Clone(m.Contracts)
	slices.SortFunc(declared, func(a, b Contract) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(deployment.Contracts, func(a, b Contract) int { return strings.Compare(a.ID, b.ID) })
	a, _ := json.Marshal(declared)
	b, _ := json.Marshal(deployment.Contracts)
	if !bytes.Equal(a, b) {
		return errors.New("deployment bindings disagree with the manifest")
	}
	for _, c := range m.Contracts {
		raw, err := readPin(root, byID[c.RuntimeFile], 8<<20)
		if err != nil {
			return err
		}
		text := strings.TrimSpace(string(raw))
		text = strings.TrimPrefix(text, "0x")
		code, err := hex.DecodeString(text)
		if err != nil || len(code) == 0 || strings.ToLower(crypto.Keccak256Hash(code).Hex()) != c.RuntimeCodeHash {
			return errors.New("contract runtime-code hash mismatch")
		}
		// Genesis predeploys also have to be the code the L2 genesis carries.
		if account, ok := g.Alloc[common.HexToAddress(c.Address)]; ok && !bytes.Equal(account.Code, code) {
			return errors.New("declared predeploy code disagrees with genesis")
		}
	}
	return nil
}
