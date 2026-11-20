package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
)

const nodeEpochSchema = 1

type nodeEpochObservation struct {
	Schema             int    `json:"schema"`
	L1ChainID          string `json:"l1ChainId"`
	L2ChainID          string `json:"l2ChainId"`
	L2GenesisHash      string `json:"l2GenesisHash"`
	LoadedRollupSHA256 string `json:"loadedRollupSha256"`
}

func (m Manifest) expectedNodeEpoch(directory string) (nodeEpochObservation, error) {
	var result nodeEpochObservation
	root, err := openDirectory(directory)
	if err != nil {
		return result, err
	}
	defer root.Close()
	// Manifest validation requires exactly one rollup file.
	index := slices.IndexFunc(m.Files, func(file File) bool { return file.Kind == "rollup" })
	raw, err := readPin(root, m.Files[index], MaxDocumentBytes)
	if err != nil {
		return result, err
	}
	cfg, err := m.BindConfiguration(raw)
	if err != nil {
		return result, err
	}
	return m.nodeEpochForConfiguration(cfg)
}

func (m Manifest) nodeEpochForConfiguration(cfg *rollup.Config) (nodeEpochObservation, error) {
	loaded, err := json.Marshal(cfg)
	if err != nil {
		return nodeEpochObservation{}, errors.New("could not fingerprint the parsed rollup configuration")
	}
	return nodeEpochObservation{
		Schema: nodeEpochSchema, L1ChainID: m.Epoch.L1ChainID, L2ChainID: m.Epoch.L2ChainID,
		L2GenesisHash: m.Epoch.L2GenesisHash, LoadedRollupSHA256: digest(loaded),
	}, nil
}

func readNodeEpoch(ctx context.Context, client *http.Client, endpoint string) (nodeEpochObservation, error) {
	var result nodeEpochObservation
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return result, errors.New("could not open the node epoch endpoint")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(req)
	if err != nil {
		return result, errors.New("node epoch response was unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, errors.New("node epoch endpoint did not report an observation")
	}
	const limit = 4 << 10
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(raw) > limit || decode(raw, &result) != nil {
		return result, errors.New("node epoch response was invalid")
	}
	return result, nil
}

func observeNodeEpochs(ctx context.Context, client *http.Client, endpoints [2]string, expected nodeEpochObservation) error {
	for i, endpoint := range endpoints {
		observed, err := readNodeEpoch(ctx, client, endpoint)
		if err != nil {
			return fmt.Errorf("node epoch endpoint %d: %w", i+1, err)
		}
		if observed != expected {
			return fmt.Errorf("node epoch endpoint %d disagrees with the signed rollup configuration", i+1)
		}
	}
	return nil
}
