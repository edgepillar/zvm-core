package release

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"time"
)

const maxL1GenesisBytes = 16 << 20

type nomGenesis struct {
	ChainID      uint64 `json:"chainId"`
	MomentumHash string `json:"momentumHash"`
}

func reconstructNoMGenesis(parent context.Context, verifier string, raw []byte) (nomGenesis, error) {
	var result nomGenesis
	if compilerJSON(raw, maxL1GenesisBytes) != nil {
		return result, errors.New("L1 genesis JSON is ambiguous or exceeds its structure bounds")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, verifier)
	cmd.Env = []string{}
	cmd.Stdin = bytes.NewReader(raw)
	cmd.WaitDelay = time.Second
	var output commandOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil || output.overflow {
		return result, errors.New("NoM genesis verifier failed within its execution limits")
	}
	if output.data.Len() > 1024 || decode(output.data.Bytes(), &result) != nil || result.ChainID == 0 || !blockHash(result.MomentumHash) {
		return nomGenesis{}, errors.New("NoM genesis verifier returned an invalid result")
	}
	return result, nil
}

func (m Manifest) verifyL1Genesis(ctx context.Context, raw []byte, verifier string) error {
	result, err := reconstructNoMGenesis(ctx, verifier, raw)
	if err != nil {
		return err
	}
	if strconv.FormatUint(result.ChainID, 10) != m.Epoch.L1ChainID {
		return errors.New("NoM genesis chain ID disagrees with the epoch")
	}
	if result.MomentumHash != m.Epoch.L1GenesisHash {
		return errors.New("NoM genesis momentum hash disagrees with the epoch")
	}
	return nil
}
