package release

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Zenoglyphs-VM/zvm-core/l2"
)

var eipBuildFences = regexp.MustCompile("(?m)^```[^\\n]*\\n([\\s\\S]*?)^```[ \\t]*(?:\\n|$)")
var eipBuildInput = regexp.MustCompile("\"input\"\\s*:\\s*\"(0x[0-9a-f]+)\"")
var eipBuildIdentity = regexp.MustCompile(`(?m)^eip: ([0-9]+)$`)
var eipBuildStatus = regexp.MustCompile(`(?m)^status: ([A-Za-z]+)$`)
var literalBuildPush = regexp.MustCompile(`^push([1-9]|[12][0-9]|3[0-2])$`)

func utf8BuildSource(raw []byte) bool { return len(raw) > 0 && len(raw) <= 1<<20 && utf8.Valid(raw) }

func mustBuildJSON(value any) []byte {
	// Used only for maps already decoded from bounded, validated JSON. Such
	// maps contain RawMessages and cannot introduce a marshal failure.
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return raw
}

// This finite assembler handles only the literal instructions in the two
// supported final EIPs. It evaluates no labels, expressions, macros or files.
func assembleBuildLiteral(source string) ([]byte, []byte, error) {
	if len(source) > 8192 || !utf8.ValidString(source) {
		return nil, nil, errors.New("assembly source exceeds its encoding or byte bound")
	}
	lines := strings.Split(source, "\n")
	if len(lines) > 256 {
		return nil, nil, errors.New("assembly line bound exceeded")
	}
	opcodes := map[string]byte{"stop": 0, "add": 1, "sub": 3, "mod": 6, "gt": 0x11, "eq": 0x14, "iszero": 0x15, "caller": 0x33, "calldataload": 0x35, "calldatasize": 0x36, "timestamp": 0x42, "number": 0x43, "mstore": 0x52, "sload": 0x54, "sstore": 0x55, "jumpi": 0x57, "jumpdest": 0x5b, "push0": 0x5f, "dup1": 0x80, "dup2": 0x81, "swap1": 0x90, "return": 0xf3, "revert": 0xfd}
	var output []byte
	var normalized []string
	for _, original := range lines {
		line := strings.TrimSpace(strings.SplitN(original, "//", 2)[0])
		if line == "" {
			continue
		}
		words := strings.Fields(line)
		if match := literalBuildPush.FindStringSubmatch(words[0]); match != nil {
			width, _ := strconv.Atoi(match[1])
			if len(words) != 2 || len(words[1]) != 2+width*2 || !strings.HasPrefix(words[1], "0x") || strings.ToLower(words[1]) != words[1] {
				return nil, nil, errors.New("invalid literal PUSH operand")
			}
			operand, err := hex.DecodeString(words[1][2:])
			if err != nil {
				return nil, nil, errors.New("invalid literal PUSH bytes")
			}
			output = append(output, byte(0x5f+width))
			output = append(output, operand...)
		} else {
			opcode, ok := opcodes[words[0]]
			if !ok || len(words) != 1 {
				return nil, nil, errors.New("unsupported literal assembly instruction")
			}
			output = append(output, opcode)
		}
		if len(output) > 1024 {
			return nil, nil, errors.New("assembled runtime exceeds its byte bound")
		}
		normalized = append(normalized, line)
	}
	if len(output) == 0 {
		return nil, nil, errors.New("empty literal assembly")
	}
	return []byte(strings.Join(normalized, "\n") + "\n"), output, nil
}

func buildEIPMaterial(source []byte, eip int) ([]byte, []byte, []byte, error) {
	if len(source) == 0 || len(source) > 65536 || !utf8.Valid(source) {
		return nil, nil, nil, errors.New("EIP document exceeds its encoding or byte bound")
	}
	identities := eipBuildIdentity.FindAllSubmatch(source, -1)
	statuses := eipBuildStatus.FindAllSubmatch(source, -1)
	if len(identities) != 1 || string(identities[0][1]) != strconv.Itoa(eip) || len(statuses) != 1 || string(statuses[0][1]) != "Final" {
		return nil, nil, nil, errors.New("EIP source identity is ambiguous or not final")
	}
	var selected string
	count := 0
	for _, match := range eipBuildFences.FindAllSubmatch(source, -1) {
		body := string(match[1])
		first := ""
		for _, line := range strings.Split(body, "\n") {
			first = strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
			if first != "" {
				break
			}
		}
		if first == "caller" {
			selected = body
			count++
		}
	}
	if count != 1 {
		return nil, nil, nil, errors.New("EIP literal assembly section is missing or ambiguous")
	}
	assembly, runtime, err := assembleBuildLiteral(selected)
	if err != nil {
		return nil, nil, nil, err
	}
	inputs := eipBuildInput.FindAllSubmatch(source, -1)
	if len(runtime) > 255 || len(inputs) != 1 {
		return nil, nil, nil, errors.New("EIP creation input is missing, oversized or ambiguous")
	}
	creation, err := hex.DecodeString(string(inputs[0][1][2:]))
	if err != nil {
		return nil, nil, nil, errors.New("invalid EIP creation bytes")
	}
	prefix := []byte{0x60, byte(len(runtime)), 0x80, 0x60, 9, 0x5f, 0x39, 0x5f, 0xf3}
	if !bytes.Equal(creation, append(prefix, runtime...)) {
		return nil, nil, nil, errors.New("EIP creation prefix or complete runtime differs")
	}
	return assembly, creation, runtime, nil
}

func (m Manifest) verifyEIPAssembly(build EIPAssemblyBuildV2, files *os.Root, packages *buildPackageReader, byID map[string]File) error {
	source := build.Source
	pin := byID[source.File]
	if !ordinaryBuildSource(source) || pin.ID == "" || pin.Kind != "artifact" || pin.Bytes > 65536 {
		return errors.New("EIP assembly requires one bounded signed Git source")
	}
	raw, err := packages.source(source, pin)
	if err != nil {
		return err
	}
	target := build.Contracts[0]
	contract, ok := m.releaseContract(target.Contract)
	name := "BeaconRoots_4788"
	if target.EIP == 2935 {
		name = "HistoryStorage_2935"
	}
	if !ok || contract.Address != strings.ToLower(l2.Predeploys()[name].Hex()) {
		return errors.New("EIP target address disagrees with the supported genesis inventory")
	}
	assembly, creation, runtime, err := buildEIPMaterial(raw, target.EIP)
	if err != nil {
		return err
	}
	if digest(assembly) != target.AssemblySHA256 || digest(creation) != target.CreationSHA256 || digest(runtime) != target.RuntimeSHA256 {
		return errors.New("complete EIP assembly, creation or runtime pin differs")
	}
	return m.compareTypedRuntime(target.Contract, runtime, files, byID)
}
