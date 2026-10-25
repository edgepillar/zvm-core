package artifacts

import (
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func machoBuildFixture() []byte {
	le := binary.LittleEndian
	data := make([]byte, 3<<20)
	put := func(offset int, value uint32) { le.PutUint32(data[offset:], value) }
	put(0, 0xfeedfacf)
	put(4, 0x100000c)
	put(12, 2)
	put(16, 2)
	put(20, 176)
	put(32, 0x19)
	put(36, 152)
	copy(data[40:], "__DATA")
	le.PutUint64(data[56:], 0x100000000)
	le.PutUint64(data[64:], uint64(len(data)-512))
	le.PutUint64(data[72:], 512)
	le.PutUint64(data[80:], uint64(len(data)-512))
	put(96, 1)
	section := data[104:184]
	copy(section, "__go_buildinfo")
	copy(section[16:], "__DATA")
	le.PutUint64(section[32:], 0x100000200)
	le.PutUint32(section[48:], 1024)
	mod := strings.Repeat("p", 16) + "path\texample.invalid/project/cmd/tool\nmod\texample.invalid/project\t(devel)\t\nbuild\tGOARCH=arm64\nbuild\tGOOS=darwin\n" + strings.Repeat("s", 16)
	blob := make([]byte, 32)
	copy(blob, "\xff Go buildinf:")
	blob[14], blob[15] = 8, 2
	blob = binary.AppendUvarint(blob, uint64(len("go1.25.14")))
	blob = append(blob, "go1.25.14"...)
	blob = binary.AppendUvarint(blob, uint64(len(mod)))
	blob = append(blob, mod...)
	le.PutUint64(section[40:], uint64(len(blob)))
	copy(data[1024:], blob)
	// A valid-range 2 MiB string table is unrelated to the tiny Go section.
	put(184, 2)
	put(188, 24)
	put(192, 4096)
	put(196, 1)
	put(200, 1<<20)
	put(204, 2<<20)
	return data
}

func TestMachOBuildMetadataAvoidsUnneededSymbolTables(t *testing.T) {
	raw := machoBuildFixture()
	legacy := &metadataReader{reader: bytes.NewReader(raw), size: int64(len(raw)), remaining: 16 << 20}
	if _, err := buildinfo.Read(legacy); err == nil {
		t.Fatal("fixture no longer exercises the general parser's excessive metadata read")
	}
	r := &metadataReader{reader: bytes.NewReader(raw), size: int64(len(raw)), remaining: 4096}
	info, err := readBuildInfo(r)
	if err != nil || info.GoVersion != "go1.25.14" || info.Path != "example.invalid/project/cmd/tool" || info.Main.Path != "example.invalid/project" || r.remaining <= 3000 {
		t.Fatalf("bounded Go section was not read independently: %+v %v", info, err)
	}
}

func TestMachOBuildMetadataRefusesAmbiguousOrUnboundedSections(t *testing.T) {
	le := binary.LittleEndian
	cases := []struct {
		name string
		edit func([]byte) []byte
	}{
		{"short-header", func(b []byte) []byte { return b[:16] }},
		{"cpu", func(b []byte) []byte { le.PutUint32(b[4:], 0); return b }},
		{"file-kind", func(b []byte) []byte { le.PutUint32(b[12:], 1); return b }},
		{"command-count", func(b []byte) []byte { le.PutUint32(b[16:], 4097); return b }},
		{"command-budget", func(b []byte) []byte { le.PutUint32(b[20:], MaxDocumentBytes+1); return b }},
		{"command-missing", func(b []byte) []byte { le.PutUint32(b[16:], 1); return b }},
		{"command-length-zero", func(b []byte) []byte { le.PutUint32(b[36:], 0); return b }},
		{"command-length-alignment", func(b []byte) []byte { le.PutUint32(b[36:], 151); return b }},
		{"section-count", func(b []byte) []byte { le.PutUint32(b[96:], 0xffffffff); return b }},
		{"segment-file-range", func(b []byte) []byte { le.PutUint64(b[72:], ^uint64(0)); return b }},
		{"section-name", func(b []byte) []byte { b[104] = 'x'; return b }},
		{"section-segment", func(b []byte) []byte { b[120] = 'x'; return b }},
		{"section-kind", func(b []byte) []byte { le.PutUint32(b[168:], 1); return b }},
		{"section-virtual-range", func(b []byte) []byte { le.PutUint64(b[136:], 0); return b }},
		{"section-budget", func(b []byte) []byte { le.PutUint64(b[144:], MaxDocumentBytes+1); return b }},
		{"section-offset", func(b []byte) []byte { le.PutUint32(b[152:], 1025); return b }},
		{"section-short", func(b []byte) []byte { le.PutUint64(b[144:], 31); return b }},
		{"section-duplicate", func(b []byte) []byte {
			segment := append([]byte{}, b[32:184]...)
			symbols := append([]byte{}, b[184:208]...)
			copy(b[184:], segment)
			copy(b[336:], symbols)
			le.PutUint32(b[16:], 3)
			le.PutUint32(b[20:], 328)
			return b
		}},
		{"section-name-alias-before-canonical", func(b []byte) []byte {
			segment := append([]byte{}, b[32:184]...)
			symbols := append([]byte{}, b[184:208]...)
			b[119] = 1 // A C-string alias must not shadow a second canonical section.
			copy(b[184:], segment)
			copy(b[336:], symbols)
			le.PutUint32(b[16:], 3)
			le.PutUint32(b[20:], 328)
			return b
		}},
		{"blob-magic", func(b []byte) []byte { b[1024] = 'x'; return b }},
		{"blob-pointer-size", func(b []byte) []byte { b[1038] = 4; return b }},
		{"legacy-pointer-format", func(b []byte) []byte { b[1039] = 0; return b }},
		{"blob-version-length", func(b []byte) []byte { copy(b[1056:], bytes.Repeat([]byte{255}, 10)); return b }},
		{"blob-version", func(b []byte) []byte { b[1057] = 'x'; return b }},
		{"blob-modules-length", func(b []byte) []byte { copy(b[1066:], bytes.Repeat([]byte{255}, 10)); return b }},
		{"cpu-setting-mismatch", func(b []byte) []byte { le.PutUint32(b[4:], 0x1000007); return b }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.edit(machoBuildFixture())
			r := &metadataReader{reader: bytes.NewReader(raw), size: int64(len(raw)), remaining: 16 << 20}
			if info, err := readBuildInfo(r); err == nil || info != nil {
				t.Fatal("invalid Mach-O metadata produced a build inventory")
			}
		})
	}
	raw := machoBuildFixture()
	if _, err := readBuildInfo(&metadataReader{reader: bytes.NewReader(raw), size: int64(len(raw)), remaining: 64}); err == nil {
		t.Fatal("cumulative read budget was relaxed")
	}
}

func TestActualCoreCLIModuleInventory(t *testing.T) {
	dir := os.Getenv("ZVM_CORE_CLI_FIXTURE_DIRECTORY")
	if dir == "" {
		t.Skip("qualified Core CLI and independent source graph controls were not provisioned")
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := ReadDocument(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	policy, mod, lock := read("policy.json"), read("go.mod"), read("go.sum")
	var p GoSBOMPolicy
	if err := decode(policy, &p); err != nil || p.MainPackage != "github.com/Zenoglyphs-VM/zvm-core/cmd/zvm" || len(p.Modules) <= 1 {
		t.Fatal("fixture must describe the real Core CLI from independent source controls")
	}
	versioned := false
	for _, module := range p.Modules {
		if module.Path == "github.com/ethereum/go-ethereum" && module.Replacement == "versioned" && module.EffectivePath == "github.com/ethereum-optimism/op-geth" {
			versioned = true
		}
	}
	if !versioned {
		t.Fatal("Core fixture must exercise its actual versioned engine replacement")
	}
	subject := filepath.Join(dir, "subject")
	doc, receipt, err := GenerateGoSBOM(policy, mod, lock, subject)
	if err != nil || receipt.ModulesVerified != len(p.Modules) || !receipt.SubjectBytesVerified || !receipt.LockedModulesMatched || receipt.ReleaseAccepted {
		t.Fatalf("actual Core CLI inventory refused: %+v %v", receipt, err)
	}
	if _, err := CheckGoSBOM(doc, policy, mod, lock, subject); err != nil {
		t.Fatal(err)
	}
	second, _, err := GenerateGoSBOM(policy, mod, lock, subject)
	if err != nil || !bytes.Equal(doc, second) {
		t.Fatal("real Core inventory was not deterministic")
	}
	p.Modules = p.Modules[1:]
	if _, _, err := GenerateGoSBOM(marshal(t, p), mod, lock, subject); err == nil {
		t.Fatal("real transitive module omission was accepted")
	}
}
