package artifacts

import (
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"errors"
	"runtime/debug"
)

// readBuildInfo keeps the existing metadata I/O budget. The general Mach-O
// parser reads symbol/string tables that are unrelated to Go build metadata;
// a regular Core CLI can have a string table larger than one metadata read.
// Thin 64-bit Mach-O is therefore inspected through its explicit build-info
// section, without loading symbols, relocations, debug data or executable code.
func readBuildInfo(r *metadataReader) (*debug.BuildInfo, error) {
	var magic [4]byte
	if _, err := r.ReadAt(magic[:], 0); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(magic[:]) == 0xfeedfacf {
		return readMachOBuildInfo(r)
	}
	return buildinfo.Read(r)
}

func metadataRange(offset, size uint64, fileSize int64) bool {
	return fileSize >= 0 && offset <= uint64(fileSize) && size <= uint64(fileSize)-offset
}

func readMachOBuildInfo(r *metadataReader) (*debug.BuildInfo, error) {
	refused := errors.New("unsupported or invalid bounded Mach-O build metadata")
	var header [32]byte
	if _, err := r.ReadAt(header[:], 0); err != nil {
		return nil, refused
	}
	le := binary.LittleEndian
	cpu, kind := le.Uint32(header[4:]), le.Uint32(header[12:])
	count, size := le.Uint32(header[16:]), le.Uint32(header[20:])
	if le.Uint32(header[:]) != 0xfeedfacf || (cpu != 0x1000007 && cpu != 0x100000c) || kind != 2 || count == 0 || count > 4096 || size > MaxDocumentBytes ||
		uint64(count)*8 > uint64(size) || !metadataRange(32, uint64(size), r.size) {
		return nil, refused
	}
	commands := make([]byte, size)
	if _, err := r.ReadAt(commands, 32); err != nil {
		return nil, refused
	}
	var infoOffset, infoSize uint64
	found := false
	for i := uint32(0); i < count; i++ {
		if len(commands) < 8 {
			return nil, refused
		}
		cmd, length := le.Uint32(commands), le.Uint32(commands[4:])
		if length < 8 || length%8 != 0 || uint64(length) > uint64(len(commands)) {
			return nil, refused
		}
		current := commands[:length]
		commands = commands[length:]
		if cmd != 0x19 { // LC_SEGMENT_64; other commands are not metadata inputs.
			continue
		}
		if length < 72 {
			return nil, refused
		}
		sections := le.Uint32(current[64:])
		if uint64(length) != 72+uint64(sections)*80 {
			return nil, refused
		}
		address, offset, fileBytes := le.Uint64(current[24:]), le.Uint64(current[40:]), le.Uint64(current[48:])
		if !metadataRange(offset, fileBytes, r.size) {
			return nil, refused
		}
		for j := uint32(0); j < sections; j++ {
			section := current[72+int(j)*80 : 72+int(j+1)*80]
			name := section[:16]
			if end := bytes.IndexByte(name, 0); end >= 0 {
				name = name[:end]
			}
			if !bytes.Equal(name, []byte("__go_buildinfo")) {
				continue
			}
			if !bytes.Equal(section[:16], []byte("__go_buildinfo\x00\x00")) {
				return nil, refused
			}
			sectionAddress, sectionBytes, sectionOffset := le.Uint64(section[32:]), le.Uint64(section[40:]), uint64(le.Uint32(section[48:]))
			if found || !bytes.Equal(section[16:32], current[8:24]) || le.Uint32(section[64:])&0xff != 0 || sectionAddress < address ||
				sectionAddress-address > fileBytes || sectionBytes > fileBytes-(sectionAddress-address) ||
				sectionOffset != offset+(sectionAddress-address) || sectionOffset < 32+uint64(size) || sectionOffset%16 != 0 || sectionBytes < 32 || sectionBytes > MaxDocumentBytes || !metadataRange(sectionOffset, sectionBytes, r.size) {
				return nil, refused
			}
			found, infoOffset, infoSize = true, sectionOffset, sectionBytes
		}
	}
	if !found || len(commands) != 0 {
		return nil, refused
	}
	blob := make([]byte, infoSize)
	if _, err := r.ReadAt(blob, int64(infoOffset)); err != nil {
		return nil, refused
	}
	// Go 1.18+ stores two length-prefixed strings after its 32-byte header.
	// Older pointer-based Mach-O metadata needs a separately bounded profile.
	if !bytes.Equal(blob[:14], []byte("\xff Go buildinf:")) || blob[14] != 8 || blob[15] != 2 {
		return nil, refused
	}
	rest := blob[32:]
	next := func() (string, bool) {
		n, prefix := binary.Uvarint(rest)
		if prefix <= 0 || n > uint64(len(rest)-prefix) {
			return "", false
		}
		value := string(rest[prefix : prefix+int(n)])
		rest = rest[prefix+int(n):]
		return value, true
	}
	version, ok := next()
	if !ok || !goVersion.MatchString(version) {
		return nil, refused
	}
	modules, ok := next()
	if !ok || len(modules) < 33 || modules[len(modules)-17] != '\n' {
		return nil, refused
	}
	info, err := debug.ParseBuildInfo(modules[16 : len(modules)-16])
	if err != nil {
		return nil, refused
	}
	info.GoVersion = version
	arch := "amd64"
	if cpu == 0x100000c {
		arch = "arm64"
	}
	for _, setting := range info.Settings {
		if setting.Key == "GOARCH" && setting.Value != arch {
			return nil, refused
		}
	}
	return info, nil
}
