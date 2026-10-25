package artifacts

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const ArchiveFormat = "zip-store-v1"
const MaxArchiveBytes int64 = (1 << 32) - 1

// ArchivePolicy independently binds the exact manifest and selection policy.
// ZIP Store avoids compressor-version variability. This profile uses ZIP32,
// fixed UTC metadata and an explicit file list; it never traverses arbitrary trees.
type ArchivePolicy struct {
	Schema                int    `json:"schema"`
	Format                string `json:"format"`
	ManifestSHA256        string `json:"manifestSha256"`
	SelectionPolicySHA256 string `json:"selectionPolicySha256"`
	SourceDateEpoch       int64  `json:"sourceDateEpoch"`
}

type ArchiveResult struct {
	ArchiveSHA256                 string `json:"archiveSha256"`
	ArchiveBytes                  int64  `json:"archiveBytes"`
	ManifestSHA256                string `json:"manifestSha256"`
	PolicySHA256                  string `json:"policySha256"`
	ArchivePolicySHA256           string `json:"archivePolicySha256"`
	FilesVerified                 int    `json:"filesVerified"`
	ArchiveSelectionVerified      bool   `json:"archiveSelectionVerified"`
	DeterministicMetadataVerified bool   `json:"deterministicMetadataVerified"`
	ProvenanceSignaturesVerified  bool   `json:"provenanceSignaturesVerified"`
	SBOMContentsVerified          bool   `json:"sbomContentsVerified"`
	ReleaseAccepted               bool   `json:"releaseAccepted"`
}

type archiveEntry struct {
	name     string
	pin      File
	mode     os.FileMode
	metadata []byte
}

func archiveInputs(manifestBytes, policyBytes, archiveBytes []byte) (Manifest, Policy, ArchivePolicy, []archiveEntry, error) {
	var m Manifest
	var p Policy
	var a ArchivePolicy
	if err := decode(manifestBytes, &m); err != nil {
		return m, p, a, nil, err
	}
	if err := decode(policyBytes, &p); err != nil {
		return m, p, a, nil, err
	}
	files, err := validate(m, p)
	if err != nil {
		return m, p, a, nil, err
	}
	if err := validateChecksums(m, files); err != nil {
		return m, p, a, nil, err
	}
	if err := decode(archiveBytes, &a); err != nil {
		return m, p, a, nil, err
	}
	canonical, _ := CanonicalPolicy(p)
	if a.Schema != 1 || a.Format != ArchiveFormat || a.ManifestSHA256 != sum(manifestBytes) || a.SelectionPolicySHA256 != sum(canonical) ||
		a.SourceDateEpoch < 315532800 || a.SourceDateEpoch > 4291747198 || a.SourceDateEpoch%2 != 0 {
		return m, p, a, nil, errors.New("invalid independent ZIP32 policy or fixed UTC epoch")
	}
	entries := []archiveEntry{{name: "manifest.json", mode: 0644, metadata: manifestBytes}, {name: "policy.json", mode: 0644, metadata: canonical}}
	subjects := map[string]bool{}
	for _, artifact := range p.Artifacts {
		subjects[artifact.SubjectPath] = artifact.Kind == "binary"
	}
	var total int64
	for _, pin := range m.Files {
		mode := os.FileMode(0644)
		if subjects[pin.Path] {
			mode = 0755
		}
		entries = append(entries, archiveEntry{name: "payloads/" + pin.Path, pin: pin, mode: mode})
		total += pin.Bytes
	}
	if total > MaxArchiveBytes-(4<<20) {
		return m, p, a, nil, errors.New("selected output set exceeds ZIP32 profile budget")
	}
	slices.SortFunc(entries, func(a, b archiveEntry) int { return strings.Compare(a.name, b.name) })
	return m, p, a, entries, nil
}

func archiveHeader(entry archiveEntry, epoch int64) *zip.FileHeader {
	h := &zip.FileHeader{Name: entry.name, Method: zip.Store, Flags: 0x800}
	h.SetMode(entry.mode)
	h.Modified = time.Unix(epoch, 0).UTC()
	return h
}

type archiveOutput struct {
	writer io.Writer
	hash   hash.Hash
	bytes  int64
}

func (w *archiveOutput) Write(raw []byte) (int, error) {
	if int64(len(raw)) > MaxArchiveBytes-w.bytes {
		return 0, errors.New("archive output exceeds profile limit")
	}
	n, err := w.writer.Write(raw)
	if n > 0 {
		w.hash.Write(raw[:n])
		w.bytes += int64(n)
	}
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	return n, err
}

// WriteArchive streams one canonical portable package to a caller-owned writer.
// It verifies byte closure and observed identities, not signatures or SBOM content.
// Callers must retain failed/incomplete output as unverified, never publish it as
// successful, and use a separately selected archive pin for later consumption.
func WriteArchive(output io.Writer, manifestBytes, policyBytes, archivePolicyBytes []byte, root string) (ArchiveResult, error) {
	return writeArchive(output, manifestBytes, policyBytes, archivePolicyBytes, root, nil)
}

func writeArchive(output io.Writer, manifestBytes, policyBytes, archivePolicyBytes []byte, root string, afterOpen func(string)) (ArchiveResult, error) {
	m, p, a, entries, err := archiveInputs(manifestBytes, policyBytes, archivePolicyBytes)
	if err != nil {
		return ArchiveResult{}, err
	}
	if output == nil {
		return ArchiveResult{}, errors.New("archive output writer is required")
	}
	stream := &archiveOutput{writer: output, hash: sha256.New()}
	writer := zip.NewWriter(stream)
	result, err := checkSelected(manifestBytes, policyBytes, root, nil, func(d *directory, files map[string]File, before map[string]os.FileInfo) error {
		for _, entry := range entries {
			member, err := writer.CreateHeader(archiveHeader(entry, a.SourceDateEpoch))
			if err != nil {
				return errors.New("archive member could not be created")
			}
			if entry.metadata != nil {
				if n, err := member.Write(entry.metadata); err != nil || n != len(entry.metadata) {
					return errors.New("archive metadata could not be written")
				}
				continue
			}
			pin := entry.pin
			f, err := openEntry(d.root, pin.Path, false)
			if err != nil {
				return err
			}
			opened, err := f.Stat()
			if err != nil || !stable(before[pin.Path], opened) {
				f.Close()
				return errors.New("archive payload identity changed while opening")
			}
			if afterOpen != nil {
				afterOpen(pin.Path)
			}
			h := sha256.New()
			n, readErr := io.Copy(io.MultiWriter(member, h), io.LimitReader(f, pin.Bytes+1))
			after, statErr := f.Stat()
			named, pathErr := d.root.Lstat(pin.Path)
			f.Close()
			if readErr != nil || statErr != nil || pathErr != nil || n != pin.Bytes || !stable(before[pin.Path], after) || !stable(before[pin.Path], named) || hex.EncodeToString(h.Sum(nil)) != pin.SHA256 {
				return errors.New("archive payload changed or could not be streamed exactly")
			}
		}
		if err := writer.Close(); err != nil {
			return errors.New("archive could not be completed")
		}
		return nil
	})
	if err != nil {
		return ArchiveResult{}, err
	}
	canonical, _ := CanonicalPolicy(p)
	return ArchiveResult{ArchiveSHA256: hex.EncodeToString(stream.hash.Sum(nil)), ArchiveBytes: stream.bytes, ManifestSHA256: sum(manifestBytes), PolicySHA256: sum(canonical),
		ArchivePolicySHA256: sum(archivePolicyBytes), FilesVerified: len(m.Files), ArchiveSelectionVerified: result.SelectionVerified, DeterministicMetadataVerified: true}, nil
}

// CheckArchive consumes an independently size/SHA-256-pinned archive without
// extraction. The independent manifest/policy are authoritative; copies inside
// the archive are compared byte-for-byte and never adopted as trust inputs.
func CheckArchive(input io.ReaderAt, size int64, pin File, manifestBytes, policyBytes, archivePolicyBytes []byte) (ArchiveResult, error) {
	_, p, a, entries, err := archiveInputs(manifestBytes, policyBytes, archivePolicyBytes)
	if err != nil {
		return ArchiveResult{}, err
	}
	if input == nil || size < 22 || size > MaxArchiveBytes || pin.Bytes != size || !relative(pin.Path) || !digest(pin.SHA256, 64) {
		return ArchiveResult{}, errors.New("independent archive size and SHA-256 pin are required")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(input, 0, size))
	if err != nil || n != size || hex.EncodeToString(h.Sum(nil)) != pin.SHA256 {
		return ArchiveResult{}, errors.New("archive bytes do not match independent pin")
	}
	// The profile has an empty comment, one disk and at most MaxFiles+2 entries.
	// Check EOCD bounds before the general ZIP parser can allocate entry metadata.
	end := make([]byte, 22)
	if _, err := input.ReadAt(end, size-22); err != nil {
		return ArchiveResult{}, errors.New("archive ending is incomplete")
	}
	if binary.LittleEndian.Uint32(end) != 0x06054b50 || binary.LittleEndian.Uint16(end[4:]) != 0 || binary.LittleEndian.Uint16(end[6:]) != 0 ||
		int(binary.LittleEndian.Uint16(end[8:])) != len(entries) || int(binary.LittleEndian.Uint16(end[10:])) != len(entries) || binary.LittleEndian.Uint16(end[20:]) != 0 ||
		int64(binary.LittleEndian.Uint32(end[12:])) > MaxDocumentBytes || int64(binary.LittleEndian.Uint32(end[12:]))+int64(binary.LittleEndian.Uint32(end[16:])) != size-22 {
		return ArchiveResult{}, errors.New("archive directory, count, disk or comment is outside canonical profile")
	}
	reader, err := zip.NewReader(input, size)
	if err != nil || len(reader.File) != len(entries) || reader.Comment != "" {
		return ArchiveResult{}, errors.New("archive directory could not be read exactly")
	}
	extra := make([]byte, 9)
	binary.LittleEndian.PutUint16(extra, 0x5455)
	binary.LittleEndian.PutUint16(extra[2:], 5)
	extra[4] = 1
	binary.LittleEndian.PutUint32(extra[5:], uint32(a.SourceDateEpoch))
	reconstructed := &archiveOutput{writer: io.Discard, hash: sha256.New()}
	canonicalWriter := zip.NewWriter(reconstructed)
	for i, entry := range entries {
		file := reader.File[i]
		if file.Name != entry.name || file.Method != zip.Store || file.Flags != 0x808 || file.Comment != "" || file.NonUTF8 || !file.Mode().IsRegular() || file.Mode().Perm() != entry.mode ||
			file.CreatorVersion != (3<<8|20) || file.ReaderVersion != 20 || file.Modified.Unix() != a.SourceDateEpoch || !bytes.Equal(file.Extra, extra) {
			return ArchiveResult{}, errors.New("archive member metadata is not canonical")
		}
		expectedBytes := entry.pin.Bytes
		expectedSHA := entry.pin.SHA256
		if entry.metadata != nil {
			expectedBytes = int64(len(entry.metadata))
			expectedSHA = sum(entry.metadata)
		}
		if file.UncompressedSize64 != uint64(expectedBytes) || file.CompressedSize64 != uint64(expectedBytes) {
			return ArchiveResult{}, errors.New("archive member size does not match selected input")
		}
		member, err := file.Open()
		if err != nil {
			return ArchiveResult{}, errors.New("archive member could not be opened")
		}
		canonicalMember, err := canonicalWriter.CreateHeader(archiveHeader(entry, a.SourceDateEpoch))
		if err != nil {
			member.Close()
			return ArchiveResult{}, errors.New("canonical archive observation failed")
		}
		h := sha256.New()
		count, readErr := io.Copy(io.MultiWriter(h, canonicalMember), io.LimitReader(member, expectedBytes+1))
		closeErr := member.Close()
		if readErr != nil || closeErr != nil || count != expectedBytes || hex.EncodeToString(h.Sum(nil)) != expectedSHA {
			return ArchiveResult{}, errors.New("archive member bytes or CRC do not match independent selection")
		}
	}
	if err := canonicalWriter.Close(); err != nil || reconstructed.bytes != size || hex.EncodeToString(reconstructed.hash.Sum(nil)) != pin.SHA256 {
		return ArchiveResult{}, errors.New("archive physical layout is not canonical")
	}
	canonical, _ := CanonicalPolicy(p)
	return ArchiveResult{ArchiveSHA256: pin.SHA256, ArchiveBytes: size, ManifestSHA256: sum(manifestBytes), PolicySHA256: sum(canonical), ArchivePolicySHA256: sum(archivePolicyBytes),
		FilesVerified: len(entries) - 2, ArchiveSelectionVerified: true, DeterministicMetadataVerified: true}, nil
}

func ParseArchivePin(raw []byte) (File, error) {
	var pin File
	if err := decode(raw, &pin); err != nil {
		return File{}, err
	}
	if !relative(pin.Path) || pin.Bytes < 22 || pin.Bytes > MaxArchiveBytes || !digest(pin.SHA256, 64) {
		return File{}, errors.New("invalid independent archive pin")
	}
	return pin, nil
}

// CheckArchiveFile observes a regular archive without following link ancestors
// and checks its identity again after streaming and canonical layout validation.
func CheckArchiveFile(name string, pin File, manifestBytes, policyBytes, archivePolicyBytes []byte) (ArchiveResult, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return ArchiveResult{}, errors.New("invalid archive path")
	}
	d, err := openDirectory(filepath.Dir(abs))
	if err != nil {
		return ArchiveResult{}, err
	}
	defer d.root.Close()
	base := filepath.Base(abs)
	before, err := d.root.Lstat(base)
	if err != nil || !before.Mode().IsRegular() || !singleLink(before) || before.Size() != pin.Bytes {
		return ArchiveResult{}, errors.New("archive is missing, linked, nonregular or has the wrong size")
	}
	f, err := openEntry(d.root, base, false)
	if err != nil {
		return ArchiveResult{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !stable(before, opened) {
		return ArchiveResult{}, errors.New("archive changed while opening")
	}
	result, err := CheckArchive(f, before.Size(), pin, manifestBytes, policyBytes, archivePolicyBytes)
	if err != nil {
		return ArchiveResult{}, err
	}
	after, statErr := f.Stat()
	named, pathErr := d.root.Lstat(base)
	if statErr != nil || pathErr != nil || !stable(before, after) || !stable(before, named) {
		return ArchiveResult{}, errors.New("archive identity changed during verification")
	}
	if err := d.checkAncestors(); err != nil {
		return ArchiveResult{}, err
	}
	return result, nil
}
