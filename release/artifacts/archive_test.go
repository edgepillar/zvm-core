package artifacts

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func archivePolicyFixture(t *testing.T, f *fixture) ArchivePolicy {
	t.Helper()
	canonical, err := CanonicalPolicy(f.p)
	if err != nil {
		t.Fatal(err)
	}
	return ArchivePolicy{Schema: 1, Format: ArchiveFormat, ManifestSHA256: independentSHA(marshal(t, f.m)), SelectionPolicySHA256: independentSHA(canonical), SourceDateEpoch: 1767225600}
}
func archivePin(raw []byte) File { return File{"candidate.zip", int64(len(raw)), independentSHA(raw)} }

func TestCanonicalArchiveByteClosureAndMetadata(t *testing.T) {
	f := prepare(t, fixturePolicy())
	a := archivePolicyFixture(t, f)
	var first, second bytes.Buffer
	r, err := WriteArchive(&first, marshal(t, f.m), marshal(t, f.p), marshal(t, a), f.root)
	if err != nil || !r.ArchiveSelectionVerified || !r.DeterministicMetadataVerified || r.FilesVerified != 5 || r.ArchiveBytes != int64(first.Len()) || r.ArchiveSHA256 != independentSHA(first.Bytes()) || r.SBOMContentsVerified || r.ProvenanceSignaturesVerified || r.ReleaseAccepted {
		t.Fatalf("incomplete archive receipt: %+v %v", r, err)
	}
	for name := range f.payloads {
		path := filepath.Join(f.root, filepath.FromSlash(name))
		if err := os.Chmod(path, 0444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, time.Unix(946684800, 0), time.Unix(946684800, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := WriteArchive(&second, marshal(t, f.m), marshal(t, f.p), marshal(t, a), f.root); err != nil || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("host modes/times changed deterministic package bytes")
	}
	checked, err := CheckArchive(bytes.NewReader(first.Bytes()), int64(first.Len()), archivePin(first.Bytes()), marshal(t, f.m), marshal(t, f.p), marshal(t, a))
	if err != nil || checked != r {
		t.Fatalf("independent archive consumption failed: %+v %v", checked, err)
	}
	reader, err := zip.NewReader(bytes.NewReader(first.Bytes()), int64(first.Len()))
	if err != nil || len(reader.File) != 7 {
		t.Fatal("unexpected actual ZIP file set")
	}
	for _, file := range reader.File {
		if file.Method != zip.Store || file.Flags != 0x808 || file.Modified.Unix() != a.SourceDateEpoch || file.Comment != "" {
			t.Fatal("ZIP metadata did not match fixed wire profile")
		}
		mode := os.FileMode(0644)
		if file.Name == "payloads/"+f.p.Artifacts[0].SubjectPath {
			mode = 0755
		}
		if file.Mode().Perm() != mode {
			t.Fatal("archive permissions were copied from host instead of role")
		}
	}
}

type failedArchiveWriter struct{ remaining int }

func (w *failedArchiveWriter) Write(raw []byte) (int, error) {
	if len(raw) > w.remaining {
		return 0, io.ErrClosedPipe
	}
	w.remaining -= len(raw)
	return len(raw), nil
}

func TestArchiveRefusesWrongPolicyPartialOutputAndSubstitution(t *testing.T) {
	f := prepare(t, fixturePolicy())
	a := archivePolicyFixture(t, f)
	cases := []struct {
		name   string
		change func(*ArchivePolicy)
	}{
		{"schema", func(a *ArchivePolicy) { a.Schema = 2 }}, {"format", func(a *ArchivePolicy) { a.Format = "zip-deflate" }},
		{"manifest", func(a *ArchivePolicy) { a.ManifestSHA256 = "" }}, {"selection-policy", func(a *ArchivePolicy) { a.SelectionPolicySHA256 = "" }},
		{"epoch-before-ZIP", func(a *ArchivePolicy) { a.SourceDateEpoch = 0 }}, {"epoch-after-profile", func(a *ArchivePolicy) { a.SourceDateEpoch = 1 << 33 }},
		{"odd-epoch", func(a *ArchivePolicy) { a.SourceDateEpoch++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := archivePolicyFixture(t, f)
			tc.change(&a)
			var output bytes.Buffer
			r, err := WriteArchive(&output, marshal(t, f.m), marshal(t, f.p), marshal(t, a), f.root)
			if err == nil || r != (ArchiveResult{}) || output.Len() != 0 {
				t.Fatal("invalid archive policy produced output/acceptance")
			}
		})
	}
	if r, err := WriteArchive(&failedArchiveWriter{remaining: 100}, marshal(t, f.m), marshal(t, f.p), marshal(t, a), f.root); err == nil || r != (ArchiveResult{}) {
		t.Fatal("partial writer failure produced a success receipt")
	}
	var output bytes.Buffer
	r, err := writeArchive(&output, marshal(t, f.m), marshal(t, f.p), marshal(t, a), f.root, func(name string) {
		if name != f.p.Artifacts[0].SubjectPath {
			return
		}
		path := filepath.Join(f.root, filepath.FromSlash(name))
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, f.payloads[name], 0600); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || r != (ArchiveResult{}) {
		t.Fatal("input replaced while streaming produced acceptance")
	}
}

func TestArchivePhysicalLayoutAndIndependentPins(t *testing.T) {
	f := prepare(t, fixturePolicy())
	a := archivePolicyFixture(t, f)
	var output bytes.Buffer
	if _, err := WriteArchive(&output, marshal(t, f.m), marshal(t, f.p), marshal(t, a), f.root); err != nil {
		t.Fatal(err)
	}
	good := append([]byte{}, output.Bytes()...)
	mutations := []struct {
		name   string
		change func([]byte) []byte
	}{
		{"trailing-bytes", func(b []byte) []byte { return append(b, 0) }},
		{"directory-count", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[len(b)-12:], 65535); return b }},
		{"archive-comment", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[len(b)-2:], 1); return b }},
		{"local-header-name", func(b []byte) []byte { b[30] = 'x'; return b }},
		{"payload-byte", func(b []byte) []byte {
			z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				t.Fatal(err)
			}
			offset, err := z.File[0].DataOffset()
			if err != nil {
				t.Fatal(err)
			}
			b[offset] ^= 1
			return b
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.change(append([]byte{}, good...))
			r, err := CheckArchive(bytes.NewReader(raw), int64(len(raw)), archivePin(raw), marshal(t, f.m), marshal(t, f.p), marshal(t, a))
			if err == nil || r != (ArchiveResult{}) {
				t.Fatal("noncanonical/changed archive accepted with an updated byte pin")
			}
		})
	}
	_, _, _, entries, err := archiveInputs(marshal(t, f.m), marshal(t, f.p), marshal(t, a))
	if err != nil {
		t.Fatal(err)
	}
	var prefixed bytes.Buffer
	prefixed.WriteString("prefix")
	writer := zip.NewWriter(&prefixed)
	writer.SetOffset(6)
	for _, entry := range entries {
		member, err := writer.CreateHeader(archiveHeader(entry, a.SourceDateEpoch))
		if err != nil {
			t.Fatal(err)
		}
		raw := entry.metadata
		if raw == nil {
			raw = f.payloads[entry.pin.Path]
		}
		if _, err := member.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckArchive(bytes.NewReader(prefixed.Bytes()), int64(prefixed.Len()), archivePin(prefixed.Bytes()), marshal(t, f.m), marshal(t, f.p), marshal(t, a)); err == nil {
		t.Fatal("prefixed physical ZIP layout accepted")
	}
	wrong := archivePin(good)
	wrong.Bytes++
	if _, err := CheckArchive(bytes.NewReader(good), int64(len(good)), wrong, marshal(t, f.m), marshal(t, f.p), marshal(t, a)); err == nil {
		t.Fatal("archive size pin was ignored")
	}
	wrong = archivePin(good)
	wrong.SHA256 = independentSHA([]byte("other"))
	if _, err := CheckArchive(bytes.NewReader(good), int64(len(good)), wrong, marshal(t, f.m), marshal(t, f.p), marshal(t, a)); err == nil {
		t.Fatal("archive hash pin was ignored")
	}
}

func TestActualQualifiedGoArchive(t *testing.T) {
	c := actualContents(t)
	f := c.f
	a := archivePolicyFixture(t, f)
	var first, second bytes.Buffer
	if _, err := CheckContents(marshal(t, f.m), marshal(t, f.p), marshal(t, c.policy), f.root, c.root); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteArchive(&first, marshal(t, f.m), marshal(t, f.p), marshal(t, a), f.root); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteArchive(&second, marshal(t, f.m), marshal(t, f.p), marshal(t, a), f.root); err != nil || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("actual qualified Go subject did not package deterministically")
	}
	pin := archivePin(first.Bytes())
	r, err := CheckArchive(bytes.NewReader(first.Bytes()), int64(first.Len()), pin, marshal(t, f.m), marshal(t, f.p), marshal(t, a))
	if err != nil || !r.ArchiveSelectionVerified || r.SBOMContentsVerified || r.ProvenanceSignaturesVerified || r.ReleaseAccepted {
		t.Fatal("actual archive scope or byte closure is wrong")
	}
	path := filepath.Join(t.TempDir(), "candidate.zip")
	if err := os.WriteFile(path, first.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckArchiveFile(path, pin, marshal(t, f.m), marshal(t, f.p), marshal(t, a)); err != nil {
		t.Fatal(err)
	}
	linked := path + ".link"
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckArchiveFile(linked, pin, marshal(t, f.m), marshal(t, f.p), marshal(t, a)); err == nil {
		t.Fatal("linked archive accepted")
	}
}
