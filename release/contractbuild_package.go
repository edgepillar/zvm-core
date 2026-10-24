package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const (
	maxBuildPackageArchives   = 16
	maxBuildPackageCompressed = 32 << 20
	maxBuildPackageExpanded   = 64 << 20
	maxBuildPackageMembers    = 4096
)

var npmPackageName = regexp.MustCompile(`^(@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*$`)

type buildPackageArchive struct {
	files         map[string][]byte
	name, version string
	integrity     [sha512.Size]byte
}

type buildPackageReader struct {
	files, sources                *os.Root
	pins                          map[string]File
	archives                      map[string]buildPackageArchive
	locks                         map[string]map[string]json.RawMessage
	compressed, expanded, members int
}

func newBuildPackageReader(files, sources *os.Root, pins map[string]File) *buildPackageReader {
	return &buildPackageReader{files: files, sources: sources, pins: pins, archives: map[string]buildPackageArchive{}, locks: map[string]map[string]json.RawMessage{}}
}

// Selected fields are case-sensitive even though encoding/json struct decoding
// otherwise accepts aliases. Other npm metadata fields remain opaque data.
func packageObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	if err := compilerJSON(raw, MaxDocumentBytes); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, errors.New("package metadata is not an object")
	}
	for key := range object {
		for _, field := range fields {
			if key != field && strings.EqualFold(key, field) {
				return nil, errors.New("package metadata case alias refused")
			}
		}
	}
	return object, nil
}

func packageString(object map[string]json.RawMessage, key string) (string, error) {
	var value string
	if json.Unmarshal(object[key], &value) != nil || value == "" {
		return "", errors.New("package metadata string missing")
	}
	return value, nil
}

// This reader intentionally accepts the locked USTAR subset only. It never
// writes extracted files. All headers, including unselected members, are
// checked; limits are shared across the entire build, not renewed per source.
func readBuildPackage(raw []byte, byteLimit, memberLimit int) (buildPackageArchive, int, int, error) {
	var archive buildPackageArchive
	if byteLimit <= 0 || byteLimit > maxBuildPackageExpanded || memberLimit <= 0 || memberLimit > maxBuildPackageMembers {
		return archive, 0, 0, errors.New("invalid package parsing budget")
	}
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return archive, 0, 0, errors.New("invalid package gzip stream")
	}
	plain, readErr := io.ReadAll(io.LimitReader(z, int64(byteLimit)+1))
	closeErr := z.Close()
	if readErr != nil || closeErr != nil || len(plain) > byteLimit || len(plain) == 0 || len(plain)%512 != 0 {
		return archive, 0, 0, errors.New("package decompression or byte bound refused")
	}
	input := bytes.NewReader(plain)
	reader := tar.NewReader(input)
	seen := map[string]bool{}
	files := map[string][]byte{}
	count := 0
	markerOffset := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return archive, 0, 0, errors.New("invalid package tar header")
		}
		count++
		name := strings.TrimSuffix(header.Name, "/")
		if count > memberLimit || header.Format != tar.FormatUSTAR || !relative(name) || !strings.HasPrefix(name, "package/") || seen[strings.ToLower(name)] || header.Linkname != "" || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir) || header.Size < 0 || header.Size > 8<<20 || (header.Typeflag == tar.TypeDir && header.Size != 0) {
			return archive, 0, 0, errors.New("unsafe, duplicate, unsupported or oversized package member")
		}
		seen[strings.ToLower(name)] = true
		payloadStart := len(plain) - input.Len()
		payloadEnd := payloadStart + int(header.Size)
		markerOffset = payloadStart + int((header.Size+511)/512)*512
		if markerOffset > len(plain) {
			return archive, 0, 0, errors.New("package member padding is truncated")
		}
		for _, b := range plain[payloadEnd:markerOffset] {
			if b != 0 {
				return archive, 0, 0, errors.New("package member padding is noncanonical")
			}
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if strings.HasSuffix(name, ".sol") || name == "package/package.json" {
			if header.Size > 1<<20 {
				return archive, 0, 0, errors.New("package source or identity file exceeds one MiB")
			}
			payload, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
			if err != nil || int64(len(payload)) != header.Size {
				return archive, 0, 0, errors.New("package member is incomplete")
			}
			files[name] = payload
		}
	}
	// tar.Reader stops at the end marker. Extra compressed members and trailing
	// nonzero tar data cannot become a second unreviewed interpretation.
	if len(plain)-markerOffset < 1024 {
		return archive, 0, 0, errors.New("package end markers are missing")
	}
	// These bytes start after the last member's complete padded payload.
	// A zero-filled payload cannot stand in for the required end blocks.
	for _, b := range plain[markerOffset:] {
		if b != 0 {
			return archive, 0, 0, errors.New("package has trailing nonzero data")
		}
	}
	identity, err := packageObject(files["package/package.json"], "name", "version")
	if err != nil {
		return archive, 0, 0, err
	}
	name, err := packageString(identity, "name")
	if err != nil {
		return archive, 0, 0, err
	}
	version, err := packageString(identity, "version")
	if err != nil {
		return archive, 0, 0, err
	}
	return buildPackageArchive{files: files, name: name, version: version}, len(plain), count, nil
}

func (r *buildPackageReader) lock(pin File) (map[string]json.RawMessage, error) {
	if object, ok := r.locks[pin.ID]; ok {
		return object, nil
	}
	if pin.ID == "" || pin.Kind != "lock" {
		return nil, errors.New("package source must bind a dependency lock file")
	}
	raw, err := readPin(r.files, pin, MaxDocumentBytes)
	if err != nil {
		return nil, err
	}
	if _, err := readPin(r.sources, pin, MaxDocumentBytes); err != nil {
		return nil, errors.New("dependency lock disagrees with its declared clean source checkout")
	}
	object, err := packageObject(raw, "lockfileVersion", "packages")
	if err != nil {
		return nil, err
	}
	var version uint32
	if json.Unmarshal(object["lockfileVersion"], &version) != nil || (version != 2 && version != 3) {
		return nil, errors.New("only exact npm lock version two or three is supported")
	}
	var packages map[string]json.RawMessage
	if json.Unmarshal(object["packages"], &packages) != nil || packages == nil {
		return nil, errors.New("npm package inventory missing")
	}
	r.locks[pin.ID] = packages
	return packages, nil
}

func (r *buildPackageReader) source(source ContractBuildSource, pin File) ([]byte, error) {
	declared := source.Member != "" || source.LockFile != "" || source.PackageKey != "" || source.PackageName != "" || source.PackageVersion != ""
	if !declared {
		raw, err := readPin(r.files, pin, 1<<20)
		if err != nil {
			return nil, err
		}
		if _, err := readPin(r.sources, pin, 1<<20); err != nil {
			return nil, errors.New("compiler source disagrees with its declared source checkout")
		}
		return raw, nil
	}
	if !relative(source.Member) || !strings.HasPrefix(source.Member, "package/") || !strings.HasSuffix(source.Member, ".sol") || !identifier.MatchString(source.LockFile) || !relative(source.PackageKey) || !npmPackageName.MatchString(source.PackageName) || len(source.PackageName) > 214 || !version.MatchString(source.PackageVersion) || source.Unit != source.PackageName+"/"+strings.TrimPrefix(source.Member, "package/") || (source.PackageKey != "node_modules/"+source.PackageName && !strings.HasSuffix(source.PackageKey, "/node_modules/"+source.PackageName)) {
		return nil, errors.New("incomplete or inconsistent package/member source binding")
	}
	lockPin := r.pins[source.LockFile]
	if lockPin.Repository != pin.Repository {
		return nil, errors.New("package archive and source lock must share their owning repository")
	}
	packages, err := r.lock(lockPin)
	if err != nil {
		return nil, err
	}
	entry, err := packageObject(packages[source.PackageKey], "version", "integrity", "resolved", "link")
	if err != nil {
		return nil, err
	}
	lockedVersion, err := packageString(entry, "version")
	if err != nil || lockedVersion != source.PackageVersion {
		return nil, errors.New("package source version disagrees with the locked entry")
	}
	if value, exists := entry["link"]; exists && !bytes.Equal(bytes.TrimSpace(value), []byte("false")) {
		return nil, errors.New("linked or ambiguous package sources are refused")
	}
	resolved, err := packageString(entry, "resolved")
	if err != nil {
		return nil, err
	}
	location, err := url.Parse(resolved)
	if err != nil || location.Scheme != "https" || location.Host == "" || location.User != nil || location.Fragment != "" {
		return nil, errors.New("package source requires a credential-free HTTPS distribution label")
	}
	integrity, err := packageString(entry, "integrity")
	if err != nil || !strings.HasPrefix(integrity, "sha512-") {
		return nil, errors.New("package source requires exact SHA-512 integrity")
	}
	expected, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(integrity, "sha512-"))
	if err != nil || len(expected) != sha512.Size || "sha512-"+base64.StdEncoding.EncodeToString(expected) != integrity {
		return nil, errors.New("noncanonical package integrity")
	}
	archive, exists := r.archives[pin.ID]
	if !exists {
		if len(r.archives) >= maxBuildPackageArchives || pin.Bytes > 16<<20 || int64(r.compressed)+pin.Bytes > maxBuildPackageCompressed {
			return nil, errors.New("package archive inventory or compressed byte budget exceeded")
		}
		raw, err := readPin(r.files, pin, 16<<20)
		if err != nil {
			return nil, err
		}
		actual := sha512.Sum512(raw)
		if !bytes.Equal(actual[:], expected) {
			return nil, errors.New("package archive SHA-512 integrity mismatch")
		}
		var expanded, count int
		archive, expanded, count, err = readBuildPackage(raw, maxBuildPackageExpanded-r.expanded, maxBuildPackageMembers-r.members)
		if err != nil {
			return nil, err
		}
		archive.integrity = actual
		r.compressed += len(raw)
		r.expanded += expanded
		r.members += count
		r.archives[pin.ID] = archive
	} else {
		// The same artifact ID may be used by many source units, but a different
		// lock/key cannot silently reinterpret that cached distribution digest.
		if !bytes.Equal(archive.integrity[:], expected) {
			return nil, errors.New("cached package archive integrity disagrees with the locked entry")
		}
	}
	if archive.name != source.PackageName || archive.version != source.PackageVersion {
		return nil, errors.New("package identity disagrees with source and lock")
	}
	raw, present := archive.files[source.Member]
	if !present {
		return nil, errors.New("literal package source member is missing")
	}
	return raw, nil
}
