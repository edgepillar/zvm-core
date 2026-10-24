package release

import (
	"errors"
	"io"
	"os"
)

// ReadDocument is a bounded regular-file read for public release inputs.
// Errors intentionally omit machine paths and raw filesystem diagnostics.
func ReadDocument(name string) ([]byte, error) {
	return readBoundedDocument(name, MaxDocumentBytes)
}

func ReadProtocolPolicyDocument(name string) ([]byte, error) {
	return readBoundedDocument(name, MaxProtocolPolicyBytes)
}

func readBoundedDocument(name string, limit int) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("release document is missing, linked or exceeds its size limit")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, errors.New("release document could not be opened")
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("release document changed before reading")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, errors.New("release document read failed or exceeded its limit")
	}
	return raw, nil
}
