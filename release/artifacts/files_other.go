//go:build !linux && !darwin

package artifacts

import (
	"errors"
	"os"
)

func singleLink(os.FileInfo) bool { return false }

func openEntry(*os.Root, string, bool) (*os.File, error) {
	return nil, errors.New("native file identity checks currently support Linux and macOS hosts only")
}
