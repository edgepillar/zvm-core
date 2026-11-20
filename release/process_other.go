//go:build !linux

package release

import (
	"context"
	"errors"
)

type processFilesSnapshot struct{}

func verifyProcessFiles(context.Context, dockerSnapshot, []processPin, func() error, *processFilesSnapshot) error {
	return errors.New("process observation requires the Linux Docker host")
}
