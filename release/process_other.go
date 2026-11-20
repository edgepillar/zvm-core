//go:build !linux

package release

import (
	"context"
	"errors"
)

func verifyProcessFiles(context.Context, dockerSnapshot, []processPin, func() error) error {
	return errors.New("process observation requires the Linux Docker host")
}
