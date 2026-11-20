package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/Zenoglyphs-VM/zvm-core/release"
)

func init() {
	register("release-observe-image", "compare a running Docker container with a signed release image", func(args []string) error {
		return releaseObserveImage(args, os.Stdout)
	})
}

func releaseObserveImage(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-observe-image", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	signatures := fs.String("signatures", "", "detached signature envelope")
	keys := fs.String("trusted-keys", "", "independently provisioned public-key inventory")
	var target release.ImageTarget
	fs.StringVar(&target.ImageID, "image", "", "image ID from the signed manifest")
	fs.StringVar(&target.ContainerID, "container", "", "complete Docker container ID")
	fs.StringVar(&target.DockerContext, "docker-context", "", "observer's Docker context")
	fs.StringVar(&target.OCIRoot, "oci-root", "", "local root containing content-addressed OCI JSON blobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *policy == "" || *signatures == "" || *keys == "" || fs.NArg() != 0 {
		return errors.New("manifest, policy, signatures and trusted keys are required")
	}
	m, p, s, k, err := signedReleaseInputs(*manifest, *policy, *signatures, *keys)
	if err != nil {
		return err
	}
	observation, err := m.ObserveImage(context.Background(), p, s, k, target)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(observation)
}
