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
	register("release-observe-process", "check a Docker process and its files against a signed release", func(args []string) error {
		return releaseObserveProcess(args, os.Stdout)
	})
}

func releaseObserveProcess(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-observe-process", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	signatures := fs.String("signatures", "", "detached signature envelope")
	keys := fs.String("trusted-keys", "", "independently provisioned public-key inventory")
	files := fs.String("files-root", "", "root of signed release files")
	var target release.ImageTarget
	fs.StringVar(&target.ImageID, "image", "", "image ID from the signed manifest")
	fs.StringVar(&target.ContainerID, "container", "", "complete Docker container ID")
	fs.StringVar(&target.DockerContext, "docker-context", "", "Docker context on the observer's Linux host")
	fs.StringVar(&target.OCIRoot, "oci-root", "", "local root containing content-addressed OCI JSON blobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *policy == "" || *signatures == "" || *keys == "" || *files == "" || fs.NArg() != 0 {
		return errors.New("manifest, policy, signatures, trusted keys and files root are required")
	}
	m, p, s, k, err := signedReleaseInputs(*manifest, *policy, *signatures, *keys)
	if err != nil {
		return err
	}
	observation, err := m.ObserveProcess(context.Background(), p, s, k, target, *files)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(observation)
}
