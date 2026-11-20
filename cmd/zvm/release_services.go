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
	register("release-observe-services", "check signed Compose services and completed jobs", func(args []string) error {
		return releaseObserveServices(args, os.Stdout)
	})
}

func bindServicesTarget(fs *flag.FlagSet, target *release.ServicesTarget) {
	fs.StringVar(&target.Project, "project", "", "Compose project")
	fs.StringVar(&target.DockerContext, "docker-context", "", "Docker context on the observer's Linux host")
	fs.StringVar(&target.OCIRoot, "oci-root", "", "local root containing content-addressed OCI JSON blobs")
	fs.StringVar(&target.FilesRoot, "files-root", "", "root of signed release files")
}

func releaseObserveServices(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-observe-services", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	signatures := fs.String("signatures", "", "detached signature envelope")
	keys := fs.String("trusted-keys", "", "independently provisioned public-key inventory")
	var target release.ServicesTarget
	bindServicesTarget(fs, &target)
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
	observation, err := m.ObserveServices(context.Background(), p, s, k, target)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(observation)
}
