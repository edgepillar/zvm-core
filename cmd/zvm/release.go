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
	register("release-message", "emit the canonical release signing message without signing", func(args []string) error { return releaseMessage(args, os.Stdout) })
	register("release-verify", "verify a signed release against independent policy and local inputs", func(args []string) error { return releaseVerify(args, os.Stdout) })
}

func releaseDocument(name string) ([]byte, error) {
	return release.ReadDocument(name)
}

func releaseMessage(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-message", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *policy == "" || fs.NArg() != 0 {
		return errors.New("manifest and independent policy are required")
	}
	m, p, err := releaseInputs(*manifest, *policy)
	if err != nil {
		return err
	}
	if err := m.ValidateAgainst(p); err != nil {
		return err
	}
	message, err := m.SigningMessage()
	if err != nil {
		return err
	}
	_, err = w.Write(message)
	return err
}

func releaseInputs(manifest, policy string) (release.Manifest, release.Policy, error) {
	var m release.Manifest
	var p release.Policy
	raw, err := releaseDocument(manifest)
	if err != nil {
		return m, p, err
	}
	m, err = release.DecodeManifest(raw)
	if err != nil {
		return m, p, err
	}
	raw, err = releaseDocument(policy)
	if err != nil {
		return m, p, err
	}
	p, err = release.DecodePolicy(raw)
	return m, p, err
}

func releaseVerify(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release-verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "release manifest")
	policy := fs.String("policy", "", "independently reviewed release inventory")
	signatures := fs.String("signatures", "", "detached signature envelope")
	keys := fs.String("trusted-keys", "", "independently provisioned public-key inventory")
	files := fs.String("files-root", "", "root of repository-relative pinned files")
	sources := fs.String("sources-root", "", "root of clean repository worktrees")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *policy == "" || *signatures == "" || *keys == "" || *files == "" || *sources == "" || fs.NArg() != 0 {
		return errors.New("manifest, policy, signatures, trusted keys, files root and sources root are required")
	}
	m, p, err := releaseInputs(*manifest, *policy)
	if err != nil {
		return err
	}
	raw, err := releaseDocument(*signatures)
	if err != nil {
		return err
	}
	s, err := release.DecodeSignatures(raw)
	if err != nil {
		return err
	}
	raw, err = releaseDocument(*keys)
	if err != nil {
		return err
	}
	k, err := release.DecodeTrustedKeys(raw)
	if err != nil {
		return err
	}
	receipt, err := m.Verify(context.Background(), p, s, k, *files, *sources)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(receipt)
}
