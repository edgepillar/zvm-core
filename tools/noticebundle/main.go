//go:build unix

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const readme = `Source notice observations for this exact CLI binary

manifest.json ties the CLI digest to its selected packages, nominal and
effective Go module identities, source and embedded-file digests, and notice
references. Each object filename is the SHA-256 of its original notice bytes.
The package paths point to reviewed source inputs, including notices inherited
from package ancestors and copyright or license text in initial source comments.

A versioned supplement retains original upstream notice text for a selected
package when the corresponding module archive omits it. The supplement records
the matching source files, module manifest and upstream Git object identifiers.

Legal review, corresponding source, relinking, Alpine notice texts and
compiler-intermediate coverage are tracked as separate distribution requirements.
The CI image observation binds this manifest to the checked source and image.

`

func collectBundle(output, binary string) (manifest, error) {
	result := manifest{Schema: 2, Status: "SOURCE_NOTICE_BUNDLE_FAILED_OR_INCOMPLETE", Entry: rootModule + "/cmd/zvm",
		RootLocks: map[string]string{}, Objects: map[string]int{}, Commands: []commandPin{},
		Modules: []moduleObservation{}, Packages: []packageObservation{},
		CorrespondingSourceOrRelinkingReview: "NOT_ASSESSED", APKLicenseTextReview: "NOT_ASSESSED",
		SourceScope: "Source files and embedded material selected for the non-test CLI build."}
	if err := os.Mkdir(output, 0755); err != nil {
		return result, safeError("new_output_directory")
	}
	project, err := os.Getwd()
	if err != nil {
		return result, safeError("project_directory")
	}
	run := func(label string, args ...string) ([]byte, error) {
		raw, pin, err := command(label, args...)
		result.Commands = append(result.Commands, pin)
		return raw, err
	}
	raw, err := run("profile", "env", "-json", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED", "GOROOT", "GOMOD")
	if err != nil {
		return result, safeError("profile_command")
	}
	var privateProfile map[string]string
	if err := uniqueJSON(raw, &privateProfile); err != nil {
		return result, safeError("profile_json")
	}
	if privateProfile["GOVERSION"] != "go1.26.11" || privateProfile["GOOS"] != "linux" ||
		privateProfile["CGO_ENABLED"] != "0" || !portable(privateProfile["GOARCH"]) ||
		!filepath.IsAbs(privateProfile["GOROOT"]) || privateProfile["GOMOD"] != filepath.Join(project, "go.mod") {
		return result, safeError("selected_build_profile")
	}
	result.Profile = map[string]string{}
	for _, name := range []string{"GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED"} {
		result.Profile[name] = privateProfile[name]
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := readRegular(project, filepath.Join(project, name), 16<<20)
		if err != nil {
			return result, safeError("root_locks")
		}
		result.RootLocks[name] = hash(data)
	}
	raw, err = run("selected_packages", "list", "-deps", "-f", listTemplate(), "./cmd/zvm")
	if err != nil {
		return result, safeError("selected_packages_command")
	}
	packages, err := parsePackages(raw)
	if err != nil {
		return result, safeError("package_projection")
	}
	c := newCollector()
	result.Packages, err = c.collect(packages, project, privateProfile["GOROOT"], privateProfile["GOVERSION"])
	if err != nil {
		return result, safeError("source_notice_collection")
	}
	if _, exists := c.modules[rootModule]; !exists {
		return result, safeError("required_source_module")
	}
	for _, name := range []string{"LICENSE", "NOTICE.md"} {
		if err := c.notice(rootModule, project, filepath.Join(project, name), "REQUIRED_PROJECT_NOTICE"); err != nil {
			return result, safeError("required_project_notices")
		}
	}
	if _, exists := c.modules["std"]; !exists {
		return result, safeError("missing_sdk_packages")
	}
	if err := c.notice("std", privateProfile["GOROOT"], filepath.Join(privateProfile["GOROOT"], "LICENSE"), "REQUIRED_SDK_NOTICE"); err != nil {
		return result, safeError("required_sdk_notice")
	}
	registry, err := readRegular(project, filepath.Join(project, supplementRegistryPath), 1<<20)
	if err != nil {
		return result, safeError("source_supplement_registry")
	}
	if err := c.supplements(project, registry); err != nil {
		return result, safeError("source_supplement_binding")
	}
	result.BinarySHA256, result.BinaryBytes, err = readBinary(binary, result.Profile, c.modules)
	if err != nil {
		return result, safeError("binary_module_binding")
	}
	result.BinaryModulesMatched = true
	if _, err := run("verify_after", "mod", "verify"); err != nil {
		return result, safeError("module_verification_after")
	}
	for name, want := range result.RootLocks {
		data, err := readRegular(project, filepath.Join(project, name), 16<<20)
		if err != nil || hash(data) != want {
			return result, safeError("source_locks_after")
		}
	}
	for _, key := range sortedKeys(c.modules) {
		module := c.modules[key]
		sort.Slice(module.Notices, func(i, j int) bool { return module.Notices[i].Path < module.Notices[j].Path })
		module.MissingNoticeFiles = len(module.Notices) == 0
		result.Modules = append(result.Modules, *module)
	}
	for digest, raw := range c.objects {
		result.Objects[digest] = len(raw)
	}
	result.Status = "SOURCE_NOTICE_BUNDLE_RECORDED_REVIEW_REQUIRED"
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil || len(encoded) > maxManifest {
		return result, safeError("manifest_output_cap")
	}
	if err := os.Mkdir(filepath.Join(output, "objects"), 0755); err != nil {
		return result, safeError("object_directory")
	}
	for _, digest := range sortedKeys(c.objects) {
		if err := writeNew(filepath.Join(output, "objects", digest), c.objects[digest]); err != nil {
			return result, safeError("object_write")
		}
	}
	if err := writeNew(filepath.Join(output, "README.txt"), []byte(readme)); err != nil {
		return result, safeError("readme_write")
	}
	if err := writeNew(filepath.Join(output, "manifest.json"), append(encoded, '\n')); err != nil {
		return result, safeError("manifest_write")
	}
	return result, nil
}

func main() {
	output := flag.String("output", "", "new notice output directory")
	binary := flag.String("binary", "", "already built CLI binary")
	flag.Parse()
	if *output == "" || *binary == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "output and binary are required")
		os.Exit(2)
	}
	result, err := collectBundle(*output, *binary)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		data, _ := json.Marshal(struct {
			Status   string       `json:"status"`
			Commands []commandPin `json:"commands"`
			Legal    bool         `json:"legalReviewComplete"`
		}{
			"SOURCE_NOTICE_BUNDLE_FAILED_OR_INCOMPLETE", result.Commands, false})
		fmt.Println(string(data))
		os.Exit(2)
	}
	data, _ := json.Marshal(map[string]any{"status": result.Status, "packages": len(result.Packages), "modules": len(result.Modules),
		"noticeObjects": len(result.Objects), "legalReviewComplete": false, "releaseAccepted": false})
	fmt.Println(string(data))
}
