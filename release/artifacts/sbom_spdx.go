package artifacts

import (
	"slices"
	"strings"
)

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}
type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}
type spdxReference struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}
type spdxPackage struct {
	ID               string          `json:"SPDXID"`
	Name             string          `json:"name"`
	Version          string          `json:"versionInfo"`
	Download         string          `json:"downloadLocation"`
	FilesAnalyzed    bool            `json:"filesAnalyzed"`
	LicenseConcluded string          `json:"licenseConcluded"`
	LicenseDeclared  string          `json:"licenseDeclared"`
	Copyright        string          `json:"copyrightText"`
	Purpose          string          `json:"primaryPackagePurpose"`
	Comment          string          `json:"comment"`
	Checksums        []spdxChecksum  `json:"checksums,omitempty"`
	References       []spdxReference `json:"externalRefs,omitempty"`
}
type spdxRelationship struct {
	ID      string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}
type spdxDocument struct {
	Version       string             `json:"spdxVersion"`
	DataLicense   string             `json:"dataLicense"`
	ID            string             `json:"SPDXID"`
	Name          string             `json:"name"`
	Namespace     string             `json:"documentNamespace"`
	Creation      spdxCreation       `json:"creationInfo"`
	Comment       string             `json:"comment"`
	Describes     []string           `json:"documentDescribes"`
	Packages      []spdxPackage      `json:"packages"`
	Relationships []spdxRelationship `json:"relationships"`
}

func goSPDX(p GoSBOMPolicy, policySHA string) spdxDocument {
	newPackage := func(id, name, version, purpose, comment string) spdxPackage {
		return spdxPackage{ID: id, Name: name, Version: version, Purpose: purpose, Comment: comment,
			Download: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", Copyright: "NOASSERTION"}
	}
	subject := newPackage("SPDXRef-Artifact", p.Subject.Path, p.Source.Commit, "APPLICATION", "Selected Go executable bytes; candidate version is an independently supplied source reference.")
	subject.Checksums = []spdxChecksum{{"SHA256", p.Subject.SHA256}}
	source := newPackage("SPDXRef-Source", p.MainModule, p.Source.Commit, "SOURCE", "Selected source "+p.Source.Repository+"; go.mod SHA256 "+p.GoModSHA256+"; go.sum SHA256 "+p.GoSumSHA256+". Source bytes/authority are not authenticated by build metadata.")
	toolchain := newPackage("SPDXRef-GoToolchain", "Go toolchain", p.GoVersion, "APPLICATION", "Version reported in embedded build metadata; compiler/runtime bytes and full standard-library file coverage are not authenticated here.")
	doc := spdxDocument{Version: "SPDX-2.3", DataLicense: "CC0-1.0", ID: "SPDXRef-DOCUMENT", Name: p.DocumentName, Namespace: p.DocumentNamespace,
		Creation:  spdxCreation{p.Created, []string{"Tool: zvm-sbom-1"}},
		Comment:   "Profile " + GoSBOMProfile + "; independent policy SHA256 " + policySHA + "; qualification reference SHA256 " + p.QualifiedInputsSHA256 + ". Scope: embedded Go module records. Standard-library files, OS/native packages, embedded assets and license/copyright coverage remain unqualified.",
		Describes: []string{"SPDXRef-Artifact"}, Packages: []spdxPackage{subject, source, toolchain},
		Relationships: []spdxRelationship{{"SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Artifact"}, {"SPDXRef-Artifact", "GENERATED_FROM", "SPDXRef-Source"}, {"SPDXRef-GoToolchain", "BUILD_TOOL_OF", "SPDXRef-Artifact"}}}
	for _, module := range p.Modules {
		id := "SPDXRef-Module-" + sum([]byte(module.Path+"\x00"+module.Version+"\x00"+module.Replacement+"\x00"+module.EffectivePath+"\x00"+module.EffectiveVersion))
		pkg := newPackage(id, module.EffectivePath, module.EffectiveVersion, "LIBRARY", "Requested Go module "+module.Path+"@"+module.Version+"; replacement "+module.Replacement+". h1 is a canonical Go file-tree checksum, not an archive/file SHA-256.")
		pkg.References = []spdxReference{{"OTHER", "https://go.dev/ref/mod#authenticating", module.Sum}}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, spdxRelationship{id, "BUILD_DEPENDENCY_OF", "SPDXRef-Artifact"})
	}
	slices.SortFunc(doc.Packages, func(a, b spdxPackage) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(doc.Relationships, func(a, b spdxRelationship) int {
		return strings.Compare(a.ID+"\x00"+a.Type+"\x00"+a.Related, b.ID+"\x00"+b.Type+"\x00"+b.Related)
	})
	return doc
}
