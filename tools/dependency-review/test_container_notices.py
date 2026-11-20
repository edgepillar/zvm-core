import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from container_inventory import image_projection
from container_notices import PREDEPLOY_NOTICE_PREFIX, ROOT_MODULE, payload_rows, verify_bundle, verify_predeploy_notices
from govulncheck_review import ReviewError


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class ImageProjectionTests(unittest.TestCase):
    def test_docker_optional_user_field_preserves_default_and_explicit_values(self):
        metadata = {"id": "sha256:" + "a" * 64, "os": "linux", "architecture": "amd64", "entrypoint": ["zvm"]}
        for value, expected_user, present in ((None, "", False), ("", "", True), ("65534:65534", "65534:65534", True)):
            with self.subTest(value=value):
                image, user_present = image_projection(json.dumps({**metadata, "user": value}).encode())
                self.assertEqual(image, {**metadata, "user": expected_user})
                self.assertIs(user_present, present)


class ContainerNoticeTests(unittest.TestCase):
    def setUp(self):
        self.project = Path("fixture")
        self.checked = {"LICENSE": b"project license", "NOTICE.md": b"project notice",
                        "l2/predeploys/fixture.hex": b"ab"}
        self.project_notices = [{"path": name, **pin(self.checked[name])} for name in ("LICENSE", "NOTICE.md")]
        self.std_notice = {"path": "LICENSE", **pin(b"standard library license")}
        self.header = pin(b"// copyright fixture\n")
        self.embedded = {"path": "l2/predeploys/fixture.hex", **pin(self.checked["l2/predeploys/fixture.hex"])}
        self.license = b"original predeploy license"
        self.catalog = {"schema": 1, "legalReviewComplete": False, "licenseFiles": {"fixture.txt": pin(self.license)},
                        "predeploys": {self.embedded["path"]: {"sha256": self.embedded["sha256"],
                                                              "licenseFiles": ["fixture.txt"]}}}
        self.catalog_path = PREDEPLOY_NOTICE_PREFIX + "sources.json"
        self.license_path = PREDEPLOY_NOTICE_PREFIX + "fixture.txt"
        self.set_predeploy_file(self.catalog_path, json.dumps(self.catalog).encode())
        self.set_predeploy_file(self.license_path, self.license)
        self.pins = [*self.project_notices, self.std_notice, self.header]
        self.module = ROOT_MODULE + "/cmd/zvm"
        self.binary = pin(b"binary")["sha256"]
        self.image = {"os": "linux", "architecture": "amd64"}
        self.source = {"goModSha256": pin(b"go.mod")["sha256"], "goSumSha256": pin(b"go.sum")["sha256"]}
        self.manifest = {
            "schema": 2, "status": "SOURCE_NOTICE_BUNDLE_RECORDED_REVIEW_REQUIRED",
            "entryPackage": self.module, "binaryModuleIdentitiesMatched": True,
            "binarySha256": self.binary, "binaryBytes": 6, "legalReviewComplete": False,
            "completeSBOM": False, "releaseAccepted": False, "privatePathsExported": False,
            "rootLockSha256": {"go.mod": self.source["goModSha256"], "go.sum": self.source["goSumSha256"]},
            "profile": {"GOVERSION": "go1.26.11", "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"},
            "objects": {row["sha256"]: row["bytes"] for row in self.pins},
            "modules": [
                {"identity": {"path": ROOT_MODULE, "effectivePath": ROOT_MODULE},
                 "notices": self.project_notices, "noCandidateNoticeFileObserved": False},
                {"identity": {"path": "std", "effectivePath": "std"},
                 "notices": [self.std_notice], "noCandidateNoticeFileObserved": False}],
            "packages": [{"path": self.module, "module": ROOT_MODULE,
                          "selectedSourceFiles": [{"path": "cmd/zvm/main.go", **pin(b"go source"),
                                                   "initialNoticeObject": self.header["sha256"]}],
                          "embeddedFiles": [self.embedded]}],
        }
        self.observed = {"objects/" + row["sha256"]: {key: row[key] for key in ("bytes", "sha256")}
                         for row in self.pins}
        self.observed["README.txt"] = pin(b"bundle guide")

    def set_predeploy_file(self, path, content):
        self.checked[path] = content
        self.project_notices.append({"path": path, **pin(content), "selectionScope": "MODULE_NOTICE_DIRECTORY"})

    def verify_predeploys(self):
        notices = {row["path"]: row for row in self.project_notices}
        embedded = {self.embedded["path"]: self.embedded["sha256"]}
        with patch("container_notices.file_bytes",
                   side_effect=lambda path, limit: self.checked[path.relative_to(self.project).as_posix()]):
            return verify_predeploy_notices(self.project, embedded, notices)

    def verify(self):
        raw = (json.dumps(self.manifest) + "\n").encode()
        with patch("container_notices.file_bytes",
                   side_effect=lambda path, limit: self.checked[path.relative_to(self.project).as_posix()]):
            return verify_bundle(raw, self.observed, self.image, self.source, self.binary, self.project)

    def test_inventory_binds_every_referenced_object_and_embedded_file(self):
        lines = [f"{row['bytes']} {path}\n" for path, row in self.observed.items()]
        lines += [f"{row['sha256']}  {path}\n" for path, row in self.observed.items()]
        self.assertEqual(payload_rows("".join(lines).encode()), self.observed)
        result = self.verify()
        self.assertEqual(result["objectCount"], 6)
        self.assertEqual(result["projectEmbeddedFiles"], {self.embedded["path"]: self.embedded["sha256"]})
        self.assertEqual(result["predeployNotices"], {
            "catalogSHA256": pin(self.checked[self.catalog_path])["sha256"], "thirdPartyEmbeddedFiles": 1,
            "licenseTexts": 1, "licenseTextBytes": len(self.license), "legalReviewComplete": False,
        })

    def test_missing_predeploy_notice_is_rejected(self):
        self.project_notices.pop()
        with self.assertRaisesRegex(ReviewError, "predeploy notice inventory differs"):
            self.verify_predeploys()

    def test_changed_predeploy_license_and_stale_embedded_digest_are_rejected(self):
        self.checked[self.license_path] = b"rewritten license"
        with self.assertRaisesRegex(ReviewError, "original byte pin"):
            self.verify_predeploys()
        self.checked[self.license_path] = self.license
        self.embedded["sha256"] = "0" * 64
        with self.assertRaisesRegex(ReviewError, "catalog output or license reference"):
            self.verify_predeploys()

    def test_changed_binary_or_lock_is_rejected(self):
        self.manifest["binarySha256"] = "0" * 64
        with self.assertRaisesRegex(ReviewError, "observed CLI"):
            self.verify()
        self.manifest["binarySha256"] = self.binary
        self.manifest["rootLockSha256"]["go.sum"] = "0" * 64
        with self.assertRaisesRegex(ReviewError, "build inputs"):
            self.verify()

    def test_object_bytes_and_references_are_independently_checked(self):
        key = "objects/" + self.header["sha256"]
        self.observed[key]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ReviewError, "payload differs"):
            self.verify()
        self.observed[key] = self.header
        del self.manifest["packages"][0]["selectedSourceFiles"][0]["initialNoticeObject"]
        with self.assertRaisesRegex(ReviewError, "object closure"):
            self.verify()

    def test_embedded_bytes_must_match_the_checked_source(self):
        self.checked[self.embedded["path"]] = b"changed"
        with self.assertRaisesRegex(ReviewError, "embedded project file differs"):
            self.verify()

    def test_truncated_or_duplicate_payload_stream_is_rejected(self):
        with self.assertRaisesRegex(ReviewError, "incomplete"):
            payload_rows(b"1 README.txt")
        with self.assertRaisesRegex(ReviewError, "duplicate"):
            payload_rows(b"1 README.txt\n1 README.txt\n")
