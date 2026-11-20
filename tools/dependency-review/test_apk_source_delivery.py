from hashlib import sha256, sha512
from io import BytesIO
import json
import os
from pathlib import Path
import unittest

from apk_source_delivery import delivery_files, verify_directory_file, verify_payload, verify_selected_files
from apk_source_index import GIT_LINK, RAW_APORTS, git_oid
from govulncheck_review import ReviewError


def byte_pin(data):
    return {"bytes": len(data), "sha256": sha256(data).hexdigest()}


class AlpineSourceDeliveryTests(unittest.TestCase):
    def setUp(self):
        commit = "a" * 40
        tree = {
            "APKBUILD": b"pkgname=example\n",
            "source.patch": b"example patch\n",
            "example.post-install": b"#!/bin/sh\nexit 0\n",
            "example.post-upgrade": b"example.post-install",
        }
        entries = []
        raw_tree = b""
        for name, data in sorted(tree.items()):
            mode = GIT_LINK if name == "example.post-upgrade" else 0o100644
            oid = git_oid("blob", data)
            entry = {"name": name, "type": "blob", "mode": mode, "oid": oid}
            if mode == GIT_LINK:
                entry["linkTarget"] = data.decode("ascii")
            entries.append(entry)
            raw_tree += f"{mode:o} {name}\0".encode() + bytes.fromhex(oid)
        prefix = f"{RAW_APORTS}{commit}/main/example/"
        archive = b"example source archive"
        patch = tree["source.patch"]
        index = {
            "schema": 1,
            "status": "APK_RECIPE_SOURCE_INDEX_REVIEW_REQUIRED",
            "sourceInventory": {},
            "origins": {
                "example": {
                    "recipeCommit": commit,
                    "recipeDirectoryTree": git_oid("tree", raw_tree),
                    "recipeDirectoryEntries": entries,
                    "sources": [
                        {"name": "patch-alias", "kind": "APORTS_SOURCE_FILE", "url": prefix + "source.patch",
                         "sha512": sha512(patch).hexdigest(), **byte_pin(patch)},
                        {"name": "example.tar.gz", "kind": "SOURCE_ARCHIVE", "url": "https://example.org/source.tar.gz",
                         "sha512": sha512(archive).hexdigest(), **byte_pin(archive)},
                    ],
                },
            },
        }
        self.index = json.dumps(index).encode()
        self.catalog = {
            "sourceInventory": {},
            "buildSourceIndex": byte_pin(self.index),
            "origins": {"example": {"recipe": {"commit": commit, "gitBlob": entries[0]["oid"], **byte_pin(tree["APKBUILD"])},
                                    "noticeCandidates": [], "reviewedRecipeInputs": 2}},
        }
        self.payloads = {f"aports/main/example/{name}": raw for name, raw in tree.items()}
        self.payloads["sources/example/example.tar.gz"] = archive

    def read_file(self, name, pin):
        if name not in self.payloads:
            raise ReviewError("selected payload is missing")
        raw = self.payloads[name]
        return verify_payload(BytesIO(raw), len(raw), pin)

    def verify(self):
        return verify_selected_files(self.index, self.catalog, self.read_file)

    def test_all_recipe_files_and_external_inputs_are_required(self):
        _, files = delivery_files(self.index, self.catalog)
        self.assertEqual(files.keys(), self.payloads.keys())
        counts = self.verify()
        self.assertEqual(counts["aportsFilesVerified"], 4)
        self.assertEqual(counts["externalFilesVerified"], 1)
        self.assertEqual(counts["gitLinkTargetsVerified"], 1)
        self.assertEqual(counts["selectedBytesVerified"], sum(map(len, self.payloads.values())))

    def test_missing_install_hook_is_rejected(self):
        del self.payloads["aports/main/example/example.post-install"]
        with self.assertRaisesRegex(ReviewError, "post-install: selected payload is missing"):
            self.verify()

    def test_schema_two_requires_packaging_file_pins_and_verifies_the_bytes(self):
        index = json.loads(self.index)
        index["schema"] = 2
        self.index = json.dumps(index).encode()
        self.catalog["buildSourceIndex"] = byte_pin(self.index)
        with self.assertRaisesRegex(ReviewError, "packaging file pins differ"):
            self.verify()

        name = "example.post-install"
        pinned = byte_pin(self.payloads[f"aports/main/example/{name}"])
        index["origins"]["example"]["packagingFilePins"] = {name: pinned}
        self.index = json.dumps(index).encode()
        self.catalog["buildSourceIndex"] = byte_pin(self.index)
        self.assertEqual(self.verify()["aportsFilesVerified"], 4)

        pinned["sha256"] = "0" * 64
        self.index = json.dumps(index).encode()
        self.catalog["buildSourceIndex"] = byte_pin(self.index)
        with self.assertRaisesRegex(ReviewError, r"post-install: Alpine source payload differs"):
            self.verify()

    def test_changed_archive_local_patch_and_link_are_rejected(self):
        paths = ("sources/example/example.tar.gz", "aports/main/example/source.patch",
                 "aports/main/example/example.post-upgrade")
        for name in paths:
            with self.subTest(name=name):
                original = self.payloads[name]
                self.payloads[name] = b"!" + original[1:]
                with self.assertRaisesRegex(ReviewError, "payload differs from the pinned bytes"):
                    self.verify()
                self.payloads[name] = original

    def test_truncated_stream_is_rejected(self):
        with self.assertRaisesRegex(ReviewError, "payload is incomplete"):
            verify_payload(BytesIO(b"short"), 6, {"bytes": 6})

    def test_directory_reader_uses_the_selected_regular_file(self):
        path = Path(__file__).resolve()
        data = path.read_bytes()
        pin = {**byte_pin(data), "gitBlob": git_oid("blob", data)}
        fd = os.open(path.parent.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            observed = verify_directory_file(fd, f"{path.parent.name}/{path.name}", pin)
        finally:
            os.close(fd)
        self.assertEqual(observed["sha256"], pin["sha256"])
