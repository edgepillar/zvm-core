import json
from pathlib import Path
import unittest

from apk_inventory import apk_licenses, load_repository_key, verify_image_repository_key
from govulncheck_review import ReviewError


BUSYBOX = (b"P:busybox\nV:1.37.0-r20\nA:x86_64\nC:Q1" + b"a" * 28 +
           b"\nI:817380\nL:GPL-2.0-only\no:busybox\nc:" + b"b" * 40 + b"\n")


def stream(body=BUSYBOX, count=1):
    return b"ZVM-APK-LICENSES-2\n" + body + f"\nEND\t{count}\n".encode()


class ApkInventoryTests(unittest.TestCase):
    def test_declarations_retain_build_recipe_checksum_size_and_license(self):
        self.assertEqual(apk_licenses(stream(), ["busybox-1.37.0-r20"]), [{
            "name": "busybox", "version": "1.37.0-r20", "architecture": "x86_64", "origin": "busybox",
            "declaredBuildCommit": "b" * 40, "declaredLicense": "GPL-2.0-only",
            "installedChecksum": "Q1" + "a" * 28, "declaredInstalledBytes": 817380,
            "licenseTextOrLegalQualificationEstablished": False,
        }])

    def test_package_list_and_end_marker_must_match(self):
        with self.assertRaisesRegex(ReviewError, "declaration count"):
            apk_licenses(stream(count=2), ["busybox-1.37.0-r20"])
        with self.assertRaisesRegex(ReviewError, "installed package inventory"):
            apk_licenses(stream(), ["busybox-1.37.0-r19"])
        with self.assertRaisesRegex(ReviewError, "output is incomplete"):
            apk_licenses(stream()[:-1], ["busybox-1.37.0-r20"])

    def test_missing_or_duplicate_fields_and_packages_are_rejected(self):
        for raw in (stream(BUSYBOX.replace(b"L:GPL-2.0-only\n", b"")),
                    stream(BUSYBOX + b"L:MIT\n"),
                    stream(BUSYBOX + b"\n" + BUSYBOX, count=2)):
            with self.subTest(raw=raw), self.assertRaises(ReviewError):
                apk_licenses(raw, ["busybox-1.37.0-r20"])

    def test_repository_key_matches_a_pinned_recipe_and_image_output(self):
        project = Path(__file__).resolve().parents[2]
        catalog = json.loads((project / "LICENSES/alpine/sources.json").read_bytes())
        expected = load_repository_key(project, catalog["installedPackages"])
        digest = expected["pem"]["sha256"]
        path = expected["imagePath"]
        lines = f'{expected["pem"]["bytes"]}\n{digest}  {path}\n'
        observed = verify_image_repository_key(lines.encode("ascii"), expected)
        self.assertTrue(observed["publisherPEMMatchesImage"])
        for wrong in (lines.replace(digest, "0" * 64), lines.replace(path, "/etc/apk/keys/other.rsa.pub"),
                      lines.split("\n", 1)[1], lines + "extra\n"):
            with self.subTest(output=wrong), self.assertRaisesRegex(ReviewError, "image differs"):
                verify_image_repository_key(wrong.encode("ascii"), expected)

    def test_repository_key_does_not_accept_a_different_installed_recipe(self):
        project = Path(__file__).resolve().parents[2]
        packages = json.loads((project / "LICENSES/alpine/sources.json").read_bytes())["installedPackages"]
        changed = [{**row, "declaredBuildCommit": "0" * 40} if row["name"] == "alpine-keys" else row for row in packages]
        with self.assertRaisesRegex(ReviewError, "key package differs"):
            load_repository_key(project, changed)
