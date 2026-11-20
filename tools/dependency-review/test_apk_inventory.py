import unittest

from apk_inventory import apk_licenses
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
