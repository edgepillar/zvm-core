from base64 import b64encode
import gzip
from hashlib import sha1, sha256
from io import BytesIO
import tarfile
import unittest
from unittest.mock import call, patch

from apk_repository import PACKAGE_FIELDS, review_archived_package, review_repository, verify_index
from govulncheck_review import ReviewError


def gzip_tar(files):
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            archive.addfile(entry, BytesIO(raw))
    return gzip.compress(output.getvalue(), mtime=0)


class ApkRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.pem = b"test publisher key"
        self.key = {"imagePath": "/etc/apk/keys/example.rsa.pub",
                    "pem": {"bytes": len(self.pem), "sha256": sha256(self.pem).hexdigest()}}
        self.signature = b"test signature bytes"
        prefix = gzip_tar({".SIGN.RSA.example.rsa.pub": self.signature})
        self.installed = {
            "name": "example", "version": "1.2.3-r0", "architecture": "x86_64", "origin": "example",
            "declaredBuildCommit": "a" * 40, "declaredLicense": "MIT", "declaredInstalledBytes": 10,
        }
        data = gzip_tar({"usr/share/example": b"test data\n"})
        pkginfo = {field: self.installed[source] for source, field in PACKAGE_FIELDS.values()}
        pkginfo["datahash"] = sha256(data).hexdigest()
        self.control = gzip_tar({".PKGINFO": "".join(f"{k} = {v}\n" for k, v in pkginfo.items()).encode()})
        self.apk = prefix + self.control + data
        row = {field: self.installed[source] for field, (source, _) in PACKAGE_FIELDS.items()}
        row["S"] = len(self.apk)
        row["C"] = "Q1" + b64encode(sha1(self.control).digest()).decode()
        self.installed["installedChecksum"] = row["C"]
        self.compressed_index = gzip_tar({
            "APKINDEX": "".join(f"{k}:{v}\n" for k, v in row.items()).encode(),
            "DESCRIPTION": b"Alpine test index\n",
        })
        self.index = prefix + self.compressed_index

    @patch("apk_repository.verify_rsa_signature")
    def test_exact_index_and_package_have_separately_verified_signatures(self, verify):
        def read_package(name, size):
            self.assertEqual((name, size), ("example-1.2.3-r0.apk", len(self.apk)))
            return self.apk

        report = review_repository(self.index, self.pem, self.key, [self.installed], read_package)
        self.assertTrue(report["complete"])
        self.assertEqual((report["indexRowsMatched"], report["packageArchivesVerified"]), (1, 1))
        self.assertEqual(verify.call_args_list, [
            call(self.compressed_index, self.pem, self.signature),
            call(self.control, self.pem, self.signature),
        ])

    @patch("apk_repository.verify_rsa_signature")
    def test_index_only_and_absent_installed_version_are_incomplete(self, verify):
        report = review_repository(self.index, self.pem, self.key, [self.installed])
        self.assertEqual((report["indexRowsMatched"], report["packageArchivesVerified"]), (1, 0))
        self.assertFalse(report["complete"])
        different = {**self.installed, "version": "1.2.2-r0"}
        report = review_repository(self.index, self.pem, self.key, [different])
        self.assertFalse(report["complete"])
        self.assertEqual(report["indexRowsMatched"], 0)
        self.assertEqual(report["packages"][0]["indexVersions"], ["1.2.3-r0"])

    @patch("apk_repository.verify_rsa_signature")
    def test_archive_with_changed_data_hash_does_not_pass(self, verify):
        changed = self.apk[:-1] + bytes([self.apk[-1] ^ 1])
        report = review_repository(self.index, self.pem, self.key, [self.installed],
                                   lambda name, size: changed)
        self.assertFalse(report["complete"])
        self.assertEqual(report["packageArchivesVerified"], 0)
        self.assertIn("data digest differs", report["packages"][0]["archiveFailure"])

    @patch("apk_repository.verify_rsa_signature")
    def test_index_mode_requires_the_signed_archive_size(self, verify):
        report = review_repository(self.index, self.pem, self.key, [self.installed],
                                   lambda name, size: self.apk[:-1])
        self.assertEqual(report["indexRowsMatched"], 1)
        self.assertFalse(report["complete"])
        self.assertIn("size differs", report["packages"][0]["archiveFailure"])
        verify.assert_called_once_with(self.compressed_index, self.pem, self.signature)

    @patch("apk_repository.verify_rsa_signature")
    def test_archive_signature_failure_is_retained(self, verify):
        verify.side_effect = [None, ReviewError("APK repository RSA signature verification failed")]
        report = review_repository(self.index, self.pem, self.key, [self.installed],
                                   lambda name, size: self.apk)
        self.assertFalse(report["complete"])
        self.assertEqual(report["indexRowsMatched"], 1)
        self.assertEqual(report["packageArchivesVerified"], 0)
        self.assertIn("signature verification failed", report["packages"][0]["archiveFailure"])

    @patch("apk_repository.verify_rsa_signature")
    def test_changed_key_is_rejected_before_using_the_signature(self, verify):
        with self.assertRaisesRegex(ReviewError, "public key differs"):
            verify_index(self.index, self.pem + b"!", self.key)
        verify.assert_not_called()

    @patch("apk_repository.verify_rsa_signature")
    def test_archived_package_matches_installed_identity_without_an_index(self, verify):
        report = review_archived_package(self.apk, self.pem, self.key, [self.installed], "example")
        self.assertTrue(report["archiveVerified"])
        self.assertTrue(report["installedIdentityMatched"])
        self.assertFalse(report["indexSignatureVerified"])
        self.assertFalse(report["complete"])
        verify.assert_called_once_with(self.control, self.pem, self.signature)

    @patch("apk_repository.verify_rsa_signature")
    def test_shared_installation_matches_one_package_signature(self, verify):
        other = {**self.installed, "legalReviewComplete": False}
        report = review_archived_package(self.apk, self.pem, self.key, [self.installed], "example",
                                         against=[[other]])
        self.assertTrue(report["archiveVerified"])
        self.assertFalse(report["complete"])
        verify.assert_called_once_with(self.control, self.pem, self.signature)

    @patch("apk_repository.verify_rsa_signature")
    def test_shared_package_requires_the_same_installed_identity_in_every_catalog(self, verify):
        for changed in ({"architecture": "aarch64"}, {"installedChecksum": "Q1" + "B" * 28}):
            other = {**self.installed, **changed}
            with self.subTest(changed=changed), self.assertRaisesRegex(ReviewError, "differs across catalogs"):
                review_archived_package(self.apk, self.pem, self.key, [self.installed], "example",
                                        against=[[other]])
        with self.assertRaisesRegex(ReviewError, "exactly once"):
            review_archived_package(self.apk, self.pem, self.key, [self.installed], "example",
                                    against=[[self.installed, self.installed]])
        verify.assert_not_called()

    @patch("apk_repository.verify_rsa_signature")
    def test_archived_package_requires_the_exact_installed_checksum_and_publisher_key(self, verify):
        changed = {**self.installed, "installedChecksum": "Q1" + "A" * 28}
        with self.assertRaisesRegex(ReviewError, "control digest differs"):
            review_archived_package(self.apk, self.pem, self.key, [changed], "example")
        with self.assertRaisesRegex(ReviewError, "public key differs"):
            review_archived_package(self.apk, self.pem + b"!", self.key, [self.installed], "example")
        verify.assert_not_called()

    @patch("apk_repository.verify_rsa_signature")
    def test_archived_package_refuses_signature_failure(self, verify):
        verify.side_effect = ReviewError("APK repository RSA signature verification failed")
        with self.assertRaisesRegex(ReviewError, "signature verification failed"):
            review_archived_package(self.apk, self.pem, self.key, [self.installed], "example")
        verify.assert_called_once()
