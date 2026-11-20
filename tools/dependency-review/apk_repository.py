"""Verify retained Alpine v2 indexes and APKs selected by the Core image."""

import argparse
from base64 import b64encode
from contextlib import contextmanager, ExitStack
from hashlib import sha1, sha256
from io import BytesIO
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zlib

from apk_inventory import IDENTITY, load_repository_key
from apk_source_delivery import open_directory_file
from apk_source_index import DIGEST, require
from govulncheck_review import ReviewError, file_bytes, unique_object


INDEX_LIMIT = 8 << 20
APK_LIMIT = 32 << 20
CONTROL_LIMIT = 512 << 10
CATALOG_LIMIT = 128 << 10
PACKAGE_FIELDS = {
    "P": ("name", "pkgname"),
    "V": ("version", "pkgver"),
    "A": ("architecture", "arch"),
    "o": ("origin", "origin"),
    "c": ("declaredBuildCommit", "commit"),
    "L": ("declaredLicense", "license"),
    "I": ("declaredInstalledBytes", "size"),
}


def gzip_section(raw, limit):
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    data = decoder.decompress(raw, limit + 1)
    require(decoder.eof and not decoder.unconsumed_tail and 0 < len(data) <= limit,
            "APK gzip member is incomplete or exceeds bounds")
    tail = decoder.unused_data
    return raw[:len(raw) - len(tail)], data, tail


def tar_members(raw, maximum_files, maximum_size):
    members = {}
    with tarfile.open(fileobj=BytesIO(raw), mode="r:") as archive:
        for item in archive:
            require(len(members) < maximum_files and item.isfile() and 0 <= item.size <= maximum_size
                    and item.name not in members and "/" not in item.name, "unexpected APK metadata member")
            with archive.extractfile(item) as stream:
                body = stream.read(item.size + 1)
            require(len(body) == item.size, "APK metadata member is incomplete")
            members[item.name] = body
    return members


@contextmanager
def small_input_fd(data):
    reader, writer = os.pipe()
    try:
        with os.fdopen(writer, "wb") as stream:
            stream.write(data)
        yield reader
    finally:
        os.close(reader)


def verify_rsa_signature(payload, pem, signature):
    require(0 < len(pem) <= 4096 and 0 < len(signature) <= 4096, "APK signature inputs exceed bounds")
    with small_input_fd(pem) as key_fd, small_input_fd(signature) as signature_fd:
        result = subprocess.run(
            ["openssl", "dgst", "-sha1", "-verify", f"/dev/fd/{key_fd}",
             "-signature", f"/dev/fd/{signature_fd}"],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(key_fd, signature_fd), timeout=10,
        )
    require(result.returncode == 0 and result.stdout.strip() == b"Verified OK",
            "APK repository RSA signature verification failed")


def signed_payload(raw, key_path):
    _, signature_tar, payload = gzip_section(raw, 64 << 10)
    signatures = tar_members(signature_tar, 8, 4096)
    expected = ".SIGN.RSA." + key_path.rsplit("/", 1)[-1]
    require(expected in signatures and all(name.startswith(".SIGN.") for name in signatures),
            "APK repository signature for the pinned key is missing")
    return signatures[expected], payload


def verify_repository_key(pem, key):
    require(len(pem) == key["pem"]["bytes"] and sha256(pem).hexdigest() == key["pem"]["sha256"],
            "APK repository public key differs from the publisher pin")


def verify_index(raw, pem, key):
    require(0 < len(raw) <= INDEX_LIMIT, "APK repository index archive size is invalid")
    verify_repository_key(pem, key)
    signature, compressed = signed_payload(raw, key["imagePath"])
    verify_rsa_signature(compressed, pem, signature)
    _, expanded, remainder = gzip_section(compressed, 16 << 20)
    require(not remainder, "APK repository index contains trailing gzip data")
    parts = tar_members(expanded, 2, 16 << 20)
    require(parts.keys() == {"APKINDEX", "DESCRIPTION"} and parts["APKINDEX"].endswith(b"\n"),
            "APK repository index metadata is incomplete")
    records = {}
    count = 0
    for block in parts["APKINDEX"].decode("utf-8").split("\n\n"):
        if not block.strip():
            continue
        row = {}
        for line in block.splitlines():
            field, separator, value = line.partition(":")
            require(separator and re.fullmatch(r"[A-Za-z]", field) and field not in row,
                    "APK repository index field is invalid or duplicated")
            row[field] = value
        require(IDENTITY.fullmatch(row.get("P", "")) and IDENTITY.fullmatch(row.get("V", "")),
                "APK repository index package identity is invalid")
        records.setdefault((row["P"], row["V"]), []).append(row)
        count += 1
        require(count <= 65536, "APK repository index has too many records")
    require(count > 0, "APK repository index is empty")
    return records, count, sha256(signature).hexdigest()


def apk_metadata(raw):
    required = {key for _, key in PACKAGE_FIELDS.values()} | {"datahash"}
    metadata = {}
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        field, separator, value = line.partition(" = ")
        require(separator and field, "APK package metadata line is invalid")
        if field in required:
            require(field not in metadata, "APK package identity field is duplicated")
            metadata[field] = value
    require(metadata.keys() == required and DIGEST.fullmatch(metadata["datahash"]),
            "APK package metadata lacks a pinned identity or data checksum")
    return metadata


def verify_package(raw, expected, pem, key):
    require(0 < len(raw) <= APK_LIMIT, "APK package size is outside the supported bounds")
    signature, payload = signed_payload(raw, key["imagePath"])
    control, raw_control, data = gzip_section(payload, CONTROL_LIMIT)
    identity = "Q1" + b64encode(sha1(control).digest()).decode("ascii")
    require(identity == expected["C"], "APK control digest differs from the expected package identity")
    verify_rsa_signature(control, pem, signature)
    members = tar_members(raw_control, 32, 128 << 10)
    require(".PKGINFO" in members, "APK package metadata is missing")
    metadata = apk_metadata(members[".PKGINFO"])
    require(all(metadata[pkginfo] == expected[field] for field, (_, pkginfo) in PACKAGE_FIELDS.items()),
            "APK package metadata differs from the expected package identity")
    require(data.startswith(b"\x1f\x8b") and sha256(data).hexdigest() == metadata["datahash"],
            "APK data digest differs from the signed control metadata")
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest(), "controlIdentity": identity,
            "dataSHA256": metadata["datahash"], "signatureVerified": True}


def archived_identity(installed, name):
    require(isinstance(installed, list) and 0 < len(installed) <= 512, "invalid installed APK inventory")
    selected = [package for package in installed if package["name"] == name]
    require(len(selected) == 1, "selected package must appear exactly once in the image catalog")
    package = selected[0]
    expected = {field: str(package[source]) for field, (source, _) in PACKAGE_FIELDS.items()}
    expected["C"] = package["installedChecksum"]
    return expected


def review_archived_package(raw, pem, key, installed, name, *, against=()):
    """Verify a publisher-signed APK once for matching installed package records."""
    verify_repository_key(pem, key)
    require(IDENTITY.fullmatch(name), "selected APK package has an invalid name")
    expected = archived_identity(installed, name)
    for catalog in against:
        require(archived_identity(catalog, name) == expected, "installed package identity differs across catalogs")
    archive = verify_package(raw, expected, pem, key)
    return {"name": name, "version": expected["V"], "archive": archive, "archiveVerified": True,
            "installedIdentityMatched": True, "indexSignatureVerified": False, "complete": False,
            "repositoryKeyPEMSHA256": key["pem"]["sha256"]}


def review_repository(raw, pem, key, installed, read_archive=None):
    records, count, signature_digest = verify_index(raw, pem, key)
    require(0 < len(installed) <= 512 and len({row["name"] for row in installed}) == len(installed),
            "selected APK package inventory is empty or duplicated")
    by_name = {}
    for name, version in records:
        by_name.setdefault(name, []).append(version)
    results = []
    for package in installed:
        name, version = package["name"], package["version"]
        require(IDENTITY.fullmatch(name) and IDENTITY.fullmatch(version), "selected APK package has an invalid name")
        row = {"name": name, "version": version, "indexMatched": False, "archiveVerified": False}
        results.append(row)
        matches = records.get((name, version), [])
        if len(matches) != 1:
            row.update(indexRecordCount=len(matches), indexVersions=sorted(by_name.get(name, [])))
            continue
        signed = matches[0]
        different = [source for field, (source, _) in PACKAGE_FIELDS.items()
                     if signed.get(field) != str(package[source])]
        if signed.get("C") != package["installedChecksum"]:
            different.append("installedChecksum")
        if different:
            row["differentFields"] = different
            continue
        require(re.fullmatch(r"[1-9][0-9]{0,7}", signed.get("S", "")) and int(signed["S"]) <= APK_LIMIT,
                "signed APK package size is outside the supported bounds")
        row["indexMatched"] = True
        row["indexArchiveBytes"] = int(signed["S"])
        if read_archive is None:
            continue
        try:
            package_bytes = read_archive(f"{name}-{version}.apk", row["indexArchiveBytes"])
            require(len(package_bytes) == row["indexArchiveBytes"], "APK package size differs from the signed index")
            row["archive"] = verify_package(package_bytes, signed, pem, key)
            row["archiveVerified"] = True
        except FileNotFoundError:
            row["archiveFailure"] = "APK archive is missing"
        except ReviewError as error:
            row["archiveFailure"] = str(error)
        except (ValueError, OSError, tarfile.TarError, zlib.error, subprocess.SubprocessError) as error:
            row["archiveFailure"] = type(error).__name__

    return {
        "indexSHA256": sha256(raw).hexdigest(),
        "indexSignatureSHA256": signature_digest,
        "indexSignatureVerified": True,
        "indexRecordCount": count,
        "repositoryKeyPEMSHA256": key["pem"]["sha256"],
        "selectedPackages": len(results),
        "indexRowsMatched": sum(row["indexMatched"] for row in results),
        "packageArchivesVerified": sum(row["archiveVerified"] for row in results),
        "complete": all(row["archiveVerified"] for row in results),
        "packages": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--index", type=Path, help="retained repository index for the full image inventory")
    mode.add_argument("--archive", help="retained APK for one installed package, or - for stdin")
    parser.add_argument("--key", required=True, help="reviewed public PEM file or - for stdin")
    parser.add_argument("--packages", type=Path, help="directory of exact package archives")
    parser.add_argument("--installed-package", help="image catalog name for --archive")
    parser.add_argument("--against-catalog", action="append", default=[], type=Path,
                        help="additional reviewed installed package catalog for --archive")
    args = parser.parse_args()
    if args.archive is not None and (args.installed_package is None or args.packages is not None):
        parser.error("--archive requires --installed-package and excludes --packages")
    if args.index is not None and args.installed_package is not None:
        parser.error("--installed-package requires --archive")
    if args.index is not None and args.against_catalog:
        parser.error("--against-catalog requires --archive")
    if len(args.against_catalog) > 8:
        parser.error("--against-catalog accepts up to eight additional catalogs")
    if args.archive == args.key == "-":
        parser.error("only one input can use stdin")
    try:
        project = Path.cwd()
        catalog_raw = file_bytes(project / "LICENSES/alpine/sources.json", CATALOG_LIMIT)
        catalog = json.loads(catalog_raw, object_pairs_hook=unique_object)
        installed = catalog["installedPackages"]
        key = load_repository_key(project, installed)
        pem = sys.stdin.buffer.read(4097) if args.key == "-" else file_bytes(Path(args.key), 4096)
        if args.archive is not None:
            additional_raw = [file_bytes(path, CATALOG_LIMIT) for path in args.against_catalog]
            additional = [json.loads(body, object_pairs_hook=unique_object)["installedPackages"]
                          for body in additional_raw]
            raw = (sys.stdin.buffer.read(APK_LIMIT + 1) if args.archive == "-"
                   else file_bytes(Path(args.archive), APK_LIMIT))
            report = review_archived_package(raw, pem, key, installed, args.installed_package, against=additional)
            if additional_raw:
                report["matchedCatalogSHA256s"] = sorted({sha256(body).hexdigest()
                                                          for body in [catalog_raw, *additional_raw]})
            result = 0
        else:
            with ExitStack() as stack:
                read_archive = None
                if args.packages is not None:
                    fd = os.open(args.packages, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    stack.callback(os.close, fd)

                    def read_archive(name, length):
                        with open_directory_file(fd, name) as (stream, size):
                            require(size == length, "APK package size differs from the signed index")
                            return stream.read(length + 1)

                report = review_repository(file_bytes(args.index, INDEX_LIMIT), pem, key, installed, read_archive)
            result = 0 if report["complete"] else 2
        report["catalogSHA256"] = sha256(catalog_raw).hexdigest()
    except (ReviewError, OSError, ValueError, KeyError, TypeError, tarfile.TarError, zlib.error,
            subprocess.SubprocessError) as error:
        failure = str(error) if isinstance(error, ReviewError) else type(error).__name__
        report = {"complete": False, "error": failure}
        result = 2
    print(json.dumps(report, sort_keys=True))
    return result


if __name__ == "__main__":
    sys.exit(main())
