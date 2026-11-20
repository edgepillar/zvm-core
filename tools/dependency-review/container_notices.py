"""Verify the notice payload inventory of the same image as the CLI."""

from hashlib import sha256
import json
from pathlib import Path
import re

from govulncheck_review import ReviewError, file_bytes, unique_object


ROOT_MODULE = "github.com/Zenoglyphs-VM/zvm-core"
NOTICE_DIRECTORY = "/usr/share/doc/zvm/notices"
MAX_MANIFEST = 8 << 20
MAX_INVENTORY = 2 << 20
PAYLOAD = r"(?:README\.txt|objects/[0-9a-f]{64})"
SIZE_ROW = re.compile(rf"([0-9]+) ({PAYLOAD})")
DIGEST_ROW = re.compile(rf"([0-9a-f]{{64}})  ({PAYLOAD})")
DIGEST = re.compile(r"[0-9a-f]{64}")
PUBLIC_PATH = re.compile(r"[A-Za-z0-9._~!+/-]+")

MANIFEST_COMMAND = f"""\
test ! -L {NOTICE_DIRECTORY}
cd {NOTICE_DIRECTORY}
test -f manifest.json
test ! -L manifest.json
exec /bin/busybox cat manifest.json
"""

PAYLOAD_COMMAND = f"""\
test ! -L {NOTICE_DIRECTORY}
cd {NOTICE_DIRECTORY}
test -d objects
test ! -L objects
for path in objects/*; do
  test -f "$path"
  test ! -L "$path"
done
for path in objects/.[!.]* objects/..?*; do
  test ! -e "$path"
  test ! -L "$path"
done
test -f README.txt
test ! -L README.txt
/bin/busybox stat -c '%s %n' README.txt objects/*
/bin/busybox sha256sum README.txt objects/*
"""


def require(condition, message):
    if not condition:
        raise ReviewError(message)


def public_path(value):
    return isinstance(value, str) and len(value) <= 1024 and PUBLIC_PATH.fullmatch(value) and all(
        part not in ("", ".", "..") for part in value.split("/"))


def payload_rows(raw):
    sizes, hashes = {}, {}
    require(raw.endswith(b"\n"), "notice object stream is incomplete")
    for line in raw.decode("ascii").splitlines():
        size = SIZE_ROW.fullmatch(line)
        if size:
            count, name = size.groups()
            require(name not in sizes and len(count) <= 6 and 0 <= int(count) <= 128 << 10,
                    "duplicate or oversized notice payload")
            sizes[name] = int(count)
            continue
        digest = DIGEST_ROW.fullmatch(line)
        require(digest is not None, "invalid notice payload row")
        value, name = digest.groups()
        require(name not in hashes, "duplicate notice digest row")
        hashes[name] = value
    require(sizes.keys() == hashes.keys() and sizes.get("README.txt", 0) > 0 and 1 < len(sizes) <= 8193,
            "notice object stream is incomplete")
    return {name: {"bytes": size, "sha256": hashes[name]} for name, size in sizes.items()}


def verify_bundle(raw, observed, image, source, binary_sha256, project):
    require(raw.endswith(b"\n") and len(raw) <= MAX_MANIFEST, "notice manifest is incomplete or oversized")
    manifest = json.loads(raw, object_pairs_hook=unique_object)
    require(manifest["schema"] == 2 and manifest["status"] == "SOURCE_NOTICE_BUNDLE_RECORDED_REVIEW_REQUIRED"
            and manifest["entryPackage"] == ROOT_MODULE + "/cmd/zvm"
            and manifest["binaryModuleIdentitiesMatched"] is True
            and manifest["binarySha256"] == binary_sha256 and 0 < manifest["binaryBytes"] <= 128 << 20,
            "notice manifest differs from the observed CLI")
    require(manifest["rootLockSha256"] == {"go.mod": source["goModSha256"], "go.sum": source["goSumSha256"]}
            and manifest["profile"]["GOOS"] == image["os"] and manifest["profile"]["GOARCH"] == image["architecture"]
            and manifest["profile"]["CGO_ENABLED"] == "0" and manifest["profile"]["GOVERSION"] == "go1.26.11",
            "notice manifest build inputs differ")
    require(all(manifest[field] is False for field in ("legalReviewComplete", "completeSBOM",
                "releaseAccepted", "privatePathsExported")), "notice manifest overstates its evidence")

    objects = manifest["objects"]
    require(isinstance(objects, dict) and 0 < len(objects) <= 8192
            and all(DIGEST.fullmatch(digest) and type(count) is int and 0 <= count <= 128 << 10
                    for digest, count in objects.items()) and sum(objects.values()) <= 8 << 20,
            "notice manifest object inventory differs")
    require(set(observed) == {"README.txt"} | {"objects/" + digest for digest in objects},
            "image notice paths differ from the manifest")
    for digest, count in objects.items():
        require(observed["objects/" + digest] == {"bytes": count, "sha256": digest},
                "image notice payload differs from the manifest")

    modules, referenced = {}, set()
    supplements = 0
    for row in manifest["modules"]:
        identity, notices = row["identity"], row["notices"]
        module = identity["path"]
        require(public_path(module) and public_path(identity["effectivePath"]) and module not in modules
                and (not notices) == row["noCandidateNoticeFileObserved"], "notice module identity or scope differs")
        modules[module] = row
        for notice in notices:
            require(public_path(notice["path"]) and objects.get(notice["sha256"]) == notice["bytes"],
                    "module notice has an invalid object reference")
            referenced.add(notice["sha256"])
            supplements += int("upstreamSupplement" in notice)
    require(1 < len(modules) <= 1024 and "std" in modules and ROOT_MODULE in modules,
            "SDK or project notice module is absent")
    required = {row["path"]: row for row in modules[ROOT_MODULE]["notices"]}
    for path in ("LICENSE", "NOTICE.md"):
        notice = required[path]
        content = file_bytes(project / path, 128 << 10)
        require(len(content) == notice["bytes"] and sha256(content).hexdigest() == notice["sha256"],
                "image project notice differs from the selected source")
    require(any(row["path"] == "LICENSE" for row in modules["std"]["notices"]), "SDK license is absent")

    packages, project_embedded = set(), {}
    source_files = 0
    for row in manifest["packages"]:
        package, module = row["path"], row["module"]
        require(public_path(package) and package not in packages and module in modules,
                "notice package identity or module reference differs")
        packages.add(package)
        source_files += len(row["selectedSourceFiles"])
        for source_file in row["selectedSourceFiles"] + row["embeddedFiles"]:
            require(public_path(source_file["path"]) and DIGEST.fullmatch(source_file["sha256"]),
                    "invalid selected notice source path or digest")
            header = source_file.get("initialNoticeObject")
            if header is not None:
                require(header in objects, "source header notice object is absent")
                referenced.add(header)
        if module == ROOT_MODULE:
            for source_file in row["embeddedFiles"]:
                path = source_file["path"]
                content = file_bytes(project / path, 32 << 20)
                require(len(content) == source_file["bytes"] and sha256(content).hexdigest() == source_file["sha256"],
                        "embedded project file differs from the selected source")
                project_embedded[path] = source_file["sha256"]
    require(manifest["entryPackage"] in packages and 0 < len(packages) <= 4096 and referenced == set(objects),
            "notice source object closure differs")
    return {"status": manifest["status"], "manifestSHA256": sha256(raw).hexdigest(),
            "manifestBytes": len(raw), "binarySHA256": binary_sha256, "selectedPackages": len(packages),
            "dependencyModules": len(modules) - 2, "selectedSourceFiles": source_files,
            "objectCount": len(objects), "objectBytes": sum(objects.values()),
            "sourceSupplements": supplements, "projectEmbeddedFiles": project_embedded,
            "modulesWithoutNoticeFiles": sorted(name for name, row in modules.items()
                if row["noCandidateNoticeFileObserved"]),
            "readme": observed["README.txt"], "completeLicenseReview": False}
