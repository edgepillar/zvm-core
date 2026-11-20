"""Verify the notice payload inventory of the same image as the CLI."""

from hashlib import sha256
import json
from pathlib import Path
import re

from apk_source_index import SOURCE_INDEX, verify_source_index
from govulncheck_review import ReviewError, file_bytes, unique_object
from oci_runtime import runtime_base_reference


ROOT_MODULE = "github.com/Zenoglyphs-VM/zvm-core"
NOTICE_DIRECTORY = "/usr/share/doc/zvm/notices"
PREDEPLOY_NOTICE_PREFIX = "LICENSES/predeploys/"
ALPINE_NOTICE_PREFIX = "LICENSES/alpine/"
PROJECT_PREDEPLOYS = {"l2/predeploys/WrappedQSR.hex", "l2/predeploys/ZVMBridge.hex"}
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


def verify_catalog_files(module_notices, prefix, expected, scope):
    collected = {path.removeprefix(prefix): row for path, row in module_notices.items() if path.startswith(prefix)}
    require(collected.keys() == expected.keys(), f"image {scope} notice inventory differs from the catalog")
    for name, pin in expected.items():
        row = collected[name]
        require(row["selectionScope"] == "MODULE_NOTICE_DIRECTORY"
                and pin == {"bytes": row["bytes"], "sha256": row["sha256"]},
                f"image {scope} notice differs from the checked source")


def verify_predeploy_notices(project, embedded, module_notices):
    catalog_bytes = file_bytes(project / (PREDEPLOY_NOTICE_PREFIX + "sources.json"), 128 << 10)
    catalog = json.loads(catalog_bytes, object_pairs_hook=unique_object)
    require(catalog["schema"] == 1 and catalog["legalReviewComplete"] is False,
            "unexpected predeploy notice catalog scope")
    catalog_pin = {"bytes": len(catalog_bytes), "sha256": sha256(catalog_bytes).hexdigest()}
    expected = {"sources.json": catalog_pin}
    licenses = catalog["licenseFiles"]
    require(isinstance(licenses, dict) and 0 < len(licenses) <= 128, "invalid predeploy license inventory")
    for name, pin in licenses.items():
        require(re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.txt", name) and len(name) <= 128,
                "invalid predeploy license filename")
        content = file_bytes(project / (PREDEPLOY_NOTICE_PREFIX + name), 128 << 10)
        observed = {"bytes": len(content), "sha256": sha256(content).hexdigest()}
        require(observed == {"bytes": pin["bytes"], "sha256": pin["sha256"]},
                "predeploy license differs from its original byte pin")
        expected[name] = observed

    verify_catalog_files(module_notices, PREDEPLOY_NOTICE_PREFIX, expected, "predeploy")

    targets = catalog["predeploys"]
    third_party = {path: digest for path, digest in embedded.items()
                   if path.startswith("l2/predeploys/") and path not in PROJECT_PREDEPLOYS}
    require(isinstance(targets, dict) and 0 < len(targets) <= 128 and targets.keys() == third_party.keys(),
            "predeploy catalog does not cover the embedded third party files")
    referenced = set()
    for path, row in targets.items():
        references = row["licenseFiles"]
        require(row["sha256"] == third_party[path] and isinstance(references, list)
                and 0 < len(references) <= len(licenses) and set(references) <= licenses.keys(),
                "predeploy catalog output or license reference differs")
        referenced.update(references)
    require(referenced == licenses.keys(), "predeploy license lacks a catalog reference")
    return {"catalogSHA256": catalog_pin["sha256"], "thirdPartyEmbeddedFiles": len(targets),
            "licenseTexts": len(licenses), "licenseTextBytes": sum(row["bytes"] for row in licenses.values()),
            "legalReviewComplete": False}


def verify_alpine_notices(project, image, installed, module_notices):
    catalog_bytes = file_bytes(project / (ALPINE_NOTICE_PREFIX + "sources.json"), 128 << 10)
    catalog = json.loads(catalog_bytes, object_pairs_hook=unique_object)
    require(catalog["schema"] == 1 and catalog["status"] == "APK_SOURCE_NOTICE_CANDIDATES_REVIEW_REQUIRED"
            and all(catalog[key] is False for key in ("legalReviewComplete", "completeCorrespondingSource",
                                                     "sourceOriginAuthenticated")),
            "unexpected Alpine notice catalog scope")
    profile = catalog["profile"]
    dockerfile = file_bytes(project / "Dockerfile", 64 << 10).decode("ascii")
    require(profile["os"] == image["os"] and profile["architecture"] == image["architecture"]
            and profile["baseImage"] == runtime_base_reference(dockerfile),
            "Alpine catalog profile differs from the selected image build")
    require(catalog["installedPackages"] == installed, "Alpine catalog differs from installed package declarations")

    by_origin = {}
    for row in installed:
        by_origin.setdefault(row["origin"], set()).add(row["declaredBuildCommit"])
    origins = catalog["origins"]
    require(isinstance(origins, dict) and 0 < len(origins) <= 512 and origins.keys() == by_origin.keys(),
            "Alpine catalog recipe coverage differs from the installed origins")
    objects = {}
    gaps = []
    occurrences = 0
    for name, entry in origins.items():
        recipe = entry["recipe"]
        require(recipe["repository"] == "https://github.com/alpinelinux/aports"
                and recipe["path"] == "main/" + name + "/APKBUILD"
                and by_origin[name] == {recipe["commit"]} and DIGEST.fullmatch(recipe["sha256"])
                and re.fullmatch(r"[0-9a-f]{40}", recipe["gitBlob"]),
                "Alpine recipe pin differs from the installed origin")
        candidates = entry["noticeCandidates"]
        references = entry["referenceDocuments"]
        require(isinstance(candidates, list) and isinstance(references, list)
                and occurrences + len(candidates) + len(references) <= 1024,
                "Alpine notice references exceed bounds")
        if not candidates and not references:
            gaps.append(name)
        for row in candidates + references:
            digest, count = row["sha256"], row["bytes"]
            require(DIGEST.fullmatch(digest) and type(count) is int and 0 < count <= 128 << 10,
                    "invalid original Alpine notice byte pin")
            path = "objects/" + digest
            pin = {"bytes": count, "sha256": digest}
            if path not in objects:
                require(len(objects) < 512, "Alpine notice objects exceed bounds")
                content = file_bytes(project / (ALPINE_NOTICE_PREFIX + path), 128 << 10)
                objects[path] = {"bytes": len(content), "sha256": sha256(content).hexdigest()}
            require(objects[path] == pin, "Alpine notice differs from its original byte pin")
            occurrences += 1
    require(objects, "Alpine notice catalog has no candidate bytes")
    catalog_pin = {"bytes": len(catalog_bytes), "sha256": sha256(catalog_bytes).hexdigest()}
    index = file_bytes(project / (ALPINE_NOTICE_PREFIX + SOURCE_INDEX), 128 << 10)
    source_index = verify_source_index(index, catalog)
    verify_catalog_files(module_notices, ALPINE_NOTICE_PREFIX,
                         {"sources.json": catalog_pin, SOURCE_INDEX: catalog["buildSourceIndex"], **objects}, "Alpine")
    return {"catalogSHA256": catalog_pin["sha256"], "installedPackages": len(installed),
            "sourceOrigins": len(origins), "noticeObjects": len(objects), "noticeOccurrences": occurrences,
            "noticeBytes": sum(row["bytes"] for row in objects.values()), "originsWithoutNoticeCandidates": sorted(gaps),
            "buildSourceIndex": source_index, "legalReviewComplete": False, "completeCorrespondingSource": False}


def verify_bundle(raw, observed, image, source, binary_sha256, project, installed):
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
    require(len(required) == len(modules[ROOT_MODULE]["notices"]), "duplicate project notice path")
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
    predeploys = verify_predeploy_notices(project, project_embedded, required)
    alpine = verify_alpine_notices(project, image, installed, required)
    return {"status": manifest["status"], "manifestSHA256": sha256(raw).hexdigest(),
            "manifestBytes": len(raw), "binarySHA256": binary_sha256, "selectedPackages": len(packages),
            "dependencyModules": len(modules) - 2, "selectedSourceFiles": source_files,
            "objectCount": len(objects), "objectBytes": sum(objects.values()),
            "sourceSupplements": supplements, "projectEmbeddedFiles": project_embedded,
            "predeployNotices": predeploys, "runtimeAPKNotices": alpine,
            "modulesWithoutNoticeFiles": sorted(name for name, row in modules.items()
                if row["noCandidateNoticeFileObserved"]),
            "readme": observed["README.txt"], "completeLicenseReview": False}
