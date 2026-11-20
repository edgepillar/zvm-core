"""Bind a built image to the pinned Alpine runtime base and BuildKit output."""

from hashlib import sha256
import json
from pathlib import Path
import re

from govulncheck_review import ReviewError, file_bytes, unique_object


FIXTURES = Path("tools/dependency-review/fixtures/alpine-runtime")
MAX_DESCRIPTOR = 64 << 10
MAX_BUILD_ID = 128
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ALPINE = re.compile(r"alpine:\d+\.\d+\.\d+@(sha256:[0-9a-f]{64})")
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json"}
CONFIG_TYPES = {"application/vnd.oci.image.config.v1+json",
                "application/vnd.docker.container.image.v1+json"}
LAYER_TYPES = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
               "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar.gzip"}


def require(condition, message):
    if not condition:
        raise ReviewError(message)


def digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value)


def pinned_json(raw, expected, length=None):
    require(0 < len(raw) <= MAX_DESCRIPTOR and (length is None or len(raw) == length)
            and "sha256:" + sha256(raw).hexdigest() == expected, "OCI registry document bytes differ from digest")
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(value, dict), "OCI registry document needs a JSON object")
    return value


def descriptor(row, media_types):
    require(isinstance(row, dict) and row["mediaType"] in media_types and digest(row["digest"])
            and type(row["size"]) is int and row["size"] > 0, "invalid OCI descriptor")
    return {key: row[key] for key in ("mediaType", "digest", "size")}


def verify_base_layers(reference, image, index_bytes, manifest_bytes, config_bytes):
    ref = ALPINE.fullmatch(reference)
    require(ref is not None, "missing pinned Alpine runtime base")
    index_digest = ref[1]
    index = pinned_json(index_bytes, index_digest)
    require(index["schemaVersion"] == 2 and index["mediaType"] in INDEX_TYPES
            and isinstance(index["manifests"], list) and 0 < len(index["manifests"]) <= 256
            and all(isinstance(row, dict) for row in index["manifests"]),
            "unsupported Alpine image index")
    platform = {"os": image["os"], "architecture": image["architecture"]}
    matches = [row for row in index["manifests"] if row.get("platform") == platform]
    require(len(matches) == 1, "Alpine image index lacks a unique runtime platform")
    selected = descriptor(matches[0], MANIFEST_TYPES)
    manifest = pinned_json(manifest_bytes, selected["digest"], selected["size"])
    require(manifest["schemaVersion"] == 2 and manifest["mediaType"] == selected["mediaType"]
            and isinstance(manifest["layers"], list) and 0 < len(manifest["layers"]) <= 128,
            "unsupported Alpine platform manifest")
    layers = [descriptor(layer, LAYER_TYPES) for layer in manifest["layers"]]
    cfg = descriptor(manifest["config"], CONFIG_TYPES)
    config = pinned_json(config_bytes, cfg["digest"], cfg["size"])
    require(all(config[k] == v for k, v in platform.items()), "Alpine image config has a different platform")
    base = config["rootfs"]["diff_ids"]
    require(config["rootfs"]["type"] == "layers" and isinstance(base, list)
            and len(base) == len(layers) and all(digest(item) for item in base), "invalid Alpine base layer identities")
    observed = image["rootfsDiffIDs"]
    require(image["rootfsType"] == "layers" and isinstance(observed, list) and len(base) < len(observed) <= 128
            and all(digest(item) for item in observed) and observed[:len(base)] == base,
            "built image root filesystem differs from the pinned Alpine base")
    return {"status": "RUNTIME_BASE_DIFF_IDS_MATCHED", "registryReference": "docker.io/library/" + reference,
            "platform": platform, "indexDigest": index_digest, "platformManifest": selected, "baseConfig": cfg,
            "registryLayerDescriptors": layers, "baseDiffIDs": base, "builtLayerCount": len(observed)}


def runtime_base_reference(dockerfile):
    stages = [line.split() for line in dockerfile.splitlines() if re.match(r"^[ \t]*FROM[ \t]+", line, re.I)]
    require(stages and len(stages[-1]) == 2, "missing final Alpine image stage")
    require(ALPINE.fullmatch(stages[-1][1]), "missing pinned Alpine runtime base")
    return stages[-1][1]


def verify_runtime_base(project, image):
    reference = runtime_base_reference(file_bytes(project / "Dockerfile", 64 << 10).decode("ascii"))
    fixtures = project / FIXTURES
    records = [file_bytes(fixtures / name, MAX_DESCRIPTOR) for name in ("index.json", "manifest.json", "config.json")]
    return verify_base_layers(reference, image, *records)


def verify_build_output(raw, image_id):
    require(0 < len(raw) <= MAX_BUILD_ID, "build image identity file exceeds bounds")
    emitted = raw.decode("ascii").removesuffix("\n")
    require(digest(emitted) and emitted == image_id, "build image identity differs from the observed image")
    return {"imageID": emitted, "observedImageIDMatched": True}
