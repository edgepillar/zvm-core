"""Verify the files selected for an Alpine source delivery without extracting them."""

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

from apk_source_index import (DIGEST, GIT_LINK, MAX_APORTS_BLOB, SOURCE_INDEX, checked_recipe,
                              checked_source_index, require, source_name)
from govulncheck_review import ReviewError, file_bytes, unique_object


MAX_DELIVERY_BYTES = 128 << 20
BLOCK_BYTES = 64 << 10


def delivery_files(raw, catalog):
    index_digest, index = checked_source_index(raw, catalog)
    files = {}
    for origin, scope in sorted(index["origins"].items()):
        require(source_name(origin), "invalid Alpine recipe origin")
        entry = catalog["origins"][origin]
        entries, sources, local, additional = checked_recipe(origin, scope, entry, index["schema"])
        recipe = entry["recipe"]
        require(type(recipe["bytes"]) is int and 0 < recipe["bytes"] <= MAX_APORTS_BLOB
                and DIGEST.fullmatch(recipe["sha256"]), "invalid APKBUILD byte pin")
        for name, blob in sorted(entries.items()):
            path = f"aports/main/{origin}/{name}"
            pinned = recipe if name == "APKBUILD" else local.get(name, additional.get(name, {}))
            files[path] = {
                **{key: pinned[key] for key in ("bytes", "sha256", "sha512") if key in pinned},
                "gitBlob": blob["oid"],
                "gitMode": blob["mode"],
            }
            if blob["mode"] == GIT_LINK:
                target = blob["linkTarget"]
                files[path].update({"bytes": len(target), "sha256": hashlib.sha256(target.encode("ascii")).hexdigest(),
                                    "linkTarget": target})
        for name, source in sorted(sources.items()):
            if source["kind"] != "APORTS_SOURCE_FILE":
                files[f"sources/{origin}/{name}"] = {key: source[key] for key in ("bytes", "sha256", "sha512")}
    require(files and len({name.casefold() for name in files}) == len(files)
            and sum(pin.get("bytes", MAX_APORTS_BLOB) for pin in files.values()) <= MAX_DELIVERY_BYTES,
            "Alpine delivery exceeds bounds or contains conflicting names")
    return index_digest, files


def verify_payload(stream, count, pin):
    """Check one bounded payload at the current position of a binary stream."""
    require(type(count) is int and 0 <= count <= pin.get("bytes", MAX_APORTS_BLOB)
            and count == pin.get("bytes", count), "Alpine source payload length differs")
    sha256, sha512 = hashlib.sha256(), hashlib.sha512()
    blob = hashlib.sha1(f"blob {count}\0".encode("ascii"))
    remaining = count
    while remaining:
        chunk_size = min(remaining, BLOCK_BYTES)
        block = stream.read(chunk_size)
        require(0 < len(block) <= chunk_size, "Alpine source payload is incomplete")
        remaining -= len(block)
        sha256.update(block)
        sha512.update(block)
        blob.update(block)
    observed = {"bytes": count, "sha256": sha256.hexdigest(), "sha512": sha512.hexdigest(), "gitBlob": blob.hexdigest()}
    require(all(observed[key] == pin[key] for key in observed.keys() & pin.keys()),
            "Alpine source payload differs from the pinned bytes")
    return observed


def verify_selected_files(raw, catalog, read_file):
    index_digest, files = delivery_files(raw, catalog)
    byte_count = 0
    for name, pin in files.items():
        try:
            byte_count += read_file(name, pin)["bytes"]
        except (OSError, ReviewError) as error:
            detail = error.strerror if isinstance(error, OSError) else str(error)
            raise ReviewError(f"{name}: {detail}") from error
    return {
        "indexSHA256": index_digest,
        "aportsFilesVerified": sum("gitBlob" in pin for pin in files.values()),
        "externalFilesVerified": sum("gitBlob" not in pin for pin in files.values()),
        "gitLinkTargetsVerified": sum("linkTarget" in pin for pin in files.values()),
        "selectedBytesVerified": byte_count,
    }


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def open_directory_file(root_fd, name):
    parts = PurePosixPath(name).parts
    directory = root_fd
    with ExitStack() as stack:
        for part in parts[:-1]:
            directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            stack.callback(os.close, directory)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as payload:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                    "Alpine source payload must be an independent regular file")
            yield payload, before.st_size
            after = os.fstat(fd)
            named = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            require(file_identity(before) == file_identity(after) == file_identity(named),
                    "Alpine source payload changed during observation")


def verify_directory_file(root_fd, name, pin):
    with open_directory_file(root_fd, name) as (payload, size):
        return verify_payload(payload, size, pin)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("--catalog", type=Path, default=Path("LICENSES/alpine/sources.json"))
    args = parser.parse_args()
    try:
        catalog = json.loads(file_bytes(args.catalog, 256 << 10), object_pairs_hook=unique_object)
        index = file_bytes(args.catalog.with_name(SOURCE_INDEX), 128 << 10)
        directory = os.open(args.source_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            result = verify_selected_files(index, catalog, lambda name, pin: verify_directory_file(directory, name, pin))
        finally:
            os.close(directory)
    except (OSError, ReviewError, ValueError, KeyError, TypeError) as error:
        detail = error.strerror if isinstance(error, OSError) else str(error)
        parser.exit(1, f"Alpine source delivery verification failed: {detail}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
