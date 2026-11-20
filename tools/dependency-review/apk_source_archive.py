"""Write or verify the selected Alpine source files as an uncompressed USTAR archive."""

import argparse
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import sys
import tarfile

from apk_source_delivery import BLOCK_BYTES, MAX_DELIVERY_BYTES, delivery_files, open_directory_file, verify_payload
from apk_source_index import SOURCE_INDEX, require
from container_notices import ALPINE_NOTICE_PREFIX, alpine_notice_pins
from govulncheck_review import ReviewError, file_bytes, unique_object


CATALOG_NAME = "sources.json"


def archive_files(index, catalog_bytes):
    catalog = json.loads(catalog_bytes, object_pairs_hook=unique_object)
    index_digest, files = delivery_files(index, catalog)
    notices, _, _ = alpine_notice_pins(catalog["origins"])
    files.update({ALPINE_NOTICE_PREFIX + name: pin for name, pin in notices.items()})
    files[ALPINE_NOTICE_PREFIX + SOURCE_INDEX] = {"bytes": len(index), "sha256": index_digest}
    files[ALPINE_NOTICE_PREFIX + CATALOG_NAME] = {"bytes": len(catalog_bytes), "sha256": sha256(catalog_bytes).hexdigest()}
    require(all({"bytes", "sha256"} <= pin.keys() for pin in files.values()),
            "source archives require a byte count and SHA-256 for every selected file")
    require(sum(pin["bytes"] for pin in files.values()) <= MAX_DELIVERY_BYTES,
            "Alpine source archive contents exceed the supported size")
    return files


def tar_entry(name, pin):
    entry = tarfile.TarInfo(name)
    if "linkTarget" in pin:
        entry.type = tarfile.SYMTYPE
        entry.mode = 0o777
        entry.linkname = pin["linkTarget"]
    else:
        entry.size = pin["bytes"]
        entry.mode = pin.get("gitMode", 0o100644) & 0o777
    return entry


def archive_size(files):
    block = tarfile.BLOCKSIZE
    length = 2 * block
    for pin in files.values():
        size = 0 if "linkTarget" in pin else pin["bytes"]
        length += block + size + (-size % block)
    return length + (-length % tarfile.RECORDSIZE)


def write_archive(output, files, open_payload):
    with tarfile.open(fileobj=output, mode="w|", format=tarfile.USTAR_FORMAT,
                      encoding="ascii", errors="strict", bufsize=BLOCK_BYTES) as archive:
        for name, pin in sorted(files.items()):
            entry = tar_entry(name, pin)
            if entry.issym():
                archive.addfile(entry)
                continue
            with open_payload(name) as (payload, size):
                require(size == entry.size, f"{name}: Alpine source payload length differs")
                archive.addfile(entry, payload)


class ArchiveReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = sha256()
        self.bytes_read = 0

    def read(self, limit):
        data = self.stream.read(limit)
        self.digest.update(data)
        self.bytes_read += len(data)
        return data


def verify_archive(stream, files):
    reader = ArchiveReader(stream)
    for name, pin in sorted(files.items()):
        entry = tar_entry(name, pin)
        header = entry.tobuf(tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
        require(reader.read(tarfile.BLOCKSIZE) == header, f"{name}: source archive header differs")
        if entry.issym():
            target = entry.linkname.encode("ascii")
            verify_payload(BytesIO(target), len(target), pin)
        else:
            try:
                verify_payload(reader, entry.size, pin)
            except ReviewError as error:
                raise ReviewError(f"{name}: {error}") from error
            padding = -entry.size % tarfile.BLOCKSIZE
            require(reader.read(padding) == bytes(padding), f"{name}: source archive padding differs")
    tail = archive_size(files) - reader.bytes_read
    require(reader.read(tail) == bytes(tail) and stream.read(1) == b"", "source archive end differs")
    return {
        "archiveBytes": reader.bytes_read,
        "archiveSHA256": reader.digest.hexdigest(),
        "membersVerified": len(files),
        "noticeObjectsVerified": sum(name.startswith(ALPINE_NOTICE_PREFIX + "objects/") for name in files),
        "gitLinkTargetsVerified": sum("linkTarget" in pin for pin in files.values()),
        "sourceIndexSHA256": files[ALPINE_NOTICE_PREFIX + SOURCE_INDEX]["sha256"],
        "catalogSHA256": files[ALPINE_NOTICE_PREFIX + CATALOG_NAME]["sha256"],
    }


@contextmanager
def directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "verify"))
    parser.add_argument("input", type=Path)
    parser.add_argument("--catalog", type=Path, default=Path(ALPINE_NOTICE_PREFIX) / CATALOG_NAME)
    args = parser.parse_args()
    try:
        catalog = file_bytes(args.catalog, 128 << 10)
        index = file_bytes(args.catalog.with_name(SOURCE_INDEX), 128 << 10)
        files = archive_files(index, catalog)
        if args.command == "verify":
            with directory(args.input.parent) as fd, open_directory_file(fd, args.input.name) as (payload, size):
                require(size == archive_size(files), "source archive length differs")
                result = verify_archive(payload, files)
            print(json.dumps(result, sort_keys=True))
            return
        with ExitStack() as stack:
            source_fd = stack.enter_context(directory(args.input))
            catalog_fd = stack.enter_context(directory(args.catalog.parent))

            @contextmanager
            def open_payload(name):
                if name == ALPINE_NOTICE_PREFIX + SOURCE_INDEX:
                    yield BytesIO(index), len(index)
                elif name == ALPINE_NOTICE_PREFIX + CATALOG_NAME:
                    yield BytesIO(catalog), len(catalog)
                elif name.startswith(ALPINE_NOTICE_PREFIX):
                    with open_directory_file(catalog_fd, name.removeprefix(ALPINE_NOTICE_PREFIX)) as data:
                        yield data
                else:
                    with open_directory_file(source_fd, name) as data:
                        yield data

            write_archive(sys.stdout.buffer, files, open_payload)
    except (OSError, ReviewError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        detail = error.strerror if isinstance(error, OSError) else str(error)
        parser.exit(1, f"Alpine source archive operation failed: {detail}\n")


if __name__ == "__main__":
    main()
