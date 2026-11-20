"""Check the source locations and Git tree pins for installed Alpine origins."""

from hashlib import sha1, sha256
import json
import re
from urllib.parse import unquote, urlsplit

from govulncheck_review import ReviewError, unique_object


SOURCE_INDEX = "build-sources.json"
DIGEST = re.compile(r"[0-9a-f]{64}")
GIT_OID = re.compile(r"[0-9a-f]{40}")
NAME = re.compile(r"[A-Za-z0-9_.+@-]{1,256}")
RAW_APORTS = "https://raw.githubusercontent.com/alpinelinux/aports/"
KINDS = {"APORTS_SOURCE_FILE", "REMOTE_SOURCE_FILE", "SOURCE_ARCHIVE"}
ARCHIVE_NOTICES = {"ARCHIVE_NOTICE_FILE", "ARCHIVE_INITIAL_SOURCE_NOTICE"}
REGULAR_MODES = {0o100644, 0o100755}
GIT_LINK = 0o120000


def require(condition, message):
    if not condition:
        raise ReviewError(message)


def source_name(name):
    return isinstance(name, str) and NAME.fullmatch(name) and name not in (".", "..")


def public_url(url):
    if not isinstance(url, str) or not url.isascii() or not 0 < len(url) <= 2048:
        return False
    parts = urlsplit(url)
    return (parts.scheme == "https" and parts.hostname and parts.netloc == parts.hostname
            and parts.path.startswith("/") and not parts.query and not parts.fragment)


def git_oid(kind, data):
    return sha1(f"{kind} {len(data)}\0".encode() + data).hexdigest()


def recipe_entries(index, recipe):
    require(index["recipeCommit"] == recipe["commit"], "APK recipe revision differs from the source index")
    rows = index["recipeDirectoryEntries"]
    require(isinstance(rows, list) and 0 < len(rows) <= 256, "APK recipe directory exceeds bounds")
    entries = {}
    for row in rows:
        name, mode, oid = row["name"], row["mode"], row["oid"]
        require(source_name(name) and name not in entries and row["type"] == "blob"
                and mode in REGULAR_MODES | {GIT_LINK} and GIT_OID.fullmatch(oid),
                "invalid APK recipe directory entry")
        entries[name] = row
    apkbuild = entries.get("APKBUILD")
    require(apkbuild and apkbuild["oid"] == recipe["gitBlob"] and apkbuild["mode"] in REGULAR_MODES,
            "APKBUILD blob differs from the installed recipe")
    raw_tree = b"".join(f'{row["mode"]:o} {name}\0'.encode() + bytes.fromhex(row["oid"])
                        for name, row in sorted(entries.items()))
    require(git_oid("tree", raw_tree) == index["recipeDirectoryTree"], "APK recipe directory tree differs")
    for row in entries.values():
        if row["mode"] == GIT_LINK:
            target = row["linkTarget"]
            require(source_name(target) and target in entries and entries[target]["mode"] in REGULAR_MODES
                    and git_oid("blob", target.encode()) == row["oid"], "APK recipe link target differs")
    return entries


def recipe_sources(index, origin, entry, entries):
    rows = index["sources"]
    require(isinstance(rows, list) and len(rows) == entry["reviewedRecipeInputs"] <= 256,
            "APK recipe source count differs")
    sources, local = {}, {}
    prefix = RAW_APORTS + entry["recipe"]["commit"] + "/main/" + origin + "/"
    for row in rows:
        name, kind, url = row["name"], row["kind"], row["url"]
        require(source_name(name) and name not in sources and kind in KINDS and public_url(url)
                and type(row["bytes"]) is int and 0 < row["bytes"] <= 80 << 20
                and DIGEST.fullmatch(row["sha256"]) and re.fullmatch(r"[0-9a-f]{128}", row["sha512"]),
                "invalid APK recipe source pin")
        if kind == "APORTS_SOURCE_FILE":
            relative = unquote(url[len(prefix):], errors="strict")
            require(url.startswith(prefix) and relative in entries and relative not in local
                    and relative != "APKBUILD" and entries[relative]["mode"] in REGULAR_MODES,
                    "APK source does not match the pinned recipe directory")
            local[relative] = row
        sources[name] = row
    return sources, local


def verify_notice_sources(notices, sources):
    for row in notices:
        scope = row["selectionScope"]
        if scope in ARCHIVE_NOTICES:
            pin = row["source"]
            require(pin["kind"] == "SOURCE_ARCHIVE" and sources.get(pin["name"]) == pin,
                    "APK notice archive differs from the recipe source")
        elif scope == "RELATED_SOURCE_COPYRIGHT":
            url, names = row["url"], row["sourceNames"]
            require(public_url(url) and url.endswith("/" + row["path"])
                    and isinstance(names, list) and 0 < len(names) <= len(sources)
                    and len(set(names)) == len(names), "invalid APK copyright source association")
            release = url.rsplit("/" + row["path"], 1)[0] + "/"
            require(all(name in sources and sources[name]["kind"] == "REMOTE_SOURCE_FILE"
                        and sources[name]["url"].startswith(release) for name in names),
                    "APK copyright notice differs from the related source release")
        else:
            raise ReviewError("unknown APK notice source association")


def checked_source_index(raw, catalog):
    pin = {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    require(0 < len(raw) <= 128 << 10 and pin == catalog["buildSourceIndex"],
            "APK source index differs from the catalog pin")
    data = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(data, dict) and data["schema"] == 1 and data["status"] == "APK_RECIPE_SOURCE_INDEX_REVIEW_REQUIRED"
            and data["sourceInventory"] == catalog["sourceInventory"]
            and isinstance(data["origins"], dict)
            and data["origins"].keys() == catalog["origins"].keys(), "APK source index scope differs")
    return pin["sha256"], data["origins"]


def checked_recipe(origin, index, catalog_entry):
    entries = recipe_entries(index, catalog_entry["recipe"])
    sources, local = recipe_sources(index, origin, catalog_entry, entries)
    verify_notice_sources(catalog_entry["noticeCandidates"], sources)
    return entries, sources, local


def verify_source_index(raw, catalog):
    digest, origins = checked_source_index(raw, catalog)
    counts = {"recipeInputs": 0, "aportsTreeEntries": 0, "additionalPackagingEntries": 0, "gitLinks": 0}
    for origin, entry in catalog["origins"].items():
        entries, sources, local = checked_recipe(origin, origins[origin], entry)
        counts["recipeInputs"] += len(sources)
        counts["aportsTreeEntries"] += len(entries)
        counts["additionalPackagingEntries"] += len(entries) - len(local) - 1
        counts["gitLinks"] += sum(row["mode"] == GIT_LINK for row in entries.values())
    return {"indexSHA256": digest, **counts}
