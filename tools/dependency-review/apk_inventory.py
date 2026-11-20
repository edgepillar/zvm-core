"""Observe Alpine package declarations, repository trust and the BusyBox HTTP client."""

import json
import re
from urllib.parse import quote

from apk_source_delivery import delivery_files
from apk_source_index import DIGEST, SOURCE_INDEX, require
from govulncheck_review import ReviewError, file_bytes, unique_object


APK_DECLARATIONS_COMMAND = r"""
exec /bin/busybox awk '
BEGIN { print "ZVM-APK-LICENSES-2" }
/^P:/ { count++ }
/^[PVACLcoI]:/ || /^$/ { print }
END { printf "END\t%d\n", count }
' /lib/apk/db/installed
"""

APK_REPOSITORY_KEY_COMMAND = r"""
test -f "$1"
size=$(/bin/busybox stat -L -c %s "$1")
test "$size" -gt 0
test "$size" -le 4096
printf '%s\n' "$size"
exec /bin/busybox sha256sum "$1"
"""

WGET_PROBE_COMMAND = r"""
client=$(command -v wget)
test "$(/bin/busybox readlink -f "$client")" = /bin/busybox
port=18549
printf 'HTTP/1.0 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\ncore-image-ready' |
    /bin/busybox nc -l -s 127.0.0.1 -p "$port" -w 5 >/dev/null &
listener=$!
trap 'kill "$listener" 2>/dev/null || true' EXIT
ready=0
for attempt in 1 2 3; do
    if /bin/busybox netstat -lnt | /bin/busybox grep -q "[[:space:]]127\\.0\\.0\\.1:$port[[:space:]]"; then
        ready=1
        break
    fi
    /bin/busybox sleep 1
done
test "$ready" = 1
response=$("$client" -Y off -T 3 -qO- "http://127.0.0.1:$port/status")
test "$response" = core-image-ready
wait "$listener"
trap - EXIT
printf 'BusyBox wget matched the loopback HTTP body\n'
"""
WGET_PROBE_RESULT = b"BusyBox wget matched the loopback HTTP body\n"

IDENTITY = re.compile(r"[A-Za-z0-9_.+~-]{1,128}")
FIELD_PATTERNS = {
    "P": IDENTITY, "V": IDENTITY, "A": IDENTITY, "o": IDENTITY,
    "C": re.compile(r"Q[12][A-Za-z0-9+/=]{20,128}"),
    "L": re.compile(r"[A-Za-z0-9.+()_ /:-]{1,4096}"),
    "c": re.compile(r"[0-9a-f]{40}"),
    "I": re.compile(r"0|[1-9][0-9]{0,11}"),
}


def apk_licenses(raw, installed):
    if not 0 < len(raw) <= 2 << 20 or not raw.endswith(b"\n"):
        raise ReviewError("APK declaration output is incomplete or oversized")
    lines = raw.decode("ascii").split("\n")
    marker = re.fullmatch(r"END\t([1-9][0-9]{0,2})", lines[-2])
    if lines[0] != "ZVM-APK-LICENSES-2" or not marker:
        raise ReviewError("APK declaration framing differs")

    rows = {}
    for block in "\n".join(lines[1:-2]).split("\n\n"):
        if not block.strip():
            continue
        fields = {}
        for line in block.strip("\n").split("\n"):
            key, separator, value = line.partition(":")
            if not separator or key not in FIELD_PATTERNS or key in fields or not FIELD_PATTERNS[key].fullmatch(value):
                raise ReviewError("invalid or duplicate APK declaration field")
            fields[key] = value
        if fields.keys() != FIELD_PATTERNS.keys() or fields["P"] in rows:
            raise ReviewError("APK declaration lacks a field or repeats a package")
        rows[fields["P"]] = {
            "name": fields["P"], "version": fields["V"], "architecture": fields["A"],
            "installedChecksum": fields["C"], "declaredInstalledBytes": int(fields["I"]),
            "origin": fields["o"], "declaredLicense": fields["L"], "declaredBuildCommit": fields["c"],
            "licenseTextOrLegalQualificationEstablished": False,
        }
    if not 0 < len(rows) <= 512 or len(rows) != int(marker[1]):
        raise ReviewError("APK declaration count differs")
    if {name + "-" + row["version"] for name, row in rows.items()} != set(installed):
        raise ReviewError("APK declarations differ from the installed package inventory")
    return [rows[name] for name in sorted(rows)]


def load_repository_key(project, installed):
    fixture = project / "tools/dependency-review/fixtures/alpine-runtime/repository-key.json"
    pinned = json.loads(file_bytes(fixture, 4096), object_pairs_hook=unique_object)
    name = pinned["filename"]
    require(type(pinned["schema"]) is int and pinned["schema"] == 1
            and re.fullmatch(r"alpine-devel@lists\.alpinelinux\.org-[0-9a-f]{8}\.rsa\.pub", name)
            and pinned["publisherURL"] == "https://alpinelinux.org/keys/" + quote(name, safe="")
            and DIGEST.fullmatch(pinned["spkiSHA256"]), "invalid Alpine repository key profile")
    package = pinned["package"]
    fields = ("name", "version", "architecture", "declaredBuildCommit")
    candidates = [row for row in installed if row["name"] == "alpine-keys"]
    require(len(candidates) == 1 and package == {key: candidates[0][key] for key in fields}
            and package["architecture"] == "x86_64" and candidates[0]["origin"] == "alpine-keys",
            "Alpine repository key package differs from the reviewed release")
    notices = project / "LICENSES/alpine"
    catalog = json.loads(file_bytes(notices / "sources.json", 128 << 10), object_pairs_hook=unique_object)
    _, files = delivery_files(file_bytes(notices / SOURCE_INDEX, 128 << 10), catalog)
    source = files.get(f"aports/main/alpine-keys/{name}")
    pem = pinned["pem"]
    require(source and pem == {key: source[key] for key in ("bytes", "sha256")}
            and catalog["origins"]["alpine-keys"]["recipe"]["commit"] == package["declaredBuildCommit"]
            and 0 < pem["bytes"] <= 4096, "Alpine repository key bytes differ from the pinned Aports source")
    return {"imagePath": "/etc/apk/keys/" + name, "package": package, "publisherURL": pinned["publisherURL"],
            "publisherSPKISHA256": pinned["spkiSHA256"], "pem": pem, "aportsGitBlob": source["gitBlob"]}


def verify_image_repository_key(raw, expected):
    lines = raw.decode("ascii").splitlines()
    pem = expected["pem"]
    require(raw.endswith(b"\n") and len(lines) == 2 and lines[0] == str(pem["bytes"])
            and lines[1].split() == [pem["sha256"], expected["imagePath"]],
            "Alpine repository key in the image differs from the publisher pin")
    return {**expected, "publisherPEMMatchesImage": True}
