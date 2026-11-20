"""Observe the Alpine package declarations and BusyBox HTTP client."""

import re

from govulncheck_review import ReviewError


APK_DECLARATIONS_COMMAND = r"""
exec /bin/busybox awk '
BEGIN { print "ZVM-APK-LICENSES-2" }
/^P:/ { count++ }
/^[PVACLcoI]:/ || /^$/ { print }
END { printf "END\t%d\n", count }
' /lib/apk/db/installed
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
