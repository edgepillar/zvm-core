#!/usr/bin/env python3
"""Retain bounded observations of one local CI image; never publish an image."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys

from container_notices import MANIFEST_COMMAND, MAX_INVENTORY, MAX_MANIFEST, PAYLOAD_COMMAND, payload_rows, verify_bundle
from govulncheck_review import ReviewError, file_bytes, run_bounded, save, source_binding


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = {"schema": 1, "observedAt": datetime.now(timezone.utc).isoformat(),
               "status": "IMAGE_OBSERVATION_FAILED_OR_INCOMPLETE", "commands": [],
               "completeSBOM": False, "vulnerabilityScanPerformed": False,
               "imageOriginAuthenticated": False, "releaseAccepted": False}
    created = False
    phase = "output_directory"
    try:
        args.output.mkdir(mode=0o700)
        created = True
        phase = "source_before"
        before = source_binding(args.source_commit)
        receipt["source"] = before

        def run(label, argv, stdout_limit=65536):
            nonlocal phase
            phase = label
            directory = args.output / label
            directory.mkdir()
            result = run_bounded(argv, directory, timeout=30,
                                 stdout_limit=stdout_limit, stderr_limit=65536)
            for name, pin in result["streams"].items():
                (directory / pin["path"]).rename(directory / name)
                pin["path"] = label + "/" + name
            receipt["commands"].append({"label": label, "process": result})
            if result["actualExit"] != 0 or not result["outputComplete"]:
                raise ReviewError("image observation command did not complete")
            return file_bytes(directory / "stdout", stdout_limit)

        template = ('{"id":{{json .Id}},"os":{{json .Os}},'
                    '"architecture":{{json .Architecture}},'
                    '"entrypoint":{{json .Config.Entrypoint}},"user":{{json .Config.User}}}')
        image = json.loads(run("image", ["docker", "image", "inspect", "--format", template, "zvm-core:ci"]))
        if (not re.fullmatch(r"sha256:[0-9a-f]{64}", image["id"]) or image["os"] != "linux" or
                image["entrypoint"] != ["zvm"]):
            raise ReviewError("unexpected CI image identity or entrypoint")
        # Pin the observed immutable local image ID for every subsequent command.
        common = ["docker", "run", "--rm", "--network=none", "--read-only", "--user=65534:65534",
                  "--cap-drop=ALL", "--security-opt=no-new-privileges"]
        packages = run("packages", common + ["--entrypoint=/sbin/apk", image["id"], "info", "-v"]).decode().splitlines()
        if (not 1 <= len(packages) <= 512 or len(set(packages)) != len(packages) or
                not {"ca-certificates-20261020-r0", "wget-1.25.0-r1"} <= set(packages) or
                any(not re.fullmatch(r"[A-Za-z0-9_.+~-]+", item) for item in packages)):
            raise ReviewError("unexpected installed package inventory")
        digest = run("binary", common + ["--entrypoint=/bin/busybox", image["id"], "sha256sum", "/usr/local/bin/zvm"]).decode().split()
        if len(digest) != 2 or not re.fullmatch(r"[0-9a-f]{64}", digest[0]) or digest[1] != "/usr/local/bin/zvm":
            raise ReviewError("invalid CLI binary digest")
        notice_command = common + ["--entrypoint=/bin/busybox", image["id"], "sh", "-ec"]
        manifest = run("notice_manifest", notice_command + [MANIFEST_COMMAND], MAX_MANIFEST)
        inventory = run("notice_objects", notice_command + [PAYLOAD_COMMAND], MAX_INVENTORY)
        phase = "notice_binding"
        notices = verify_bundle(manifest, payload_rows(inventory), image, before, digest[0], Path.cwd())
        receipt["sourceNotices"] = notices
        phase = "source_after"
        if source_binding(args.source_commit) != before:
            raise ReviewError("source changed during image observation")
        receipt.update(status="IMAGE_AND_PACKAGE_INPUTS_OBSERVED", image=image,
                       installedPackages=sorted(packages), cliBinarySha256=digest[0],
                       hostPathsOrConfigValuesRecorded=False)
        result = 0
    except (ReviewError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        receipt.update(failureStage=phase, errorType=type(error).__name__)
        if isinstance(error, ReviewError) and re.fullmatch(r"[A-Za-z -]{1,160}", str(error)):
            receipt["failureReason"] = str(error)
        result = 2
    if created:
        save(args.output / "inventory.json", receipt)
    summary = {"status": receipt["status"], "exit": result, "completeSBOM": False,
               "releaseAccepted": False, "sourceNotices": receipt.get("sourceNotices")}
    if result:
        summary.update(failureStage=receipt["failureStage"], errorType=receipt["errorType"],
                       failureReason=receipt.get("failureReason"))
        summary["commands"] = [
            {"label": row["label"], "actualExit": row["process"]["actualExit"],
             "outputComplete": row["process"]["outputComplete"],
             "terminationReason": row["process"]["terminationReason"],
             "stdoutBytes": row["process"]["streams"]["stdout"]["bytes"],
             "stderrBytes": row["process"]["streams"]["stderr"]["bytes"]}
            for row in receipt["commands"]]
    print(json.dumps(summary))
    return result


if __name__ == "__main__":
    sys.exit(main())
