#!/usr/bin/env python3
"""Retain bounded observations of one local CI image; never publish an image."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys

from apk_inventory import APK_DECLARATIONS_COMMAND, WGET_PROBE_COMMAND, WGET_PROBE_RESULT, apk_licenses
from container_notices import MANIFEST_COMMAND, MAX_INVENTORY, MAX_MANIFEST, PAYLOAD_COMMAND, payload_rows, verify_bundle
from govulncheck_review import ReviewError, file_bytes, run_bounded, save, source_binding
from oci_runtime import MAX_BUILD_ID, verify_build_output, verify_runtime_base


IMAGE_TEMPLATE = ('{"id":{{json .Id}},"os":{{json .Os}},'
                  '"architecture":{{json .Architecture}},'
                  '"entrypoint":{{json .Config.Entrypoint}},"user":{{json (index .Config "User")}},'
                  '"reportedSizeBytes":{{json .Size}},"rootfsType":{{json .RootFS.Type}},'
                  '"rootfsDiffIDs":{{json .RootFS.Layers}}}')


def image_projection(raw):
    image = json.loads(raw)
    if (not re.fullmatch(r"sha256:[0-9a-f]{64}", image["id"]) or image["os"] != "linux" or
            image["entrypoint"] != ["zvm"] or type(image["reportedSizeBytes"]) is not int
            or image["reportedSizeBytes"] <= 0):
        raise ReviewError("unexpected CI image identity or entrypoint")
    user_present = image["user"] is not None
    if not user_present:
        image["user"] = ""
    if not isinstance(image["user"], str):
        raise ReviewError("unexpected CI image user")
    return image, user_present


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-image-id", type=Path, required=True)
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

        image, user_present = image_projection(
            run("image", ["docker", "image", "inspect", "--format", IMAGE_TEMPLATE, "zvm-core:ci"]))
        receipt["imageUserFieldPresent"] = user_present
        receipt["image"] = image
        phase = "build_output"
        receipt["buildOutput"] = verify_build_output(file_bytes(args.build_image_id, MAX_BUILD_ID), image["id"])
        phase = "runtime_base"
        receipt["runtimeBase"] = verify_runtime_base(Path.cwd(), image)
        # Pin the observed immutable local image ID for every subsequent command.
        common = ["docker", "run", "--rm", "--network=none", "--read-only", "--user=65534:65534",
                  "--cap-drop=ALL", "--security-opt=no-new-privileges"]
        packages = run("packages", common + ["--entrypoint=/sbin/apk", image["id"], "info", "-v"]).decode().splitlines()
        if (not 1 <= len(packages) <= 512 or len(set(packages)) != len(packages) or
                "ca-certificates-20261020-r0" not in packages or any(name.startswith("wget-") for name in packages) or
                any(not re.fullmatch(r"[A-Za-z0-9_.+~-]+", item) for item in packages)):
            raise ReviewError("unexpected installed package inventory")
        digest = run("binary", common + ["--entrypoint=/bin/busybox", image["id"], "sha256sum", "/usr/local/bin/zvm"]).decode().split()
        if len(digest) != 2 or not re.fullmatch(r"[0-9a-f]{64}", digest[0]) or digest[1] != "/usr/local/bin/zvm":
            raise ReviewError("invalid CLI binary digest")
        image_shell = common + ["--entrypoint=/bin/busybox", image["id"], "sh", "-ec"]
        declarations = run("apk_declarations", image_shell + [APK_DECLARATIONS_COMMAND], 2 << 20)
        installed = apk_licenses(declarations, packages)
        probe = run("wget_loopback", image_shell + [WGET_PROBE_COMMAND], 4096)
        if probe != WGET_PROBE_RESULT:
            raise ReviewError("unexpected BusyBox wget loopback result")
        receipt["busyboxWget"] = {"provider": "/bin/busybox", "loopbackHTTPBodyMatched": True}
        receipt["runtimeAPKLicenseDeclarations"] = installed
        manifest = run("notice_manifest", image_shell + [MANIFEST_COMMAND], MAX_MANIFEST)
        inventory = run("notice_objects", image_shell + [PAYLOAD_COMMAND], MAX_INVENTORY)
        phase = "notice_binding"
        notices = verify_bundle(manifest, payload_rows(inventory), image, before, digest[0], Path.cwd(), installed)
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
               "imageUserFieldPresent": receipt.get("imageUserFieldPresent"),
               "releaseAccepted": False, "sourceNotices": receipt.get("sourceNotices")}
    if not result:
        summary.update(image=receipt["image"], installedPackages=receipt["installedPackages"],
                       busyboxWget=receipt["busyboxWget"], buildOutput=receipt["buildOutput"],
                       runtimeBase=receipt["runtimeBase"])
    if result:
        summary.update(failureStage=receipt["failureStage"], errorType=receipt["errorType"],
                       failureReason=receipt.get("failureReason"))
        if "image" in receipt:
            summary["observedImageID"] = receipt["image"]["id"]
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
