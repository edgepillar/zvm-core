from pathlib import Path
import unittest

from govulncheck_review import ReviewError
from oci_runtime import FIXTURES, runtime_base_reference, verify_base_layers, verify_build_output, verify_runtime_base


PROJECT = Path(__file__).resolve().parents[2]
REFERENCE = "alpine:3.22.8@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f"
ALPINE_DIFF_ID = "sha256:fdc5834cb53a4bde074c41b5baf85f9d5cece29df379fecafea8c396ba8c29d9"


class RuntimeLayerTests(unittest.TestCase):
    def setUp(self):
        self.image = {"os": "linux", "architecture": "amd64", "rootfsType": "layers",
                      "rootfsDiffIDs": [ALPINE_DIFF_ID, "sha256:" + "a" * 64]}
        self.docs = [(PROJECT / FIXTURES / name).read_bytes() for name in ("index.json", "manifest.json", "config.json")]

    def test_pinned_linux_manifest_and_config_match_the_base_prefix(self):
        result = verify_runtime_base(PROJECT, self.image)
        self.assertEqual(result["baseDiffIDs"], [ALPINE_DIFF_ID])
        self.assertEqual(result["platformManifest"]["digest"],
                         "sha256:9db2934886712d877c932e07249c75a59e6ca27adfbccc05261987a17bef2d63")
        self.assertEqual(result["baseConfig"]["digest"],
                         "sha256:812e99317af7009fea987b5ad913e63f8494c2d6e596b59b6ac8b8f91f7766e8")
        self.assertEqual(result["builtLayerCount"], 2)

    def test_raw_bytes_of_all_registry_documents_are_bound(self):
        for index in range(3):
            docs = list(self.docs)
            docs[index] += b"\n"
            with self.subTest(document=index), self.assertRaisesRegex(ReviewError, "bytes differ from digest"):
                verify_base_layers(REFERENCE, self.image, *docs)

    def test_wrong_layer_order_or_replaced_base_is_rejected(self):
        for layers in (list(reversed(self.image["rootfsDiffIDs"])), ["sha256:" + "b" * 64, ALPINE_DIFF_ID]):
            with self.subTest(layers=layers), self.assertRaisesRegex(ReviewError, "root filesystem differs"):
                verify_base_layers(REFERENCE, {**self.image, "rootfsDiffIDs": layers}, *self.docs)

    def test_an_earlier_alpine_stage_does_not_select_the_runtime(self):
        with self.assertRaisesRegex(ReviewError, "missing pinned Alpine runtime base"):
            runtime_base_reference("FROM " + REFERENCE + " AS builder\nFROM scratch\n")

    def test_exported_image_identity_must_match_the_local_id(self):
        image_id = "sha256:" + "c" * 64
        for ending in (b"", b"\n"):
            with self.subTest(ending=ending):
                self.assertEqual(verify_build_output(image_id.encode() + ending, image_id),
                                 {"imageID": image_id, "observedImageIDMatched": True})
        for value in (b"additional metadata", ("sha256:" + "d" * 64).encode()):
            with self.subTest(value=value), self.assertRaisesRegex(ReviewError, "identity differs from the observed"):
                verify_build_output(value, image_id)
