import unittest
import os
import ruamel.yaml as yaml
from checker_modules.octoscan import OctoScanChecker


class TestOctoScanChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_data_path = os.path.join("unit_tests", "test_data")
        cls.expected_octoscan = {
            "testdata-download-artifact.yml": {"EXTERNAL_DANGEROUS_ACTION"},
            "testdata-upload-artifact-dangerous-path.yml": {"UPLOAD_ARTIFACT_SENSITIVE_PATH"},
            "testdata-dangerous-checkout.yml": {"DANGEROUS_CHECKOUT_REF", "MANUAL_GIT_CHECKOUT"},
            "testdata-clean.yml": set()
        }

    def test_octoscan_checker(self):
        for filename, expected_types in self.expected_octoscan.items():
            with self.subTest(file=filename):
                file_path = os.path.join(self.test_data_path, filename)
                self.assertTrue(os.path.isfile(file_path),
                                f"{file_path} not found.")

                with open(file_path, "r", encoding="utf-8") as f:
                    loader = yaml.YAML()
                    text = f.read()

                data = loader.load(text) or {}

                checker = OctoScanChecker(data)
                checker.analyze_all()
                found_types = {issue["type"] for issue in checker.get_issues()}

                missing = expected_types - found_types
                self.assertFalse(
                    missing,
                    f"{filename}: Missing OctoScan issues {missing}. Found: {found_types}"
                )
                unwanted_find = found_types - expected_types
                self.assertFalse(
                    unwanted_find,
                    f"{unwanted_find} should not have been found"
                )
