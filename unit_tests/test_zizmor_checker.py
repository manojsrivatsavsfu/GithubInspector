import unittest
import os
import ruamel.yaml as yaml
from checker_modules.zizmor import Zizmor


class TestZizmorChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_data_path = os.path.join("unit_tests", "test_data")
        cls.expected_zizmor = {
            "testdata-secrets-inherit.yml": {"REGEX"},
            "testdata-container-cred.yml": {"REGEX"}
        }

    def test_zizmor_checker(self):
        for filename, expected_types in self.expected_zizmor.items():
            with self.subTest(file=filename):
                file_path = os.path.join(self.test_data_path, filename)
                self.assertTrue(os.path.isfile(file_path),
                                f"{file_path} not found.")

                with open(file_path, "r", encoding="utf-8") as f:
                    loader = yaml.YAML()
                    text = f.read()

                data = loader.load(text) or {}

                checker = Zizmor(data)
                checker.analyze_all()
                found_types = {issue["type"] for issue in checker.get_issues()}

                missing = expected_types - found_types
                self.assertFalse(
                    missing,
                    f"{filename}: Missing Zizmor issues {missing}. Found: {found_types}"
                )
