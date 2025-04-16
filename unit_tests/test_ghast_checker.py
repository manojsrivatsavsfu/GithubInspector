import unittest
import os
import ruamel.yaml as yaml
from checker_modules.ghast import GhastChecker


class TestGhastChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_data_path = os.path.join("unit_tests", "test_data")
        cls.expected_ghast = {
            "testdata-inline-script-13.yml": {"NO_DECLARATION", "GITHUB_CONTEXT_USAGE"},
            "testdata-taint-to-sink-3.yml": {"NO_DECLARATION"},
            "testdata-taint-to-def-docker-7.yml": {"NO_DECLARATION"},
            "testdata-arg-to-sink-1.yml": {"NO_DECLARATION"},
            "testdata-reusable-wf-taint-output-11.yml": {"NO_DECLARATION"},
            "testdata-write-permissions-all-jobs.yml": {"ONLY_WF_DECLARATION"},
            "testdata-argus-habit-manager-repo.yml": {"SECRETS_USAGE"},
            "testdata-using-upload-artifact.yml": {"NO_PINNING"},
            "testdata-download-artifact.yml": set(),
            "testdata-upload-artifact-dangerous-path.yml": set(),
            "testdata-dangerous-checkout.yml": set(),
            "testdata-aws-cred-leak.yml": {"NO_PINNING"},
        }

    def test_ghast_checker(self):
        for filename, expected_types in self.expected_ghast.items():
            with self.subTest(file=filename):
                file_path = os.path.join(self.test_data_path, filename)
                self.assertTrue(os.path.isfile(file_path),
                                f"{file_path} not found.")

                with open(file_path, "r", encoding="utf-8") as f:
                    loader = yaml.YAML()
                    text = f.read()

                data = loader.load(text) or {}

                checker = GhastChecker(data)
                checker.analyze_all()
                found_types = {issue["type"] for issue in checker.get_issues()}

                missing = expected_types - found_types
                self.assertFalse(
                    missing,
                    f"{filename}: Missing Ghast issues {missing}. Found: {found_types}"
                )
