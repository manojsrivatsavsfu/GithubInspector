import unittest
import os
import ruamel.yaml as yaml
from checker_modules.argus import ArgusChecker


class TestArgusChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_data_path = os.path.join("unit_tests", "test_data")
        cls.expected_argus = {
            "testdata-inline-script-13.yml": {
                "SHELL_WITH_TAINT",
                "ENV_TO_SINK",
                "ENV_TO_SHELL_WITH_TAINT",
                "TAINT_TO_DOCKER",
            },
            "testdata-taint-to-sink-3.yml": {"TAINT_TO_SINK"},
            "testdata-taint-to-def-docker-7.yml": {
                "TAINT_TO_DEF_DOCKER",
                "ENV_TO_SINK",
                "ENV_TO_SHELL_WITH_TAINT",
            },
            "testdata-arg-to-sink-1.yml": {
                "ARG_TO_SINK",
                "ARG_TO_LSINK",
            },
            "testdata-reusable-wf-taint-output-11.yml": {"REUSABLE_WF_TAINT_OUTPUT"},
        }

    def test_argus_checker(self):
        for filename, expected_types in self.expected_argus.items():
            with self.subTest(file=filename):
                file_path = os.path.join(self.test_data_path, filename)
                self.assertTrue(os.path.isfile(file_path),
                                f"{file_path} not found.")

                with open(file_path, "r", encoding="utf-8") as f:
                    loader = yaml.YAML()
                    text = f.read()

                data = loader.load(text) or {}

                checker = ArgusChecker(data)
                checker.analyze_all()
                found_types = {issue["type"] for issue in checker.get_issues()}

                missing = expected_types - found_types
                self.assertFalse(
                    missing,
                    f"{filename}: Missing Argus issues {missing}. Found: {found_types}"
                )
