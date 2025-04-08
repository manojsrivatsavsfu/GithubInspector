import yaml
import re
import json
import glob


class GWChecker:
    def __init__(self, file):
        self.file = file
        self.workflow = {}
        self.issues = []
        with open("regex.json", "r") as f:
            self.regex_data = json.load(f)

    def analyze_all(self):
        for group_name, patterns_dict in self.regex_data.items():
            for pattern_name, pattern_regex in patterns_dict.items():
                self.regex_search(self.workflow, pattern_regex,
                                  group_name, pattern_name)

    def regex_search(self, data, pattern, group_name, pattern_name):
        if isinstance(data, dict):
            for key, value in data.items():
                self.regex_search(key, pattern)
                self.regex_search(value, pattern)
        elif isinstance(data, list):
            for item in data:
                self.regex_search(item, pattern)
        elif isinstance(data, str):
            if re.search(pattern, data):
                self.issues.append({
                    "type": "REGEX",
                    "message": f"Match found: '{data}' for pattern: '{pattern}'"
                })

    def print_issues(self):
        if not self.issues:
            print(f"No problems found in workflow {self.file}")
            return
        print(f"Issues found in {self.file}")
        for i, issue in enumerate(self.issues):
            print(f"{i}. {issue}")

    def get_issues(self):
        return self.issues
