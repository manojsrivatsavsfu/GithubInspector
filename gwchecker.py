import yaml
import re
import json
import glob

class GWChecker:
    def __init__(self, file):
        self.file = file
        self.workflow = {}
        self.issues = []
        self.parse_file()
        with open('regex.json') as f:
            self.regex = json.load(f)

    def parse_file(self):
        try:
            with open(self.file, 'r') as file:
                self.workflow = yaml.safe_load(file)
        except Exception as e:
            print(f"Error reading YAML file: {e}")
            return
        
        for pattern in self.regex:
            self.regex_search(self.workflow, self.regex[pattern])

    def regex_search(self, data, pattern):
        # safe_load returns a DICT object
        if isinstance(data, dict):
            for key, value in data.items():
                self.regex_search(key, pattern)
                self.regex_search(value, pattern)
        elif isinstance(data, list):
            for item in data:
                self.regex_search(item, pattern)
        elif isinstance(data, str):
            if re.search(pattern, data):
                self.issues.append(f"Match found: {data} For pattern: {pattern}")

    def print_issues(self):
        if not self.issues:
            print(f"No problems found in workflow {self.file}")
            return
        print(f"Issues found in {self.file}")
        for i, message in enumerate(self.issues):
            print(f"{i}. {message}")

if __name__ == "__main__":
    for file in glob.glob("actions/*.yml"):
        analyzer = GWChecker(file)
        analyzer.parse_file()
        analyzer.print_issues()