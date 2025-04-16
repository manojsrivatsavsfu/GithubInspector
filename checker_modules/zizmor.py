import yaml
import re
import json
import glob
import bs4 as BeautifulSoup
import requests

class Zizmor:
    def __init__(self, file):
        self.file = file
        self.workflow = file
        self.issues = []
        f = open("checker_modules/regex2.json", "r")
        self.regex_data = json.load(f)
        f.close()

    def analyze_all(self):
        try:
            for group_name, patterns_dict in self.regex_data.items():
                for pattern_name, pattern_regex in patterns_dict.items():
                    self.regex_search(self.workflow, pattern_regex,
                                    group_name, pattern_name)
        except Exception as e:
            print(f"Error in Zizmor: {e}")

    def regex_search(self, data, pattern, group_name, pattern_name):
        if isinstance(data, dict):
            for key, value in data.items():
                if key == "credentials":
                    self.regex_search('password: '+ value['password'], pattern, group_name, pattern_name)
                if key == "secrets":
                    try:
                        self.regex_search('secrets: '+ value, pattern, group_name, pattern_name)
                    except:
                        pass
                self.regex_search(key, pattern, group_name, pattern_name)
                self.regex_search(value, pattern, group_name, pattern_name)
        elif isinstance(data, list):
            for item in data:
                self.regex_search(item, pattern, group_name, pattern_name)
        elif isinstance(data, str):
            if re.search(pattern, data):
                self.issues.append({
                    "type": "REGEX",
                    "message": f"Match found: '{data}' for pattern: '{pattern_name}'"
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