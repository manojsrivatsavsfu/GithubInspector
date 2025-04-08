import yaml
import re
import json
import glob
import bs4 as BeautifulSoup
import requests

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
    
    def verify_action(action, author):
        URL = f"https://github.com/marketplace?type=actions&query={action} publisher:{author}"
        resp = requests.get(URL)
        
        if resp.status_code != 200:
            return -1

        soup = BeautifulSoup(resp.text, 'html.parser')
        result_section = soup.select(".col-md-6.mb-4.d-flex.no-underline")
        
        if not result_section:
            return -1
        
        item = BeautifulSoup(str(result_section[0]), 'html.parser')
        verified_icon = item.select('.octicon-verified')
        
        if verified_icon:
            return 0 

    def print_issues(self):
        if not self.issues:
            print(f"No problems found in workflow {self.file}")
            return
        print(f"Issues found in {self.file}")
        for i, issue in enumerate(self.issues):
            print(f"{i}. {issue}")

    def get_issues(self):
        return self.issues