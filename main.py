import glob
import os
import sys
import ruamel.yaml as yaml
from checker_modules.gwchecker import GWChecker
from checker_modules.ghast import GhastChecker
from checker_modules.octoscan import OctoScanChecker
from checker_modules.argus import ArgusChecker


severity_map = {
    "NO_DECLARATION": "MEDIUM",
    "ONLY_WF_DECLARATION": "LOW",
    "SECRETS_USAGE": "HIGH",
    "GITHUB_CONTEXT_USAGE": "LOW",
    "NO_PINNING": "MEDIUM",
    "EXPRESSION_IN_CONTAINER_IMAGE": "MEDIUM",
    "DANGEROUS_ARTIFACT_DOWNLOAD": "HIGH",
    "LOCAL_DANGEROUS_ACTION": "HIGH",
    "EXTERNAL_DANGEROUS_ACTION": "HIGH",
    "DOWNLOAD_ARTIFACT_IN_GITHUB_SCRIPT": "MEDIUM",
    "UPLOAD_ARTIFACT_SENSITIVE_PATH": "HIGH",
    "DANGEROUS_CHECKOUT_REF": "MEDIUM",
    "MANUAL_GIT_CHECKOUT": "LOW",
    "MANUAL_GH_PR_CHECKOUT": "LOW",
    "REGEX": "MEDIUM",
    "ARG_TO_SINK": "HIGH",
    "ENV_TO_SINK": "HIGH",
    "TAINT_TO_SINK": "HIGH",
    "SHELL_WITH_TAINT": "HIGH",
    "ENV_TO_SHELL_WITH_TAINT": "HIGH",
    "TAINT_TO_DOCKER": "HIGH",
    "TAINT_TO_DEF_DOCKER": "HIGH",
    "TAINT_TO_UNKNOWN": "MEDIUM",
    "ARG_TO_LSINK": "MEDIUM",
    "ENV_TO_LSINK": "MEDIUM",
    "REUSABLE_WF_TAINT_OUTPUT": "MEDIUM",
    "CONTEXT_TO_SINK": "MEDIUM"
}


def load_yaml(file_path):
    with open(file_path, "r") as f:
        text = f.read()
    loader = yaml.YAML()
    return loader.load(text)


def analyze_file(file_path):
    data = load_yaml(file_path)
    if not data:
        return []
    rc = GWChecker(data)
    gc = GhastChecker(data)
    oc = OctoScanChecker(data)
    ac = ArgusChecker(data)
    rc.analyze_all()
    gc.analyze_all()
    oc.analyze_all()
    ac.analyze_all()
    issues = rc.get_issues() + gc.get_issues() + oc.get_issues() + ac.get_issues()
    filtered = []
    seen = set()
    for i in issues:
        key = (i.get("type"), i.get("message"))
        if key not in seen:
            seen.add(key)
            filtered.append(i)
    for i in filtered:
        i["severity"] = severity_map.get(i["type"], "LOW")
    return filtered


def print_issues(file_path, issues):
    if not issues:
        print(f"No issues in {file_path}")
        return
    print(f"Issues found in {file_path}")
    high = []
    medium = []
    low = []
    for i in issues:
        if i["severity"] == "HIGH":
            high.append(i)
        elif i["severity"] == "MEDIUM":
            medium.append(i)
        else:
            low.append(i)
    for i in high:
        print(f"HIGH: {i['type']} - {i['message']}")
    for i in medium:
        print(f"MEDIUM: {i['type']} - {i['message']}")
    for i in low:
        print(f"LOW: {i['type']} - {i['message']}")


def main(path):
    if os.path.isfile(path):
        print(path)
        issues = analyze_file(path)
        print_issues(path, issues)
    else:
        yml_files = glob.glob(os.path.join(path, "*.yml"))
        for yf in yml_files:
            issues = analyze_file(yf)
            print_issues(yf, issues)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py [path-to-file-or-directory]")
        sys.exit(1)
    main(sys.argv[1])
