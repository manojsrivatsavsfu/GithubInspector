import ruamel.yaml as yaml
import re
import glob


class Analyzer:
    def __init__(self, file):
        self.file = file
        self.workflow = {}
        self.issues = []
        self.parse_file()

    def parse_file(self):
        with open(self.file, "r") as f:
            text = f.read()
        yaml_loader = yaml.YAML()
        self.workflow = yaml_loader.load(text)

    def analyze_all(self):
        top_permissions = self.workflow.get("permissions", None)
        jobs = self.workflow.get("jobs", {})
        if not jobs:
            if top_permissions is None:
                self.issues.append(
                    ("WORKFLOW", "NO_DECLARATION", "Permissions are not declared in the workflow"))
            return
        for id, job in jobs.items():
            self.check_permissions(
                id, top_permissions, job)
            steps = job.get("steps", [])
            for i, step in enumerate(steps):
                self.check_run_commands(
                    id, i, step)
                self.check_action_usage(
                    id, i, step)

    def check_permissions(self, job_name, workflow_perms, job_data):
        job_level_perms = job_data.get("permissions", None)
        if workflow_perms is not None and job_level_perms is None:
            self.issues.append(
                (job_name, "ONLY_WF_DECLARATION", "Permissions only set at workflow level"))
        elif workflow_perms is None and job_level_perms is None:
            self.issues.append(
                (job_name, "NO_DECLARATION", "No permissions at workflow or job level"))

    def check_run_commands(self, job_name, step_num, step_data):
        run_content = step_data.get("run")
        if not run_content:
            return
        script = run_content.split("\n")
        for i, line in enumerate(script):
            if "secrets." in line:
                self.issues.append(
                    (job_name, f"STEP-{step_num}", f"Line-{i}", "SECRETS_USAGE", line))
            if "${{ github." in line:
                self.issues.append(
                    (job_name, f"STEP-{step_num}", f"Line-{i}", "GITHUB_CONTEXT_USAGE", line))

    def check_action_usage(self, job_name, step_num, step_data):
        uses_val = step_data.get("uses")
        if not uses_val:
            return
        parts = uses_val.split("@")
        if len(parts) == 2:
            ref_part = parts[1].strip()
            commit_pattern = r"^[0-9a-f]{40}$"
            if not re.match(commit_pattern, ref_part):
                self.issues.append(
                    (job_name, f"STEP-{step_num}", "NO_PINNING", uses_val))
        else:
            self.issues.append(
                (job_name, f"STEP-{step_num}", "NO_PINNING", uses_val))

    def print_issues(self):
        if not self.issues:
            print(f"NO ISSUES FOUND in workflow {self.file}")
            return
        print(f"ISSUES found in {self.file}")
        for i, message in enumerate(self.issues):
            print(f"{i}. {message}")


if __name__ == "__main__":
    for file in glob.glob("actions/*.yml"):
        analyzer = Analyzer(file)
        analyzer.analyze_all()
        analyzer.print_issues()
