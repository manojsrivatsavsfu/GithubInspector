import re
import glob


class GhastChecker:
    def __init__(self, workflow):
        self.workflow = workflow
        self.issues = []

    def analyze_all(self):
        top_permissions = self.workflow.get("permissions")
        jobs = self.workflow.get("jobs", {})
        if not jobs:
            if top_permissions is None:
                self.issues.append({
                    "type": "NO_DECLARATION",
                    "message": "Permissions are not declared in the workflow"
                })
            return
        for job_name, job_data in jobs.items():
            self.check_permissions(job_name, top_permissions, job_data)
            steps = job_data.get("steps", [])
            for i, step in enumerate(steps):
                self.check_run_commands(job_name, i, step)
                self.check_action_usage(job_name, i, step)

    def check_permissions(self, job_name, workflow_perms, job_data):
        job_level_perms = job_data.get("permissions")
        if workflow_perms is not None and job_level_perms is None:
            self.issues.append({
                "type": "ONLY_WF_DECLARATION",
                "message": f"Permissions only set at workflow level in job {job_name}"
            })
        elif workflow_perms is None and job_level_perms is None:
            self.issues.append({
                "type": "NO_DECLARATION",
                "message": f"No permissions at workflow or job level in job {job_name}"
            })

    def check_run_commands(self, job_name, step_num, step_data):
        run_content = step_data.get("run")
        if not run_content:
            return
        lines = run_content.split("\n")
        for i, line in enumerate(lines):
            if "secrets." in line:
                self.issues.append({
                    "type": "SECRETS_USAGE",
                    "message": f"{job_name} step {step_num} line {i} uses secrets: {line.strip()}"
                })
            if "${{ github." in line:
                self.issues.append({
                    "type": "GITHUB_CONTEXT_USAGE",
                    "message": f"{job_name} step {step_num} line {i} uses github context: {line.strip()}"
                })

    def check_action_usage(self, job_name, step_num, step_data):
        uses_val = step_data.get("uses")
        if not uses_val:
            return
        parts = uses_val.split("@")
        if len(parts) != 2:
            self.issues.append({
                "type": "NO_PINNING",
                "message": f"{job_name} step {step_num} has no pinned ref: {uses_val}"
            })
        else:
            commit_pattern = r"^[0-9a-f]{40}$"
            ref_part = parts[1].strip()
            if not re.match(commit_pattern, ref_part):
                self.issues.append({
                    "type": "NO_PINNING",
                    "message": f"{job_name} step {step_num} has no pinned ref: {uses_val}"
                })

    def print_issues(self):
        if not self.issues:
            print(f"NO ISSUES FOUND in workflow {self.file}")
            return
        print(f"ISSUES found in {self.file}")
        for i, issue in enumerate(self.issues):
            print(f"{i}. {issue}")

    def get_issues(self):
        return self.issues
