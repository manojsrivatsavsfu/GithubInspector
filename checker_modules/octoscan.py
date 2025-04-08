import ruamel.yaml as yaml
import re
import glob

download_artifact_action_external = [
    "dawidd6/action-download-artifact",
    "aochmann/actions-download-artifact",
    "bettermarks/action-artifact-download",
]

download_artifact_action_local = [
    "blablacar/action-download-last-artifact",
]

dangerous_actions = download_artifact_action_local
sensitive_paths = [".", "./", ".\\"]
static_ref_regex = r"^refs/(heads|tags)/[\w\-/]+$"


class OctoScanChecker:
    def __init__(self, workflow):
        self.workflow = workflow
        self.issues = []

    def analyze_all(self):
        jobs = self.workflow.get("jobs", {})
        for job_name, job_data in jobs.items():
            services = job_data.get("services", {})
            for svc_name, svc_data in services.items():
                self.check_expression_injection(job_name, svc_name, svc_data)
            steps = job_data.get("steps", [])
            for step_num, step_data in enumerate(steps):
                self.check_run_commands(job_name, step_num, step_data)
                self.check_action_usage(job_name, step_num, step_data)
                self.check_upload_artifact(job_name, step_num, step_data)
                self.check_dangerous_checkout(job_name, step_num, step_data)

    def check_expression_injection(self, job_name, svc_name, svc_data):
        image = svc_data.get("image", "")
        if re.search(r"\$\{\{.*\}\}", image):
            self.issues.append({
                "type": "EXPRESSION_IN_CONTAINER_IMAGE",
                "message": f"{job_name} service {svc_name} has untrusted image reference: {image}"
            })

    def check_run_commands(self, job_name, step_num, step_data):
        run_content = step_data.get("run", "")
        if not run_content:
            return
        for i, line in enumerate(run_content.split("\n")):
            if re.search(r"\bgh\s+run\s+download\b", line):
                self.issues.append({
                    "type": "DANGEROUS_ARTIFACT_DOWNLOAD",
                    "message": f"{job_name} step {step_num} line {i} uses gh run download"
                })

    def check_action_usage(self, job_name, step_num, step_data):
        uses_val = step_data.get("uses", "")
        if not uses_val:
            return
        for action in dangerous_actions:
            if uses_val.startswith(action):
                self.issues.append({
                    "type": "LOCAL_DANGEROUS_ACTION",
                    "message": f"{job_name} step {step_num} uses {uses_val}"
                })
        for action in download_artifact_action_external:
            if uses_val.startswith(action):
                has_with_repo = (
                    "with" in step_data
                    and isinstance(step_data["with"], dict)
                    and "repo" in step_data["with"]
                )
                if has_with_repo:
                    self.issues.append({
                        "type": "EXTERNAL_DANGEROUS_ACTION",
                        "message": f"{job_name} step {step_num} uses {uses_val} with external artifact"
                    })
                else:
                    self.issues.append({
                        "type": "EXTERNAL_DANGEROUS_ACTION",
                        "message": f"{job_name} step {step_num} uses {uses_val}"
                    })
        if uses_val.startswith("actions/github-script"):
            if "with" in step_data and isinstance(step_data["with"], dict):
                script_val = step_data["with"].get("script", "")
                if script_val:
                    for i, line in enumerate(script_val.split("\n")):
                        if "downloadArtifact" in line:
                            self.issues.append({
                                "type": "DOWNLOAD_ARTIFACT_IN_GITHUB_SCRIPT",
                                "message": f"{job_name} step {step_num} line {i} uses downloadArtifact in github-script"
                            })

    def check_upload_artifact(self, job_name, step_num, step_data):
        uses_val = step_data.get("uses", "")
        if uses_val.startswith("actions/upload-artifact"):
            with_dict = step_data.get("with", {})
            path_val = with_dict.get("path", "")
            if path_val in sensitive_paths:
                self.issues.append({
                    "type": "UPLOAD_ARTIFACT_SENSITIVE_PATH",
                    "message": f"{job_name} step {step_num} uploads sensitive path {path_val}"
                })

    def check_dangerous_checkout(self, job_name, step_num, step_data):
        uses_val = step_data.get("uses", "")
        run_content = step_data.get("run", "")
        if uses_val.startswith("actions/checkout"):
            step_with = step_data.get("with", {})
            ref_val = step_with.get("ref")
            if ref_val and not re.match(static_ref_regex, ref_val):
                self.issues.append({
                    "type": "DANGEROUS_CHECKOUT_REF",
                    "message": f"{job_name} step {step_num} uses custom ref {ref_val}"
                })
        if run_content:
            lines = run_content.split("\n")
            for i, line in enumerate(lines):
                if re.search(r"\bgit\s+checkout\b", line):
                    self.issues.append({
                        "type": "MANUAL_GIT_CHECKOUT",
                        "message": f"{job_name} step {step_num} line {i} uses git checkout"
                    })
                if re.search(r"\bgh\s+pr\s+checkout\b", line):
                    self.issues.append({
                        "type": "MANUAL_GH_PR_CHECKOUT",
                        "message": f"{job_name} step {step_num} line {i} uses gh pr checkout"
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
