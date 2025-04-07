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


class Analyzer:
    def __init__(self, file):
        self.file = file
        self.workflow = {}
        self.issues = []
        self.parse_file()

    def parse_file(self):
        with open(self.file, "r") as f:
            text = f.read()
        loader = yaml.YAML()
        self.workflow = loader.load(text)

    def analyze_all(self):
        jobs = self.workflow.get("jobs", {})
        for job_name, job_data in jobs.items():
            services = job_data.get("services", {})
            for svc_name, svc_data in services.items():
                self.check_expression_injection(
                    job_name,
                    svc_name,
                    svc_data,
                )
            steps = job_data.get("steps", [])
            for step_num, step_data in enumerate(steps):
                self.check_run_commands(job_name, step_num, step_data)
                self.check_action_usage(job_name, step_num, step_data)
                self.check_upload_artifact(job_name, step_num, step_data)
                self.check_dangerous_checkout(job_name, step_num, step_data)

    def check_expression_injection(self, job_name, svc_name, svc_data):
        image = svc_data.get("image", "")
        if re.search(r"\$\{\{.*\}\}", image):
            self.issues.append(
                (
                    job_name,
                    f"SERVICE-{svc_name}",
                    "EXPRESSION_IN_CONTAINER_IMAGE",
                    f"Container image references untrusted expression '{image}'.",
                )
            )

    def check_run_commands(self, job_name, step_num, step_data):
        run_content = step_data.get("run", "")
        if not run_content:
            return
        lines = run_content.split("\n")
        for i, line in enumerate(lines):
            if re.search(r"\bgh\s+run\s+download\b", line):
                self.issues.append(
                    (
                        job_name,
                        f"STEP-{step_num}",
                        f"Line-{i}",
                        "DANGEROUS_ARTIFACT_DOWNLOAD",
                        line.strip(),
                    )
                )

    def check_action_usage(self, job_name, step_num, step_data):
        uses_val = step_data.get("uses", "")
        if not uses_val:
            return
        for action in dangerous_actions:
            if uses_val.startswith(action):
                self.issues.append(
                    (
                        job_name,
                        f"STEP-{step_num}",
                        "LOCAL_DANGEROUS_ACTION",
                        f"Use of action '{uses_val}'.",
                    )
                )
        for action in download_artifact_action_external:
            if uses_val.startswith(action):
                has_with_repo = (
                    "with" in step_data
                    and isinstance(step_data["with"], dict)
                    and "repo" in step_data["with"]
                )
                if has_with_repo:
                    self.issues.append(
                        (
                            job_name,
                            f"STEP-{step_num}",
                            "EXTERNAL_DANGEROUS_ACTION",
                            f"Use of action '{uses_val}' with external artifact.",
                        )
                    )
                else:
                    self.issues.append(
                        (
                            job_name,
                            f"STEP-{step_num}",
                            "EXTERNAL_DANGEROUS_ACTION",
                            f"Use of action '{uses_val}'.",
                        )
                    )
        if uses_val.startswith("actions/github-script"):
            if "with" in step_data and isinstance(step_data["with"], dict):
                script_val = step_data["with"].get("script", "")
                if script_val:
                    for i, line in enumerate(script_val.split("\n")):
                        if "downloadArtifact" in line:
                            self.issues.append(
                                (
                                    job_name,
                                    f"STEP-{step_num}",
                                    f"Line-{i}",
                                    "DOWNLOAD_ARTIFACT_IN_GITHUB_SCRIPT",
                                    line.strip(),
                                )
                            )

    def check_upload_artifact(self, job_name, step_num, step_data):
        uses_val = step_data.get("uses", "")
        if not uses_val.startswith("actions/upload-artifact"):
            return
        with_dict = step_data.get("with", {})
        path_val = with_dict.get("path", "")
        if path_val in sensitive_paths:
            self.issues.append(
                (
                    job_name,
                    f"STEP-{step_num}",
                    "UPLOAD_ARTIFACT_SENSITIVE_PATH",
                    f"Use of '{uses_val}' with sensitive path '{path_val}'.",
                )
            )

    def check_dangerous_checkout(self, job_name, step_num, step_data):
        uses_val = step_data.get("uses", "")
        run_content = step_data.get("run", "")
        if uses_val.startswith("actions/checkout"):
            step_with = step_data.get("with", {})
            ref_val = step_with.get("ref")
            if ref_val:
                if not re.match(static_ref_regex, ref_val):
                    self.issues.append(
                        (
                            job_name,
                            f"STEP-{step_num}",
                            "DANGEROUS_CHECKOUT_REF",
                            f"Use of 'actions/checkout' with a custom ref: '{ref_val}'.",
                        )
                    )
        if run_content:
            lines = run_content.split("\n")
            for i, line in enumerate(lines):
                if re.search(r"\bgit\s+checkout\b", line):
                    self.issues.append(
                        (
                            job_name,
                            f"STEP-{step_num}",
                            f"Line-{i}",
                            "MANUAL_GIT_CHECKOUT",
                            line.strip(),
                        )
                    )
                if re.search(r"\bgh\s+pr\s+checkout\b", line):
                    self.issues.append(
                        (
                            job_name,
                            f"STEP-{step_num}",
                            f"Line-{i}",
                            "MANUAL_GH_PR_CHECKOUT",
                            line.strip(),
                        )
                    )

    def print_issues(self):
        if not self.issues:
            print(f"NO ISSUES FOUND in workflow {self.file}")
            return
        print(f"ISSUES found in {self.file}")
        for i, issue in enumerate(self.issues):
            print(f"{i}. {issue}")


if __name__ == "__main__":
    for file in glob.glob("actions/*.yml"):
        analyzer = Analyzer(file)
        analyzer.analyze_all()
        analyzer.print_issues()
