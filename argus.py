import ruamel.yaml as yaml
import glob
import os
import re

TAINT_PATTERNS = [
    ("ARG_TO_SINK",         r"\$\{\{\s*inputs\..+?\}\}"),
    ("ENV_TO_SINK",         r"\$\{\{\s*env\..+?\}\}"),
    ("TAINT_TO_SINK",       r"\$\{\{\s*steps\..+?outputs.+?\}\}"),
    ("SHELL_WITH_TAINT",    r"\$\{\{\s*github\..+?\}\}"),
    ("ENV_TO_SHELL_WITH_TAINT", r"\$\{\{\s*env\..+?\}\}"),
    ("TAINT_TO_DOCKER",     r"docker\s+run.+\$\{\{.+?\}\}"),
    ("TAINT_TO_DEF_DOCKER", r"docker\s+build.+\$\{\{.+?\}\}"),
    ("TAINT_TO_UNKNOWN",    r"\$\{\{.+?\}\}"),
    ("ARG_TO_LSINK",        r"\$\{\{\s*inputs\..+?\}\}"),
    ("ENV_TO_LSINK",        r"\$\{\{\s*env\..+?\}\}"),
    ("REUSABLE_WF_TAINT_OUTPUT", r"\$\{\{\s*needs\..+?\}\}"),
    ("CONTEXT_TO_SINK",     r"\$\{\{\s*github\..+?\}\}")
]


class Analyzer:

    def __init__(self, file_path, parent_context=None):
        self.file_path = file_path
        self.workflow = {}
        self.issues = []
        self.tainted_inputs = set()
        self.tainted_env_workflow = set()
        self.tainted_env_job = {}
        self.tainted_env_step = {}
        self.tainted_step_outputs = {}
        self.tainted_job_outputs = {}
        if parent_context:
            self.tainted_inputs |= parent_context.get("tainted_inputs", set())
            self.tainted_env_workflow |= parent_context.get(
                "tainted_env_workflow", set())
        self.yaml_loader = yaml.YAML()
        self.parse_file()

    def parse_file(self):
        if not os.path.exists(self.file_path):
            self.workflow = {}
            return
        with open(self.file_path, "r", encoding="utf-8") as f:
            text = f.read()
        self.workflow = self.yaml_loader.load(text)

    def get_workflow_inputs(self):
        on_conf = self.workflow.get("on", {})
        if "workflow_call" not in on_conf:
            return
        inputs_def = on_conf["workflow_call"].get("inputs", {})
        for inp_name, inp_conf in inputs_def.items():
            self.tainted_inputs.add(inp_name)

    def get_workflow_env(self):
        env_dict = self.workflow.get("env", {})
        for var_name, val in env_dict.items():
            if self.contains_dangerous_reference(val):
                self.tainted_env_workflow.add(var_name)

    def analyze_job(self, job_id, job_data):
        self.tainted_env_job[job_id] = set()
        job_env = job_data.get("env", {})
        for var_name, val in job_env.items():
            if self.contains_dangerous_reference(val):
                self.tainted_env_job[job_id].add(var_name)
        uses_val = job_data.get("uses")
        if uses_val:
            pass
        else:
            steps = job_data.get("steps", [])
            self.tainted_env_step[job_id] = {}
            for idx, step_data in enumerate(steps):
                step_id = step_data.get("id") or f"anon_step_{idx}"
                self.analyze_step(job_id, step_id, idx, step_data)
        self.collect_job_outputs(job_id, job_data)

    def analyze_all(self):
        if not self.workflow:
            return
        self.get_workflow_inputs()
        self.get_workflow_env()
        jobs = self.workflow.get("jobs", {})
        for job_id, job_data in jobs.items():
            self.analyze_job(job_id, job_data)

    def analyze_step(self, job_id, step_id, step_index, step_data):
        self.tainted_env_step[job_id][step_id] = set()
        step_env = step_data.get("env", {})
        for k, v in step_env.items():
            if self.contains_dangerous_reference(v):
                self.tainted_env_step[job_id][step_id].add(k)
        run_content = step_data.get("run", "")
        if run_content:
            for line_num, line_text in enumerate(run_content.split("\n")):
                self.check_taint(job_id, step_id, step_index,
                                 line_num, line_text)
        outputs_dict = step_data.get("outputs", {})
        if outputs_dict:
            self.handle_step_outputs(job_id, step_id, outputs_dict)

    def handle_step_outputs(self, job_id, step_id, outputs_dict):
        key = (job_id, step_id)
        self.tainted_step_outputs[key] = set()
        for out_name, out_val in outputs_dict.items():
            if self.contains_dangerous_reference(out_val):
                self.tainted_step_outputs[key].add(out_name)

    def collect_job_outputs(self, job_id, job_data):
        self.tainted_job_outputs[job_id] = set()
        outputs_dict = job_data.get("outputs", {})
        for out_name, out_expr in outputs_dict.items():
            if self.contains_dangerous_reference(out_expr):
                if self.references_tainted_step_output(job_id, out_expr):
                    self.tainted_job_outputs[job_id].add(out_name)

    def references_tainted_step_output(self, job_id, expr):
        match = re.search(r"steps\.([\w-]+)\.outputs\.([\w-]+)", expr)
        if not match:
            return False
        ref_step = match.group(1)
        ref_output = match.group(2)
        key = (job_id, ref_step)
        if key in self.tainted_step_outputs:
            return ref_output in self.tainted_step_outputs[key]
        return False

    def check_taint(self, job_id, step_id, step_index, line_num, line_text):
        for alert_type, pattern in TAINT_PATTERNS:
            if re.search(pattern, line_text):
                self.issues.append(
                    (
                        f"JOB-{job_id}",
                        f"STEP-{step_id}-{step_index}",
                        f"Line-{line_num}",
                        alert_type,
                        line_text.strip()
                    )
                )

    def contains_dangerous_reference(self, val):
        if not isinstance(val, str):
            return False
        return bool(re.search(r"\$\{\{[^}]+?\}\}", val))

    def get_tainted_workflow_outputs(self):
        results = set()
        for j_id, outs in self.tainted_job_outputs.items():
            for out_name in outs:
                results.add(f"{j_id}.{out_name}")
        return results

    def print_issues(self):
        if not self.issues:
            print(f"NO ISSUES FOUND in {self.file_path}")
            return
        print(f"ISSUES found in {self.file_path}:")
        for idx, issue in enumerate(self.issues):
            print(f"{idx}. {issue}")


if __name__ == "__main__":
    for file in glob.glob("actions/*.yml"):
        analyzer = Analyzer(file)
        analyzer.analyze_all()
        analyzer.print_issues()
