import json
import os

def export_nested_workflows(json_file, output_dir="workflows_output"):
    os.makedirs(output_dir, exist_ok=True)

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    workflow_count = 0

    for entry_index, entry in enumerate(data):
        workflows = entry.get("workflows", [])
        for workflow_index, workflow in enumerate(workflows):
            yaml_content = workflow.get("workflow_yaml")
            if yaml_content:
                workflow_count += 1
                filename = f"workflow_{workflow_count}.yml"
                file_path = os.path.join(output_dir, filename)
                with open(file_path, 'w', encoding='utf-8') as yaml_file:
                    yaml_file.write(yaml_content)
                print(f"Exported: {file_path}")
            else:
                print("Error")

if __name__ == "__main__":
    export_nested_workflows("C:\\Users\\rnani\\OneDrive\\Desktop\\C.json")