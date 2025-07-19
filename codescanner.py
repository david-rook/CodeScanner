import json
import subprocess
import os
import glob
import requests
import argparse
from openai import OpenAI

from configparser import ConfigParser

# Load config
config = ConfigParser()
config.read("config.properties")

api_key = config.get("DEFAULT", "OPENAI_API_KEY")
github_token = config.get("DEFAULT", "GITHUB_TOKEN")

# Parse CLI
parser = argparse.ArgumentParser(description="AI security analysis and auto-fix for GitHub repos.")
parser.add_argument("--repo-url", required=True, help="GitHub repository URL (e.g., https://github.com/user/repo.git)")
args = parser.parse_args()

repo_url = args.repo_url.rstrip("/")

# Inject token into URL
if github_token and "@" not in repo_url:
    repo_url = repo_url.replace("https://", f"https://{github_token}@")

repo_parts = repo_url.split("/")
repo_owner = repo_parts[-2]
repo_name = repo_parts[-1].replace(".git", "")
default_branch = "main"

local_path = os.path.join(os.getcwd(), repo_name)

# Clone repo
if not os.path.exists(local_path):
    print("Cloning repo...")
    subprocess.run(["git", "clone", repo_url], check=True)
else:
    print("Repo already exists, pulling latest...")
    subprocess.run(["git", "-C", local_path, "checkout", default_branch], check=True)
    subprocess.run(["git", "-C", local_path, "pull", "origin", default_branch], check=True)

# Run Bearer scan
print("Running Bearer scan...")

scan_output_file = os.path.join(local_path, "scan-result.json")

scan_command = [
    "bearer",
    "scan",
    local_path,
    "--force",
    "--format",
    "json",
    "--output",
    scan_output_file
]

result = subprocess.run(scan_command, capture_output=True, text=True)
print(result.stdout)

if result.returncode != 0:
    print("Bearer scan finished with findings. Processing results.")
else:
    print("\n Bearer scan completed and saved.")

# Load scan results
with open(scan_output_file, "r", encoding="utf-8") as f:
    data = json.load(f)

critical_findings = data.get("critical", [])
high_findings = data.get("high", [])
combined_findings = critical_findings + high_findings

if not combined_findings:
    print("⚠️ No critical or high findings found.")
    exit(0)

client = OpenAI(api_key=api_key)
updated_files = set()

# Data flow analysis - test project is only java and js hence the below
def trace_data_flow(finding, file_content, local_file_path, client):
    files_to_include = [local_file_path]
    additional_files = glob.glob(os.path.join(os.path.dirname(local_file_path), "*.java"))
    additional_files += glob.glob(os.path.join(os.path.dirname(local_file_path), "*.js"))
    additional_files = list(set(additional_files))
    if local_file_path in additional_files:
        additional_files.remove(local_file_path)
    files_to_include += additional_files

    project_files_content = ""
    for file in files_to_include:
        if not os.path.isfile(file):
            continue
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            project_files_content += f"\n\n---\n### File: {file}\n\n```java\n{content}\n```"

    finding_text = f"{json.dumps(finding, indent=2)}"
    analysis_prompt = (
        f"You are a static analysis and security expert.\n\n"
        f"## Vulnerability Finding\n{finding_text}\n\n"
        f"## Vulnerable File Content\n```java\n{file_content}\n```\n\n"
        f"## Project Files\n{project_files_content}\n\n"
        f"Please describe the data flow from source to sink step by step, identify intermediate functions and variables, "
        f"and conclude whether this is a true or false positive and why. "
        f"In addition, generate a Mermaid diagram inside a ```mermaid block that shows this data flow. "
        f"Finally, at the end of your analysis, add a heading '### Determination' and write exactly one line: either 'This is a TRUE positive.' or 'This is a FALSE positive.'"
    )

    messages = [
        {"role": "system", "content": "You are a static analysis and security expert."},
        {"role": "user", "content": analysis_prompt}
    ]

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages
    )

    analysis_response = response.choices[0].message.content.strip()
    analysis_file_path = local_file_path + "_dataflow.md"

    with open(analysis_file_path, "w", encoding="utf-8") as f:
        f.write(analysis_response)

    return analysis_file_path

# Review and suggest fix
for idx, finding in enumerate(combined_findings, start=1):
    rel_file_path = finding.get("full_filename")
    if not rel_file_path:
        continue

    if repo_name in rel_file_path:
        rel_file_path = rel_file_path.split(f"{repo_name}/", 1)[-1]

    local_file_path = os.path.join(local_path, rel_file_path.replace("/", os.sep))

    if not os.path.isfile(local_file_path):
        print(f"File not found: {local_file_path}")
        continue

    print(f"\nProcessing fix {idx}/{len(combined_findings)}: {rel_file_path}")

    with open(local_file_path, "r", encoding="utf-8", errors="ignore") as code_file:
        original_file_content = code_file.read()

    dataflow_file_path = trace_data_flow(finding, original_file_content, local_file_path, client)
    print(f"🔬 Data flow analysis written to: {dataflow_file_path}")
    updated_files.add(dataflow_file_path)

    with open(dataflow_file_path, "r", encoding="utf-8") as f_df:
        df_content = f_df.read().lower()

    determination_line = None
    for line in df_content.splitlines():
        if line.strip().startswith("this is a true positive.") or line.strip().startswith("this is a false positive."):
            determination_line = line.strip()
            break

    if determination_line == "this is a false positive.":
        print(f"Skipping code fix for: {rel_file_path} (determined to be false positive)")
        continue

    finding_text = (
        f"=== Finding Details ===\n"
        f"{json.dumps(finding, indent=2)}\n\n"
        f"=== Full file content ===\n{original_file_content}\n\n"
    )

    messages = [
        {
            "role": "system",
            "content": "You are a security expert and senior software engineer. Please provide a secure, corrected version of the file code based on the described vulnerabilities. Reply ONLY with the corrected code. Then separately provide a short markdown analysis summary under '## Analysis' heading."
        },
        {
            "role": "user",
            "content": finding_text
        }
    ]

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages
    )

    answer = response.choices[0].message.content.strip()

    if "## Analysis" in answer:
        corrected_code, analysis = answer.split("## Analysis", 1)
        analysis = "## Analysis" + analysis
    else:
        corrected_code = answer
        analysis = "## Analysis\nNo additional analysis provided."

    if corrected_code and corrected_code.strip() != original_file_content.strip():
        with open(local_file_path, "w", encoding="utf-8") as f_out:
            f_out.write(corrected_code.strip())
        updated_files.add(rel_file_path)
        print(f"Applied suggested fix to: {rel_file_path}")

        analysis_file_path = local_file_path + "_analysis.md"
        with open(analysis_file_path, "w", encoding="utf-8") as f_md:
            f_md.write(analysis.strip())
        updated_files.add(analysis_file_path)
        print(f"Analysis file created: {analysis_file_path}")
    else:
        print(f"No changes suggested for: {rel_file_path}")

# Commit & push
branch_name = "ai/suggested-security-fixes"

if updated_files:
    result = subprocess.run(
        ["git", "-C", local_path, "branch", "--list", branch_name],
        stdout=subprocess.PIPE,
        text=True
    )

    if result.stdout.strip():
        print(f"Branch '{branch_name}' already exists. Checking it out...")
        subprocess.run(["git", "-C", local_path, "checkout", branch_name], check=True)
    else:
        print(f"Creating new branch '{branch_name}'...")
        subprocess.run(["git", "-C", local_path, "checkout", "-b", branch_name], check=True)

    subprocess.run(["git", "-C", local_path, "add", "."], check=True)
    subprocess.run(["git", "-C", local_path, "commit", "-m", "Apply AI-suggested security fixes"], check=True)

    print("Force pushing branch...")
    subprocess.run(["git", "-C", local_path, "push", "-u", "origin", branch_name, "--force"], check=True)

    headers = {"Authorization": f"token {github_token}"}
    pr_body = "This PR includes AI-suggested security fixes, analysis markdown files, and detailed data flow traces. Please review carefully."

    pr_data = {
        "title": "AI-applied security fixes, analysis, and data flow traces",
        "head": branch_name,
        "base": default_branch,
        "body": pr_body
    }

    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls"
    response = requests.post(url, json=pr_data, headers=headers)

    if response.status_code == 201:
        pr_url = response.json()["html_url"]
        print(f"✅ Pull request created: {pr_url}")
    else:
        print(f"❌ Failed to create PR: {response.status_code}")
        print(response.text)
else:
    print("No actual code changes detected. Nothing to commit or push.")
