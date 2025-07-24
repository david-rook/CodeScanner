import json
import subprocess
import os
import glob
import requests
import argparse
import sys
import time
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
if github_token and "@" not in repo_url:
    repo_url = repo_url.replace("https://", f"https://{github_token}@")

repo_parts = repo_url.split("/")
repo_owner = repo_parts[-2]
repo_name = repo_parts[-1].replace(".git", "")
default_branch = "main"
local_path = os.path.join(os.getcwd(), repo_name)

# Clone or update repo
if not os.path.exists(local_path):
    print("Cloning repo...")
    subprocess.run(["git", "clone", repo_url], check=True)
else:
    print("Repo already exists, pulling latest...")
    subprocess.run(["git", "-C", local_path, "checkout", default_branch], check=True)
    subprocess.run(["git", "-C", local_path, "pull", "origin", default_branch], check=True)

# === Generate AST ===
print("Generating unified AST using external script...")
venv_python = os.path.join(os.getcwd(), "venv311", "bin", "python")
ast_script_path = os.path.join(os.getcwd(), "generate_asts.py")

if not os.path.exists(venv_python):
    raise RuntimeError(f"❌ Python interpreter for AST venv not found: {venv_python}")
subprocess.run([venv_python, ast_script_path, local_path], check=True)

ast_path = os.path.join(os.getcwd(), "project.ast.json")
if os.path.exists(ast_path):
    with open(ast_path, "r", encoding="utf-8") as f:
        unified_ast = json.load(f)

    symbol_summary = json.dumps(unified_ast.get("symbols", {}), indent=2)[:2000]
    ast_sample = json.dumps(unified_ast.get("files", [])[0].get("ast", {}), indent=2)[:3000]

    system_prompt = (
        "You are a static analysis and security expert. The following is the unified AST and symbol table for the project. Use this context for every analysis:\n\n"
        f"=== Project-wide AST (sample/truncated) ===\n{ast_sample}\n\n"
        f"=== Symbol Summary ===\n{symbol_summary}\n"
    )
else:
    system_prompt = "You are a static analysis and security expert. AST context could not be loaded; proceed with best-effort manual analysis."

# === Run Bearer scan ===
print("Running Bearer scan...")
scan_output_file = os.path.join(local_path, "scan-result.json")
scan_command = [
    "bearer", "scan", local_path,
    "--force", "--format", "json", "--output", scan_output_file
]

result = subprocess.run(scan_command, capture_output=True, text=True)
print(result.stdout)

if result.returncode != 0:
    print("Bearer scan finished with findings. Processing results.")
else:
    print("Bearer scan completed and saved.")

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

# === Shared chat thread ===
messages = [
    {
        "role": "system",
        "content": system_prompt
    }
]

# === Main loop ===
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

    finding_text = json.dumps(finding, indent=2)
    prompt = (
        f"Analyze the following vulnerability finding:\n\n"
        f"=== Finding ===\n{finding_text}\n\n"
        f"=== Vulnerable File Content ===\n```java\n{original_file_content}\n```\n\n"
        f"Using the AST describe the data flow from source to sink, determine TRUE or FALSE positive, and explain why you came to this conclusions from looking at the code and AST. "
        f"Also include a Mermaid diagram if possible. End with '### Determination' and either 'This is a TRUE positive.' or 'This is a FALSE positive.'"
    )

    messages.append({"role": "user", "content": prompt})

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages
        )
    except Exception as e:
        print(f"❌ Error during OpenAI request: {e}")
        break

    reply = response.choices[0].message.content
    analysis_path = local_file_path + "_dataflow.md"

    with open(analysis_path, "w", encoding="utf-8") as f:
        f.write(reply)

    print(f"🔬 Data flow analysis written to: {analysis_path}")
    updated_files.add(analysis_path)

    determination_line = next((line.strip().lower() for line in reply.splitlines() if "this is a true positive." in line.lower() or "this is a false positive." in line.lower()), None)

    if determination_line == "this is a false positive.":
        print(f"Skipping fix for {rel_file_path} (determined FALSE positive)")
        for _ in range(min(2, len(messages))):
            messages.pop()
        continue

    # Ask for a fix
    fix_prompt = (
        f"Please provide a secure, corrected version of this file based on the vulnerability above. "
        f"Only return the corrected code first. Then under '## Analysis' give a brief explanation."
    )

    messages.append({"role": "user", "content": fix_prompt})
    response = client.chat.completions.create(model="gpt-4o", messages=messages)
    answer = response.choices[0].message.content

    if "## Analysis" in answer:
        corrected_code, analysis = answer.split("## Analysis", 1)
        analysis = "## Analysis" + analysis
    else:
        corrected_code = answer
        analysis = "## Analysis\nNo additional explanation provided."

    if corrected_code.strip() != original_file_content.strip():
        with open(local_file_path, "w", encoding="utf-8") as f:
            f.write(corrected_code.strip())
        updated_files.add(rel_file_path)
        print(f"✅ Fix applied to: {rel_file_path}")

        with open(local_file_path + "_analysis.md", "w", encoding="utf-8") as f:
            f.write(analysis)
        print("📄 Analysis saved.")
    else:
        print(f"No fix required for: {rel_file_path}")

    # Trim message history safely
    for _ in range(min(4, len(messages))):
        messages.pop()
    time.sleep(1.2)

# === Commit & PR ===
branch_name = "ai/suggested-security-fixes"

if updated_files:
    result = subprocess.run(["git", "-C", local_path, "branch", "--list", branch_name], stdout=subprocess.PIPE, text=True)
    if result.stdout.strip():
        subprocess.run(["git", "-C", local_path, "checkout", branch_name], check=True)
    else:
        subprocess.run(["git", "-C", local_path, "checkout", "-b", branch_name], check=True)

    subprocess.run(["git", "-C", local_path, "add", "."], check=True)
    subprocess.run(["git", "-C", local_path, "commit", "-m", "Apply AI-suggested security fixes"], check=True)
    subprocess.run(["git", "-C", local_path, "push", "-u", "origin", branch_name, "--force"], check=True)

    pr_data = {
        "title": "AI-applied security fixes, analysis, and data flow traces",
        "head": branch_name,
        "base": default_branch,
        "body": "This PR includes AI-suggested security fixes and analysis for critical/high findings."
    }

    headers = {"Authorization": f"token {github_token}"}
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls"
    response = requests.post(url, json=pr_data, headers=headers)

    if response.status_code == 201:
        print(f"✅ Pull request created: {response.json()['html_url']}")
    else:
        print(f"❌ Failed to create PR: {response.status_code}")
else:
    print("No changes to commit.")
