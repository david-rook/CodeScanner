import json
import subprocess
import os
import glob
import requests
import argparse
import sys
import time
import anthropic
from configparser import ConfigParser

# Load config
config = ConfigParser()
config.read("claudeconfig.properties")

# Updated to use Claude API key instead of OpenAI
# ConfigParser converts keys to lowercase, so we need to use lowercase
claude_api_key = config.get("DEFAULT", "claude_api_key")
github_token = config.get("DEFAULT", "github_token")

# === Claude conversation management with full AST context ===
def create_smart_ast_context(unified_ast, max_tokens=8000):
    """
    Create AST context that prioritizes completeness while respecting token limits.
    Uses intelligent truncation to preserve cross-file relationships.
    """
    if not unified_ast:
        return "You are a static analysis and security expert. AST context could not be loaded; proceed with best-effort manual analysis."
    
    # Start with symbol summary (critical for cross-file analysis)
    symbol_summary = json.dumps(unified_ast.get("symbols", {}), indent=2)
    
    # Get file structure overview
    files_overview = []
    detailed_asts = []
    
    for file_data in unified_ast.get("files", []):
        file_path = file_data.get("path", "")
        file_ast = file_data.get("ast", {})
        
        # Always include file overview for cross-file context
        overview = {
            "path": file_path,
            "classes": [cls.get("name", "") for cls in file_ast.get("classes", [])],
            "methods": [method.get("name", "") for method in file_ast.get("methods", [])],
            "imports": file_ast.get("imports", [])
        }
        files_overview.append(overview)
        
        # Include detailed AST for security-relevant files
        if any(keyword in file_path.lower() for keyword in ['controller', 'service', 'security', 'auth', 'api', 'util']):
            detailed_asts.append({"path": file_path, "ast": file_ast})
    
    # Build context with priority ordering
    context_parts = []
    context_parts.append("You are a static analysis and security expert. Use the following complete application context for cross-file data flow analysis:\n")
    
    # Always include symbol summary (most important for cross-file analysis)
    if len(symbol_summary) < max_tokens // 3:
        context_parts.append(f"=== Symbol Summary (Cross-file References) ===\n{symbol_summary}\n")
        remaining_tokens = max_tokens - len(symbol_summary)
    else:
        # Truncate symbols but keep structure
        truncated_symbols = symbol_summary[:max_tokens // 3] + "\n... (truncated for length)"
        context_parts.append(f"=== Symbol Summary (Cross-file References) ===\n{truncated_symbols}\n")
        remaining_tokens = max_tokens * 2 // 3
    
    # Include files overview for application structure
    overview_text = json.dumps(files_overview, indent=2)
    if len(overview_text) < remaining_tokens // 2:
        context_parts.append(f"=== Application Structure ===\n{overview_text}\n")
        remaining_tokens -= len(overview_text)
    else:
        truncated_overview = overview_text[:remaining_tokens // 2] + "\n... (truncated)"
        context_parts.append(f"=== Application Structure ===\n{truncated_overview}\n")
        remaining_tokens = remaining_tokens // 2
    
    # Include detailed ASTs for critical files
    if detailed_asts and remaining_tokens > 1000:
        detailed_text = json.dumps(detailed_asts, indent=2)[:remaining_tokens - 100]
        context_parts.append(f"=== Detailed AST (Security-relevant files) ===\n{detailed_text}\n")
    
    return "".join(context_parts)

# Parse CLI
parser = argparse.ArgumentParser(description="AI security analysis and auto-fix for GitHub repos using Claude.")
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
    
    # Create smart AST context that preserves cross-file analysis capability
    full_ast_context = create_smart_ast_context(unified_ast)
    print(f"📊 AST context prepared: {len(full_ast_context)} characters")
else:
    full_ast_context = "You are a static analysis and security expert. AST context could not be loaded; proceed with best-effort manual analysis."
    unified_ast = None

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

# Initialize Claude client instead of OpenAI
client = anthropic.Anthropic(api_key=claude_api_key)
updated_files = set()

# === Claude conversation management with full AST context ===
def create_smart_ast_context(unified_ast, max_tokens=8000):
    """
    Create AST context that prioritizes completeness while respecting token limits.
    Uses intelligent truncation to preserve cross-file relationships.
    """
    if not unified_ast:
        return "You are a static analysis and security expert. AST context could not be loaded; proceed with best-effort manual analysis."
    
    # Start with symbol summary (critical for cross-file analysis)
    symbol_summary = json.dumps(unified_ast.get("symbols", {}), indent=2)
    
    # Get file structure overview
    files_overview = []
    detailed_asts = []
    
    for file_data in unified_ast.get("files", []):
        file_path = file_data.get("path", "")
        file_ast = file_data.get("ast", {})
        
        # Always include file overview for cross-file context
        overview = {
            "path": file_path,
            "classes": [cls.get("name", "") for cls in file_ast.get("classes", [])],
            "methods": [method.get("name", "") for method in file_ast.get("methods", [])],
            "imports": file_ast.get("imports", [])
        }
        files_overview.append(overview)
        
        # Include detailed AST for security-relevant files
        if any(keyword in file_path.lower() for keyword in ['controller', 'service', 'security', 'auth', 'api', 'util']):
            detailed_asts.append({"path": file_path, "ast": file_ast})
    
    # Build context with priority ordering
    context_parts = []
    context_parts.append("You are a static analysis and security expert. Use the following complete application context for cross-file data flow analysis:\n")
    
    # Always include symbol summary (most important for cross-file analysis)
    if len(symbol_summary) < max_tokens // 3:
        context_parts.append(f"=== Symbol Summary (Cross-file References) ===\n{symbol_summary}\n")
        remaining_tokens = max_tokens - len(symbol_summary)
    else:
        # Truncate symbols but keep structure
        truncated_symbols = symbol_summary[:max_tokens // 3] + "\n... (truncated for length)"
        context_parts.append(f"=== Symbol Summary (Cross-file References) ===\n{truncated_symbols}\n")
        remaining_tokens = max_tokens * 2 // 3
    
    # Include files overview for application structure
    overview_text = json.dumps(files_overview, indent=2)
    if len(overview_text) < remaining_tokens // 2:
        context_parts.append(f"=== Application Structure ===\n{overview_text}\n")
        remaining_tokens -= len(overview_text)
    else:
        truncated_overview = overview_text[:remaining_tokens // 2] + "\n... (truncated)"
        context_parts.append(f"=== Application Structure ===\n{truncated_overview}\n")
        remaining_tokens = remaining_tokens // 2
    
    # Include detailed ASTs for critical files
    if detailed_asts and remaining_tokens > 1000:
        detailed_text = json.dumps(detailed_asts, indent=2)[:remaining_tokens - 100]
        context_parts.append(f"=== Detailed AST (Security-relevant files) ===\n{detailed_text}\n")
    
    return "".join(context_parts)

# Create the full context once and reuse
full_ast_context = None

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
    
    # Construct the analysis prompt with full AST context for cross-file analysis
    analysis_prompt = f"""{full_ast_context}

Analyze the following vulnerability finding with particular attention to cross-file data flows:

=== Finding ===
{finding_text}

=== Vulnerable File Content ===
```java
{original_file_content}
```

Using the complete application AST context above, trace the data flow from source to sink across multiple files if necessary. Determine TRUE or FALSE positive, and explain your reasoning based on the full application context. Include a Mermaid diagram showing the data flow path. End with '### Determination' and either 'This is a TRUE positive.' or 'This is a FALSE positive.'"""

    try:
        # Use Claude's message API
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",  # Using Claude 3.5 Sonnet
            max_tokens=4000,
            messages=[
                {
                    "role": "user",
                    "content": analysis_prompt
                }
            ]
        )
        
        reply = response.content[0].text
        
    except Exception as e:
        print(f"❌ Error during Claude API request: {e}")
        break

    analysis_path = local_file_path + "_dataflow.md"

    with open(analysis_path, "w", encoding="utf-8") as f:
        f.write(reply)

    print(f"🔬 Data flow analysis written to: {analysis_path}")
    updated_files.add(analysis_path)

    # Check determination
    determination_line = next((line.strip().lower() for line in reply.splitlines() if "this is a true positive." in line.lower() or "this is a false positive." in line.lower()), None)

    if determination_line == "this is a false positive.":
        print(f"Skipping fix for {rel_file_path} (determined FALSE positive)")
        continue

    # Ask for a fix with full application context
    fix_prompt = f"""{full_ast_context}

Based on the vulnerability analysis for {rel_file_path} and the complete application context, provide a secure fix. Consider how this fix might impact other parts of the application based on the AST context.

Only return the corrected code first. Then under '## Analysis' give a brief explanation of the fix and any cross-file implications.

Original vulnerable code:
```java
{original_file_content}
```

Vulnerability finding:
{finding_text}"""

    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4000,
            messages=[
                {
                    "role": "user", 
                    "content": fix_prompt
                }
            ]
        )
        
        answer = response.content[0].text
        
    except Exception as e:
        print(f"❌ Error during Claude API request for fix: {e}")
        continue

    if "## Analysis" in answer:
        corrected_code, analysis = answer.split("## Analysis", 1)
        analysis = "## Analysis" + analysis
    else:
        corrected_code = answer
        analysis = "## Analysis\nNo additional explanation provided."

    # Clean up code block markers if present
    corrected_code = corrected_code.strip()
    if corrected_code.startswith("```"):
        lines = corrected_code.split('\n')
        if lines[0].startswith("```"):
            lines = lines[1:]  # Remove opening ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]  # Remove closing ```
        corrected_code = '\n'.join(lines)

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

    # Rate limiting - Claude has different limits than OpenAI
    time.sleep(2)  # Slightly longer delay for Claude API

# === Commit & PR ===
branch_name = "claude-ai/suggested-security-fixes"

if updated_files:
    result = subprocess.run(["git", "-C", local_path, "branch", "--list", branch_name], stdout=subprocess.PIPE, text=True)
    if result.stdout.strip():
        subprocess.run(["git", "-C", local_path, "checkout", branch_name], check=True)
    else:
        subprocess.run(["git", "-C", local_path, "checkout", "-b", branch_name], check=True)

    subprocess.run(["git", "-C", local_path, "add", "."], check=True)
    subprocess.run(["git", "-C", local_path, "commit", "-m", "Apply Claude AI-suggested security fixes"], check=True)
    subprocess.run(["git", "-C", local_path, "push", "-u", "origin", branch_name, "--force"], check=True)

    pr_data = {
        "title": "Claude AI-applied security fixes, analysis, and data flow traces",
        "head": branch_name,
        "base": default_branch,
        "body": "This PR includes Claude AI-suggested security fixes and analysis for critical/high findings."
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