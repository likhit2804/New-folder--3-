import os
import sys
import subprocess
import requests
import time
import json
import uuid

# --- Configuration from CI/CD Environment Variables ---

# The base URL of your API, e.g., "https://55kbf4azs5.execute-api.us-east-1.amazonaws.com/prod"
API_ENDPOINT = os.environ.get("TA_IAC_API_URL")

# How long to wait (in seconds) between polling for results
POLL_INTERVAL = int(os.environ.get("TA_IAC_POLL_INTERVAL", 10))

# The maximum time (in seconds) to wait for a scan to complete
MAX_WAIT_SECONDS = int(os.environ.get("TA_IAC_MAX_WAIT", 300))

# The severity level that will fail the build: "CRITICAL", "HIGH", "MEDIUM", "LOW"
BLOCK_ON_SEVERITY = os.environ.get("TA_IAC_BLOCK_SEVERITY", "HIGH")

# Severity order for comparison
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}
BLOCK_LEVEL = SEVERITY_ORDER.get(BLOCK_ON_SEVERITY.upper(), 3)
# ---

def run_command(command):
    """Helper function to run shell commands and exit on failure."""
    try:
        # Using shell=True for simplicity with terraform commands
        result = subprocess.run(command, check=True, capture_output=True, text=True, shell=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}", file=sys.stderr)
        print(f"STDERR: {e.stderr}", file=sys.stderr)
        print(f"STDOUT: {e.stdout}", file=sys.stderr)
        sys.exit(1)

def generate_terraform_plan():
    """
    Runs `terraform plan` and `terraform show` to generate the JSON plan.
    """
    print("Initializing Terraform...")
    run_command("terraform init")
    
    print("Generating Terraform plan...")
    run_command("terraform plan -out=tfplan.bin")
    
    print("Exporting plan to JSON...")
    plan_json_str = run_command("terraform show -json tfplan.bin")
    
    try:
        return json.loads(plan_json_str)
    except json.JSONDecodeError as e:
        print(f"Error decoding terraform plan JSON: {e}", file=sys.stderr)
        sys.exit(1)

def submit_scan(api_endpoint, plan_data):
    """
    Submits the JSON plan to the scanner API and returns the scan_id.
    """
    # Use a unique ID from the CI environment or generate one
    scan_id = os.environ.get("GITHUB_RUN_ID") or f"cli-{str(uuid.uuid4())}"
    post_url = f"{api_endpoint}/scans"
    
    body = {
        "scan_id": scan_id,
        "iac_plan": plan_data
        # You can add other CI metadata here if needed
    }
    
    print(f"Submitting scan {scan_id} to {post_url}...")
    try:
        response = requests.post(post_url, json=body, timeout=30)
        response.raise_for_status()
        print(f"Scan submitted. API Response: {response.json()}")
        return scan_id
    except requests.exceptions.RequestException as e:
        print(f"Error submitting scan: {e}", file=sys.stderr)
        sys.exit(1)

def poll_scan_results(api_endpoint, scan_id):
    """
    Polls the GET /scans/{scan_id} endpoint until the scan is COMPLETED or FAILED.
    """
    status_url = f"{api_endpoint}/scans/{scan_id}"
    start_time = time.time()
    
    print(f"Waiting for results... Polling {status_url}")
    
    while (time.time() - start_time) < MAX_WAIT_SECONDS:
        try:
            response = requests.get(status_url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            status = data.get("status")
            if status == "COMPLETED":
                print("Scan COMPLETED.")
                return data
            elif status == "FAILED":
                print(f"Scan FAILED: {data.get('error_message', 'Unknown error')}", file=sys.stderr)
                sys.exit(1)
            else: # Status is PENDING
                print("Scan is PENDING. Waiting...")
                time.sleep(POLL_INTERVAL)
                
        except requests.exceptions.RequestException as e:
            print(f"Error polling for status: {e}", file=sys.stderr)
            time.sleep(POLL_INTERVAL)
    
    print(f"Scan timed out after {MAX_WAIT_SECONDS} seconds.", file=sys.stderr)
    sys.exit(1)

def generate_markdown_report(scan_results):
    """
    Parses the final JSON and generates a human-readable Markdown report.
    This fulfills the "Human-Readable Report Generator" requirement.
    """
    print("\n--- Generating Scan Report ---")
    findings = []
    try:
        # results_json is a string, so we must load it
        findings_data = json.loads(scan_results.get("results_json", "[]"))
        if isinstance(findings_data, list):
            findings = findings_data
    except json.JSONDecodeError as e:
        print(f"Warning: Could not parse results_json from API response: {e}", file=sys.stderr)

    skipped_feeds = scan_results.get("skipped_feeds", [])
    
    # --- Build the Markdown Report ---
    report_lines = [
        "## 🛡️ Threat-Aware IaC Scan Report\n",
        f"**Scan ID:** `{scan_results.get('scan_id')}`",
    ]
    
    # Filter findings by severity (assuming 'risk_score' is the field)
    critical_findings = [f for f in findings if f.get("risk_score") == "CRITICAL"]
    high_findings = [f for f in findings if f.get("risk_score") == "HIGH"]
    
    if not critical_findings and not high_findings:
        report_lines.append("\n✅ **No CRITICAL or HIGH severity threats found.**")
    else:
        report_lines.append("\n❌ **Action Required: High-priority threats detected!**")
    
    def format_findings_to_markdown(finding_list, severity):
        lines = [f"\n### {severity.upper()} Findings ({len(finding_list)})\n"]
        for f in finding_list:
            lines.append(f"- **Resource:** `{f.get('resource_id', 'N/A')}`")
            # 'details' and 'threat_source' come from your explanation_builder.py
            lines.append(f"  - **Threat:** {f.get('details', 'No details available')}")
            lines.append(f"  - **Source:** `{f.get('threat_source', 'N/A')}`")
        return "\n".join(lines)

    if critical_findings:
        report_lines.append(format_findings_to_markdown(critical_findings, "CRITICAL"))
    
    if high_findings:
        report_lines.append(format_findings_to_markdown(high_findings, "HIGH"))
        
    if skipped_feeds:
        report_lines.append("\n### Scan Notes\n")
        report_lines.append(f"⚠️ The following threat feeds were skipped due to outages: `{', '.join(skipped_feeds)}`")

    report_lines.append("\n---\n*Report generated by TA-IaC Scanner*")
    return "\n".join(report_lines)

def main():
    if not API_ENDPOINT:
        print("Error: TA_IAC_API_URL environment variable is not set.", file=sys.stderr)
        print("Please set this variable in your CI/CD settings.", file=sys.stderr)
        sys.exit(1)

    # 1. Generate Plan
    plan_data = generate_terraform_plan()
    
    # 2. Submit Scan
    scan_id = submit_scan(API_ENDPOINT, plan_data)
    
    # 3. Poll for Results
    results_data = poll_scan_results(API_ENDPOINT, scan_id)
    
    # 4. Generate Report
    report_md = generate_markdown_report(results_data)
    
    # Print the report to the CI console
    print(report_md)
    
    # Save report to a file for use as a PR comment or artifact
    try:
        with open("scan_report.md", "w") as f:
            f.write(report_md)
        print("\nReport saved to scan_report.md")
    except Exception as e:
        print(f"Warning: Could not save report file: {e}", file=sys.stderr)

    # 5. Interpret Final Result and Fail Pipeline if needed
    findings = json.loads(results_data.get("results_json", "[]"))
    
    block_build = False
    for f in findings:
        severity = f.get("risk_score", "LOW").upper()
        if SEVERITY_ORDER.get(severity, 1) >= BLOCK_LEVEL:
            block_build = True
            break
            
    if block_build:
        print(f"\n--- ❌ BUILD FAILED: Findings at or above '{BLOCK_ON_SEVERITY}' severity detected. ---", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\n--- ✅ BUILD SUCCEEDED: No findings at or above '{BLOCK_ON_SEVERITY}' severity detected. ---")
        sys.exit(0)

if __name__ == "__main__":
    main()