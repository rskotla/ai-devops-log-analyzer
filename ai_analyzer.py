
import json
import argparse
import sys

from pathlib import Path
from datetime import datetime
from severity_validator import validate_severity
from azure_ai_analyzer import AzureAIAnalyzer, DEPLOYMENT_NAME


REPORT_DIR = Path("reports")


# Log File Configuration
LOG_FILES = {
    "1": {
        "name": "Jenkins",
        "path": Path("logs/jenkins/jenkins-build.log")
    },
    "2": {
        "name": "Docker",
        "path": Path("logs/docker/docker-app.log")
    },
    "3": {
        "name": "Kubernetes",
        "path": Path("logs/kubernetes/k8s-pod.log")
    }
}


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Azure AI DevOps Log Analyzer"
    )

    parser.add_argument(
        "--source",
        choices=["jenkins", "docker", "kubernetes", "all"],
        help="Select log source for AI analysis"
    )

    return parser.parse_args()


def read_log_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()

    except (FileNotFoundError, OSError) as error:
        print(f"Unable to read log file: {error}")
        return None


def analyze_logs(log_content, source):

    prompt = f"""
You are an expert DevOps Engineer and Site Reliability Engineer.

Analyze the provided DevOps logs.

Return ONLY valid JSON. Do not use Markdown code fences.

Use exactly this JSON structure:

{{
    "problem_summary": "Description of the problem",
    "severity": "LOW, MEDIUM, HIGH or CRITICAL",
    "root_cause": "Root cause or uncertainty",
    "evidence": ["Evidence from logs"],
    "troubleshooting_steps": ["Step 1", "Step 2"],
    "preventive_actions": ["Action 1", "Action 2"]
}}

Rules:
- Use only evidence from the supplied logs.
- Clearly mention uncertainty.
- Do not invent infrastructure details.
- Never execute commands.
- Only recommend troubleshooting actions.
- Preserve historical versus current incident status.

Log Source: {source}

Logs:
{log_content}
"""

    analyzer = None

    try:
        analyzer = AzureAIAnalyzer()
        ai_response = analyzer.analyze(prompt)
        return json.loads(ai_response)

    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Azure AI returned invalid JSON for {source}"
        ) from error

    except Exception as error:
        raise RuntimeError(
            f"Azure AI analysis failed for {source}: "
            f"{type(error).__name__}: {error}"
        ) from error

    finally:
        if analyzer:
            analyzer.close()


def save_report(source, log_path, analysis):

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "log_source": source,
        "log_file": str(log_path),
        "generated_at": datetime.now().astimezone().isoformat(),
        "model": DEPLOYMENT_NAME,
        "analysis": analysis
    }

    report_file = REPORT_DIR / f"{source.lower()}-report.json"

    try:
        with open(report_file, "w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(f"\nJSON report saved: {report_file}")

    except OSError as error:
        raise RuntimeError(f"Unable to save report: {error}") from error


def process_log(selected_log):

    source = selected_log["name"]
    file_path = selected_log["path"]

    print(f"\n{'=' * 50}")
    print(f"Starting {source} Log Analysis")
    print(f"{'=' * 50}")

    print(f"\nReading {source} logs...")

    log_content = read_log_file(file_path)

    if not log_content:
        raise RuntimeError(
            f"No log content available for {source}: {file_path}"
        )

    print(f"\nSending {source} logs to Azure AI Foundry...")
    print(f"Azure AI Deployment: {DEPLOYMENT_NAME}")

    analysis = analyze_logs(log_content, source)

    if not isinstance(analysis, dict):
        raise RuntimeError(
            f"Invalid AI response format for {source}"
        )

    if "analysis_error" in analysis:
        raise RuntimeError(
            f"Invalid AI analysis response for {source}: "
            f"{analysis['analysis_error']}"
        )

    severity_validation = validate_severity(analysis)

    analysis["severity_validation"] = severity_validation

    print("\n===== AZURE AI ROOT CAUSE ANALYSIS =====")

    print(json.dumps(
        analysis,
        indent=4,
        ensure_ascii=False
    ))

    print("\n===== SEVERITY VALIDATION =====")

    print(json.dumps(
        severity_validation,
        indent=4,
        ensure_ascii=False
    ))

    save_report(source, file_path, analysis)


def main():

    args = parse_arguments()

    if args.source:

        if args.source == "all":
            selected_sources = list(LOG_FILES.values())

        else:
            selected_sources = [
                item
                for item in LOG_FILES.values()
                if item["name"].lower() == args.source
            ]

        print("\n===== AZURE AI DEVOPS LOG ANALYZER =====")
        print(f"Selected source: {args.source.upper()}")

        try:
            for selected_log in selected_sources:
                process_log(selected_log)

        except Exception as error:
            print(
                f"\nPIPELINE ANALYSIS FAILED: "
                f"{type(error).__name__}: {error}",
                file=sys.stderr
            )
            sys.exit(1)

        print("\n===== AZURE AI LOG ANALYSIS COMPLETED =====")

        return

    while True:

        print("\n===== AZURE AI DEVOPS LOG ANALYZER =====")
        print("1. Jenkins Log Analysis")
        print("2. Docker Log Analysis")
        print("3. Kubernetes Log Analysis")
        print("4. Exit")

        choice = input("\nSelect option (1-4): ").strip()

        if choice == "4":
            print("\nExiting Azure AI DevOps Log Analyzer...")
            break

        if choice not in LOG_FILES:
            print("\nInvalid selection.")
            continue

        selected_log = LOG_FILES[choice]

        process_log(selected_log)


if __name__ == "__main__":
    main()
