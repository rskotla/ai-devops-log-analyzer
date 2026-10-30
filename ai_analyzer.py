
import requests
import json
import os
import argparse

from pathlib import Path
from datetime import datetime
from severity_validator import validate_severity


# Ollama Configuration
OLLAMA_HOST = os.getenv(
    "OLLAMA_HOST",
    "http://localhost:11434"
).rstrip("/")

OLLAMA_API = f"{OLLAMA_HOST}/api/chat"

MODEL = "llama3.2:latest"

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
        description="AI DevOps Log Analyzer"
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

    system_prompt = """
    You are an expert DevOps Engineer.

    Analyze the provided DevOps logs.

    Return ONLY valid JSON. Do not use Markdown code fences.

    Use exactly this JSON structure:

    {
        "problem_summary": "Description of the problem",
        "severity": "LOW, MEDIUM, HIGH or CRITICAL",
        "root_cause": "Root cause or uncertainty",
        "evidence": ["Evidence from logs"],
        "troubleshooting_steps": ["Step 1", "Step 2"],
        "preventive_actions": ["Action 1", "Action 2"]
    }

    Rules:
    - Use only evidence from the logs.
    - Clearly mention uncertainty.
    - Do not invent infrastructure details.
    - Never execute commands.
    - Only recommend troubleshooting actions.
    """

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": f"""
                Log Source: {source}

                Analyze these logs:

                {log_content}
                """
            }
        ],
        "stream": False
    }

    try:
        response = requests.post(
            OLLAMA_API,
            json=payload,
            timeout=180
        )

        response.raise_for_status()

        result = response.json()

        ai_response = result["message"]["content"]

        return json.loads(ai_response)

    except json.JSONDecodeError:
        return {
            "analysis_error": "AI did not return valid JSON",
            "raw_response": ai_response
        }

    except (requests.exceptions.RequestException, KeyError) as error:
        print(f"Ollama API Error: {error}")
        return None


def save_report(source, log_path, analysis):

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "log_source": source,
        "log_file": str(log_path),
        "generated_at": datetime.now().astimezone().isoformat(),
        "model": MODEL,
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
        print(f"Unable to save report: {error}")


def process_log(selected_log):

    source = selected_log["name"]
    file_path = selected_log["path"]

    print(f"\n{'=' * 50}")
    print(f"Starting {source} Log Analysis")
    print(f"{'=' * 50}")

    print(f"\nReading {source} logs...")

    log_content = read_log_file(file_path)

    if not log_content:
        print(f"No log content available for {source}.")
        return

    print(f"\nSending {source} logs to Ollama AI...")
    print(f"Ollama API: {OLLAMA_API}")
    print(f"Model: {MODEL}")

    analysis = analyze_logs(log_content, source)

    if analysis is None:
        print(f"\nAI analysis failed for {source}.")
        return

    if not isinstance(analysis, dict):
        print("\nInvalid AI response format.")
        return

    # Independent severity validation
    severity_validation = validate_severity(analysis)

    # Attach validation result to AI analysis
    analysis["severity_validation"] = severity_validation

    print("\n===== AI ROOT CAUSE ANALYSIS =====")

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

    # Save AI analysis and validation in JSON report
    save_report(source, file_path, analysis)


def main():

    args = parse_arguments()

    # CLI Mode: Jenkins pipeline or command line
    if args.source:

        if args.source == "all":

            selected_sources = list(LOG_FILES.values())

        else:

            selected_sources = [
                item
                for item in LOG_FILES.values()
                if item["name"].lower() == args.source
            ]

        print("\n===== AI DEVOPS LOG ANALYZER =====")
        print(f"Selected source: {args.source.upper()}")

        for selected_log in selected_sources:
            process_log(selected_log)

        print("\n===== AI LOG ANALYSIS COMPLETED =====")

        return

    # Interactive Mode: Manual execution
    while True:

        print("\n===== AI DEVOPS LOG ANALYZER =====")
        print("1. Jenkins Log Analysis")
        print("2. Docker Log Analysis")
        print("3. Kubernetes Log Analysis")
        print("4. Exit")

        choice = input("\nSelect option (1-4): ").strip()

        if choice == "4":
            print("\nExiting AI DevOps Log Analyzer...")
            break

        if choice not in LOG_FILES:
            print("\nInvalid selection.")
            continue

        selected_log = LOG_FILES[choice]

        process_log(selected_log)


if __name__ == "__main__":
    main()
