import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from azure_ai_analyzer import AzureAIAnalyzer
from severity_validator import validate_severity
from ai_output_validator import validate_ai_output


SOURCE_REPORT = Path("reports/live-kubernetes-report.json")
OUTPUT_REPORT = Path("reports/azure-incident-review.json")


def main():
    if not SOURCE_REPORT.exists():
        raise FileNotFoundError(f"Source report not found: {SOURCE_REPORT}")

    with SOURCE_REPORT.open("r", encoding="utf-8") as file:
        source = json.load(file)

    source_context = {
        "analysis": source.get("analysis", {}),
        "incident_correlations": source.get("incident_correlations", []),
        "diagnostic_signals": source.get("diagnostic_signals", []),
        "pod_status_validation": source.get("pod_status_validation", {}),
        "evidence_validation": source.get("evidence_validation", {}),
        "source_evidence_validation": source.get("source_evidence_validation", {})
    }

    prompt = f"""
You are a senior Kubernetes SRE performing an independent incident review.

Analyze the supplied Kubernetes evidence independently.
Do not blindly accept the existing AI analysis.

Important rules:
- Distinguish historical previous-container logs from current pod health.
- Do not claim a pod is currently down if its current phase is Running.
- Do not label additional pods as affected without supporting evidence.
- Distinguish temporal correlation from proven root cause.
- Preserve the observed order of database connection error followed by worker failure.
- Do not invent events, outages, customer impact, or evidence.
- Do not recommend unverified configuration changes.
- Use only LOW, MEDIUM, HIGH, or CRITICAL for severity.
- If the ultimate root cause is unknown, explicitly say so.
- Return only one valid JSON object. No Markdown or code fences.

The JSON must contain exactly these fields:
{{
  "problem_summary": "string",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "root_cause": "string",
  "evidence": ["string"],
  "troubleshooting_steps": ["string"],
  "preventive_actions": ["string"]
}}

Incident source context:
{json.dumps(source_context, ensure_ascii=False, indent=2)}
"""

    analyzer = None

    try:
        print("Connecting to Azure AI Foundry...")
        analyzer = AzureAIAnalyzer()

        print("Requesting independent incident analysis...")
        response_text = analyzer.analyze(prompt)

        print("Parsing Azure JSON response...")
        analysis = json.loads(response_text)

        if not isinstance(analysis, dict):
            raise ValueError("Azure response must be a JSON object")

        required_fields = {
            "problem_summary",
            "severity",
            "root_cause",
            "evidence",
            "troubleshooting_steps",
            "preventive_actions"
        }

        missing_fields = required_fields - analysis.keys()

        if missing_fields:
            raise ValueError(
                f"Azure response is missing fields: {sorted(missing_fields)}"
            )

        print("Running existing severity validator...")
        severity_result = validate_severity(analysis)

        print("Running existing AI output validator...")
        ai_validation = validate_ai_output(
            analysis,
            source,
            severity_result
        )

        result = {
            "report_type": "AZURE_INDEPENDENT_INCIDENT_REVIEW",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_report": str(SOURCE_REPORT),
            "model": "gpt-5.4-mini",
            "analysis": analysis,
            "severity_validation": severity_result,
            "ai_output_validation": ai_validation
        }

        OUTPUT_REPORT.parent.mkdir(parents=True, exist_ok=True)

        with OUTPUT_REPORT.open("w", encoding="utf-8") as file:
            json.dump(result, file, indent=2, ensure_ascii=False)

        print("\n========== AZURE INCIDENT REVIEW ==========")
        print("Severity:", analysis["severity"])
        print("Severity validation:", severity_result["validation_status"])
        print("AI output validation:", ai_validation["validation_status"])
        print("Output report:", OUTPUT_REPORT)
        print("============================================")

    finally:
        if analyzer:
            analyzer.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
