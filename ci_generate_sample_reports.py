
import json
from pathlib import Path
from datetime import datetime, timezone


REPORT_DIR = Path("reports")

SAMPLE_REPORTS = {
    "jenkins": {
        "log_source": "Jenkins",
        "log_file": "logs/jenkins/jenkins-build.log",
        "problem_summary": "Jenkins build failed during dependency installation.",
        "severity": "HIGH",
        "root_cause": "The requested Flask package version is unavailable.",
        "evidence": ["ERROR: No matching distribution found for flask==99.99.99"],
    },
    "docker": {
        "log_source": "Docker",
        "log_file": "logs/docker/docker-app.log",
        "problem_summary": "Docker application failed during database connection.",
        "severity": "HIGH",
        "root_cause": "PostgreSQL connection was refused.",
        "evidence": ["Connection refused: PostgreSQL database unavailable"],
    },
    "kubernetes": {
        "log_source": "Kubernetes",
        "log_file": "logs/kubernetes/k8s-pod.log",
        "problem_summary": "Kubernetes pod entered CrashLoopBackOff.",
        "severity": "HIGH",
        "root_cause": "Application could not connect to database service.",
        "evidence": ["Connection timed out", "Pod Status: CrashLoopBackOff"],
    },
}


def generate_sample_reports():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    for name, sample in SAMPLE_REPORTS.items():
        report = {
            "log_source": sample["log_source"],
            "log_file": sample["log_file"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": "CI-SAMPLE-NOT-AI-ANALYSIS",
            "analysis": {
                "problem_summary": sample["problem_summary"],
                "severity": sample["severity"],
                "root_cause": sample["root_cause"],
                "evidence": sample["evidence"],
                "troubleshooting_steps": [
                    "Inspect the relevant service logs.",
                    "Verify service configuration and dependencies.",
                ],
                "preventive_actions": [
                    "Add automated health checks.",
                    "Monitor service availability.",
                ],
                "severity_validation": {
                    "validation_status": "REVIEW_REQUIRED",
                    "ai_severity": sample["severity"],
                    "impact_evidence_found": False,
                    "issues": [
                        "Synthetic CI report. Human impact assessment required."
                    ],
                },
            },
        }

        output_file = REPORT_DIR / f"{name}-report.json"

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print(f"Sample report generated: {output_file}")


if __name__ == "__main__":
    generate_sample_reports()
