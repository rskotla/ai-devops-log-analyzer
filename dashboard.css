
import json
import html
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
HTML_DIR = REPORT_DIR / "html"

SOURCES = {
    "Jenkins": "jenkins-report.json",
    "Docker": "docker-report.json",
    "Kubernetes": "kubernetes-report.json",
}

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def load_reports():
    reports = []

    for source, filename in SOURCES.items():
        report_path = REPORT_DIR / filename

        if not report_path.exists():
            print(f"WARNING: Report not found: {report_path}")
            continue

        try:
            with report_path.open("r", encoding="utf-8") as file:
                report = json.load(file)

            report["dashboard_source"] = source
            reports.append(report)

        except (json.JSONDecodeError, OSError) as error:
            print(f"ERROR: Could not read {filename}: {error}")

    return reports


def safe(value):
    return html.escape(str(value if value is not None else "N/A"))


def severity_class(severity):
    value = str(severity).upper()
    return value.lower() if value in SEVERITIES else "unknown"


def generate_dashboard(reports):
    total = len(reports)

    review_count = sum(
        1
        for report in reports
        if report.get("analysis", {})
        .get("severity_validation", {})
        .get("validation_status") == "REVIEW_REQUIRED"
    )

    severity_counts = {
        severity: sum(
            1
            for report in reports
            if report.get("analysis", {}).get("severity", "").upper()
            == severity
        )
        for severity in SEVERITIES
    }

    cards = []

    for report in reports:
        analysis = report.get("analysis", {})
        source = report.get("dashboard_source", "Unknown")
        severity = analysis.get("severity", "UNKNOWN").upper()

        validation = analysis.get("severity_validation", {})
        validation_status = validation.get(
            "validation_status", "NOT_AVAILABLE"
        )

        report_file = f"{source.lower()}-report.html"

        cards.append(f"""
        <article class="source-card">
            <div class="card-heading">
                <h2>{safe(source)}</h2>
                <span class="badge {severity_class(severity)}">
                    {safe(severity)}
                </span>
            </div>

            <p class="problem">{safe(analysis.get("problem_summary"))}</p>

            <div class="detail">
                <strong>Root Cause</strong>
                <p>{safe(analysis.get("root_cause"))}</p>
            </div>

            <div class="detail">
                <strong>Validation Status</strong>
                <p>{safe(validation_status)}</p>
            </div>

            <div class="detail">
                <strong>Generated At</strong>
                <p>{safe(report.get("generated_at"))}</p>
            </div>

            <a class="report-link" href="{safe(report_file)}">
                View Detailed Report →
            </a>
        </article>
        """)

    severity_cards = "".join(
        f"""
        <div class="severity-card">
            <span>{severity}</span>
            <strong>{severity_counts[severity]}</strong>
        </div>
        """
        for severity in SEVERITIES
    )

    generated_at = datetime.now().astimezone().strftime(
        "%d %b %Y, %I:%M %p %Z"
    )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI DevOps Central Dashboard</title>
    <link rel="stylesheet" href="dashboard.css">
</head>

<body>
<div class="container">

    <header>
        <h1>AI DevOps Central Dashboard</h1>
        <p>AI-powered Jenkins, Docker and Kubernetes log analysis</p>
        <p>Dashboard generated: {safe(generated_at)}</p>
    </header>

    <section class="summary">
        <div class="summary-card">
            <span>Total Reports</span>
            <strong>{total}</strong>
        </div>

        <div class="summary-card">
            <span>Reports Requiring Review</span>
            <strong>{review_count}</strong>
        </div>

        <div class="summary-card">
            <span>AI Model</span>
            <strong class="model-name">Llama 3.2</strong>
        </div>
    </section>

    <h2 class="section-title">Severity Distribution</h2>

    <section class="severity-grid">
        {severity_cards}
    </section>

    <h2 class="section-title">Log Source Reports</h2>

    <section class="reports-grid">
        {''.join(cards) if cards else '<p>No reports available.</p>'}
    </section>

    <footer>
        AI DevOps Log Analyzer | Powered by Ollama and Llama 3.2
    </footer>

</div>
</body>
</html>
"""

    HTML_DIR.mkdir(parents=True, exist_ok=True)

    output_file = HTML_DIR / "index.html"
    output_file.write_text(page, encoding="utf-8")

    print(f"Dashboard generated successfully: {output_file}")
    print(f"Total reports: {total}")
    print(f"Reports requiring review: {review_count}")


def main():
    reports = load_reports()
    generate_dashboard(reports)


if __name__ == "__main__":
    main()
