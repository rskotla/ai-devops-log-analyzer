
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
    return str(severity).lower() if severity in SEVERITIES else "unknown"


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
        validation_status = validation.get("validation_status", "NOT_AVAILABLE")

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

    generated_at = datetime.now().astimezone().strftime("%d %b %Y, %I:%M %p %Z")

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI DevOps Central Dashboard</title>

    <style>
        * {{ box-sizing: border-box; }}

        body {{
            margin: 0;
            padding: 30px;
            font-family: Arial, sans-serif;
            background: #f1f5f9;
            color: #172033;
        }}

        .container {{ max-width: 1200px; margin: auto; }}

        header {{
            padding: 35px;
            border-radius: 16px;
            background: linear-gradient(120deg, #10213f, #2457a7);
            color: white;
            margin-bottom: 28px;
        }}

        header h1 {{ margin: 0 0 10px; }}
        header p {{ color: #dbeafe; }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}

        .summary-card, .source-card, .severity-card {{
            background: white;
            padding: 22px;
            border-radius: 12px;
            box-shadow: 0 3px 12px rgba(0,0,0,.05);
        }}

        .summary-card span, .severity-card span {{
            color: #64748b;
            font-size: 13px;
        }}

        .summary-card strong, .severity-card strong {{
            display: block;
            font-size: 30px;
            margin-top: 10px;
        }}

        .section-title {{ margin: 30px 0 16px; }}

        .severity-grid, .reports-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
        }}

        .source-card h2 {{ margin: 0; }}

        .card-heading {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
        }}

        .badge {{
            padding: 6px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            background: #e2e8f0;
        }}

        .critical {{ background: #fee2e2; color: #991b1b; }}
        .high {{ background: #ffedd5; color: #9a3412; }}
        .medium {{ background: #fef3c7; color: #92400e; }}
        .low {{ background: #dcfce7; color: #166534; }}
        .unknown {{ background: #e2e8f0; color: #334155; }}

        .problem {{ font-weight: bold; line-height: 1.5; }}

        .detail {{
            border-top: 1px solid #e2e8f0;
            padding-top: 12px;
            margin-top: 12px;
        }}

        .detail strong {{ font-size: 13px; }}
        .detail p {{ color: #475569; line-height: 1.5; }}

        .report-link {{
            display: inline-block;
            margin-top: 12px;
            color: #2563eb;
            font-weight: bold;
            text-decoration: none;
        }}

        footer {{
            text-align: center;
            color: #64748b;
            margin-top: 35px;
            font-size: 13px;
        }}

        @media (max-width: 600px) {{
            body {{ padding: 15px; }}
            header {{ padding: 24px; }}
        }}

        @media print {{
            body {{ background: white; }}
            .source-card, .summary-card {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
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
            <strong style="font-size:18px">Llama 3.2</strong>
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
