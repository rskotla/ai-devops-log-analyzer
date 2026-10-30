
import json
import html
import re

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
HTML_DIR = REPORT_DIR / "html"

CSS_FILE = "report.css"


def safe_text(value):
    """Escape content before displaying it in HTML."""
    return html.escape(str(value if value is not None else "N/A"))


def severity_class(severity):
    value = str(severity).upper()
    if value in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return value.lower()
    return "unknown"


def validation_class(status):
    value = str(status).upper()
    allowed = {
        "CHECK_PASSED": "check-passed",
        "REVIEW_REQUIRED": "review-required",
        "INVALID_RESPONSE": "invalid-response",
    }
    return allowed.get(value, "default")


def generate_html_report(report):

    analysis = report["analysis"]
    validation = analysis.get("severity_validation", {})

    source = safe_text(report.get("log_source"))
    log_file = safe_text(report.get("log_file"))
    generated_at = safe_text(report.get("generated_at"))
    model = safe_text(report.get("model"))

    summary = safe_text(analysis.get("problem_summary"))
    severity = safe_text(analysis.get("severity"))
    root_cause = safe_text(analysis.get("root_cause"))

    validation_status = safe_text(
        validation.get("validation_status", "NOT AVAILABLE")
    )

    evidence = analysis.get("evidence", [])
    troubleshooting = analysis.get("troubleshooting_steps", [])
    preventive_actions = analysis.get("preventive_actions", [])
    validation_issues = validation.get("issues", [])

    raw_severity = str(analysis.get("severity", "N/A")).upper()
    raw_validation = str(
        validation.get("validation_status", "NOT AVAILABLE")
    ).upper()

    severity_css = severity_class(raw_severity)
    validation_css = validation_class(raw_validation)

    def create_list(items):
        if not isinstance(items, list) or not items:
            return "<li>No information available</li>"

        return "".join(
            f"<li>{safe_text(item)}</li>"
            for item in items
        )

    review_warning = ""

    if raw_validation == "REVIEW_REQUIRED":
        review_warning = """
        <div class="warning">
            <strong>Human Review Required</strong>
            <p>
                Business or production impact has not been established.
                Review the AI severity before accepting it.
            </p>
        </div>
        """

    elif raw_validation == "INVALID_RESPONSE":
        review_warning = """
        <div class="warning danger">
            <strong>Invalid AI Response</strong>
            <p>
                The AI analysis did not pass independent validation.
                Manual investigation is required.
            </p>
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">

        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">

        <title>{source} - AI DevOps Report</title>

        <link rel="stylesheet" href="{CSS_FILE}">
    </head>

    <body>

    <div class="container">

        <div class="header">

            <h1>AI DevOps Log Analysis</h1>

            <div class="subtitle">
                Intelligent Log Analysis and Root Cause Investigation
            </div>

            <div class="metadata">

                <div class="metadata-item">
                    <span class="metadata-label">Log Source</span>
                    <strong>{source}</strong>
                </div>

                <div class="metadata-item">
                    <span class="metadata-label">AI Model</span>
                    <strong>{model}</strong>
                </div>

                <div class="metadata-item">
                    <span class="metadata-label">Log File</span>
                    {log_file}
                </div>

                <div class="metadata-item">
                    <span class="metadata-label">Generated At</span>
                    {generated_at}
                </div>

            </div>

        </div>

        <div class="summary-grid">

            <div class="summary-card">

                <h2>Problem Summary</h2>

                <p>{summary}</p>

            </div>

            <div class="summary-card severity-summary-{severity_css}">

                <h2>AI Severity</h2>

                <span class="badge severity-badge-{severity_css}">
                    {severity}
                </span>

            </div>

        </div>

        <div class="card">

            <h2>Root Cause Analysis</h2>

            <p>{root_cause}</p>

        </div>

        <div class="card">

            <h2>Evidence from Logs</h2>

            <ul>
                {create_list(evidence)}
            </ul>

        </div>

        <div class="card">

            <h2>Severity Validation</h2>

            <span class="badge validation-badge-{validation_css}">
                {validation_status}
            </span>

            {review_warning}

            <ul>
                {create_list(validation_issues)}
            </ul>

        </div>

        <div class="card">

            <h2>Troubleshooting Steps</h2>

            <ol>
                {create_list(troubleshooting)}
            </ol>

        </div>

        <div class="card">

            <h2>Preventive Actions</h2>

            <ul>
                {create_list(preventive_actions)}
            </ul>

        </div>

        <div class="footer">
            AI DevOps Log Analyzer | Powered by Ollama
        </div>

    </div>

    </body>
    </html>
    """


def main():

    HTML_DIR.mkdir(parents=True, exist_ok=True)

    for json_file in REPORT_DIR.glob("*-report.json"):

        with json_file.open("r", encoding="utf-8") as file:
            report = json.load(file)

        html_content = generate_html_report(report)

        output_file = HTML_DIR / (
            json_file.stem + ".html"
        )

        output_file.write_text(
            html_content,
            encoding="utf-8"
        )

        print(f"HTML report generated: {output_file}")


if __name__ == "__main__":
    main()
