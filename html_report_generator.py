
import json
import html

from pathlib import Path

REPORT_DIR = Path("reports")
HTML_DIR = REPORT_DIR / "html"


def safe_text(value):
    """Escape content before displaying it in HTML."""
    return html.escape(str(value))


def generate_html_report(report):

    analysis = report["analysis"]
    validation = analysis.get("severity_validation", {})

    source = safe_text(report["log_source"])
    log_file = safe_text(report["log_file"])
    generated_at = safe_text(report["generated_at"])
    model = safe_text(report["model"])

    summary = safe_text(analysis.get("problem_summary", "N/A"))
    severity = safe_text(analysis.get("severity", "N/A"))
    root_cause = safe_text(analysis.get("root_cause", "N/A"))

    validation_status = safe_text(
        validation.get("validation_status", "NOT AVAILABLE")
    )

    evidence = analysis.get("evidence", [])
    troubleshooting = analysis.get("troubleshooting_steps", [])
    preventive_actions = analysis.get("preventive_actions", [])
    validation_issues = validation.get("issues", [])

    def create_list(items):

        if not isinstance(items, list) or not items:
            return "<li>No information available</li>"

        return "".join(
            f"<li>{safe_text(item)}</li>"
            for item in items
        )

    # Severity styling
    severity_colors = {
        "LOW": "#15803d",
        "MEDIUM": "#a16207",
        "HIGH": "#c2410c",
        "CRITICAL": "#b91c1c"
    }

    raw_severity = str(
        analysis.get("severity", "N/A")
    ).upper()

    severity_color = severity_colors.get(
        raw_severity,
        "#64748b"
    )

    # Validation styling
    validation_colors = {
        "CHECK_PASSED": "#15803d",
        "REVIEW_REQUIRED": "#b45309",
        "INVALID_RESPONSE": "#b91c1c"
    }

    raw_validation = str(
        validation.get("validation_status", "NOT AVAILABLE")
    ).upper()

    validation_color = validation_colors.get(
        raw_validation,
        "#64748b"
    )

    # Human review warning
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

        <style>

            * {{
                box-sizing: border-box;
            }}

            body {{
                font-family: Arial, Helvetica, sans-serif;
                background: #f1f5f9;
                margin: 0;
                padding: 30px;
                color: #1e293b;
                line-height: 1.6;
            }}

            .container {{
                max-width: 1050px;
                margin: auto;
            }}

            /* Header */

            .header {{
                background: linear-gradient(
                    135deg,
                    #172554,
                    #1e40af
                );

                color: white;
                padding: 30px;
                border-radius: 14px;
                box-shadow: 0 5px 15px rgba(15, 23, 42, 0.12);
            }}

            .header h1 {{
                margin: 0 0 20px;
                font-size: 28px;
            }}

            .subtitle {{
                color: #bfdbfe;
                font-size: 14px;
                margin-bottom: 20px;
            }}

            .metadata {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
            }}

            .metadata-item {{
                background: rgba(255, 255, 255, 0.10);
                padding: 12px;
                border-radius: 8px;
                overflow-wrap: anywhere;
                font-size: 13px;
            }}

            .metadata-label {{
                color: #bfdbfe;
                display: block;
                font-size: 11px;
                text-transform: uppercase;
                margin-bottom: 4px;
            }}

            /* Summary cards */

            .summary-grid {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
                margin-top: 20px;
            }}

            .summary-card {{
                background: white;
                padding: 22px;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(15, 23, 42, 0.05);
                border-left: 5px solid #2563eb;
            }}

            .summary-card h2 {{
                margin: 0 0 12px;
                font-size: 16px;
                color: #64748b;
            }}

            .summary-card p {{
                margin: 0;
                font-size: 15px;
                overflow-wrap: anywhere;
            }}

            /* General report cards */

            .card {{
                background: white;
                padding: 24px;
                margin-top: 20px;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(15, 23, 42, 0.05);
            }}

            .card h2 {{
                margin: 0 0 16px;
                font-size: 19px;
                color: #172554;
                border-bottom: 1px solid #e2e8f0;
                padding-bottom: 12px;
            }}

            .card p {{
                overflow-wrap: anywhere;
            }}

            /* Badges */

            .badge {{
                display: inline-block;
                color: white;
                padding: 7px 14px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: bold;
                letter-spacing: 0.4px;
            }}

            /* Lists */

            ul, ol {{
                padding-left: 22px;
                margin-bottom: 0;
            }}

            li {{
                margin-bottom: 10px;
                line-height: 1.6;
                overflow-wrap: anywhere;
            }}

            /* Warning */

            .warning {{
                background: #fffbeb;
                border-left: 5px solid #d97706;
                padding: 16px 20px;
                border-radius: 8px;
                margin-top: 16px;
                color: #92400e;
            }}

            .warning p {{
                margin: 6px 0 0;
            }}

            .danger {{
                background: #fef2f2;
                border-left-color: #dc2626;
                color: #991b1b;
            }}

            /* Footer */

            .footer {{
                text-align: center;
                margin-top: 30px;
                padding: 20px;
                color: #64748b;
                font-size: 13px;
            }}

            /* Responsive layout */

            @media (max-width: 650px) {{

                body {{
                    padding: 12px;
                }}

                .header {{
                    padding: 22px;
                }}

                .header h1 {{
                    font-size: 22px;
                }}

                .metadata,
                .summary-grid {{
                    grid-template-columns: 1fr;
                }}

                .card {{
                    padding: 18px;
                }}
            }}

            /* Print layout */

            @media print {{

                body {{
                    background: white;
                    padding: 0;
                }}

                .header,
                .card,
                .summary-card {{
                    box-shadow: none;
                    break-inside: avoid;
                }}

            }}

        </style>

    </head>

    <body>

    <div class="container">

        <!-- Header -->

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

        <!-- Summary -->

        <div class="summary-grid">

            <div class="summary-card">

                <h2>Problem Summary</h2>

                <p>{summary}</p>

            </div>

            <div class="summary-card"
                 style="border-left-color:{severity_color}">

                <h2>AI Severity</h2>

                <span class="badge"
                      style="background:{severity_color}">

                    {severity}

                </span>

            </div>

        </div>

        <!-- Root Cause -->

        <div class="card">

            <h2>Root Cause Analysis</h2>

            <p>{root_cause}</p>

        </div>

        <!-- Evidence -->

        <div class="card">

            <h2>Evidence from Logs</h2>

            <ul>
                {create_list(evidence)}
            </ul>

        </div>

        <!-- Validation -->

        <div class="card">

            <h2>Severity Validation</h2>

            <span class="badge"
                  style="background:{validation_color}">

                {validation_status}

            </span>

            {review_warning}

            <ul>
                {create_list(validation_issues)}
            </ul>

        </div>

        <!-- Troubleshooting -->

        <div class="card">

            <h2>Troubleshooting Steps</h2>

            <ol>
                {create_list(troubleshooting)}
            </ol>

        </div>

        <!-- Prevention -->

        <div class="card">

            <h2>Preventive Actions</h2>

            <ul>
                {create_list(preventive_actions)}
            </ul>

        </div>

        <!-- Footer -->

        <div class="footer">

            <strong>AI DevOps Log Analyzer</strong>

            <p>
                Generated using Python and Ollama LLM
            </p>

            <p>
                AI-generated recommendations require human review.
            </p>

        </div>

    </div>

    </body>

    </html>
    """


def main():

    HTML_DIR.mkdir(parents=True, exist_ok=True)

    report_files = list(
        REPORT_DIR.glob("*-report.json")
    )

    if not report_files:
        print("No JSON reports found.")
        return

    for report_file in report_files:

        try:

            with open(
                report_file,
                "r",
                encoding="utf-8"
            ) as file:

                report = json.load(file)

            required_fields = [
                "log_source",
                "log_file",
                "generated_at",
                "model",
                "analysis"
            ]

            if not isinstance(report, dict):
                print(f"Invalid report structure: {report_file}")
                continue

            if not all(
                field in report
                for field in required_fields
            ):

                print(f"Missing required fields: {report_file}")
                continue

            if not isinstance(report["analysis"], dict):
                print(f"Invalid analysis structure: {report_file}")
                continue

            html_content = generate_html_report(report)

            output_file = HTML_DIR / (
                f"{report_file.stem}.html"
            )

            with open(
                output_file,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(html_content)

            print(f"HTML report generated: {output_file}")

        except (
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError
        ) as error:

            print(
                f"Report generation failed for "
                f"{report_file}: {error}"
            )


if __name__ == "__main__":
    main()
