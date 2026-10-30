
import unittest

from html_report_generator import generate_html_report


class TestHTMLReportGenerator(unittest.TestCase):

    def setUp(self):

        self.report = {
            "log_source": "Jenkins",
            "log_file": "logs/jenkins/jenkins-build.log",
            "generated_at": "2026-10-30T19:00:00+05:30",
            "model": "llama3.2:latest",
            "analysis": {
                "problem_summary": "Jenkins build failed",
                "severity": "MEDIUM",
                "root_cause": "Invalid Flask package version",
                "evidence": [
                    "No matching distribution found"
                ],
                "troubleshooting_steps": [
                    "Check requirements.txt"
                ],
                "preventive_actions": [
                    "Use compatible package versions"
                ],
                "severity_validation": {
                    "validation_status": "REVIEW_REQUIRED",
                    "ai_severity": "MEDIUM",
                    "impact_evidence_found": False,
                    "issues": [
                        "Production impact is not established"
                    ]
                }
            }
        }

    def test_html_document_generation(self):

        result = generate_html_report(self.report)

        self.assertIn("<!DOCTYPE html>", result)
        self.assertIn("</html>", result)

    def test_report_source_displayed(self):

        result = generate_html_report(self.report)

        self.assertIn("Jenkins", result)

    def test_severity_displayed(self):

        result = generate_html_report(self.report)

        self.assertIn("MEDIUM", result)

    def test_validation_status_displayed(self):

        result = generate_html_report(self.report)

        self.assertIn("REVIEW_REQUIRED", result)

    def test_html_content_is_escaped(self):

        report = self.report.copy()
        report["analysis"] = self.report["analysis"].copy()

        report["analysis"]["problem_summary"] = (
            "<script>alert('test')</script>"
        )

        result = generate_html_report(report)

        self.assertNotIn(
            "<script>alert('test')</script>",
            result
        )

        self.assertIn(
            "&lt;script&gt;",
            result
        )


if __name__ == "__main__":
    unittest.main()
