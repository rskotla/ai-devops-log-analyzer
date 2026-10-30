
import unittest
import json

from pathlib import Path


REPORT_DIR = Path("reports")

EXPECTED_REPORTS = {
    "jenkins-report.json": "Jenkins",
    "docker-report.json": "Docker",
    "kubernetes-report.json": "Kubernetes"
}


class TestReports(unittest.TestCase):

    def test_all_reports_exist(self):

        for filename in EXPECTED_REPORTS:
            report_path = REPORT_DIR / filename

            with self.subTest(report=filename):
                self.assertTrue(report_path.is_file())

    def test_reports_contain_valid_json(self):

        for filename in EXPECTED_REPORTS:

            report_path = REPORT_DIR / filename

            with self.subTest(report=filename):
                with open(report_path, "r", encoding="utf-8") as file:
                    report = json.load(file)

                self.assertIsInstance(report, dict)

    def test_report_required_fields(self):

        required_fields = [
            "log_source",
            "log_file",
            "generated_at",
            "model",
            "analysis"
        ]

        for filename in EXPECTED_REPORTS:

            report_path = REPORT_DIR / filename

            with self.subTest(report=filename):
                with open(report_path, "r", encoding="utf-8") as file:
                    report = json.load(file)

                for field in required_fields:
                    self.assertIn(field, report)

    def test_report_source_matches_filename(self):

        for filename, expected_source in EXPECTED_REPORTS.items():

            report_path = REPORT_DIR / filename

            with self.subTest(report=filename):
                with open(report_path, "r", encoding="utf-8") as file:
                    report = json.load(file)

                self.assertEqual(
                    report["log_source"],
                    expected_source
                )

    def test_severity_validation_exists(self):

        for filename in EXPECTED_REPORTS:

            report_path = REPORT_DIR / filename

            with self.subTest(report=filename):
                with open(report_path, "r", encoding="utf-8") as file:
                    report = json.load(file)

                analysis = report["analysis"]

                self.assertIn("severity_validation", analysis)

                validation = analysis["severity_validation"]

                self.assertIn("validation_status", validation)
                self.assertIn("ai_severity", validation)
                self.assertIn("impact_evidence_found", validation)


if __name__ == "__main__":
    unittest.main()
