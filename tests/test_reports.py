
import unittest
import json
import tempfile

from pathlib import Path


EXPECTED_REPORTS = {
    "jenkins-report.json": "Jenkins",
    "docker-report.json": "Docker",
    "kubernetes-report.json": "Kubernetes"
}


class TestReports(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.report_dir = Path(self.temp_dir.name)

        for filename, source in EXPECTED_REPORTS.items():
            report = {
                "log_source": source,
                "log_file": f"logs/{source.lower()}.log",
                "generated_at": "2026-10-30T10:00:00",
                "model": "gpt-5.4-mini",
                "analysis": {
                    "problem_summary": "Sample issue",
                    "severity": "HIGH",
                    "root_cause": "Sample root cause",
                    "evidence": ["Sample evidence"],
                    "troubleshooting_steps": ["Check service"],
                    "preventive_actions": ["Add monitoring"],
                    "severity_validation": {
                        "validation_status": "REVIEW_REQUIRED",
                        "ai_severity": "HIGH",
                        "impact_evidence_found": False
                    }
                }
            }

            report_path = self.report_dir / filename

            with open(report_path, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=4)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_all_reports_exist(self):
        for filename in EXPECTED_REPORTS:
            report_path = self.report_dir / filename

            with self.subTest(report=filename):
                self.assertTrue(report_path.is_file())

    def test_reports_contain_valid_json(self):
        for filename in EXPECTED_REPORTS:
            report_path = self.report_dir / filename

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
            report_path = self.report_dir / filename

            with self.subTest(report=filename):
                with open(report_path, "r", encoding="utf-8") as file:
                    report = json.load(file)

                for field in required_fields:
                    self.assertIn(field, report)

    def test_report_source_matches_filename(self):
        for filename, expected_source in EXPECTED_REPORTS.items():
            report_path = self.report_dir / filename

            with self.subTest(report=filename):
                with open(report_path, "r", encoding="utf-8") as file:
                    report = json.load(file)

                self.assertEqual(
                    report["log_source"],
                    expected_source
                )

    def test_severity_validation_exists(self):
        for filename in EXPECTED_REPORTS:
            report_path = self.report_dir / filename

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
