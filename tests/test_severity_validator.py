
import unittest

from severity_validator import validate_severity


class TestSeverityValidator(unittest.TestCase):

    def setUp(self):

        self.valid_analysis = {
            "problem_summary": "Application startup failure",
            "severity": "CRITICAL",
            "root_cause": "Database connection failed",
            "evidence": [
                "Connection refused"
            ],
            "troubleshooting_steps": [
                "Check database connectivity"
            ],
            "preventive_actions": [
                "Implement connection monitoring"
            ]
        }

    def test_missing_impact_evidence(self):

        result = validate_severity(self.valid_analysis)

        self.assertEqual(
            result["validation_status"],
            "REVIEW_REQUIRED"
        )

        self.assertFalse(
            result["impact_evidence_found"]
        )

    def test_production_impact_evidence(self):

        analysis = self.valid_analysis.copy()

        analysis["evidence"] = [
            "Production outage confirmed",
            "Customer impact reported"
        ]

        result = validate_severity(analysis)

        self.assertEqual(
            result["validation_status"],
            "CHECK_PASSED"
        )

        self.assertTrue(
            result["impact_evidence_found"]
        )

    def test_invalid_severity(self):

        analysis = self.valid_analysis.copy()
        analysis["severity"] = "URGENT"

        result = validate_severity(analysis)

        self.assertEqual(
            result["validation_status"],
            "INVALID_RESPONSE"
        )

    def test_missing_required_field(self):

        analysis = self.valid_analysis.copy()
        del analysis["root_cause"]

        result = validate_severity(analysis)

        self.assertEqual(
            result["validation_status"],
            "INVALID_RESPONSE"
        )


if __name__ == "__main__":
    unittest.main()
