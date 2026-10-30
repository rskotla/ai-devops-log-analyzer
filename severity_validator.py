
ALLOWED_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
}

REQUIRED_FIELDS = [
    "problem_summary",
    "severity",
    "root_cause",
    "evidence",
    "troubleshooting_steps",
    "preventive_actions"
]

IMPACT_KEYWORDS = [
    "production outage",
    "production down",
    "customer impact",
    "business impact",
    "data loss",
    "service unavailable",
    "multiple services affected"
]


def validate_severity(analysis):

    issues = []

    # Step 1: Validate response structure
    if not isinstance(analysis, dict):
        return {
            "validation_status": "INVALID_RESPONSE",
            "issues": ["AI response must be a JSON object"]
        }

    for field in REQUIRED_FIELDS:
        if field not in analysis:
            issues.append(f"Missing required field: {field}")

    if issues:
        return {
            "validation_status": "INVALID_RESPONSE",
            "issues": issues
        }

    # Step 2: Validate severity value
    severity = analysis["severity"]

    if not isinstance(severity, str) or severity.upper() not in ALLOWED_SEVERITIES:
        issues.append("Invalid severity value")

    # Step 3: Validate evidence
    evidence = analysis["evidence"]

    if not isinstance(evidence, list) or not evidence:
        issues.append("Evidence must be a non-empty list")

    if issues:
        return {
            "validation_status": "INVALID_RESPONSE",
            "issues": issues
        }

    # Step 4: Check impact context
    evidence_text = " ".join(str(item) for item in evidence).lower()

    impact_found = any(
        keyword in evidence_text
        for keyword in IMPACT_KEYWORDS
    )

    if not impact_found:
        return {
            "validation_status": "REVIEW_REQUIRED",
            "ai_severity": severity.upper(),
            "impact_evidence_found": False,
            "issues": [
                "Business or production impact is not established by the evidence.",
                "Human review is required before accepting the AI severity."
            ]
        }

    return {
        "validation_status": "CHECK_PASSED",
        "ai_severity": severity.upper(),
        "impact_evidence_found": True,
        "issues": []
    }
