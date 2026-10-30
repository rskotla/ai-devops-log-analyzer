
import json


def validate_evidence(analysis, source_data):

    issues = []
    verified_evidence = []
    unsupported_evidence = []

    source_text = json.dumps(
        source_data,
        ensure_ascii=False
    ).lower()

    evidence = analysis.get("evidence", [])

    if not isinstance(evidence, list) or not evidence:
        return {
            "grounding_status": "INVALID",
            "verified_evidence": [],
            "unsupported_evidence": [],
            "issues": ["Evidence must be a non-empty list"]
        }

    for item in evidence:

        if not isinstance(item, str) or not item.strip():
            unsupported_evidence.append(str(item))
            continue

        if item.strip().lower() in source_text:
            verified_evidence.append(item)
        else:
            unsupported_evidence.append(item)

    if unsupported_evidence:
        issues.append(
            "AI generated evidence that could not be verified "
            "in the original Kubernetes report."
        )

    status = "PASS" if not issues else "REVIEW_REQUIRED"

    return {
        "grounding_status": status,
        "verified_evidence": verified_evidence,
        "unsupported_evidence": unsupported_evidence,
        "issues": issues
    }
