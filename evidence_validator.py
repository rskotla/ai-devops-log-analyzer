def _collect_source_strings(value):
    """
    Recursively collect original string values from a nested source report.
    This avoids JSON escaping changing quotes and backslashes in log lines.
    """
    strings = []

    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for nested_value in value.values():
            strings.extend(_collect_source_strings(nested_value))
    elif isinstance(value, list):
        for nested_value in value:
            strings.extend(_collect_source_strings(nested_value))

    return strings


def validate_evidence(analysis, source_data):

    issues = []
    verified_evidence = []
    unsupported_evidence = []

    source_text = "\n".join(
        _collect_source_strings(source_data)
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
