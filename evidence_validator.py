import re


MIN_SOURCE_MATCH_LENGTH = 24


def _collect_source_strings(value):
    """Recursively collect original string values from the source report."""
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


def _matching_pods_for_evidence(evidence, source_data):
    """Resolve pod identity using namespace when pod names are duplicated."""
    pods = source_data.get("pods", {}).get("pods", [])

    matching = [
        pod for pod in pods
        if pod.get("name")
        and re.search(
            r"\b" + re.escape(pod["name"].lower()) + r"\b",
            evidence.lower()
        )
    ]

    if len(matching) <= 1:
        return matching

    qualified = []

    for pod in matching:
        namespace = pod.get("namespace") or source_data.get("namespace")

        if not namespace:
            continue

        pattern = (
            r"(?<![a-z0-9.-])"
            + re.escape(namespace.lower())
            + r"(?![a-z0-9.-])"
        )

        if re.search(pattern, evidence.lower()):
            qualified.append(pod)

    return qualified if len(qualified) == 1 else []


def _find_source_fragment(evidence, source_strings):
    """Accept only complete, explicitly quoted log fragments found in source."""
    quote_match = re.search(
        r'\b(?:contain|contains|show|shows)\s+"(.+)"\s*[.!?]*$',
        evidence,
        re.IGNORECASE
    )

    if not quote_match:
        return None

    fragment = quote_match.group(1).strip()
    normalized_fragment = fragment.replace(chr(92) + '"', '"')

    if len(normalized_fragment) < MIN_SOURCE_MATCH_LENGTH:
        return None

    for source in source_strings:
        if not source:
            continue

        normalized_source = source.replace(chr(92) + '"', '"')
        index = normalized_source.lower().find(
            normalized_fragment.lower()
        )

        if index >= 0:
            return normalized_source[
                index:index + len(normalized_fragment)
            ]

    return None

def _verify_structured_evidence(evidence, source_data):
    """
    Verify supported Kubernetes pod and container status claims.

    Returns:
        True  - all detected structured claims are supported.
        False - at least one structured claim is unsupported.
        None  - no structured Kubernetes claim was detected.
    """
    text = evidence.lower()

    structured_markers = (
        "phase",
        "ready",
        "exitcode",
        "previous_state",
        "previous state",
        "current running state",
        "current state"
    )

    if not any(marker in text for marker in structured_markers):
        return None

    pods = source_data.get("pods", {}).get("pods", [])

    # Identify the exact pod mentioned in the evidence.
    matching_pods = _matching_pods_for_evidence(evidence, source_data)

    if len(matching_pods) != 1:
        return False

    pod = matching_pods[0]

    # Verify pod phase when claimed.
    phase_match = re.search(
        r'["\']?phase["\']?\s*:\s*["\']?([a-zA-Z]+)',
        evidence,
        re.IGNORECASE
    )

    if phase_match:
        claimed_phase = phase_match.group(1).lower()

        if str(pod.get("phase", "")).lower() != claimed_phase:
            return False

    # Identify the exact container mentioned in the evidence.
    containers = pod.get("containers", [])
    matching_containers = [
        container for container in containers
        if container.get("name")
        and re.search(
            r"\b" + re.escape(container["name"].lower()) + r"\b",
            text
        )
    ]

    if not matching_containers:
        return False

    if len(matching_containers) != 1:
        return False

    container = matching_containers[0]

    # Verify container readiness when claimed.
    ready_match = re.search(
        r'["\']?ready["\']?\s*:\s*(true|false)\b',
        evidence,
        re.IGNORECASE
    )

    if ready_match:
        claimed_ready = ready_match.group(1).lower() == "true"

        if container.get("ready") is not claimed_ready:
            return False

    # Verify current running state when explicitly claimed.
    if "current running state" in text:
        current_state = container.get("state", {})

        if not isinstance(current_state, dict) or "running" not in current_state:
            return False

    # Verify previous termination details.
    exit_match = re.search(
        r"\bexitcode\s*[:=]?\s*(\d+)\b",
        evidence,
        re.IGNORECASE
    )

    reason_match = re.search(
        r'\breason\b\s*(?:[:=]\s*)?["\']?([a-zA-Z0-9_-]+)',
        evidence,
        re.IGNORECASE
    )

    if exit_match or reason_match or "previous_state" in text or "previous state" in text:

        last_state = container.get("last_state", {})
        terminated = last_state.get("terminated", {})

        if not isinstance(terminated, dict) or not terminated:
            return False

        if exit_match:
            claimed_exit_code = int(exit_match.group(1))

            if terminated.get("exitCode") != claimed_exit_code:
                return False

        if reason_match:
            claimed_reason = reason_match.group(1).lower()

            if str(terminated.get("reason", "")).lower() != claimed_reason:
                return False

    return True


def validate_evidence(analysis, source_data):

    issues = []
    verified_evidence = []
    unsupported_evidence = []

    source_strings = _collect_source_strings(source_data)
    source_text = "\n".join(source_strings).lower()

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

        normalized_item = item.strip()

        # Structured Kubernetes claims must pass structured verification.
        structured_result = _verify_structured_evidence(
            normalized_item,
            source_data
        )

        if structured_result is not None:
            if (
                structured_result
                and _verify_compound_log_claims(normalized_item, source_data)
            ):
                verified_evidence.append(normalized_item)
            else:
                unsupported_evidence.append(normalized_item)
            continue

        # Previous-log claims must be verified only against container logs.
        if re.search(
            r"(?:(?:previous|current)\s+)?(?:container[\s_]+)?logs?(?:\s+entry\b.*?)?\s+(?:show|shows|contain|contains)\s*:?",
            normalized_item,
            re.IGNORECASE
        ):
            if _verify_compound_log_claims(normalized_item, source_data):
                verified_evidence.append(normalized_item)
            else:
                unsupported_evidence.append(normalized_item)
            continue

        # Preserve exact source matching for ordinary log evidence.
        if normalized_item.lower() in source_text:
            if normalized_item not in verified_evidence:
                verified_evidence.append(normalized_item)
            continue

        # Verify a continuous source fragment for quoted log evidence.
        source_fragment = _find_source_fragment(
            normalized_item,
            source_strings
        )

        if source_fragment:
            if source_fragment not in verified_evidence:
                verified_evidence.append(source_fragment)
        else:
            unsupported_evidence.append(normalized_item)

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


def _verify_compound_log_claims(evidence, source_data):
    """Verify previous-log claims against the correct container log record."""
    log_match = re.search(
        r'(?:(previous|current)\s+)?(?:container[\s_]+)?logs?(?:\s+entry\b.*?)?\s+(?:show|shows|contain|contains)\s*:?\s*(.+)$',
        evidence,
        re.IGNORECASE
    )

    if not log_match:
        return True

    log_scope = (
        log_match.group(1).lower()
        if log_match.group(1)
        else None
    )
    log_claim = log_match.group(2)

    fragments = [
        fragment.strip()
        for fragment in re.findall(r'"([^"]+)"', log_claim)
        if fragment.strip()
    ]

    if not fragments:
        return False

    records = source_data.get("container_logs", [])
    if not records:
        return False

    pods = source_data.get("pods", {}).get("pods", [])
    matching_pods = _matching_pods_for_evidence(evidence, source_data)

    if pods:
        mentioned_pod_names = [
            pod.get("name")
            for pod in pods
            if pod.get("name")
            and re.search(
                r"\b" + re.escape(pod["name"].lower()) + r"\b",
                evidence.lower()
            )
        ]

        if mentioned_pod_names and len(matching_pods) != 1:
            return False

    if len(matching_pods) == 1:
        pod = matching_pods[0]
        pod_name = pod.get("name")
        pod_namespace = pod.get("namespace") or source_data.get("namespace")

        matching_containers = [
            container.get("name")
            for container in pod.get("containers", [])
            if container.get("name")
            and re.search(
                r"\b" + re.escape(container["name"].lower()) + r"\b",
                evidence.lower()
            )
        ]

        if len(matching_containers) != 1:
            return False

        container_name = matching_containers[0]

        matching_records = [
            record for record in records
            if record.get("pod") == pod_name
            and record.get("container") == container_name
            and (record.get("namespace") or source_data.get("namespace"))
                == pod_namespace
        ]

    elif not pods and len(records) == 1:
        # Preserve the legacy fallback for a single unambiguous record.
        matching_records = records

    elif not pods:
        # Logs-only batches may contain multiple records. Require explicit
        # namespace, pod and container identity before selecting a record.
        candidates = []

        def mentioned(value):
            if not isinstance(value, str) or not value:
                return False

            pattern = (
                r"(?<![a-z0-9_.-])"
                + re.escape(value.lower())
                + r"(?![a-z0-9_.-])"
            )
            return re.search(pattern, evidence.lower()) is not None

        for record in records:
            pod_name = record.get("pod")
            container_name = record.get("container")
            namespace = (
                record.get("namespace")
                or source_data.get("namespace")
            )

            if not mentioned(pod_name) or not mentioned(container_name):
                continue

            # Namespaced records require the namespace to be stated too.
            if not namespace or not mentioned(namespace):
                continue

            candidates.append(record)

        matching_records = candidates if len(candidates) == 1 else []

    else:
        return False

    if not matching_records:
        return False

    matching_logs = []

    for record in matching_records:
        scopes = [log_scope] if log_scope else ["previous", "current"]

        for scope in scopes:
            log_data = record.get(scope, {})
            logs = (
                log_data.get("logs", "")
                if isinstance(log_data, dict)
                else log_data if isinstance(log_data, str)
                else ""
            )

            if isinstance(logs, str) and logs:
                matching_logs.append(logs)

    if not matching_logs:
        return False

    original_logs = "\n".join(matching_logs).lower()

    # Normal case: independently verify every quoted fragment.
    if all(fragment.lower() in original_logs for fragment in fragments):
        return True

    # Also support nested quotes inside a single log message.
    return _find_source_fragment(evidence, matching_logs) is not None
