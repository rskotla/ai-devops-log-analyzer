import re

# Recommendations that can change runtime state or configuration. These are
# review triggers, not proof that the recommendation is always unsafe.
ACTION_PATTERN = re.compile(
    r"\b(?:restart(?:ing|ed|s)?|reboot(?:ing|ed|s)?|delet(?:e|ing|ed)|"
    r"remov(?:e|ing|ed)|kill(?:ing|ed)?|terminat(?:e|ing|ed)|"
    r"scal(?:e|ing|ed)|patch(?:ing|ed)?|apply(?:ing|ied)?|"
    r"roll(?:out|ing\s+back)|drain(?:ing|ed)?|cordon(?:ing|ed)?|"
    r"uncordon(?:ing|ed)?|force(?:d|fully)?|flush(?:ing|ed)?|"
    r"reset(?:ting)?|reconfigur(?:e|ing|ed)|updat(?:e|ing|ed)|"
    r"chang(?:e|ing|ed)|modif(?:y|ying|ied)|increas(?:e|ing|ed)|"
    r"decreas(?:e|ing|ed))\b",
    re.IGNORECASE,
)
CONFIG_TARGET_PATTERN = re.compile(
    r"\b(?:restart[_ ]?count|replicas?|image|tag|driver|connection\s+string|"
    r"environment\s+variables?|config(?:uration)?|deployment|statefulset|"
    r"service\s+configuration|database\s+settings?)\b",
    re.IGNORECASE,
)
CURRENT_OUTAGE_PATTERN = re.compile(
    r"\b(?:currently|right\s+now|at\s+present|today|ongoing|still)\b"
    r".{0,70}\b(?:down|stopped|crashed|failing|failed|unavailable|"
    r"connection\s+(?:failure|failed|error)|not\s+reachable)\b|"
    r"\b(?:service|database|postgres(?:ql)?|application|pod)\s+is\s+"
    r"(?:down|stopped|crashed|unavailable|failing)\b|"
    r"\bproduction\s+is\s+down\b",
    re.IGNORECASE | re.DOTALL,
)
PROBE_ONLY_PATTERN = re.compile(
    r"\b(?:probe\s+summary|health.?check\s+summary|successful\s+probes?)\b",
    re.IGNORECASE,
)

UNCERTAINTY_PATTERN = re.compile(
    r"\b(?:possible|possibly|may|might|could|appears?|observed|correlation|"
    r"not proven|not established|unknown|undetermined|cannot confirm|"
    r"insufficient evidence|not enough evidence|unclear|uncertain|"
    r"do not prove|does not prove|doesn't prove|"
    r"cannot be proven|cannot establish|not confirmed|"
    r"not enough information|ultimate root cause is unconfirmed)\b",
    re.IGNORECASE,
)

HISTORICAL_PATTERN = re.compile(
    r"\b(?:historical|previous logs|previous container|earlier logs|"
    r"past incident|prior incident|previously|earlier failure)\b",
    re.IGNORECASE,
)
WORKER_BEFORE_DATABASE_PATTERN = re.compile(
    r"\b(?:worker\s+(?:failure|failed|crash(?:ed)?)|gunicorn\s+worker\s+"
    r"(?:failure|failed|crash(?:ed)?))\b.{0,100}\b(?:before|preceded)\b"
    r".{0,100}\b(?:database|postgres(?:ql)?|sqlalchemy|psycopg)\b",
    re.IGNORECASE | re.DOTALL,
)


def _as_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(item for item in value if isinstance(item, str))
    return ""


def _record(checks, issues, name, passed, detail):
    checks.append({
        "check": name,
        "status": "PASS" if passed else "REVIEW_REQUIRED",
        "detail": detail,
    })
    if not passed:
        issues.append(detail)





NEGATED_OUTAGE_PATTERN = re.compile(
    r"\b(?:no|not|without)\s+(?:clear\s+)?"
    r"(?:evidence|indication|sign)\b|"
    r"\brather\s+than\s+(?:clear\s+)?evidence\s+that\b|"
    r"\bdoes\s+not\s+show\s+that\b|"
    r"\bthere\s+is\s+no\s+evidence\s+that\b",
    re.IGNORECASE,
)



def _has_unnegated_current_outage(text):
    for match in CURRENT_OUTAGE_PATTERN.finditer(text):
        preceding_text = text[max(0, match.start() - 120):match.start()]

        if NEGATED_OUTAGE_PATTERN.search(preceding_text):
            continue

        return True

    return False


def _is_historical_status_investigation(line):
    investigation = re.search(
        r"\b(?:confirm|check|verify|review|inspect|determine)\b",
        line, re.IGNORECASE
    )
    uncertainty = re.search(r"\b(?:whether|if)\b", line, re.IGNORECASE)
    historical_status = re.search(
        r"\b(?:was|were|had been)\s+"
        r"(?:restarting|restarted|terminating|terminated)\b",
        line, re.IGNORECASE
    )
    time_context = re.search(
        r"\b(?:at|around|during)\s+(?:the\s+)?"
        r"(?:time|incident|timestamp)\b",
        line, re.IGNORECASE
    )

    return bool(
        investigation and uncertainty and historical_status and time_context
    )




def _is_read_only_recommendation(line):
    read_only = re.match(
        r"^\s*(?:inspect|review|check|verify|determine)\b",
        line, re.IGNORECASE
    )

    historical_sources = re.search(
        r"\b(?:logs?|events?|history|historical|previous-container)\b",
        line, re.IGNORECASE
    )

    retain_logs = re.match(
        r"^\s*retain\b", line, re.IGNORECASE
    ) and re.search(
        r"\b(?:logs?|log\s+retention)\b",
        line, re.IGNORECASE
    )

    return bool(
        (read_only and historical_sources) or retain_logs
    )


def validate_ai_output(analysis, context, severity_validation):
    """Flag unsupported interpretations and recommendations needing review."""
    issues = []
    checks = []
    summary = _as_text(analysis.get("problem_summary"))
    root_cause = _as_text(analysis.get("root_cause"))
    recommendations = (
        _as_text(analysis.get("troubleshooting_steps")) + "\n"
        + _as_text(analysis.get("preventive_actions"))
    )
    correlations = context.get("incident_correlations", [])
    correlation = correlations[0] if correlations else None

    _record(checks, issues, "problem_summary_present", bool(summary.strip()),
            "Problem summary is missing or empty.")
    _record(checks, issues, "root_cause_present",
            bool(root_cause.strip()) and root_cause.strip().lower() != "none",
            "Root cause is not established or the explanation is missing.")

    if correlation:
        incident_pod = correlation.get("pod")
        combined = f"{summary}\n{root_cause}"
        probe_only = bool(PROBE_ONLY_PATTERN.search(summary)) and not re.search(
            r"database|sqlalchemy|psycopg|gunicorn|worker|connection",
            summary, re.IGNORECASE
        )
        _record(checks, issues, "incident_focus", not probe_only,
                "Problem summary focuses on health probes instead of the correlated incident.")

        
        if incident_pod:
            _record(
                checks,
                issues,
                "affected_pod_identification",
                incident_pod.lower() in combined.lower(),
                f"Summary or root-cause explanation does not identify affected pod '{incident_pod}'.",
            )

            # Identify pods explicitly listed in an affected-pod claim.
            affected_claim_pattern = re.compile(
                r"\b(?:errors?\s+(?:occurred|found)\s+in|"
                r"affected pods?|failed pods?|crashed pods?)\b"
                r"([^.;]*)",
                re.IGNORECASE,
            )

            affected_pod_mentions = set()

            for match in affected_claim_pattern.finditer(summary):
                affected_pod_mentions.update(
                    re.findall(
                        r"\bshopnova-[a-z0-9-]+\b",
                        match.group(1),
                        re.IGNORECASE,
                    )
                )

            other_pods = sorted(
                pod for pod in affected_pod_mentions
                if pod.lower() != incident_pod.lower()
            )

            unsupported_scope = bool(other_pods)

            _record(
                checks,
                issues,
                "incident_scope",
                not unsupported_scope,
                (
                    "Summary appears to label additional pods as affected without "
                    "a matching incident correlation: " + ", ".join(other_pods)
                ) if unsupported_scope else
                "No unsupported additional affected-pod claim was detected.",
            )


        historical = correlation.get("time_scope") == "HISTORICAL_PREVIOUS_CONTAINER_LOGS"
        if historical:
            historical_wording = bool(HISTORICAL_PATTERN.search(combined))
            _record(checks, issues, "historical_context", historical_wording,
                    "The analysis does not clearly label the failure as historical/previous-log evidence.")

            if correlation.get("current_pod_phase") == "Running":
                current_outage = _has_unnegated_current_outage(combined)
                _record(checks, issues, "current_vs_historical_status", not current_outage,
                        "The analysis appears to describe a current outage although the source pod phase is Running.")

        if correlation.get("incident_type") == (
            "DATABASE_CONNECTION_FAILURE_WITH_APPLICATION_WORKER_FAILURE"
        ):
            _record(checks, issues, "root_cause_certainty",
                    bool(UNCERTAINTY_PATTERN.search(root_cause)),
                    "Root-cause wording is too definitive for a temporal database/worker correlation; the ultimate cause is unconfirmed.")

            expected_sequence = correlation.get("observed_sequence", "")
            sequence_contradiction = bool(WORKER_BEFORE_DATABASE_PATTERN.search(combined))
            _record(checks, issues, "incident_sequence_consistency",
                    not sequence_contradiction,
                    ("The analysis reverses the observed order. Source correlation says the database connection error "
                     "appears before the Gunicorn worker failure. " + expected_sequence)
                    if sequence_contradiction else
                    "No contradiction with the observed database-error-before-worker-failure sequence was detected.")

    review_recommendations = [
        line.strip() for line in recommendations.splitlines()
        if line.strip()
        and ACTION_PATTERN.search(line)
        and not _is_historical_status_investigation(line)
        and not _is_read_only_recommendation(line)
    ]
    config_change_recommendations = [
        line for line in review_recommendations if CONFIG_TARGET_PATTERN.search(line)
    ]
    _record(checks, issues, "recommendation_safety", not review_recommendations,
            ("Potentially disruptive or unverified recommendation(s) require human approval: "
             + " | ".join(review_recommendations)) if review_recommendations else
            "No configured runtime-action or configuration-change words were detected in recommendations.")
    _record(checks, issues, "configuration_change_review", not config_change_recommendations,
            ("Recommendation(s) propose changing infrastructure/application configuration and require validation: "
             + " | ".join(config_change_recommendations)) if config_change_recommendations else
            "No explicit infrastructure/application configuration change was detected.")

    severity_status = severity_validation.get("validation_status")
    _record(checks, issues, "severity_confidence", severity_status == "CHECK_PASSED",
            "Severity remains unverified by the existing severity validator; human review is required.")

    return {
        "validation_status": "PASS" if not issues else "REVIEW_REQUIRED",
        "checks": checks,
        "issues": issues,
        "unsafe_recommendations": review_recommendations,
        "recommendations_requiring_review": review_recommendations,
        "configuration_change_recommendations": config_change_recommendations,
        "severity_validation_status": severity_status,
        "note": ("PASS means no configured output-quality rule was triggered. "
                 "It does not prove that the AI's root-cause conclusion is true. "
                 "REVIEW_REQUIRED recommendations are review triggers, not automatic prohibitions."),
    }
