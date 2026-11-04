from ai_output_validator import validate_ai_output


def context():
    return {"incident_correlations": [{
        "incident_type": "DATABASE_CONNECTION_FAILURE_WITH_APPLICATION_WORKER_FAILURE",
        "time_scope": "HISTORICAL_PREVIOUS_CONTAINER_LOGS",
        "pod": "shopnova-api-example",
        "current_pod_phase": "Running",
        "observed_sequence": "A database connection error appears before a Gunicorn worker failure.",
    }]}


def severity(status="CHECK_PASSED"):
    return {"validation_status": status}


def analysis(**changes):
    result = {
        "problem_summary": "Historical database connection error preceded a Gunicorn worker failure in pod shopnova-api-example.",
        "severity": "MEDIUM",
        "root_cause": "The observed database connection failure may be related to the worker failure, but the ultimate cause is not established.",
        "evidence": ["source-backed line"],
        "troubleshooting_steps": ["Review PostgreSQL and application logs."],
        "preventive_actions": ["Add connection monitoring."],
    }
    result.update(changes)
    return result


def check(result, name):
    return next(item for item in result["checks"] if item["check"] == name)


def test_supported_historical_analysis_passes():
    assert validate_ai_output(analysis(), context(), severity())["validation_status"] == "PASS"


def test_probe_only_summary_is_flagged():
    result = validate_ai_output(analysis(problem_summary="Kubernetes Probe Summary"), context(), severity())
    assert result["validation_status"] == "REVIEW_REQUIRED"


def test_missing_affected_pod_is_flagged():
    result = validate_ai_output(
        analysis(problem_summary="Historical database connection error preceded a worker failure.",
                 root_cause="The observed failure may be related, but the ultimate cause is unknown."),
        context(), severity()
    )
    assert check(result, "affected_pod_identification")["status"] == "REVIEW_REQUIRED"


def test_definitive_root_cause_is_flagged():
    result = validate_ai_output(analysis(root_cause="PostgreSQL connection failure"), context(), severity())
    assert check(result, "root_cause_certainty")["status"] == "REVIEW_REQUIRED"


def test_restart_inflection_is_flagged():
    result = validate_ai_output(analysis(troubleshooting_steps=["Consider restarting the PostgreSQL service."]), context(), severity())
    assert result["validation_status"] == "REVIEW_REQUIRED"
    assert result["unsafe_recommendations"]


def test_restart_count_parameter_change_is_flagged():
    result = validate_ai_output(analysis(preventive_actions=["Increase restart_count for the database container."]), context(), severity())
    assert result["validation_status"] == "REVIEW_REQUIRED"
    assert result["configuration_change_recommendations"]


def test_driver_configuration_change_is_flagged():
    result = validate_ai_output(analysis(preventive_actions=["Update the database driver to postgresql+psycopg2."]), context(), severity())
    assert check(result, "configuration_change_review")["status"] == "REVIEW_REQUIRED"


def test_current_outage_claim_conflicts_with_running_pod():
    result = validate_ai_output(
        analysis(problem_summary="The database is down right now after a historical connection failure in pod shopnova-api-example."),
        context(), severity()
    )
    assert check(result, "current_vs_historical_status")["status"] == "REVIEW_REQUIRED"


def test_worker_before_database_sequence_is_flagged():
    result = validate_ai_output(
        analysis(root_cause="A worker failure occurred before the database connection error; this may be related."),
        context(), severity()
    )
    assert check(result, "incident_sequence_consistency")["status"] == "REVIEW_REQUIRED"


def test_database_before_worker_sequence_passes():
    result = validate_ai_output(
        analysis(root_cause="The database error appeared before the worker failure; their relationship is uncertain."),
        context(), severity()
    )
    assert check(result, "incident_sequence_consistency")["status"] == "PASS"


def test_unrelated_pods_not_labeled_affected():
    result = validate_ai_output(
        analysis(problem_summary="Historical database connection error preceded a worker failure in pod shopnova-api-example; PostgreSQL may be a dependency."),
        context(), severity()
    )
    assert check(result, "incident_scope")["status"] == "PASS"


def test_multiple_pods_claimed_affected_without_correlation_is_flagged():
    result = validate_ai_output(
        analysis(problem_summary="Historical errors occurred in shopnova-api-example, shopnova-postgres-0 and shopnova-backup-check."),
        context(), severity()
    )
    assert check(result, "incident_scope")["status"] == "REVIEW_REQUIRED"


def test_unverified_severity_requires_review():
    result = validate_ai_output(analysis(), context(), severity("REVIEW_REQUIRED"))
    assert result["validation_status"] == "REVIEW_REQUIRED"

def test_negated_current_outage_statement_passes():
    result = validate_ai_output(
        analysis(
            problem_summary=(
                "Historical previous-container logs show a database connection "
                "error followed by a worker failure. Current pod phase is Running, "
                "so there is no evidence here that the pod is currently down."
            )
        ),
        context(), severity()
    )
    assert check(result, "current_vs_historical_status")["status"] == "PASS"


def test_historical_restart_status_investigation_passes():
    result = validate_ai_output(
        analysis(
            troubleshooting_steps=[
                "Confirm whether the PostgreSQL endpoint was restarting or terminating at the time of the historical incident.",
                "Review Kubernetes events around the incident timestamp."
            ]
        ),
        context(), severity()
    )
    assert check(result, "recommendation_safety")["status"] == "PASS"
    assert result["unsafe_recommendations"] == []

def test_read_only_postgres_restart_investigation_passes():
    result = validate_ai_output(
        analysis(troubleshooting_steps=[
            "Inspect PostgreSQL logs to determine whether the server closed the connection unexpectedly or restarted."
        ]),
        context(), severity()
    )
    assert check(result, "recommendation_safety")["status"] == "PASS"


def test_read_only_deployment_event_review_passes():
    result = validate_ai_output(
        analysis(troubleshooting_steps=[
            "Review the API deployment events and readiness/liveness probe history to determine whether the worker failure caused a container restart."
        ]),
        context(), severity()
    )
    assert check(result, "recommendation_safety")["status"] == "PASS"
    assert check(result, "configuration_change_review")["status"] == "PASS"


def test_log_retention_recommendation_passes():
    result = validate_ai_output(
        analysis(preventive_actions=[
            "Retain sufficient previous-container logs for application pods to preserve failure context after restarts."
        ]),
        context(), severity()
    )
    assert check(result, "recommendation_safety")["status"] == "PASS"


def test_presence_check_details_are_accurate():
    result = validate_ai_output(analysis(), context(), severity())

    assert check(result, "problem_summary_present")["status"] == "PASS"
    assert check(result, "problem_summary_present")["detail"] == "Problem summary is present."

    assert check(result, "root_cause_present")["status"] == "PASS"
    assert check(result, "root_cause_present")["detail"] == "Root cause explanation is present."


def test_missing_summary_and_root_cause_details_are_accurate():
    result = validate_ai_output(
        analysis(problem_summary="", root_cause=""),
        context(),
        severity(),
    )

    assert check(result, "problem_summary_present")["status"] == "REVIEW_REQUIRED"
    assert check(result, "problem_summary_present")["detail"] == "Problem summary is missing or empty."

    assert check(result, "root_cause_present")["status"] == "REVIEW_REQUIRED"
    assert check(result, "root_cause_present")["detail"] == (
        "Root cause is not established or the explanation is missing."
    )


def test_restart_history_maintenance_recommendation_passes():
    result = validate_ai_output(
        analysis(preventive_actions=[
            "Maintain correlation data for real application errors and restart history to support future root-cause analysis."
        ]),
        context(),
        severity(),
    )

    assert check(result, "recommendation_safety")["status"] == "PASS"
    assert result["unsafe_recommendations"] == []


def test_restart_action_is_still_flagged_with_restart_history_context():
    result = validate_ai_output(
        analysis(preventive_actions=[
            "Maintain restart history and restart the PostgreSQL service."
        ]),
        context(),
        severity(),
    )

    assert check(result, "recommendation_safety")["status"] == "REVIEW_REQUIRED"
