
import pytest

from kubernetes_live_analyzer import validate_pod_status_claims


@pytest.fixture
def running_pod_context():
    """Sample Kubernetes context with a running PostgreSQL pod."""
    return {
        "pods": [
            {
                "name": "shopnova-postgres-0",
                "phase": "Running",
                "containers": [
                    {
                        "name": "postgres",
                        "ready": True,
                        "restart_count": 2,
                    }
                ],
            }
        ]
    }


def test_running_pod_incorrectly_claimed_as_not_running(
    running_pod_context,
):
    """A false stopped claim must require manual review."""

    analysis = {
        "problem_summary": (
            "The PostgreSQL pod shopnova-postgres-0 is not running."
        ),
        "root_cause": "Database failure",
        "evidence": ["Database connection failed"],
        "troubleshooting_steps": [],
        "preventive_actions": [],
    }

    result = validate_pod_status_claims(
        analysis,
        running_pod_context,
    )

    assert result["validation_status"] == "REVIEW_REQUIRED"
    assert result["verified_pods"] == []
    assert len(result["issues"]) == 1


def test_correct_running_pod_claim_passes(
    running_pod_context,
):
    """A correct running status claim should pass validation."""

    analysis = {
        "problem_summary": (
            "The PostgreSQL pod shopnova-postgres-0 is currently running."
        ),
        "root_cause": "No current pod failure identified.",
        "evidence": ["Pod phase is Running."],
        "troubleshooting_steps": [],
        "preventive_actions": [],
    }

    result = validate_pod_status_claims(
        analysis,
        running_pod_context,
    )

    assert result["validation_status"] == "CHECK_PASSED"
    assert "shopnova-postgres-0" in result["verified_pods"]
    assert "shopnova-postgres-0/postgres" in result["verified_pods"]
    assert result["issues"] == []


def test_historical_termination_does_not_mean_pod_stopped(
    running_pod_context,
):
    """Historical container termination must not imply current pod failure."""

    analysis = {
        "problem_summary": (
            "The PostgreSQL pod shopnova-postgres-0 is currently running."
        ),
        "root_cause": (
            "The postgres container previously terminated, "
            "but the pod is now running."
        ),
        "evidence": ["Previous container exit code was 255."],
        "troubleshooting_steps": [],
        "preventive_actions": [],
    }

    result = validate_pod_status_claims(
        analysis,
        running_pod_context,
    )

    assert result["validation_status"] == "CHECK_PASSED"
    assert "shopnova-postgres-0" in result["verified_pods"]
    assert result["issues"] == []
