import pytest

from evidence_validator import validate_evidence


@pytest.fixture
def source_data():
    return {
        "container_logs": [
            {
                "pod": "shopnova-postgres-0",
                "container": "postgres",
                "previous": {
                    "logs": (
                        "LOG: could not send data to client: Broken pipe\n"
                        "FATAL: connection to client lost"
                    )
                }
            }
        ]
    }


def test_exact_source_evidence_passes(source_data):
    analysis = {
        "evidence": [
            "FATAL: connection to client lost"
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "PASS"
    assert len(result["verified_evidence"]) == 1
    assert result["unsupported_evidence"] == []


def test_quoted_source_log_fragment_is_recognized(source_data):
    analysis = {
        "evidence": [
            'Previous logs contain "FATAL: connection to client lost".'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "PASS"
    assert result["verified_evidence"]


def test_fabricated_evidence_requires_review(source_data):
    analysis = {
        "evidence": [
            "Database was permanently corrupted."
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"
    assert result["unsupported_evidence"]


def test_mixed_evidence_preserves_unsupported_items(source_data):
    analysis = {
        "evidence": [
            "FATAL: connection to client lost",
            "All customer orders were lost."
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"


def test_empty_evidence_is_invalid(source_data):
    result = validate_evidence({"evidence": []}, source_data)

    assert result["grounding_status"] == "INVALID"


def test_non_string_evidence_is_not_verified(source_data):
    result = validate_evidence(
        {"evidence": [123]},
        source_data
    )

    assert result["grounding_status"] == "REVIEW_REQUIRED"


def test_nested_quoted_nginx_log_fragment_is_recognized():
    source_data = {
        "container_logs": [
            {
                "pod": "shopnova-web-68698dddcf-kh722",
                "container": "web",
                "previous": {
                    "logs": (
                        '2026-10-28T14:36:04.878997724+05:30 '
                        '2026/10/28 09:05:59 [emerg] 1#1: '
                        'host not found in upstream "api" '
                        'in /etc/nginx/conf.d/default.conf:8'
                    )
                }
            }
        ]
    }

    analysis = {
        "evidence": [
            'Previous logs contain "host not found in upstream '
            '"api" in /etc/nginx/conf.d/default.conf:8".'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "PASS"
    assert any(
        'host not found in upstream "api" '
        'in /etc/nginx/conf.d/default.conf:8' in item
        for item in result["verified_evidence"]
    )
    assert result["unsupported_evidence"] == []


def test_structured_pod_status_evidence_is_verified():
    source_data = {
        "pods": {
            "pods": [{
                "name": "shopnova-postgres-0",
                "phase": "Running",
                "containers": [{
                    "name": "postgres",
                    "ready": True,
                    "state": {"running": {"startedAt": "2026-10-28T09:06:54Z"}}
                }]
            }]
        }
    }

    analysis = {
        "evidence": [
            'shopnova-postgres-0 is currently "phase": "Running" '
            'and its postgres container is "ready": true with current running state.'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "PASS"
    assert result["unsupported_evidence"] == []


def test_structured_previous_termination_evidence_is_verified():
    source_data = {
        "pods": {
            "pods": [{
                "name": "shopnova-postgres-0",
                "containers": [{
                    "name": "postgres",
                    "last_state": {
                        "terminated": {
                            "exitCode": 255,
                            "reason": "Unknown"
                        }
                    }
                }]
            }]
        }
    }

    analysis = {
        "evidence": [
            'shopnova-postgres-0 previous_state shows exitCode 255 '
            'with reason "Unknown" for the postgres container.'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "PASS"
    assert result["unsupported_evidence"] == []


def test_structured_evidence_with_wrong_exit_code_requires_review():
    source_data = {
        "pods": {
            "pods": [{
                "name": "shopnova-postgres-0",
                "containers": [{
                    "name": "postgres",
                    "last_state": {
                        "terminated": {
                            "exitCode": 255,
                            "reason": "Unknown"
                        }
                    }
                }]
            }]
        }
    }

    analysis = {
        "evidence": [
            'shopnova-postgres-0 previous_state shows exitCode 0 '
            'with reason "Completed" for the postgres container.'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"
    assert result["unsupported_evidence"]


def test_compound_structured_evidence_with_fabricated_log_requires_review():
    source_data = {
        "pods": {
            "pods": [{
                "name": "shopnova-api-test",
                "phase": "Running",
                "containers": [{
                    "name": "api",
                    "ready": True,
                    "state": {"running": {"startedAt": "2026-11-04T02:28:54Z"}}
                }]
            }]
        },
        "container_logs": [{
            "pod": "shopnova-api-test",
            "container": "api",
            "previous": {
                "logs": "Worker exiting\nShutting down: Master"
            }
        }]
    }

    analysis = {
        "evidence": [
            'shopnova-api-test is currently "phase": "Running" '
            'and its api container is "ready": true with current running state; '
            'previous logs show "Worker exiting" and '
            '"Database permanently destroyed due to disk failure".'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"
    assert result["unsupported_evidence"]


def test_compound_structured_evidence_with_verified_logs_passes():
    source_data = {
        "pods": {
            "pods": [{
                "name": "shopnova-api-test",
                "phase": "Running",
                "containers": [{
                    "name": "api",
                    "ready": True,
                    "state": {"running": {"startedAt": "2026-11-04T02:28:54Z"}}
                }]
            }]
        },
        "container_logs": [{
            "pod": "shopnova-api-test",
            "container": "api",
            "previous": {
                "logs": "Worker exiting\nShutting down: Master"
            }
        }]
    }

    analysis = {
        "evidence": [
            'shopnova-api-test is currently "phase": "Running" '
            'and its api container is "ready": true with current running state; '
            'previous logs show "Worker exiting" and "Shutting down: Master".'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "PASS"
    assert result["unsupported_evidence"] == []


def test_wrong_termination_reason_with_correct_exit_code_requires_review():
    source_data = {
        "pods": {
            "pods": [{
                "name": "shopnova-postgres-0",
                "containers": [{
                    "name": "postgres",
                    "last_state": {
                        "terminated": {
                            "exitCode": 255,
                            "reason": "Unknown"
                        }
                    }
                }]
            }]
        }
    }

    analysis = {
        "evidence": [
            'shopnova-postgres-0 previous_state shows exitCode 255 '
            'with reason "Completed" for the postgres container.'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"
    assert result["unsupported_evidence"]


def test_compound_logs_from_wrong_namespace_require_review():
    source_data = {
        "pods": {
            "pods": [{
                "namespace": "namespace-a",
                "name": "shared-pod",
                "phase": "Running",
                "containers": [{
                    "name": "app",
                    "ready": True,
                    "state": {"running": {"startedAt": "2026-11-04T02:00:00Z"}}
                }]
            }]
        },
        "container_logs": [{
            "namespace": "namespace-b",
            "pod": "shared-pod",
            "container": "app",
            "previous": {
                "logs": "Database permanently destroyed due to disk failure"
            }
        }]
    }

    analysis = {
        "evidence": [
            'In namespace-a, shared-pod is currently "phase": "Running" '
            'and its app container is "ready": true with current running state; '
            'previous logs show "Database permanently destroyed due to disk failure".'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"
    assert result["unsupported_evidence"]


def test_partial_log_match_with_fabricated_claim_requires_review(source_data):
    analysis = {
        "evidence": [
            "FATAL: connection to client lost; "
            "all customer data was permanently deleted."
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"
    assert result["unsupported_evidence"]


def test_quoted_log_evidence_found_only_in_event_requires_review():
    source_data = {
        "container_logs": [],
        "events": {
            "events": [{
                "message": "Database connection reset by peer after timeout"
            }]
        }
    }

    analysis = {
        "evidence": [
            'Previous logs contain "Database connection reset by peer after timeout".'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"
    assert result["unsupported_evidence"]


def test_container_log_evidence_found_only_in_event_requires_review():
    source_data = {
        "container_logs": [],
        "events": {
            "events": [{
                "message": "Database connection reset by peer after timeout"
            }]
        }
    }

    analysis = {
        "evidence": [
            'Container logs show "Database connection reset by peer after timeout".'
        ]
    }

    result = validate_evidence(analysis, source_data)

    assert result["grounding_status"] == "REVIEW_REQUIRED"
    assert result["unsupported_evidence"]
