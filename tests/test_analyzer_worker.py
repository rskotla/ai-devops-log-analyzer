import json

import pytest

import analyzer_worker as worker


def setup_worker(tmp_path, monkeypatch):
    incoming = tmp_path / "incoming"
    state_dir = tmp_path / "worker-state"

    incoming.mkdir()

    monkeypatch.setattr(worker, "INCOMING_DIR", incoming)
    monkeypatch.setattr(worker, "STATE_DIR", state_dir)
    monkeypatch.setattr(worker, "STATE_FILE", state_dir / "worker-state.json")

    return incoming


def write_batch(incoming, name):
    payload = {
        "batch_id": name,
        "source": "test",
        "pods": {"pods": []},
        "container_logs": [
            {
                "namespace": "default",
                "pod": "test-pod",
                "container": "test-container",
                "current": {
                    "success": True,
                    "logs": "test log",
                    "error": None
                },
                "previous": {
                    "success": False,
                    "logs": "",
                    "error": None
                }
            }
        ],
        "events": {"events": []}
    }

    path = incoming / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_first_startup_skips_existing_batches(tmp_path, monkeypatch):
    incoming = setup_worker(tmp_path, monkeypatch)
    old_batch = write_batch(incoming, "old-batch.json")
    old_batch.chmod(0o600)

    state = worker.load_or_initialize_state()

    assert old_batch.name in state["baseline_files"]
    assert state["processed"] == []

    monkeypatch.setattr(
        worker,
        "run_analyzer",
        lambda path: (_ for _ in ()).throw(
            AssertionError("Historical batch must not be processed")
        )
    )

    worker.process_pending(state, retry_seconds=60)


def test_new_batch_is_processed(tmp_path, monkeypatch):
    incoming = setup_worker(tmp_path, monkeypatch)
    batch = write_batch(incoming, "new-batch.json")

    state = {
        "baseline_files": [],
        "processed": [],
        "failed": {}
    }

    calls = []

    monkeypatch.setattr(worker, "is_stable_file", lambda path: True)
    monkeypatch.setattr(
        worker,
        "run_analyzer",
        lambda path: calls.append(path.name) or tmp_path / "report.json"
    )

    worker.process_pending(state, retry_seconds=60)

    assert calls == [batch.name]
    assert batch.name in state["processed"]
    assert batch.name not in state["failed"]


def test_successful_batch_is_not_processed_twice(tmp_path, monkeypatch):
    incoming = setup_worker(tmp_path, monkeypatch)
    batch = write_batch(incoming, "duplicate-test.json")

    state = {
        "baseline_files": [],
        "processed": [],
        "failed": {}
    }

    calls = []

    monkeypatch.setattr(worker, "is_stable_file", lambda path: True)
    monkeypatch.setattr(
        worker,
        "run_analyzer",
        lambda path: calls.append(path.name) or tmp_path / "report.json"
    )

    worker.process_pending(state, retry_seconds=60)
    worker.process_pending(state, retry_seconds=60)

    assert calls == [batch.name]


def test_failed_batch_is_preserved_and_retry_is_delayed(
    tmp_path, monkeypatch
):
    incoming = setup_worker(tmp_path, monkeypatch)
    batch = write_batch(incoming, "failed-batch.json")

    state = {
        "baseline_files": [],
        "processed": [],
        "failed": {}
    }

    calls = []

    monkeypatch.setattr(worker, "is_stable_file", lambda path: True)

    def fail_analysis(path):
        calls.append(path.name)
        raise RuntimeError("Simulated analyzer failure")

    monkeypatch.setattr(worker, "run_analyzer", fail_analysis)

    worker.process_pending(state, retry_seconds=3600)
    worker.process_pending(state, retry_seconds=3600)

    assert batch.exists()
    assert batch.name not in state["processed"]
    assert state["failed"][batch.name]["attempts"] == 1
    assert calls == [batch.name]



def test_in_progress_receiver_file_is_not_baselined(
    tmp_path, monkeypatch
):
    incoming = setup_worker(tmp_path, monkeypatch)
    batch = write_batch(incoming, "in-progress-batch.json")

    # Receiver has not yet applied its final mode 600.
    batch.chmod(0o644)

    state = worker.load_or_initialize_state()

    assert batch.name not in state["baseline_files"]

    calls = []

    monkeypatch.setattr(worker, "is_stable_file", lambda path: True)
    monkeypatch.setattr(
        worker,
        "run_analyzer",
        lambda path: calls.append(path.name) or tmp_path / "report.json"
    )

    # Simulate the receiver completing its write.
    batch.chmod(0o600)

    worker.process_pending(state, retry_seconds=60)

    assert calls == [batch.name]
    assert batch.name in state["processed"]


def setup_report_validation(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    monkeypatch.setattr(worker, "REPORT_DIR", reports)

    batch = tmp_path / "incoming-batch.json"
    batch.write_text("{}", encoding="utf-8")

    return reports, batch


def write_valid_report(reports, source_file):
    report = {
        "report_type": "LIVE_KUBERNETES_AI_ANALYSIS",
        "source_file": source_file,
        "analysis": {"problem_summary": "Test analysis"},
    }
    path = reports / "live-kubernetes-report-test.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_valid_report_matching_batch_is_accepted(tmp_path, monkeypatch):
    reports, batch = setup_report_validation(tmp_path, monkeypatch)
    report = write_valid_report(reports, batch.name)

    result = worker.validate_saved_report(report, batch)

    assert result == report.resolve()


def test_report_with_wrong_source_file_is_rejected(tmp_path, monkeypatch):
    reports, batch = setup_report_validation(tmp_path, monkeypatch)
    report = write_valid_report(reports, "different-batch.json")

    with pytest.raises(RuntimeError, match="source does not match"):
        worker.validate_saved_report(report, batch)

def test_report_with_wrong_type_is_rejected(tmp_path, monkeypatch):
    reports, batch = setup_report_validation(tmp_path, monkeypatch)
    report = write_valid_report(reports, batch.name)

    data = json.loads(report.read_text())
    data["report_type"] = "UNEXPECTED_REPORT"
    report.write_text(json.dumps(data))

    with pytest.raises(RuntimeError, match="report type"):
        worker.validate_saved_report(report, batch)

def test_invalid_report_json_is_rejected(tmp_path, monkeypatch):
    reports, batch = setup_report_validation(tmp_path, monkeypatch)
    report = reports / "live-kubernetes-report-invalid.json"
    report.write_text("{invalid json")

    with pytest.raises(RuntimeError, match="valid readable JSON"):
        worker.validate_saved_report(report, batch)

def test_report_outside_reports_directory_is_rejected(tmp_path, monkeypatch):
    reports, batch = setup_report_validation(tmp_path, monkeypatch)
    outside = tmp_path / "live-kubernetes-report-outside.json"
    outside.write_text(json.dumps({
        "report_type": "LIVE_KUBERNETES_AI_ANALYSIS",
        "source_file": batch.name,
        "analysis": {},
    }))

    with pytest.raises(RuntimeError, match="outside the reports directory"):
        worker.validate_saved_report(outside, batch)

def test_symlink_report_is_rejected(tmp_path, monkeypatch):
    reports, batch = setup_report_validation(tmp_path, monkeypatch)
    actual = write_valid_report(reports, batch.name)
    link = reports / "live-kubernetes-report-link.json"
    link.symlink_to(actual)

    with pytest.raises(RuntimeError, match="symlink"):
        worker.validate_saved_report(link, batch)

def test_worker_skips_batch_without_receiver_completion_permission(
    tmp_path, monkeypatch
):
    incoming = setup_worker(tmp_path, monkeypatch)
    batch = write_batch(incoming, "not-completed.json")
    batch.chmod(0o644)

    state = {
        "baseline_files": [],
        "processed": [],
        "failed": {}
    }

    calls = []

    monkeypatch.setattr(worker, "is_stable_file", lambda path: True)
    monkeypatch.setattr(
        worker,
        "run_analyzer",
        lambda path: calls.append(path.name)
    )

    worker.process_pending(state, retry_seconds=60)

    assert calls == []
    assert batch.name not in state["processed"]
    assert batch.name not in state["failed"]
    assert batch.exists()
