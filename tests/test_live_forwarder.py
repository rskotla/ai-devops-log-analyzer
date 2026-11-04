import json
import sys

import pytest

import live_forwarder as forwarder


def make_record(namespace, pod, container, log, timestamp):
    return {
        "collection_timestamp": timestamp,
        "source": "Kubernetes",
        "namespace": namespace,
        "pod": pod,
        "container": container,
        "log": log
    }


def test_same_container_logs_are_aggregated():
    records = [
        make_record("app-ns", "api-pod", "api", "Log line one", "2026-11-04T10:00:00Z"),
        make_record("app-ns", "api-pod", "api", "Log line two", "2026-11-04T10:00:01Z")
    ]

    result = forwarder.group_log_records(records)

    assert len(result) == 1
    assert result[0]["current"]["logs"] == "Log line one\nLog line two"
    assert result[0]["namespace"] == "app-ns"
    assert result[0]["pod"] == "api-pod"
    assert result[0]["container"] == "api"
    assert result[0]["current"]["success"] is True
    assert result[0]["previous"]["logs"] == ""


def test_different_namespaces_are_kept_separate():
    records = [
        make_record("namespace-a", "shared-pod", "app", "Log A", "2026-11-04T10:00:00Z"),
        make_record("namespace-b", "shared-pod", "app", "Log B", "2026-11-04T10:00:01Z")
    ]

    result = forwarder.group_log_records(records)

    assert len(result) == 2
    assert result[0]["namespace"] == "namespace-a"
    assert result[1]["namespace"] == "namespace-b"


def test_payload_matches_analyzer_input_structure():
    records = [
        make_record("app-ns", "api-pod", "api", "Database timeout", "2026-11-04T10:00:00Z")
    ]

    payload = forwarder.build_payload(records, "test-batch-123")

    assert payload["batch_id"] == "test-batch-123"
    assert payload["pods"] == {"pods": []}
    assert payload["events"] == {"events": []}

    entry = payload["container_logs"][0]

    assert entry["current"]["success"] is True
    assert entry["current"]["logs"] == "Database timeout"
    assert entry["current"]["error"] is None
    assert entry["previous"]["success"] is False
    assert entry["previous"]["logs"] == ""


def test_batch_id_is_stable_for_same_file_range():
    first = forwarder.build_batch_id(1, 100, 500, 900)
    second = forwarder.build_batch_id(1, 100, 500, 900)
    different = forwarder.build_batch_id(1, 100, 500, 901)

    assert first == second
    assert first != different


def test_incomplete_jsonl_line_is_not_consumed(tmp_path, monkeypatch):
    source = tmp_path / "logs.jsonl"

    complete_record = make_record(
        "app-ns",
        "api-pod",
        "api",
        "Complete log",
        "2026-11-04T10:00:00Z"
    )

    complete_line = (
        json.dumps(complete_record).encode("utf-8") + b"\n"
    )

    source.write_bytes(
        complete_line + b'{"namespace":"incomplete'
    )

    monkeypatch.setattr(forwarder, "SOURCE_FILE", source)

    records, next_offset = forwarder.read_complete_records(0)

    assert len(records) == 1
    assert records[0]["log"] == "Complete log"
    assert next_offset == len(complete_line)


def configure_forwarder_paths(tmp_path, monkeypatch, initial_bytes=b""):
    source = tmp_path / "live-kubernetes-logs.jsonl"
    state_dir = tmp_path / "forwarder-state"
    checkpoint = state_dir / "checkpoint.json"

    source.write_bytes(initial_bytes)

    monkeypatch.setattr(forwarder, "SOURCE_FILE", source)
    monkeypatch.setattr(forwarder, "STATE_DIR", state_dir)
    monkeypatch.setattr(forwarder, "CHECKPOINT_FILE", checkpoint)

    return source, checkpoint


def read_checkpoint(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_first_startup_checkpoint_skips_existing_history(tmp_path, monkeypatch):
    historical = b'{"log":"old historical record"}\n'
    source, checkpoint_path = configure_forwarder_paths(
        tmp_path, monkeypatch, historical
    )

    checkpoint = forwarder.load_or_initialize_checkpoint()

    assert checkpoint["offset"] == len(historical)
    assert checkpoint["offset"] == source.stat().st_size
    assert checkpoint_path.exists()


def test_successful_delivery_advances_checkpoint(tmp_path, monkeypatch):
    source, checkpoint_path = configure_forwarder_paths(tmp_path, monkeypatch)
    forwarder.load_or_initialize_checkpoint()

    record = make_record(
        "app-ns", "api-pod", "api", "New log", "2026-11-04T10:00:00Z"
    )
    with source.open("ab") as output:
        output.write(json.dumps(record).encode() + b"\n")

    sent = {}

    def fake_send(payload, secret):
        sent["payload"] = payload
        sent["secret"] = secret
        return "accepted"

    monkeypatch.setattr(forwarder, "send_batch", fake_send)

    processed = forwarder.process_once("test-secret")

    assert processed == 1
    assert sent["secret"] == "test-secret"
    assert sent["payload"]["container_logs"][0]["current"]["logs"] == "New log"
    assert read_checkpoint(checkpoint_path)["offset"] == source.stat().st_size


def test_failed_delivery_does_not_advance_checkpoint(tmp_path, monkeypatch):
    source, checkpoint_path = configure_forwarder_paths(tmp_path, monkeypatch)
    initial = forwarder.load_or_initialize_checkpoint()
    original_offset = initial["offset"]

    record = make_record(
        "app-ns", "api-pod", "api", "Retry me", "2026-11-04T10:00:00Z"
    )
    with source.open("ab") as output:
        output.write(json.dumps(record).encode() + b"\n")

    def failed_send(payload, secret):
        raise RuntimeError("simulated network failure")

    monkeypatch.setattr(forwarder, "send_batch", failed_send)

    with pytest.raises(RuntimeError, match="simulated network failure"):        forwarder.process_once("test-secret")

    assert read_checkpoint(checkpoint_path)["offset"] == original_offset


def test_duplicate_delivery_advances_checkpoint(tmp_path, monkeypatch):
    source, checkpoint_path = configure_forwarder_paths(tmp_path, monkeypatch)
    forwarder.load_or_initialize_checkpoint()

    record = make_record(
        "app-ns", "api-pod", "api", "Already accepted", "2026-11-04T10:00:00Z"
    )
    with source.open("ab") as output:
        output.write(json.dumps(record).encode() + b"\n")

    monkeypatch.setattr(
        forwarder, "send_batch", lambda payload, secret: "duplicate"
    )

    processed = forwarder.process_once("test-secret")

    assert processed == 1
    assert read_checkpoint(checkpoint_path)["offset"] == source.stat().st_size


def test_source_rotation_stops_forwarding(tmp_path, monkeypatch):
    source, checkpoint_path = configure_forwarder_paths(
        tmp_path, monkeypatch, b'{"log":"before rotation"}\n'
    )
    original = forwarder.load_or_initialize_checkpoint()

    replacement = tmp_path / "replacement.jsonl"
    replacement.write_bytes(b'{"log":"after rotation"}\n')
    replacement.replace(source)

    assert source.stat().st_ino != original["inode"]

    with pytest.raises(RuntimeError, match="rotation detected"):
        forwarder.load_or_initialize_checkpoint()


def configure_test_ca(tmp_path, monkeypatch, exists=True):
    ca_file = tmp_path / "test-ca.crt"

    if exists:
        ca_file.write_text("test certificate", encoding="utf-8")

    monkeypatch.setattr(forwarder, "CA_FILE", ca_file)


def test_https_delivery_uses_ca_and_bearer_token(monkeypatch, tmp_path):
    captured = {}

    class FakeResponse:
        status = 201

        def read(self):
            return json.dumps({
                "status": "accepted",
                "batch_id": "test-123",
                "file": "batch-test-123.json"
            }).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    fake_context = object()

    def fake_create_default_context(cafile):
        captured["cafile"] = cafile
        return fake_context

    def fake_urlopen(request, context, timeout):
        captured["request"] = request
        captured["context"] = context
        captured["timeout"] = timeout
        return FakeResponse()

    configure_test_ca(tmp_path, monkeypatch)
    monkeypatch.setattr(
        forwarder.ssl, "create_default_context",
        fake_create_default_context
    )
    monkeypatch.setattr(forwarder, "urlopen", fake_urlopen)

    result = forwarder.send_batch(
        {"batch_id": "test-123"}, "unit-test-secret"
    )

    assert result == "accepted"
    assert captured["cafile"] == str(forwarder.CA_FILE)
    assert captured["context"] is fake_context
    assert captured["request"].get_header("Authorization") == (
        "Bearer unit-test-secret"
    )
    assert captured["request"].get_method() == "POST"
    assert captured["timeout"] == forwarder.REQUEST_TIMEOUT


def test_https_delivery_handles_duplicate_http_409(monkeypatch, tmp_path):
    from urllib.error import HTTPError

    configure_test_ca(tmp_path, monkeypatch)
    monkeypatch.setattr(
        forwarder.ssl, "create_default_context",
        lambda cafile: object()
    )

    import io

    def fake_urlopen(*args, **kwargs):
        response_body = json.dumps({
            "error": "Duplicate batch",
            "batch_id": "duplicate-123"
        }).encode("utf-8")

        raise HTTPError(
            forwarder.RECEIVER_URL,
            409,
            "Conflict",
            {},
            io.BytesIO(response_body)
        )

    monkeypatch.setattr(forwarder, "urlopen", fake_urlopen)

    assert forwarder.send_batch(
        {"batch_id": "duplicate-123"}, "test-secret"
    ) == "duplicate"


def test_https_delivery_rejects_unauthorized_http_401(monkeypatch, tmp_path):
    from urllib.error import HTTPError

    configure_test_ca(tmp_path, monkeypatch)
    monkeypatch.setattr(
        forwarder.ssl, "create_default_context",
        lambda cafile: object()
    )

    def fake_urlopen(*args, **kwargs):
        raise HTTPError(
            forwarder.RECEIVER_URL, 401, "Unauthorized", {}, None
        )

    monkeypatch.setattr(forwarder, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="HTTP 401"):
        forwarder.send_batch(
            {"batch_id": "auth-test"}, "wrong-secret"
        )


def test_https_delivery_reports_tls_verification_failure(monkeypatch, tmp_path):
    import ssl
    from urllib.error import URLError

    configure_test_ca(tmp_path, monkeypatch)
    monkeypatch.setattr(
        forwarder.ssl, "create_default_context",
        lambda cafile: object()
    )

    def fake_urlopen(*args, **kwargs):
        raise URLError(
            ssl.SSLCertVerificationError("certificate verification failed")
        )

    monkeypatch.setattr(forwarder, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="Receiver connection failed"):
        forwarder.send_batch(
            {"batch_id": "tls-test"}, "test-secret"
        )


def test_https_delivery_fails_if_ca_certificate_is_missing(monkeypatch, tmp_path):
    configure_test_ca(tmp_path, monkeypatch, exists=False)

    with pytest.raises(RuntimeError, match="CA certificate is missing"):
        forwarder.send_batch(
            {"batch_id": "missing-ca"}, "test-secret"
        )


def test_first_startup_skips_incomplete_trailing_record(tmp_path, monkeypatch):
    complete_line = b'{"log":"complete historical record"}\n'
    incomplete_line = b'{"log":"unfinished historical record'

    source, checkpoint_path = configure_forwarder_paths(
        tmp_path,
        monkeypatch,
        complete_line + incomplete_line
    )

    checkpoint = forwarder.load_or_initialize_checkpoint()

    assert checkpoint["offset"] == source.stat().st_size
    assert checkpoint["offset"] > len(complete_line)
    assert checkpoint["discard_until_newline"] is True

    saved = read_checkpoint(checkpoint_path)
    assert saved["offset"] == source.stat().st_size
    assert saved["discard_until_newline"] is True


def test_first_startup_does_not_forward_record_completed_after_startup(
    tmp_path, monkeypatch
):
    historical = b'{"log":"old historical record"}\n'

    record = make_record(
        "app-ns",
        "api-pod",
        "api",
        "Historical partial log",
        "2026-11-04T10:00:00Z"
    )

    record_line = json.dumps(record).encode("utf-8") + b"\n"
    split_at = len(record_line) // 2

    initial_bytes = historical + record_line[:split_at]

    source, checkpoint_path = configure_forwarder_paths(
        tmp_path, monkeypatch, initial_bytes
    )

    # Initialize forwarder while the record is incomplete.
    initial_checkpoint = forwarder.load_or_initialize_checkpoint()

    assert initial_checkpoint["offset"] == len(initial_bytes)
    assert initial_checkpoint["discard_until_newline"] is True

    # Simulate collector completing the previously incomplete record.
    with source.open("ab") as output:
        output.write(record_line[split_at:])

    sent = []

    def fake_send(payload, secret):
        sent.append(payload)
        return "accepted"

    monkeypatch.setattr(forwarder, "send_batch", fake_send)

    processed = forwarder.process_once("test-secret")

    # Historical partial record must not be forwarded.
    assert processed == 0
    assert sent == []

    # Checkpoint should move past the discarded historical record.
    saved = read_checkpoint(checkpoint_path)
    assert saved["offset"] == source.stat().st_size
    assert saved["discard_until_newline"] is False


def test_startup_partial_discard_preserves_new_records_after_newline(
    tmp_path, monkeypatch
):
    historical = b'{"log":"old historical record"}\n'
    partial_record = make_record(
        "app-ns",
        "api-pod",
        "api",
        "Historical partial log",
        "2026-11-04T10:00:00Z"
    )
    partial_line = json.dumps(partial_record).encode("utf-8") + b"\n"
    split_at = len(partial_line) // 2

    source, checkpoint_path = configure_forwarder_paths(
        tmp_path,
        monkeypatch,
        historical + partial_line[:split_at]
    )

    forwarder.load_or_initialize_checkpoint()

    new_record = make_record(
        "app-ns",
        "api-pod",
        "api",
        "Genuinely new log",
        "2026-11-04T10:00:05Z"
    )
    new_line = json.dumps(new_record).encode("utf-8") + b"\n"

    with source.open("ab") as output:
        output.write(partial_line[split_at:] + new_line)

    sent = []

    def fake_send(payload, secret):
        sent.append(payload)
        return "accepted"

    monkeypatch.setattr(forwarder, "send_batch", fake_send)

    processed = forwarder.process_once("test-secret")

    assert processed == 1
    assert len(sent) == 1
    assert sent[0]["container_logs"][0]["current"]["logs"] == "Genuinely new log"
    assert read_checkpoint(checkpoint_path)["offset"] == source.stat().st_size
    assert read_checkpoint(checkpoint_path)["discard_until_newline"] is False


def test_oversized_combined_payload_uses_smaller_batch(
    tmp_path, monkeypatch
):
    source, checkpoint_path = configure_forwarder_paths(
        tmp_path, monkeypatch
    )
    initial = forwarder.load_or_initialize_checkpoint()

    records = [
        make_record(
            "app-ns", "api-pod", "api",
            "A" * 300, "2026-11-04T10:00:00Z"
        ),
        make_record(
            "app-ns", "api-pod", "api",
            "B" * 300, "2026-11-04T10:00:01Z"
        )
    ]

    lines = [json.dumps(record).encode() + b"\n" for record in records]

    with source.open("ab") as output:
        output.writelines(lines)

    single_sizes = [
        len(json.dumps(
            forwarder.build_payload([record], "x" * 32),
            ensure_ascii=False
        ).encode("utf-8"))
        for record in records
    ]

    combined_size = len(json.dumps(
        forwarder.build_payload(records, "x" * 32),
        ensure_ascii=False
    ).encode("utf-8"))

    request_limit = max(single_sizes)
    assert combined_size > request_limit

    monkeypatch.setattr(
        forwarder, "MAX_BATCH_BYTES",
        sum(map(len, lines)) + 100
    )
    monkeypatch.setattr(
        forwarder, "MAX_REQUEST_BYTES", request_limit
    )

    sent = {}

    def fake_send(payload, secret):
        sent["payload"] = payload
        return "accepted"

    monkeypatch.setattr(forwarder, "send_batch", fake_send)

    processed = forwarder.process_once("test-secret")

    assert processed == 1
    assert len(sent["payload"]["container_logs"]) == 1
    assert read_checkpoint(checkpoint_path)["offset"] == len(lines[0])
    assert read_checkpoint(checkpoint_path)["offset"] > initial["offset"]


def test_single_oversized_serialized_record_does_not_advance_checkpoint(
    tmp_path, monkeypatch
):
    source, checkpoint_path = configure_forwarder_paths(
        tmp_path, monkeypatch
    )
    initial = forwarder.load_or_initialize_checkpoint()

    record = make_record(
        "app-ns", "api-pod", "api",
        "Z" * 300, "2026-11-04T10:00:00Z"
    )
    line = json.dumps(record).encode() + b"\n"

    with source.open("ab") as output:
        output.write(line)

    monkeypatch.setattr(
        forwarder, "MAX_BATCH_BYTES", len(line) + 100
    )
    monkeypatch.setattr(
        forwarder, "MAX_REQUEST_BYTES", len(line)
    )

    with pytest.raises(ValueError, match="payload larger"):
        forwarder.process_once("test-secret")

    assert read_checkpoint(checkpoint_path)["offset"] == initial["offset"]


def test_https_delivery_rejects_mismatched_duplicate_batch_id(
    monkeypatch, tmp_path
):
    import io
    from urllib.error import HTTPError

    configure_test_ca(tmp_path, monkeypatch)

    monkeypatch.setattr(
        forwarder.ssl, "create_default_context",
        lambda cafile: object()
    )

    def fake_urlopen(*args, **kwargs):
        body = json.dumps({
            "error": "Duplicate batch",
            "batch_id": "some-other-batch"
        }).encode()

        raise HTTPError(
            forwarder.RECEIVER_URL, 409, "Conflict", {},
            io.BytesIO(body)
        )

    monkeypatch.setattr(forwarder, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="different or unknown batch"):
        forwarder.send_batch(
            {"batch_id": "expected-batch"}, "test-secret"
        )


def test_https_delivery_rejects_invalid_duplicate_response(
    monkeypatch, tmp_path
):
    import io
    from urllib.error import HTTPError

    configure_test_ca(tmp_path, monkeypatch)

    monkeypatch.setattr(
        forwarder.ssl, "create_default_context",
        lambda cafile: object()
    )

    def fake_urlopen(*args, **kwargs):
        raise HTTPError(
            forwarder.RECEIVER_URL,
            409,
            "Conflict",
            {},
            io.BytesIO(b"not-json")
        )

    monkeypatch.setattr(forwarder, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="invalid duplicate response"):
        forwarder.send_batch(
            {"batch_id": "expected-batch"}, "test-secret"
        )

def test_https_delivery_rejects_unexpected_duplicate_error(
    monkeypatch, tmp_path
):
    import io
    from urllib.error import HTTPError

    configure_test_ca(tmp_path, monkeypatch)
    monkeypatch.setattr(
        forwarder.ssl, "create_default_context",
        lambda cafile: object()
    )

    def fake_urlopen(*args, **kwargs):
        body = json.dumps({
            "error": "Unexpected conflict",
            "batch_id": "expected-batch"
        }).encode()

        raise HTTPError(
            forwarder.RECEIVER_URL,
            409,
            "Conflict",
            {},
            io.BytesIO(body)
        )

    monkeypatch.setattr(forwarder, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="different or unknown batch"):
        forwarder.send_batch(
            {"batch_id": "expected-batch"}, "test-secret"
        )


def test_second_forwarder_instance_is_rejected(tmp_path, monkeypatch):
    state_dir = tmp_path / "forwarder-state"
    lock_path = state_dir / "forwarder.lock"

    monkeypatch.setattr(forwarder, "STATE_DIR", state_dir)
    monkeypatch.setattr(forwarder, "LOCK_FILE", lock_path)
    monkeypatch.setattr(
        forwarder, "load_receiver_secret",
        lambda: "unit-test-secret"
    )
    monkeypatch.setattr(
        sys, "argv",
        ["live_forwarder.py", "--once"]
    )

    state_dir.mkdir(mode=0o700)

    with lock_path.open("a", encoding="utf-8") as existing_lock:
        forwarder.fcntl.flock(
            existing_lock.fileno(),
            forwarder.fcntl.LOCK_EX | forwarder.fcntl.LOCK_NB
        )

        with pytest.raises(
            SystemExit,
            match="Another live forwarder is already running"
        ):
            forwarder.main()
