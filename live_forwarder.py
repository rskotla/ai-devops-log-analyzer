import argparse
import fcntl
import hashlib
import json
import os
import ssl
import tempfile
import time

from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_DIR = Path(__file__).resolve().parent
SOURCE_FILE = Path(
    "/opt/ai-devops-log-analyzer/reports/live-kubernetes-logs.jsonl"
)

STATE_DIR = Path("/opt/ai-devops-log-analyzer/forwarder-state")
CHECKPOINT_FILE = STATE_DIR / "checkpoint.json"
LOCK_FILE = STATE_DIR / "forwarder.lock"

ENV_FILE = PROJECT_DIR / "live_receiver" / ".env"
CA_FILE = PROJECT_DIR / "live_receiver" / "certs" / "ca.crt"

RECEIVER_URL = "https://192.168.1.32:8080/api/v1/logs"

MAX_BATCH_BYTES = 3 * 1024 * 1024
MAX_REQUEST_BYTES = 5 * 1024 * 1024
REQUEST_TIMEOUT = 15


def load_receiver_secret():
    if not ENV_FILE.is_file():
        raise RuntimeError("Receiver environment file is missing")

    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("RECEIVER_SECRET="):
            secret = line.split("=", 1)[1].strip()
            if secret:
                return secret

    raise RuntimeError("RECEIVER_SECRET is missing")


def save_checkpoint(device, inode, offset, discard_until_newline=False):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)

    checkpoint = {
        "device": device,
        "inode": inode,
        "offset": offset,
        "discard_until_newline": discard_until_newline,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }

    fd, temporary_path = tempfile.mkstemp(
        prefix=".checkpoint-",
        dir=str(STATE_DIR)
    )

    try:
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(checkpoint, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())

        os.replace(temporary_path, CHECKPOINT_FILE)
        os.chmod(CHECKPOINT_FILE, 0o600)

        directory_fd = os.open(
            STATE_DIR,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def find_last_complete_offset(source_file):
    """Return EOF if complete, otherwise the byte after the last newline."""
    with source_file.open("rb") as source:
        source.seek(0, os.SEEK_END)
        size = source.tell()

        if size == 0:
            return 0

        source.seek(size - 1)
        if source.read(1) == b"\n":
            return size

        chunk_size = 8192
        position = size

        while position > 0:
            read_size = min(chunk_size, position)
            position -= read_size
            source.seek(position)
            chunk = source.read(read_size)

            newline_index = chunk.rfind(b"\n")
            if newline_index != -1:
                return position + newline_index + 1

        return 0


def load_or_initialize_checkpoint():
    if not SOURCE_FILE.is_file():
        raise RuntimeError("Source JSONL file is missing")

    source_stat = SOURCE_FILE.stat()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)

    if not CHECKPOINT_FILE.exists():
        # Snapshot the current EOF. Any partial record already present at
        # startup is historical and must be discarded through its newline.
        with SOURCE_FILE.open("rb") as source:
            opened_stat = os.fstat(source.fileno())

            if (
                opened_stat.st_dev != source_stat.st_dev
                or opened_stat.st_ino != source_stat.st_ino
            ):
                raise RuntimeError(
                    "Source file changed during checkpoint initialization"
                )

            initial_offset = opened_stat.st_size
            discard_partial = False

            if initial_offset > 0:
                source.seek(initial_offset - 1)
                discard_partial = source.read(1) != b"\n"

        save_checkpoint(
            source_stat.st_dev,
            source_stat.st_ino,
            initial_offset,
            discard_partial
        )

        print(
            f"First startup: skipped {initial_offset} historical bytes. "
            f"Trailing partial record: {discard_partial}"
        )

    checkpoint = json.loads(
        CHECKPOINT_FILE.read_text(encoding="utf-8")
    )

    if (
        checkpoint.get("device") != source_stat.st_dev
        or checkpoint.get("inode") != source_stat.st_ino
    ):
        raise RuntimeError(
            "Source file rotation detected. "
            "Forwarding stopped to prevent data loss."
        )

    offset = checkpoint.get("offset")

    if not isinstance(offset, int) or offset < 0:
        raise RuntimeError("Invalid checkpoint offset")

    if offset > source_stat.st_size:
        raise RuntimeError(
            "Source file was truncated. Forwarding stopped."
        )

    discard_flag = checkpoint.get("discard_until_newline", False)

    if not isinstance(discard_flag, bool):
        raise RuntimeError("Invalid discard_until_newline checkpoint value")

    checkpoint["discard_until_newline"] = discard_flag

    return checkpoint


def discard_startup_partial_record(checkpoint):
    if not checkpoint.get("discard_until_newline", False):
        return checkpoint

    offset = checkpoint["offset"]

    with SOURCE_FILE.open("rb") as source:
        source_stat = os.fstat(source.fileno())

        if (
            source_stat.st_dev != checkpoint["device"]
            or source_stat.st_ino != checkpoint["inode"]
        ):
            raise RuntimeError(
                "Source file rotation detected while discarding startup data"
            )

        if offset > source_stat.st_size:
            raise RuntimeError(
                "Source file was truncated while discarding startup data"
            )

        source.seek(offset)

        while True:
            chunk = source.read(8192)

            if not chunk:
                new_offset = source.tell()

                if new_offset > offset:
                    save_checkpoint(
                        checkpoint["device"],
                        checkpoint["inode"],
                        new_offset,
                        True
                    )
                    checkpoint["offset"] = new_offset

                return checkpoint

            newline_index = chunk.find(b"\n")

            if newline_index != -1:
                chunk_start = source.tell() - len(chunk)
                new_offset = chunk_start + newline_index + 1

                save_checkpoint(
                    checkpoint["device"],
                    checkpoint["inode"],
                    new_offset,
                    False
                )

                checkpoint["offset"] = new_offset
                checkpoint["discard_until_newline"] = False

                print("Skipped historical partial JSONL record.")

                return checkpoint


def read_complete_records(offset, max_bytes=MAX_BATCH_BYTES):
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("Batch byte limit must be a positive integer")

    if not isinstance(offset, int) or offset < 0:
        raise ValueError("Source offset must be a non-negative integer")

    records = []
    total_bytes = 0
    next_offset = offset

    with SOURCE_FILE.open("rb") as source:
        opened_stat = os.fstat(source.fileno())
        path_stat = SOURCE_FILE.stat()

        if (opened_stat.st_dev, opened_stat.st_ino) != (
            path_stat.st_dev, path_stat.st_ino
        ):
            raise RuntimeError("Source rotation detected")

        if offset > opened_stat.st_size:
            raise RuntimeError("Source truncation detected")

        source.seek(offset)

        while total_bytes < max_bytes:
            line = source.readline()

            if not line:
                break

            if not line.endswith(b"\n"):
                break

            if total_bytes + len(line) > max_bytes:
                if records:
                    break

                if len(line) > MAX_REQUEST_BYTES:
                    raise ValueError(
                        "A single JSONL record exceeds receiver request size limit"
                    )

            try:
                record = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    "Invalid complete JSONL record; checkpoint unchanged"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError("JSONL record must be an object")

            records.append(record)
            total_bytes += len(line)
            next_offset = source.tell()

            if total_bytes >= max_bytes:
                break

        final_stat = os.fstat(source.fileno())
        final_path_stat = SOURCE_FILE.stat()

        if (final_stat.st_dev, final_stat.st_ino) != (
            opened_stat.st_dev, opened_stat.st_ino
        ) or (final_path_stat.st_dev, final_path_stat.st_ino) != (
            opened_stat.st_dev, opened_stat.st_ino
        ):
            raise RuntimeError("Source rotation detected during read")

        if (
            final_stat.st_size < next_offset
            or final_path_stat.st_size < next_offset
        ):
            raise RuntimeError("Source truncation detected during read")

    return records, next_offset


def group_log_records(records):
    grouped = {}

    for record in records:
        namespace = record.get("namespace")
        pod = record.get("pod")
        container = record.get("container")
        log_line = record.get("log")

        if not all(
            isinstance(value, str) and value
            for value in (namespace, pod, container)
        ):
            raise ValueError(
                "Log record has missing namespace, pod or container"
            )

        if not isinstance(log_line, str):
            raise ValueError("Log field must be a string")

        identity = (namespace, pod, container)

        if identity not in grouped:
            grouped[identity] = {
                "namespace": namespace,
                "pod": pod,
                "container": container,
                "log_lines": [],
                "log_timestamps": []
            }

        grouped[identity]["log_lines"].append(log_line)

        timestamp = record.get("collection_timestamp")
        if timestamp is not None:
            grouped[identity]["log_timestamps"].append(timestamp)

    container_logs = []

    for item in grouped.values():
        container_logs.append({
            "namespace": item["namespace"],
            "pod": item["pod"],
            "container": item["container"],
            "current": {
                "success": True,
                "logs": "\n".join(item["log_lines"]),
                "error": None
            },
            "previous": {
                "success": False,
                "logs": "",
                "error": None
            },
            "log_timestamps": item["log_timestamps"]
        })

    return container_logs


def build_batch_id(device, inode, start_offset, end_offset):
    identity = (
        f"{device}:{inode}:{start_offset}:{end_offset}"
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def build_payload(records, batch_id):
    if not records:
        raise ValueError("Cannot build an empty batch")

    timestamps = [
        record.get("collection_timestamp")
        for record in records
        if record.get("collection_timestamp")
    ]

    return {
        "batch_id": batch_id,
        "source": "Kubernetes Live Forwarder",
        "collection_timestamp": timestamps[-1] if timestamps else None,
        "pods": {
            "pods": []
        },
        "container_logs": group_log_records(records),
        "events": {
            "events": []
        }
    }


def send_batch(payload, secret):
    body = json.dumps(
        payload,
        ensure_ascii=False
    ).encode("utf-8")

    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("Batch exceeds receiver request size limit")

    if not CA_FILE.is_file():
        raise RuntimeError("Receiver CA certificate is missing")

    context = ssl.create_default_context(cafile=str(CA_FILE))

    request = Request(
        RECEIVER_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urlopen(
            request,
            context=context,
            timeout=REQUEST_TIMEOUT
        ) as response:
            if response.status != 201:
                raise RuntimeError(
                    f"Unexpected receiver status: {response.status}"
                )

            try:
                accepted_response = json.loads(
                    response.read().decode("utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise RuntimeError(
                    "Receiver returned an invalid acceptance response"
                ) from None

            if (
                not isinstance(accepted_response, dict)
                or accepted_response.get("status") != "accepted"
                or accepted_response.get("batch_id") != payload.get("batch_id")
            ):
                raise RuntimeError(
                    "Receiver acceptance response does not match submitted batch"
                )

            return "accepted"

    except HTTPError as exc:
        if exc.code == 409:
            try:
                duplicate_response = json.loads(
                    exc.read().decode("utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise RuntimeError(
                    "Receiver returned an invalid duplicate response"
                ) from None

            if (
                not isinstance(duplicate_response, dict)
                or duplicate_response.get("error") != "Duplicate batch"
                or duplicate_response.get("batch_id") != payload.get("batch_id")
            ):
                raise RuntimeError(
                    "Receiver returned HTTP 409 for a different or unknown batch"
                )

            return "duplicate"

        raise RuntimeError(
            f"Receiver rejected batch with HTTP {exc.code}"
        ) from None

    except URLError as exc:
        raise RuntimeError(
            f"Receiver connection failed: {exc.reason}"
        ) from None


def process_once(secret):
    checkpoint = load_or_initialize_checkpoint()
    checkpoint = discard_startup_partial_record(checkpoint)

    start_offset = checkpoint["offset"]

    batch_limit = MAX_BATCH_BYTES

    while True:
        records, end_offset = read_complete_records(
            start_offset,
            max_bytes=batch_limit
        )

        if not records:
            return 0

        batch_id = build_batch_id(
            checkpoint["device"],
            checkpoint["inode"],
            start_offset,
            end_offset
        )

        payload = build_payload(records, batch_id)

        encoded_size = len(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )

        if encoded_size <= MAX_REQUEST_BYTES:
            break

        if len(records) == 1:
            raise ValueError(
                "A single JSONL record produces a payload larger than "
                "the receiver request limit; checkpoint unchanged"
            )

        smaller_limit = max(1, batch_limit // 2)

        if smaller_limit == batch_limit:
            raise ValueError(
                "Unable to reduce batch below receiver request limit"
            )

        batch_limit = smaller_limit

    result = send_batch(payload, secret)

    # Advance checkpoint only after receiver acceptance or duplicate.
    save_checkpoint(
        checkpoint["device"],
        checkpoint["inode"],
        end_offset
    )

    print(
        f"Batch {batch_id}: {result}; "
        f"records={len(records)}; "
        f"containers={len(payload['container_logs'])}"
    )

    return len(records)


def main():
    parser = argparse.ArgumentParser(
        description="Secure Kubernetes JSONL log forwarder"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process at most one batch and exit"
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=2,
        help="Polling interval in seconds"
    )
    args = parser.parse_args()

    if args.poll_seconds < 1:
        parser.error("--poll-seconds must be at least 1")

    secret = load_receiver_secret()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)

    with open(LOCK_FILE, "a", encoding="utf-8") as lock_file:
        os.chmod(LOCK_FILE, 0o600)

        try:
            fcntl.flock(
                lock_file.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB
            )
        except BlockingIOError:
            raise SystemExit("Another live forwarder is already running")

        print("AI DevOps Live Log Forwarder")
        print("----------------------------")
        print("Source:", SOURCE_FILE)
        print("Receiver:", RECEIVER_URL)
        print("Checkpoint:", CHECKPOINT_FILE)

        while True:
            try:
                processed = process_once(secret)

                if args.once:
                    print(
                        f"One-shot completed. Records forwarded: {processed}"
                    )
                    break

                if processed == 0:
                    time.sleep(args.poll_seconds)

            except KeyboardInterrupt:
                print("\\nForwarder stopped by user.")
                break

            except Exception as exc:
                print(f"Forwarding error: {exc}")

                if args.once:
                    raise SystemExit(1)

                time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
