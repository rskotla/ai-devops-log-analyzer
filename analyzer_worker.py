import argparse
import fcntl
import json
import os
import subprocess
import stat
import sys
import tempfile
import time
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
RECEIVER_DIR = PROJECT_DIR / "live_receiver"
INCOMING_DIR = RECEIVER_DIR / "incoming"

STATE_DIR = RECEIVER_DIR / "worker-state"
STATE_FILE = STATE_DIR / "worker-state.json"
LOCK_FILE = STATE_DIR / "worker.lock"

ANALYZER_SCRIPT = PROJECT_DIR / "kubernetes_live_analyzer.py"
REPORT_DIR = PROJECT_DIR / "reports"

DEFAULT_POLL_SECONDS = 5
DEFAULT_RETRY_SECONDS = 60
ANALYZER_TIMEOUT_SECONDS = 900


def ensure_state_directory():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)


def save_state(state):
    ensure_state_directory()

    fd, temp_name = tempfile.mkstemp(
        prefix=".worker-state-",
        suffix=".tmp",
        dir=STATE_DIR
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(state, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        os.chmod(temp_name, 0o600)
        os.replace(temp_name, STATE_FILE)

        directory_fd = os.open(STATE_DIR, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def is_completed_receiver_batch(path):
    """Only baseline fully written receiver batches."""

    try:
        if path.is_symlink() or not path.is_file():
            return False

        # The receiver applies mode 600 only after writing and fsyncing.
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            return False

        if not is_stable_file(path):
            return False

        validate_batch(path)
        return True

    except (OSError, ValueError, json.JSONDecodeError):
        return False


def load_or_initialize_state():
    ensure_state_directory()

    if STATE_FILE.exists():
        with open(STATE_FILE, "r", encoding="utf-8") as file:
            state = json.load(file)

        if not isinstance(state, dict):
            raise ValueError("Invalid worker state")

        required = {"baseline_files", "processed", "failed"}
        if not required.issubset(state):
            raise ValueError("Worker state is missing required fields")

        return state

    existing_files = sorted(
        path.name
        for path in INCOMING_DIR.glob("*.json")
        if is_completed_receiver_batch(path)
    )

    state = {
        "baseline_files": existing_files,
        "processed": [],
        "failed": {}
    }

    save_state(state)

    print(
        "Worker initialized. Existing incoming batches skipped: "
        f"{len(existing_files)}"
    )

    return state


def is_stable_file(path):
    if path.is_symlink() or not path.is_file():
        return False

    first = path.stat()
    time.sleep(1)
    second = path.stat()

    return (
        first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
    )


def validate_batch(path):
    with open(path, "r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError("Batch must contain a JSON object")

    pods = payload.get("pods", {}).get("pods")
    container_logs = payload.get("container_logs")

    if not isinstance(pods, list):
        raise ValueError("Invalid pods.pods data")

    if not isinstance(container_logs, list):
        raise ValueError("Invalid container_logs data")

    return payload


def validate_saved_report(report_path, batch_path):
    """Verify that an analyzer report belongs to the submitted batch."""
    if report_path.is_symlink() or not report_path.is_file():
        raise RuntimeError("Analyzer report is missing or is a symlink")

    try:
        report_root = REPORT_DIR.resolve(strict=True)
        resolved_report = report_path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("Unable to resolve analyzer report path") from exc

    if resolved_report.parent != report_root:
        raise RuntimeError("Analyzer report is outside the reports directory")

    if not resolved_report.name.startswith("live-kubernetes-report-"):
        raise RuntimeError("Unexpected analyzer report filename")

    try:
        with resolved_report.open("r", encoding="utf-8") as file:
            report = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Analyzer report is not valid readable JSON") from exc

    if not isinstance(report, dict):
        raise RuntimeError("Analyzer report must be a JSON object")

    if report.get("report_type") != "LIVE_KUBERNETES_AI_ANALYSIS":
        raise RuntimeError("Unexpected analyzer report type")

    if report.get("source_file") != batch_path.name:
        raise RuntimeError("Analyzer report source does not match submitted batch")

    if not isinstance(report.get("analysis"), dict):
        raise RuntimeError("Analyzer report analysis must be a JSON object")

    return resolved_report


def run_analyzer(batch_path):
    if not ANALYZER_SCRIPT.is_file():
        raise FileNotFoundError("Analyzer script not found")

    before_reports = set(REPORT_DIR.glob("live-kubernetes-report-*.json"))

    result = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            str(batch_path)
        ],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        timeout=ANALYZER_TIMEOUT_SECONDS,
        check=False
    )

    saved_report = None

    for line in result.stdout.splitlines():
        marker = "AI report saved:"
        if marker in line:
            candidate = Path(line.split(marker, 1)[1].strip())
            if candidate.is_file() and not candidate.is_symlink():
                saved_report = candidate
                break

    if saved_report is None:
        after_reports = set(REPORT_DIR.glob("live-kubernetes-report-*.json"))
        new_reports = after_reports - before_reports

        if len(new_reports) == 1:
            saved_report = next(iter(new_reports))

    if result.returncode != 0 or saved_report is None:
        diagnostic_lines = []

        for output in (result.stdout, result.stderr):
            if not output:
                continue

            for line in output.splitlines():
                if (
                    "Analysis failed:" in line
                    or line.startswith("ERROR:")
                ):
                    diagnostic_lines.append(line.strip())

        diagnostic = (
            "\\n".join(diagnostic_lines[-10:])
            if diagnostic_lines
            else "No explicit analyzer error message captured."
        )

        raise RuntimeError(
            "Analyzer did not complete successfully or save a report. "
            f"Exit code: {result.returncode}. "
            f"Details: {diagnostic}"
        )

    return validate_saved_report(saved_report, batch_path)


def process_pending(state, retry_seconds):
    baseline = set(state["baseline_files"])
    processed = set(state["processed"])
    failed = state["failed"]

    candidates = sorted(INCOMING_DIR.glob("*.json"))

    for batch_path in candidates:
        name = batch_path.name

        if name in baseline or name in processed:
            continue

        if batch_path.is_symlink() or not batch_path.is_file():
            continue

        failure = failed.get(name, {})
        last_attempt = failure.get("last_attempt", 0)

        if time.time() - last_attempt < retry_seconds:
            continue

        # The receiver applies mode 600 only after the batch is
        # completely written and fsynced.
        try:
            if stat.S_IMODE(batch_path.stat().st_mode) != 0o600:
                continue
        except OSError:
            continue

        if not is_stable_file(batch_path):
            continue

        try:
            validate_batch(batch_path)

            print(f"Processing new batch: {name}")

            report_path = run_analyzer(batch_path)

            state["processed"].append(name)
            state["failed"].pop(name, None)
            save_state(state)

            print(f"Analysis successful: {report_path}")

        except Exception as error:
            previous_attempts = failure.get("attempts", 0)
            error_message = str(error).strip()[:1500]

            state["failed"][name] = {
                "attempts": previous_attempts + 1,
                "last_attempt": time.time(),
                "error_type": type(error).__name__,
                "error_message": error_message
            }

            save_state(state)

            print(
                f"Batch processing failed: {name}. "
                f"Will retry after {retry_seconds} seconds. "
                f"Error type: {type(error).__name__}. "
                f"Details: {error_message}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Background worker for live Kubernetes AI analysis"
    )

    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=DEFAULT_POLL_SECONDS
    )

    parser.add_argument(
        "--retry-seconds",
        type=int,
        default=DEFAULT_RETRY_SECONDS
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one processing cycle and exit"
    )

    args = parser.parse_args()

    if args.poll_seconds < 1 or args.retry_seconds < 1:
        parser.error("Polling and retry intervals must be positive")

    if not INCOMING_DIR.is_dir():
        raise SystemExit("Receiver incoming directory does not exist")

    ensure_state_directory()

    with open(LOCK_FILE, "a", encoding="utf-8") as lock_file:
        os.chmod(LOCK_FILE, 0o600)

        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Another analyzer worker is already running")

        state = load_or_initialize_state()

        print("AI Kubernetes Analyzer Worker started.")

        if args.once:
            process_pending(state, args.retry_seconds)
            return

        try:
            while True:
                process_pending(state, args.retry_seconds)
                time.sleep(args.poll_seconds)

        except KeyboardInterrupt:
            print("\nAnalyzer worker stopped.")


if __name__ == "__main__":
    main()
