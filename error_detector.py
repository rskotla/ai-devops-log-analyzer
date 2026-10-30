
from pathlib import Path

LOG_FILES = {
    "1": Path("logs/jenkins/jenkins-build.log"),
    "2": Path("logs/docker/docker-app.log"),
    "3": Path("logs/kubernetes/k8s-pod.log")
}

ERROR_KEYWORDS = [
    "ERROR",
    "FAILURE",
    "CRITICAL",
    "WARNING",
    "CrashLoopBackOff",
    "BackOff"
]


def read_log_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None


def detect_errors(log_content):
    detected_lines = []

    for line in log_content.splitlines():
        if any(keyword.lower() in line.lower()
               for keyword in ERROR_KEYWORDS):
            detected_lines.append(line)

    return detected_lines


def main():
    print("\n===== AI DEVOPS ERROR DETECTOR =====")
    print("1. Jenkins")
    print("2. Docker")
    print("3. Kubernetes")

    choice = input("\nSelect log source (1-3): ").strip()

    if choice not in LOG_FILES:
        print("Invalid selection!")
        return

    log_content = read_log_file(LOG_FILES[choice])

    if log_content is None:
        return

    errors = detect_errors(log_content)

    print("\n===== ERROR DETECTION REPORT =====")

    for error in errors:
        print(f"[DETECTED] {error}")

    print(f"\nTotal issues detected: {len(errors)}")


if __name__ == "__main__":
    main()
