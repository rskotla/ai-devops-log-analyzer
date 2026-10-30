
from pathlib import Path

LOG_DIR = Path("logs")


def read_log_file(file_path):
    """Read and return the contents of a log file."""

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()

    except FileNotFoundError:
        print(f"Log file not found: {file_path}")
        return ""

    except OSError as error:
        print(f"Unable to read log file: {error}")
        return ""


def main():
    log_files = {
        "1": LOG_DIR / "jenkins" / "jenkins-build.log",
        "2": LOG_DIR / "docker" / "docker-app.log",
        "3": LOG_DIR / "kubernetes" / "k8s-pod.log"
    }

    print("\n===== AI DEVOPS LOG ANALYZER =====")
    print("1. Jenkins Logs")
    print("2. Docker Logs")
    print("3. Kubernetes Logs")

    choice = input("\nSelect log source (1-3): ").strip()

    if choice not in log_files:
        print("Invalid selection!")
        return

    selected_file = log_files[choice]

    print(f"\nReading: {selected_file}")

    log_content = read_log_file(selected_file)

    if log_content:
        print("\n===== LOG CONTENT =====")
        print(log_content)


if __name__ == "__main__":
    main()
