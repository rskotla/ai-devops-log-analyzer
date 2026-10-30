#!/usr/bin/env python3
"""
AI DevOps Log Analyzer - Kubernetes Collector

Collects read-only Kubernetes information from the ShopNova namespace.
Uses a temporary kubeconfig and a short-lived ServiceAccount token.
"""

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from getpass import getpass


NAMESPACE = "shopnova"
REPORT_DIR = Path(__file__).parent / "reports"
KUBECTL = "kubectl"


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def run_kubectl(args, kubeconfig):
    """Execute kubectl without exposing credentials in command arguments."""

    command = [
        KUBECTL,
        "--kubeconfig", str(kubeconfig),
        *args,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        return {
            "success": result.returncode == 0,
            "output": result.stdout.strip(),
            "error": result.stderr.strip(),
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": "",
            "error": "kubectl command timed out",
        }

    except FileNotFoundError:
        return {
            "success": False,
            "output": "",
            "error": "kubectl executable not found",
        }


def collect_pods(kubeconfig):
    result = run_kubectl(
        [
            "get", "pods",
            "-n", NAMESPACE,
            "-o", "json",
        ],
        kubeconfig,
    )

    if not result["success"]:
        return {"error": result["error"]}

    try:
        data = json.loads(result["output"])
        pods = []

        for pod in data.get("items", []):
            status = pod.get("status", {})

            containers = []

            for container in status.get("containerStatuses", []):
                containers.append({
                    "name": container.get("name"),
                    "ready": container.get("ready"),
                    "restart_count": container.get("restartCount"),
                    "state": container.get("state"),
                    "last_state": container.get("lastState"),
                })

            pods.append({
                "name": pod["metadata"]["name"],
                "phase": status.get("phase"),
                "pod_ip": status.get("podIP"),
                "node": pod.get("spec", {}).get("nodeName"),
                "start_time": status.get("startTime"),
                "containers": containers,
            })

        return {"pods": pods}

    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return {"error": f"Unable to parse pod data: {exc}"}


def collect_pod_logs(pod_name, container_name, kubeconfig, previous=False):
    args = [
        "logs",
        pod_name,
        "-n", NAMESPACE,
        "-c", container_name,
        "--timestamps",
        "--tail=200",
    ]

    if previous:
        args.append("--previous")

    result = run_kubectl(args, kubeconfig)

    return {
        "success": result["success"],
        "logs": result["output"],
        "error": result["error"] or None,
    }


def collect_all_logs(kubeconfig, pods_data):
    collected = []

    for pod in pods_data.get("pods", []):
        for container in pod.get("containers", []):
            entry = {
                "pod": pod["name"],
                "container": container["name"],
                "current": collect_pod_logs(
                    pod["name"],
                    container["name"],
                    kubeconfig,
                ),
            }

            if container.get("restart_count", 0) > 0:
                entry["previous"] = collect_pod_logs(
                    pod["name"],
                    container["name"],
                    kubeconfig,
                    previous=True,
                )

            collected.append(entry)

    return collected


def collect_events(kubeconfig):
    result = run_kubectl(
        [
            "get", "events",
            "-n", NAMESPACE,
            "-o", "json",
        ],
        kubeconfig,
    )

    if not result["success"]:
        return {"error": result["error"]}

    try:
        data = json.loads(result["output"])
        events = []

        for event in data.get("items", []):
            events.append({
                "type": event.get("type"),
                "reason": event.get("reason"),
                "message": event.get("message"),
                "object": event.get("involvedObject", {}).get("name"),
                "first_timestamp": event.get("firstTimestamp"),
                "last_timestamp": event.get("lastTimestamp"),
                "count": event.get("count"),
            })

        return {"events": events}

    except (json.JSONDecodeError, TypeError) as exc:
        return {"error": f"Unable to parse events: {exc}"}


def main():
    print("\nAI DevOps - Kubernetes Log Collector")
    print("------------------------------------")
    print(f"Namespace: {NAMESPACE}")

    token = getpass("Enter short-lived ServiceAccount token: ")

    if not token.strip():
        print("ERROR: Token cannot be empty.")
        return

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    kubeconfig_path = None

    try:
        # Temporary kubeconfig: never save the token permanently.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as temp_file:

            os.chmod(temp_file.name, 0o600)

            temp_file.write(
                "apiVersion: v1\n"
                "kind: Config\n"
                "clusters:\n"
                "- name: k3s-cluster\n"
                "  cluster:\n"
                "    server: https://192.168.1.33:6443\n"
                "    certificate-authority: /opt/ai-devops-log-analyzer/k3s-ca.crt\n"
                "contexts:\n"
                "- name: shopnova-context\n"
                "  context:\n"
                "    cluster: k3s-cluster\n"
                "    namespace: shopnova\n"
                "    user: ai-log-collector\n"
                "current-context: shopnova-context\n"
                "users:\n"
                "- name: ai-log-collector\n"
                "  user:\n"
                f"    token: {json.dumps(token.strip())}\n"
            )

            kubeconfig_path = Path(temp_file.name)

        del token

        # Authentication and connectivity test.
        auth = run_kubectl(
            ["get", "pods", "-n", NAMESPACE],
            kubeconfig_path,
        )

        if not auth["success"]:
            print("ERROR: Kubernetes authentication failed.")
            print(auth["error"])
            return

        print("Authentication successful.")

        print("Collecting pod information...")
        pods_data = collect_pods(kubeconfig_path)

        print("Collecting current and previous container logs...")
        logs_data = collect_all_logs(
            kubeconfig_path,
            pods_data,
        )

        print("Collecting Kubernetes events...")
        events_data = collect_events(kubeconfig_path)

        report = {
            "project": "AI DevOps Log Analyzer",
            "source": "Kubernetes",
            "namespace": NAMESPACE,
            "collection_timestamp": timestamp(),
            "collection_host": __import__("socket").gethostname(),
            "pods": pods_data,
            "container_logs": logs_data,
            "events": events_data,
        }

        filename = (
            "kubernetes-"
            + datetime.now().strftime("%Y%m%d-%H%M%S")
            + ".json"
        )

        report_path = REPORT_DIR / filename

        report_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        os.chmod(report_path, 0o600)

        print("\nCollection completed.")
        print(f"Report saved: {report_path}")
        print(f"Pods collected: {len(pods_data.get('pods', []))}")
        print(f"Log entries: {len(logs_data)}")
        print(
            "Events collected: "
            f"{len(events_data.get('events', []))}"
        )

    finally:
        if kubeconfig_path and kubeconfig_path.exists():
            kubeconfig_path.unlink()

        print("Temporary kubeconfig cleanup completed.")


if __name__ == "__main__":
    main()