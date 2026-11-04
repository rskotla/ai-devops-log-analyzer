#!/usr/bin/env python3

import hmac
import json
import os
import re
import ssl
import uuid

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


PROJECT_DIR = Path(__file__).resolve().parent.parent
RECEIVER_DIR = PROJECT_DIR / "live_receiver"
INCOMING_DIR = RECEIVER_DIR / "incoming"
CERT_DIR = RECEIVER_DIR / "certs"
ENV_FILE = RECEIVER_DIR / ".env"

HOST = "192.168.1.32"
PORT = 8080

MAX_REQUEST_SIZE = 5 * 1024 * 1024

BATCH_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def load_secret():
    if not ENV_FILE.is_file():
        raise RuntimeError("Receiver .env file not found")

    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("RECEIVER_SECRET="):
            secret = line.split("=", 1)[1].strip()
            if secret:
                return secret

    raise RuntimeError("RECEIVER_SECRET is missing")


class LogReceiverHandler(BaseHTTPRequestHandler):

    server_version = "AI-DevOps-Log-Receiver"
    sys_version = ""

    def send_json(self, status, payload):
        response = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

        self.wfile.write(response)

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/health":
            self.send_json(200, {
                "status": "healthy",
                "service": "AI DevOps Live Log Receiver"
            })
            return

        self.send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        path = urlparse(self.path).path

        if path != "/api/v1/logs":
            self.send_json(404, {"error": "Endpoint not found"})
            return

        authorization = self.headers.get("Authorization", "")
        supplied_token = ""

        if authorization.startswith("Bearer "):
            supplied_token = authorization[7:].strip()

        if not supplied_token or not hmac.compare_digest(
            supplied_token, self.server.receiver_secret
        ):
            self.send_json(401, {"error": "Unauthorized"})
            return

        content_type = self.headers.get("Content-Type", "")

        if "application/json" not in content_type.lower():
            self.send_json(415, {
                "error": "Content-Type must be application/json"
            })
            return

        content_length = self.headers.get("Content-Length")

        if not content_length:
            self.send_json(411, {"error": "Content-Length required"})
            return

        try:
            size = int(content_length)
        except ValueError:
            self.send_json(400, {"error": "Invalid Content-Length"})
            return

        if size <= 0:
            self.send_json(400, {"error": "Empty request body"})
            return

        if size > MAX_REQUEST_SIZE:
            self.send_json(413, {"error": "Payload exceeds 5 MB limit"})
            return

        try:
            raw_data = self.rfile.read(size)
            payload = json.loads(raw_data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON payload"})
            return

        if not isinstance(payload, dict):
            self.send_json(400, {"error": "JSON root must be an object"})
            return

        pods = payload.get("pods")
        container_logs = payload.get("container_logs")
        events = payload.get("events")

        if not isinstance(pods, dict) or not isinstance(
            pods.get("pods"), list
        ):
            self.send_json(400, {"error": "Invalid pods structure"})
            return

        if not isinstance(container_logs, list):
            self.send_json(400, {"error": "container_logs must be a list"})
            return

        if not isinstance(events, dict) or not isinstance(
            events.get("events"), list
        ):
            self.send_json(400, {"error": "Invalid events structure"})
            return

        batch_id = payload.get("batch_id")

        if batch_id is None:
            batch_id = uuid.uuid4().hex

        if not isinstance(batch_id, str) or not BATCH_ID_PATTERN.fullmatch(
            batch_id
        ):
            self.send_json(400, {"error": "Invalid batch_id"})
            return

        filename = f"batch-{batch_id}.json"
        destination = INCOMING_DIR / filename

        payload["receiver_metadata"] = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "batch_id": batch_id,
            "source_ip": self.client_address[0]
        }

        try:
            with destination.open("x", encoding="utf-8") as file:
                json.dump(payload, file, indent=2, ensure_ascii=False)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())

            os.chmod(destination, 0o600)

        except FileExistsError:
            self.send_json(409, {
                "error": "Duplicate batch",
                "batch_id": batch_id
            })
            return

        except OSError:
            self.send_json(500, {"error": "Unable to store batch"})
            return

        self.send_json(201, {
            "status": "accepted",
            "batch_id": batch_id,
            "file": filename
        })

    def log_message(self, format_string, *args):
        print(
            f"[Receiver] {self.client_address[0]} - "
            f"{format_string % args}"
        )


def main():
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(INCOMING_DIR, 0o700)

    secret = load_secret()

    cert_file = CERT_DIR / "server.crt"
    key_file = CERT_DIR / "server.key"

    if not cert_file.is_file() or not key_file.is_file():
        raise RuntimeError("TLS certificate or private key missing")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=str(cert_file),
        keyfile=str(key_file)
    )

    server = ThreadingHTTPServer(
        (HOST, PORT),
        LogReceiverHandler
    )

    server.socket = context.wrap_socket(
        server.socket,
        server_side=True
    )

    server.receiver_secret = secret

    print("AI DevOps Live Log Receiver")
    print("---------------------------")
    print(f"Listening on: https://{HOST}:{PORT}")
    print("Health endpoint: /health")
    print("Log endpoint: POST /api/v1/logs")
    print(f"Incoming directory: {INCOMING_DIR}")
    print("Authentication: Bearer token enabled")
    print("TLS: Enabled (minimum TLS 1.2)")
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nReceiver shutdown requested.")
    finally:
        server.server_close()
        print("Receiver stopped.")


if __name__ == "__main__":
    main()
