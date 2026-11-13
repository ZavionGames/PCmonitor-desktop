"""Local stand-in for the web API. Not part of the product server."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class MockState:
    def __init__(self) -> None:
        self.device_id = "device-test"
        self.device_key = "device-key-test"
        self.seen: set[str] = set()
        self.fail_next: int | None = None
        self.config_version = 1
        self.events: list[dict[str, Any]] = []
        self.heartbeats: list[dict[str, Any]] = []


class MockApi:
    def __init__(self) -> None:
        self.state = MockState()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("mock server is not running")
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> None:
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                path = self.path.split("?", 1)[0]
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    body = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    self._send(400, {"error": "json"})
                    return
                if state.fail_next is not None and path != "/api/pair":
                    code = state.fail_next
                    state.fail_next = None
                    self._send(code, {"error": "forced"})
                    return
                if path == "/api/pair":
                    self._send(
                        200,
                        {"deviceId": state.device_id, "deviceKey": state.device_key},
                    )
                    return
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                if path == "/api/events":
                    results = []
                    for event in body.get("events", []):
                        event_id = str(event.get("eventId"))
                        if event_id in state.seen:
                            results.append({"eventId": event_id, "status": "duplicate"})
                        else:
                            state.seen.add(event_id)
                            state.events.append(event)
                            results.append({"eventId": event_id, "status": "accepted"})
                    self._send(200, {"results": results})
                    return
                if path == "/api/heartbeat":
                    state.heartbeats.append(body)
                    self._send(
                        200,
                        {
                            "serverTimeUtc": datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            "configVersion": state.config_version,
                        },
                    )
                    return
                self._send(404, {"error": "not found"})

            def do_GET(self) -> None:  # noqa: N802
                path = self.path.split("?", 1)[0]
                if path != "/api/config":
                    self._send(404, {"error": "not found"})
                    return
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                self._send(
                    200,
                    {
                        "configVersion": state.config_version,
                        "trackedApps": [],
                        "ignoredApps": ["noise.exe"],
                        "trackSystemEvents": True,
                        "heartbeatIntervalSeconds": 300,
                    },
                )

            def _authorized(self) -> bool:
                header = self.headers.get("Authorization", "")
                device = self.headers.get("X-Device-Id", "")
                return header == f"Bearer {state.device_key}" and device == state.device_id

            def _send(self, code: int, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()


def main() -> None:
    api = MockApi()
    api.start()
    print(f"mock API {api.base_url}")
    assert api._thread is not None
    try:
        api._thread.join()
    except KeyboardInterrupt:
        api.stop()


if __name__ == "__main__":
    main()
