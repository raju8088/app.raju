"""Stub Upstream OmniDimension Server for Integration Tests.

Simulates the upstream voice-agent platform endpoints with Bearer auth verification,
mock data responses, and simulated HTTP error codes.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class StubOmniDimensionHandler(BaseHTTPRequestHandler):
    """Handles mock OmniDimension API requests."""

    agents: dict[str, dict[str, Any]] = {
        "158910": {"id": "158910", "name": "Sales Rep", "voice": "alloy"},
        "agent-1": {"id": "agent-1", "name": "Customer Support", "voice": "echo"},
    }
    calls: list[dict[str, Any]] = []

    def _send_json_resp(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 0:
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return {}
        return {}

    def _check_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or len(auth.split(" ", 1)[1].strip()) == 0:
            self._send_json_resp({"error": "Unauthorized: Missing or invalid API key", "ok": False}, status=401)
            return False
        return True

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/test/health":
            self._send_json_resp({"status": "healthy"})
            return

        if not self._check_auth():
            return

        if path in {"/v1/agents", "/agents"}:
            self._send_json_resp({"agents": list(self.agents.values()), "total": len(self.agents)})
            return

        if path.startswith("/v1/agents/") or path.startswith("/agents/"):
            agent_id = path.split("/")[-1]
            if agent_id == "rate-limit-429":
                self._send_json_resp({"error": "Rate limit exceeded. Please back off."}, status=429)
                return
            if agent_id == "server-error-500":
                self._send_json_resp({"error": "Internal platform error."}, status=500)
                return
            if agent_id in self.agents:
                self._send_json_resp(self.agents[agent_id])
            else:
                self._send_json_resp({"error": f"Agent {agent_id} not found"}, status=404)
            return

        if path in {"/v1/phone_number/list", "/phone_number/list"}:
            self._send_json_resp({"numbers": ["+15551234567", "+15557654321"]})
            return

        if path in {"/v1/reseller/concurrency", "/reseller/concurrency"}:
            self._send_json_resp({"allocated": 10, "max": 50})
            return

        if path == "/v1/error/429":
            self._send_json_resp({"error": "Rate limit exceeded. Please back off."}, status=429)
            return

        if path == "/v1/error/500":
            self._send_json_resp({"error": "Internal platform error."}, status=500)
            return

        self._send_json_resp({"message": "OK", "path": path})

    def do_POST(self) -> None:
        if not self._check_auth():
            return

        body = self._read_body()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in {"/v1/agents/create", "/agents/create", "/v1/agents", "/agents"}:
            new_id = f"agent-{len(self.agents) + 1}"
            new_agent = {"id": new_id, "name": body.get("name", "New Agent"), "voice": body.get("voice", "nova")}
            self.agents[new_id] = new_agent
            self._send_json_resp(new_agent, status=201)
            return

        if path in {"/v1/calls/dispatch", "/calls/dispatch"}:
            call_record = {
                "call_id": f"call-{len(self.calls) + 1}",
                "to_number": body.get("to_number", "+10000000000"),
                "status": "queued",
            }
            self.calls.append(call_record)
            self._send_json_resp(call_record, status=200)
            return

        if "/calls/bulk_call/" in path and "/add_contact" in path:
            self._send_json_resp({"added": True, "contact": body.get("phone_number")})
            return

        if path.startswith("/v1/phone_number/import/"):
            provider = path.split("/")[-1]
            self._send_json_resp({"imported": True, "provider": provider, "status": "active"})
            return

        if path in {"/v1/reseller/users/add", "/reseller/users/add"}:
            self._send_json_resp({"user_id": "user-42", "email": body.get("email")}, status=201)
            return

        self._send_json_resp({"status": "received", "path": path, "body": body})

    def do_PUT(self) -> None:
        if not self._check_auth():
            return

        body = self._read_body()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/v1/agents/") or path.startswith("/agents/"):
            parts = path.split("/")
            agent_id = parts[3] if parts[1] == "v1" else parts[2]
            if agent_id in self.agents:
                self.agents[agent_id].update(body)
                self._send_json_resp(self.agents[agent_id])
            else:
                self._send_json_resp({"error": "Agent not found"}, status=404)
            return

        self._send_json_resp({"updated": True, "path": path, "body": body})

    def do_PATCH(self) -> None:
        if not self._check_auth():
            return

        body = self._read_body()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/v1/agents/") or path.startswith("/agents/"):
            parts = path.split("/")
            agent_id = parts[3] if parts[1] == "v1" else parts[2]
            if agent_id in self.agents:
                self.agents[agent_id].update(body)
                self._send_json_resp(self.agents[agent_id])
            else:
                self._send_json_resp({"error": "Agent not found"}, status=404)
            return

        self._send_json_resp({"patched": True, "path": path, "body": body})

    def do_DELETE(self) -> None:
        if not self._check_auth():
            return

        self._read_body()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/v1/agents/") or path.startswith("/agents/"):
            agent_id = path.split("/")[-1]
            if agent_id in self.agents:
                del self.agents[agent_id]
                self._send_json_resp({"deleted": True, "agent_id": agent_id})
            else:
                self._send_json_resp({"error": "Agent not found"}, status=404)
            return

        self._send_json_resp({"deleted": True, "path": path})

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # Suppress logs during integration testing


class StubUpstreamServer:
    """Manages the background lifecycle of the stub upstream OmniDimension server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.server = ThreadingHTTPServer((host, port), StubOmniDimensionHandler)
        self.host, self.port = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> str:
        self.thread.start()
        return f"http://{self.host}:{self.port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
