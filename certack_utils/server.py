from __future__ import annotations

import json
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .actions import dispatch
from .webhooks import MAX_BODY_BYTES, fresh, parse_event, verify_signature

log = logging.getLogger("certack_utils.server")


class Handler(BaseHTTPRequestHandler):
    settings: dict = {}
    client = None
    seen: dict = {}

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, status: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] == "/healthz":
            self._send(200, {"ok": True, "ts": int(time.time())})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?")[0] != "/hooks/certack":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send(413 if length > MAX_BODY_BYTES else 400, {"error": "bad length"})
            return
        raw = self.rfile.read(length)
        timestamp = self.headers.get("X-Webhook-Timestamp", "")
        signature = self.headers.get("X-Webhook-Signature", "")
        secret = (self.settings.get("webhook_secret") or "")
        if secret and not verify_signature(secret, timestamp, raw, signature):
            self._send(401, {"error": "bad signature"})
            return
        try:
            event = parse_event(raw)
        except ValueError:
            self._send(400, {"error": "bad json"})
            return
        if timestamp and not fresh(timestamp):
            self._send(401, {"error": "stale timestamp"})
            return
        now = time.time()
        self.seen = {k: v for k, v in self.seen.items() if now - v < 600}
        if event.delivery_id in self.seen:
            self._send(200, {"ok": True, "deduped": True})
            return
        self.seen[event.delivery_id] = now
        try:
            out = dispatch(event.event, event.data, self.settings, self.client)
        except Exception as e:  # noqa: BLE001
            log.warning("dispatch failed: %s", e)
            self._send(500, {"error": "dispatch failed"})
            return
        self._send(200, {"ok": True, "event": event.event, "result": out})


def serve(settings: dict, client=None) -> None:
    handler = type("BoundHandler", (Handler,), {})
    handler.settings = settings
    handler.client = client
    addr = (settings.get("listen_addr", "0.0.0.0"), int(settings.get("listen_port", 8080)))
    server = ThreadingHTTPServer(addr, handler)
    log.info("listening on %s:%s", *addr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
