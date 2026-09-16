from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass


MAX_BODY_BYTES = 256 * 1024
SKEW_SECONDS = 300


@dataclass(frozen=True)
class WebhookEvent:
    event: str
    timestamp: str
    data: dict
    delivery_id: str


def verify_signature(secret: str, timestamp: str, raw_body: bytes, header: str) -> bool:
    if not secret or not timestamp or not raw_body or not header:
        return False
    want = header.strip()
    if want.startswith("sha256="):
        want = want[len("sha256="):]
    payload = timestamp.encode("utf-8") + b"." + raw_body
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, want.lower())


def parse_event(raw_body: bytes) -> WebhookEvent:
    obj = json.loads(raw_body.decode("utf-8"))
    data = obj.get("data", {}) if isinstance(obj, dict) else {}
    stamp = str(obj.get("timestamp", ""))
    event = str(obj.get("event", ""))
    fp = hashlib.sha256(raw_body).hexdigest()[:16]
    return WebhookEvent(event=event, timestamp=stamp, data=data if isinstance(data, dict) else {}, delivery_id=fp)


def fresh(timestamp: str, now: float | None = None, skew: int = SKEW_SECONDS) -> bool:
    from datetime import datetime, timezone

    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    base = now if now is not None else time.time()
    return abs(base - dt.timestamp()) <= skew
