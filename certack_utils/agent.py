from __future__ import annotations

import hashlib
import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

log = logging.getLogger("certack_utils.agent")


@dataclass(frozen=True)
class TlsProbe:
    host: str
    port: int
    ok: bool
    days_remaining: int | None = None
    subject: str = ""
    issuer: str = ""
    fingerprint: str = ""
    error: str = ""


def probe_tls(host: str, port: int = 443, timeout: float = 8.0) -> TlsProbe:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                info = tls.getpeercert() or {}
        fp = hashlib.sha256(der).hexdigest() if der else ""
        subject = "".join(f"/{k}={v}" for t in info.get("subject", []) for k, v in t)
        issuer = "".join(f"/{k}={v}" for t in info.get("issuer", []) for k, v in t)
        not_after = str(info.get("notAfter", ""))
        days = None
        if not_after:
            try:
                exp = ssl.cert_time_to_seconds(not_after)
                import time

                days = max(0, int((exp - time.time()) // 86400))
            except ValueError:
                days = None
        return TlsProbe(host=host, port=port, ok=True, days_remaining=days, subject=subject, issuer=issuer, fingerprint=fp)
    except Exception as e:  # noqa: BLE001
        return TlsProbe(host=host, port=port, ok=False, error=str(e)[:300])


def scan_many(targets: list, concurrency: int = 5, timeout: float = 8.0) -> list:
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(probe_tls, h, p, timeout) for h, p in targets]
        return [f.result() for f in futures]


def find_drift(probes: list, checks_by_domain: dict, warn_days: int = 30) -> list:
    drift = []
    for p in probes:
        if not p.ok:
            drift.append({"host": p.host, "port": p.port, "kind": "unreachable", "error": p.error})
            continue
        if p.days_remaining is not None and p.days_remaining <= warn_days:
            drift.append({"host": p.host, "port": p.port, "kind": "expiring", "days_remaining": p.days_remaining})
        remote = (checks_by_domain.get(p.host) or {})
        if p.fingerprint and remote.get("fingerprint") and remote["fingerprint"] != p.fingerprint:
            drift.append({"host": p.host, "port": p.port, "kind": "changed"})
    return drift
