from __future__ import annotations

import json
import logging
import shlex
import subprocess
import urllib.request

log = logging.getLogger("certack_utils.actions")


def severity_of(event: str, data: dict) -> str:
    for k in ("severity", "level", "priority"):
        v = data.get(k)
        if isinstance(v, str) and v:
            return v.lower()
    if event in ("ssl.invalid", "alert.escalated"):
        return "critical"
    if event in ("ssl.expiring", "domain.expiring", "alert.triggered"):
        return "warning"
    return "info"


def render_text(event: str, data: dict) -> str:
    domain = data.get("domain") or data.get("host") or data.get("site_id") or "unknown"
    message = data.get("message") or data.get("error") or event
    days = data.get("days_remaining", data.get("days_left", ""))
    suffix = f" ({days}d left)" if isinstance(days, int) else ""
    return f"[{severity_of(event, data).upper()}] {event} {domain}{suffix}: {message}"


def notify_slack(webhook_url: str, text: str, timeout: float = 10.0) -> bool:
    if not webhook_url:
        return False
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(webhook_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return 200 <= res.status < 300
    except Exception as e:  # noqa: BLE001
        log.warning("slack notify failed: %s", e)
        return False


def notify_pagerduty(routing_key: str, summary: str, severity: str = "warning", dedup_key: str = "", timeout: float = 10.0) -> bool:
    if not routing_key:
        return False
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key or summary[:255],
        "payload": {"summary": summary[:1024], "severity": severity if severity in ("critical", "error", "warning", "info") else "warning", "source": "certack"},
    }
    req = urllib.request.Request(
        "https://events.pagerduty.com/v2/enqueue",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return 200 <= res.status < 300
    except Exception as e:  # noqa: BLE001
        log.warning("pagerduty notify failed: %s", e)
        return False


def run_hook(command: str, event: str, data: dict, timeout: float = 60.0) -> int:
    if not command:
        return 0
    argv = shlex.split(command) + [event, json.dumps(data, separators=(",", ":"))]
    try:
        proc = subprocess.run(argv, timeout=timeout, capture_output=True, text=True)
        if proc.returncode != 0:
            log.warning("hook exit=%s err=%s", proc.returncode, proc.stderr[:500])
        return proc.returncode
    except Exception as e:  # noqa: BLE001
        log.warning("hook failed: %s", e)
        return 1


def dispatch(event: str, data: dict, settings: dict, client=None) -> dict:
    text = render_text(event, data)
    sev = severity_of(event, data)
    dedup = str(data.get("alert_id") or data.get("site_id") or data.get("domain") or event)
    out = {"slack": False, "pagerduty": False, "hook": 0, "resolved": False}
    if settings.get("slack_webhook_url"):
        out["slack"] = notify_slack(settings["slack_webhook_url"], text)
    if settings.get("pagerduty_routing_key") and sev in ("critical", "warning"):
        out["pagerduty"] = notify_pagerduty(settings["pagerduty_routing_key"], text, "critical" if sev == "critical" else "warning", f"certack/{dedup}")
    if settings.get("hook_command"):
        out["hook"] = run_hook(settings["hook_command"], event, data)
    if client is not None and event == "alert.resolved" and data.get("alert_id"):
        try:
            client.resolve_alert(str(data["alert_id"]))
            out["resolved"] = True
        except Exception as e:  # noqa: BLE001
            log.warning("resolve failed: %s", e)
    log.info("dispatch event=%s severity=%s %s", event, sev, out)
    return out
