from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


@dataclass(frozen=True)
class CertackError(Exception):
    status: int
    message: str
    retry_after: int = 0


def normalize_base_url(raw: str) -> str:
    base = (raw or "").strip().rstrip("/")
    if not base:
        raise ValueError("empty base url")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    return base


def validate_domain(value: str) -> str:
    v = (value or "").strip().lower().rstrip(".")
    if not v or len(v) > 253 or not _DOMAIN_RE.match(v):
        raise ValueError(f"invalid domain: {value!r}")
    return v


def load_settings(env: dict | None = None) -> dict:
    e = env if env is not None else os.environ
    return {
        "base_url": normalize_base_url(e.get("CERTACK_BASE_URL", "https://certack.com")),
        "api_key": (e.get("CERTACK_API_KEY", "") or "").strip(),
        "webhook_secret": (e.get("CERTACK_WEBHOOK_SECRET", "") or "").strip(),
        "domains_file": (e.get("CERTACK_DOMAINS_FILE", "certack_utils/domains.yaml") or "").strip(),
        "timeout_seconds": float(e.get("CERTACK_TIMEOUT_SECONDS", "15")),
        "max_retries": int(e.get("CERTACK_MAX_RETRIES", "3")),
        "dry_run": (e.get("CERTACK_DRY_RUN", "0") or "").strip().lower() in ("1", "true", "yes"),
        "prune": (e.get("CERTACK_PRUNE", "0") or "").strip().lower() in ("1", "true", "yes"),
        "slack_webhook_url": (e.get("SLACK_WEBHOOK_URL", "") or "").strip(),
        "pagerduty_routing_key": (e.get("PAGERDUTY_ROUTING_KEY", "") or "").strip(),
        "hook_command": (e.get("CERTACK_HOOK_COMMAND", "") or "").strip(),
        "listen_addr": (e.get("CERTACK_LISTEN_ADDR", "0.0.0.0") or "").strip() or "0.0.0.0",
        "listen_port": int(e.get("CERTACK_LISTEN_PORT", "8080")),
    }


def load_domains(path: str) -> list:
    from .config import DomainSpec

    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        import yaml  # type: ignore

        raw = yaml.safe_load(text)
    except ImportError:
        raw = json.loads(text) if text.lstrip().startswith(("{", "[")) else _parse_simple_yaml(text)
    items = raw.get("domains", raw) if isinstance(raw, dict) else raw
    specs = []
    for entry in items or []:
        domain = validate_domain(str(entry.get("domain", "")))
        port = int(entry.get("port", 443))
        if not 1 <= port <= 65535:
            raise ValueError(f"invalid port for {domain}")
        check_types = tuple(entry.get("check_types", ["ssl", "dns", "domain"]))
        specs.append(
            DomainSpec(
                domain=domain,
                port=port,
                check_types=check_types,
                alert_days=int(entry.get("alert_days", 30)),
                check_interval_minutes=int(entry.get("check_interval_minutes", 60)),
                origin_ip=entry.get("origin_ip"),
                labels=dict(entry.get("labels", {})),
            )
        )
    seen = set()
    for s in specs:
        key = (s.domain, s.port)
        if key in seen:
            raise ValueError(f"duplicate domain target: {s.domain}:{s.port}")
        seen.add(key)
    return specs


def _parse_simple_yaml(text: str) -> list:
    items: list = []
    current: dict | None = None
    for line in text.splitlines():
        s = line.rstrip()
        if s.strip().startswith("- domain:"):
            if current:
                items.append(current)
            current = {"domain": s.split(":", 1)[1].strip()}
        elif current is not None and ":" in s and not s.strip().startswith("#"):
            k, v = s.strip().split(":", 1)
            k, v = k.strip(), v.strip().strip("\"'")
            if k in ("port", "alert_days", "check_interval_minutes"):
                current[k] = int(v)
            elif k == "origin_ip":
                current[k] = None if v.lower() in ("", "null", "~") else v
            elif k in ("check_types", "labels"):
                try:
                    current[k] = json.loads(v)
                except ValueError:
                    current[k] = [x.strip() for x in v.strip("[]").split(",") if x.strip()]
            else:
                current[k] = v
    if current:
        items.append(current)
    return items


class CertackClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 15.0, max_retries: int = 3, opener=None):
        if not api_key.startswith("ct_"):
            raise ValueError("api key must start with ct_")
        self.base_url = normalize_base_url(base_url)
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.opener = opener or urllib.request.build_opener()

    def _request(self, method: str, path: str, body=None, query: dict | None = None):
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        data = None
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": "certack-utils/1.0",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        last: CertackError | None = None
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with self.opener.open(req, timeout=self.timeout) as res:
                    payload = res.read().decode("utf-8", "replace")
                    return json.loads(payload) if payload else {}
            except urllib.error.HTTPError as e:
                raw = e.read().decode("utf-8", "replace") if hasattr(e, "read") else ""
                try:
                    msg = json.loads(raw).get("error", raw) if raw else e.reason
                except ValueError:
                    msg = raw or str(e.reason)
                retry_after = 0
                if e.code == 429:
                    try:
                        retry_after = int(e.headers.get("Retry-After", "60"))
                    except ValueError:
                        retry_after = 60
                last = CertackError(e.code, str(msg), retry_after)
                if e.code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                    time.sleep(min(2**attempt + (os.getpid() % 100) / 100.0, 20))
                    continue
                raise last
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = CertackError(0, str(e))
                if attempt < self.max_retries:
                    time.sleep(min(2**attempt + 0.2, 20))
                    continue
                raise last
        raise last or CertackError(0, "request failed")

    def list_sites(self) -> list:
        res = self._request("GET", "/api/sites")
        return res.get("sites", res.get("data", [])) if isinstance(res, dict) else []

    def create_site(self, spec) -> dict:
        return self._request(
            "POST",
            "/api/sites",
            {
                "domain": spec.domain,
                "custom_port": None if spec.port == 443 else spec.port,
                "origin_ip": spec.origin_ip,
                "alert_days": spec.alert_days,
                "check_types": list(spec.check_types),
                "check_interval_minutes": spec.check_interval_minutes,
            },
        )

    def update_site(self, site_id: str, patch: dict) -> dict:
        return self._request("PATCH", "/api/sites", patch, {"id": site_id})

    def delete_site(self, site_id: str) -> dict:
        return self._request("DELETE", "/api/sites", None, {"id": site_id})

    def list_alerts(self, resolved: str = "false", limit: int = 50) -> dict:
        return self._request("GET", "/api/alerts", None, {"resolved": resolved, "limit": limit})

    def list_checks(self, site_id: str) -> dict:
        return self._request("GET", "/api/checks", None, {"site_id": site_id})

    def trigger_ssl_check(self, domain: str, site_id: str | None = None, port: int = 443) -> dict:
        body = {"domain": domain, "port": port}
        if site_id:
            body["site_id"] = site_id
        return self._request("POST", "/api/check-ssl", body)

    def resolve_alert(self, alert_id: str) -> dict:
        return self._request("PATCH", "/api/alerts", None, {"id": alert_id})
