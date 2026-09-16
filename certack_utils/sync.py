from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Plan:
    to_create: tuple = ()
    to_update: tuple = ()
    to_delete: tuple = ()
    unchanged: tuple = ()


@dataclass
class SyncResult:
    created: int = 0
    updated: int = 0
    deleted: int = 0
    unchanged: int = 0
    errors: list = field(default_factory=list)


def _key(domain: str, port: int) -> tuple:
    return (domain.strip().lower().rstrip("."), int(port or 443))


def _remote_key(site: dict) -> tuple:
    port = site.get("custom_port") or site.get("port") or 443
    return _key(str(site.get("domain", "")), int(port))


def _site_patch(site: dict, spec) -> dict:
    patch: dict = {}
    want_types = sorted(spec.check_types)
    have_types = sorted(site.get("check_types") or [])
    if have_types != want_types:
        patch["check_types"] = list(spec.check_types)
    want_interval = int(spec.check_interval_minutes)
    if site.get("check_interval_minutes") not in (None, want_interval):
        patch["check_interval_minutes"] = want_interval
    want_days = int(spec.alert_days)
    thresholds = site.get("alert_thresholds")
    if isinstance(thresholds, list) and thresholds:
        if min(thresholds) != want_days:
            patch["alert_thresholds"] = [want_days]
    elif site.get("alert_days") not in (None, want_days):
        patch["alert_days"] = want_days
    if (site.get("origin_ip") or None) != (spec.origin_ip or None):
        patch["origin_ip"] = spec.origin_ip
    return patch


def build_plan(remote_sites: list, desired: list, prune: bool = False) -> Plan:
    by_remote = {}
    for s in remote_sites:
        by_remote.setdefault(_remote_key(s), s)
    to_create: list = []
    to_update: list = []
    seen: set = set()
    for spec in desired:
        k = _key(spec.domain, spec.port)
        seen.add(k)
        site = by_remote.get(k)
        if site is None:
            to_create.append(spec)
            continue
        patch = _site_patch(site, spec)
        if patch:
            to_update.append((site, patch))
    to_delete: list = []
    if prune:
        for k, site in by_remote.items():
            if k not in seen:
                to_delete.append(site)
    unchanged = len(desired) - len(to_create) - len(to_update)
    return Plan(tuple(to_create), tuple(to_update), tuple(to_delete), (unchanged,))


def reconcile(client, desired: list, prune: bool = False, dry_run: bool = False) -> SyncResult:
    result = SyncResult()
    try:
        remote = client.list_sites()
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"list_sites failed: {e}")
        return result
    plan = build_plan(remote or [], desired, prune=prune)
    if dry_run:
        result.created = len(plan.to_create)
        result.updated = len(plan.to_update)
        result.deleted = len(plan.to_delete)
        result.unchanged = plan.unchanged[0] if plan.unchanged else 0
        return result
    for spec in plan.to_create:
        try:
            client.create_site(spec)
            result.created += 1
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"create {spec.domain}:{spec.port} failed: {e}")
    for site, patch in plan.to_update:
        try:
            client.update_site(str(site.get("id")), patch)
            result.updated += 1
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"update {site.get('domain')} failed: {e}")
    for site in plan.to_delete:
        try:
            client.delete_site(str(site.get("id")))
            result.deleted += 1
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"delete {site.get('domain')} failed: {e}")
    result.unchanged = plan.unchanged[0] if plan.unchanged else 0
    return result
