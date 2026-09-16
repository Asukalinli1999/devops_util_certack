from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from .agent import find_drift, scan_many
from .client import CertackClient, load_domains, load_settings
from .server import serve
from .sync import reconcile

log = logging.getLogger("certack_utils")


def _logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _client(settings: dict) -> CertackClient:
    if not settings.get("api_key"):
        raise SystemExit("CERTACK_API_KEY is required")
    return CertackClient(settings["base_url"], settings["api_key"], settings["timeout_seconds"], settings["max_retries"])


def cmd_sync(args) -> int:
    _logging(args.verbose)
    settings = load_settings()
    if args.domains:
        settings["domains_file"] = args.domains
    if args.dry_run:
        settings["dry_run"] = True
    if args.prune:
        settings["prune"] = True
    desired = load_domains(settings["domains_file"])
    result = reconcile(_client(settings), desired, prune=settings["prune"], dry_run=settings["dry_run"])
    print(json.dumps(result.__dict__, ensure_ascii=False))
    return 1 if result.errors else 0


def cmd_serve(args) -> int:
    _logging(args.verbose)
    settings = load_settings()
    client = None
    try:
        client = _client(settings)
    except SystemExit:
        log.warning("starting without api client (no key)")
    serve(settings, client)
    return 0


def cmd_probe(args) -> int:
    _logging(args.verbose)
    settings = load_settings()
    if args.domains:
        settings["domains_file"] = args.domains
    desired = load_domains(settings["domains_file"])
    targets = [(s.domain, s.port) for s in desired]
    probes = scan_many(targets, concurrency=args.concurrency, timeout=settings["timeout_seconds"])
    warn = args.warn_days
    bad = [p for p in probes if not p.ok or (p.days_remaining is not None and p.days_remaining <= warn)]
    for p in probes:
        print(json.dumps(p.__dict__, ensure_ascii=False))
    return 1 if bad else 0


def cmd_watch(args) -> int:
    _logging(args.verbose)
    settings = load_settings()
    if args.domains:
        settings["domains_file"] = args.domains
    client = _client(settings)
    interval = max(60, int(args.interval))
    while True:
        desired = load_domains(settings["domains_file"])
        result = reconcile(client, desired, prune=settings["prune"])
        log.info("sync created=%s updated=%s deleted=%s errors=%s", result.created, result.updated, result.deleted, len(result.errors))
        targets = [(s.domain, s.port) for s in desired]
        probes = scan_many(targets, timeout=settings["timeout_seconds"])
        drift = find_drift(probes, {}, warn_days=args.warn_days)
        for d in drift:
            log.warning("drift %s", d)
        if args.once:
            return 1 if result.errors or drift else 0
        time.sleep(interval)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="certack-utils")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sync")
    s.add_argument("--domains", default="")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--prune", action="store_true")
    s.set_defaults(func=cmd_sync)
    v = sub.add_parser("serve")
    v.set_defaults(func=cmd_serve)
    p = sub.add_parser("probe")
    p.add_argument("--domains", default="")
    p.add_argument("--concurrency", type=int, default=5)
    p.add_argument("--warn-days", type=int, default=30)
    p.set_defaults(func=cmd_probe)
    w = sub.add_parser("watch")
    w.add_argument("--domains", default="")
    w.add_argument("--interval", type=int, default=900)
    w.add_argument("--warn-days", type=int, default=30)
    w.add_argument("--once", action="store_true")
    w.set_defaults(func=cmd_watch)
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(json.dumps({"error": str(e)}))
        return 2
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
