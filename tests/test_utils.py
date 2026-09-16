import hashlib
import hmac
import json
import unittest

from certack_utils.client import normalize_base_url, validate_domain
from certack_utils.sync import build_plan
from certack_utils.config import DomainSpec
from certack_utils.webhooks import fresh, parse_event, verify_signature


class TestClientHelpers(unittest.TestCase):
    def test_base_url(self):
        self.assertEqual(normalize_base_url("certack.com"), "https://certack.com")
        self.assertEqual(normalize_base_url("https://certack.com/"), "https://certack.com")

    def test_domain(self):
        self.assertEqual(validate_domain("Example.COM."), "example.com")
        with self.assertRaises(ValueError):
            validate_domain("not a domain!!!")


class TestSyncPlan(unittest.TestCase):
    def test_create_update_prune(self):
        desired = [DomainSpec(domain="a.com"), DomainSpec(domain="b.com", port=8443)]
        remote = [{"id": "1", "domain": "a.com", "custom_port": None, "check_types": ["ssl"], "alert_days": 30}]
        plan = build_plan(remote, desired)
        self.assertEqual(len(plan.to_create), 1)
        self.assertEqual(len(plan.to_update), 1)
        plan2 = build_plan(remote, desired, prune=True)
        self.assertEqual(len(plan2.to_delete), 0)
        plan3 = build_plan(remote + [{"id": "9", "domain": "old.com"}], desired, prune=True)
        self.assertEqual(len(plan3.to_delete), 1)


class TestWebhooks(unittest.TestCase):
    def test_verify(self):
        secret = "s3cret"
        ts = "2026-09-16T00:00:00.000Z"
        payload = {"version": "2026-07-09", "event": "ssl.expiring", "timestamp": ts, "data": {"domain": "a.com"}}
        raw = json.dumps(payload).encode()
        sig = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
        self.assertTrue(verify_signature(secret, ts, raw, sig))
        self.assertFalse(verify_signature(secret, ts, raw, "sha256=deadbeef"))

    def test_parse_and_fresh(self):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        raw = json.dumps({"event": "site.added", "timestamp": now, "data": {}}).encode()
        ev = parse_event(raw)
        self.assertEqual(ev.event, "site.added")
        self.assertTrue(fresh(now))
        self.assertFalse(fresh("2000-01-01T00:00:00.000Z"))
        self.assertFalse(fresh("garbage"))


if __name__ == "__main__":
    unittest.main()
