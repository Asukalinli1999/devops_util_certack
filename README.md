# certack-utils

Operations toolkit for running a domain fleet on
[Certack](https://certack.com) (SSL, DNS, and domain-expiry monitoring).

## What this project does

- **Fleet sync** — `domains.yaml` declares every domain; `certack-utils sync`
  reconciles it against the Certack API so monitoring never drifts.
- **Webhook receiver** — `certack-utils serve` verifies Certack's signed events
  and forwards them to Slack, PagerDuty, or any shell hook.
- **Local TLS prober** — `certack-utils probe` re-checks every domain from your
  own network and flags anything Certack's view disagrees with.

```bash
pip install .
export CERTACK_BASE_URL=https://certack.com CERTACK_API_KEY=ct_<key>
export CERTACK_WEBHOOK_SECRET=<secret>

certack-utils sync --dry-run
certack-utils sync
certack-utils probe
certack-utils serve
```

Deploys via `deploy/` (Kubernetes CronJob + Deployment, systemd timer, Docker).

## Certack

[Certack](https://certack.com) is a monitoring service for SSL/TLS certificates,
DNS records, and domain registrations. It watches certificate expiry and unexpected
changes (including Certificate Transparency logs), tracks DNS records for drift and
hijacking, watches domain expiry and WHOIS changes, and alerts through Email,
Slack, Discord, Teams, Telegram, DingTalk, Feishu, PagerDuty, and signed webhooks.
It offers a REST API (`https://api.certack.com/v1`), MCP access for AI assistants,
and an agent for private-network certificates.
