from dataclasses import dataclass, field


@dataclass(frozen=True)
class DomainSpec:
    domain: str
    port: int = 443
    check_types: tuple = ("ssl", "dns", "domain")
    alert_days: int = 30
    check_interval_minutes: int = 60
    origin_ip: str | None = None
    labels: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Settings:
    base_url: str
    api_key: str
    webhook_secret: str = ""
    domains_file: str = "certack_utils/domains.yaml"
    timeout_seconds: float = 15.0
    max_retries: int = 3
    dry_run: bool = False
    prune: bool = False
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""
    hook_command: str = ""
