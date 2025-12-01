from dataclasses import dataclass


@dataclass(frozen=True)
class HostInsightConfig:
    # Only show these connection statuses (ESTABLISHED = active connections)
    allowed_statuses: tuple[str, ...] = ("ESTABLISHED",)

    # Try to resolve remote IPs to hostnames (reverse DNS)
    resolve_hostnames: bool = True

    # Maximum number of connections to show (None = no limit)
    max_connections: int | None = 200


HOST_INSIGHT_CONFIG = HostInsightConfig()
