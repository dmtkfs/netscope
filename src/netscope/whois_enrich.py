from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, Optional

try:
    from ipwhois import IPWhois  # type: ignore[import-untyped]
except Exception:  # library missing or import error
    IPWhois = None  # type: ignore[assignment]


@dataclass
class WhoisEnricher:
    """Thread-safe WHOIS/RDAP-based IP -> org name enricher.

    - Purely passive: only makes outbound WHOIS/RDAP queries.
    - Never modifies system configuration.
    - Caches results aggressively to avoid repeated lookups.
    """

    _cache: Dict[str, Optional[str]] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def _is_public_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback or addr.is_link_local)
        except ValueError:
            return False

    def lookup_org(self, ip: str) -> Optional[str]:
        """Return a short org/owner name for an IP, or None if unknown."""
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]

        # Private/local IPs: skip
        if not self._is_public_ip(ip):
            with self._lock:
                self._cache[ip] = None
            return None

        if IPWhois is None:
            # ipwhois library not available
            with self._lock:
                self._cache[ip] = None
            return None

        org: Optional[str] = None
        try:
            obj = IPWhois(ip)
            # RDAP is preferred; fall back to whois if needed
            result = obj.lookup_rdap(asn_methods=["whois"])
            # Try a few common fields
            net = result.get("network") or {}
            org = net.get("name") or result.get("asn_description") or result.get("asn")
            if isinstance(org, str):
                org = org.strip()
        except Exception:
            org = None

        # Cache result (even None) to avoid repeated lookups
        with self._lock:
            self._cache[ip] = org

        return org
