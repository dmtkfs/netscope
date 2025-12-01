from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional


@dataclass
class DnsMapper:
    """Thread-safe mapping from IP -> list of domain names seen via DNS or SNI.

    Populated by:
    - DNS responses (A records)
    - TLS ClientHello SNI hostnames

    Purely passive: no packets are sent or system config changed.
    """

    _ip_to_names: Dict[str, List[str]] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def _add_name(self, ip: str, name: str) -> None:
        name = name.rstrip(".")
        if not name:
            return
        with self._lock:
            names = self._ip_to_names.setdefault(ip, [])
            if name not in names:
                names.append(name)

    def update_from_dns_response(self, qname: str, ips: List[str]) -> None:
        """Record that DNS name qname resolved to these IP addresses."""
        for ip in ips:
            self._add_name(ip, qname)

    def update_from_sni(self, ip: str, hostname: str) -> None:
        """Record that we saw SNI 'hostname' for a connection to this IP."""
        self._add_name(ip, hostname)

    def lookup(self, ip: str) -> Optional[str]:
        """Return a 'best' domain name for this IP, if we have one."""
        with self._lock:
            names = self._ip_to_names.get(ip)
            if not names:
                return None
            # Prefer the most recently added name
            return names[-1]

    def all_for_ip(self, ip: str) -> List[str]:
        with self._lock:
            return list(self._ip_to_names.get(ip, []))

    def snapshot(self) -> Dict[str, List[str]]:
        with self._lock:
            return {ip: list(names) for ip, names in self._ip_to_names.items()}
