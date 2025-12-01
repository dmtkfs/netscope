from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional, Iterable

import psutil

from .config import HOST_INSIGHT_CONFIG


@dataclass
class ConnectionInfo:
    pid: Optional[int]
    process_name: str
    laddr_ip: str
    laddr_port: int
    raddr_ip: Optional[str]
    raddr_port: Optional[int]
    status: str
    hostname: Optional[str]


class HostInsight:
    def __init__(self) -> None:
        # cache for reverse DNS lookups: ip -> hostname
        self._dns_cache: dict[str, Optional[str]] = {}

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname with caching. Never raises."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]

        if not HOST_INSIGHT_CONFIG.resolve_hostnames:
            self._dns_cache[ip] = None
            return None

        try:
            name, _, _ = socket.gethostbyaddr(ip)
            self._dns_cache[ip] = name
            return name
        except Exception:
            # Timeouts / no PTR / etc.
            self._dns_cache[ip] = None
            return None

    def get_connections(self) -> list[ConnectionInfo]:
        """
        Return a snapshot of active inet connections on this host.

        This only reads OS state via psutil; it does not alter system config.
        """
        raw_conns = psutil.net_connections(kind="inet")

        conns: list[ConnectionInfo] = []
        for c in raw_conns:
            status = c.status or ""
            is_udp = c.type == socket.SOCK_DGRAM
            if not is_udp:
                if (
                    HOST_INSIGHT_CONFIG.allowed_statuses
                    and status not in HOST_INSIGHT_CONFIG.allowed_statuses
                ):
                    continue

            laddr_ip, laddr_port = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
            raddr_ip, raddr_port = (
                (c.raddr.ip, c.raddr.port) if c.raddr else (None, None)
            )

            # best-effort process name
            proc_name = "unknown"
            if c.pid is not None:
                try:
                    proc = psutil.Process(c.pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "unknown"

            hostname = self._resolve_hostname(raddr_ip) if raddr_ip else None

            info = ConnectionInfo(
                pid=c.pid,
                process_name=proc_name,
                laddr_ip=laddr_ip,
                laddr_port=laddr_port,
                raddr_ip=raddr_ip,
                raddr_port=raddr_port,
                status=status,
                hostname=hostname,
            )
            conns.append(info)

        # sort by process name then remote host/ip
        conns.sort(
            key=lambda x: (x.process_name.lower(), x.hostname or x.raddr_ip or "")
        )

        if HOST_INSIGHT_CONFIG.max_connections is not None:
            conns = conns[: HOST_INSIGHT_CONFIG.max_connections]

        return conns

    @staticmethod
    def summarize(conns: Iterable[ConnectionInfo]) -> dict[str, int]:
        """
        Simple summary: counts of unique remote IPs and hostnames.
        """
        ips = {c.raddr_ip for c in conns if c.raddr_ip}
        hosts = {c.hostname for c in conns if c.hostname}
        return {
            "total_connections": len(list(conns)),
            "unique_remote_ips": len(ips),
            "unique_hostnames": len(hosts),
        }
