from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ArpRecord:
    ip: str
    mac: str


@dataclass
class MitmSafetyPlan:
    iface_name: str
    iface_ip: str
    target_ip: str
    target_mac: Optional[str]
    gateway_ip: str
    gateway_mac: Optional[str]
    ip_forwarding_enabled: Optional[bool]
    arp_table_snapshot: Dict[str, ArpRecord]


def _parse_arp_table() -> Dict[str, ArpRecord]:
    """Parse 'arp -a' output into a mapping of ip -> ArpRecord.

    Read-only: just inspects the OS ARP cache, no changes.
    """
    mapping: Dict[str, ArpRecord] = {}
    try:
        result = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except Exception:
        return mapping

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Windows: "Interface: 10.0.0.36 --- 0x13"
        if line.lower().startswith("interface:"):
            continue

        if "internet address" in line.lower():
            # header row
            continue

        parts = line.split()
        if len(parts) >= 2:
            ip, mac = parts[0], parts[1]
            mapping[ip] = ArpRecord(ip=ip, mac=mac)

    return mapping


def _get_ip_forwarding_enabled() -> Optional[bool]:
    """Best-effort check of IPv4 forwarding status on Windows.

    Uses 'netsh interface ipv4 show global' and parses 'IPV4 forwarding'.
    Returns True/False if detected, or None on failure.
    """
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "global"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except Exception:
        return None

    for line in result.stdout.splitlines():
        line_l = line.strip().lower()
        if "ipv4 forwarding" in line_l:
            if "enabled" in line_l:
                return True
            if "disabled" in line_l:
                return False
    return None


def _set_ip_forwarding(enabled: bool) -> bool:
    """Best-effort change of IPv4 forwarding status on Windows.

    Uses 'netsh interface ipv4 set global forwarding=enabled/disabled'.
    Returns True if the command appears to succeed, False otherwise.
    """
    state = "enabled" if enabled else "disabled"
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "set", "global", f"forwarding={state}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


@dataclass
class IpForwardingManager:
    """Tracks original IPv4 forwarding state and restores it on cleanup."""

    original_state: Optional[bool]

    @classmethod
    def from_current(cls) -> "IpForwardingManager":
        return cls(original_state=_get_ip_forwarding_enabled())

    def ensure_enabled(self) -> None:
        """Ensure IPv4 forwarding is enabled (best-effort)."""
        if self.original_state is True:
            # Already enabled; leave as-is.
            return
        ok = _set_ip_forwarding(True)
        if not ok:
            print("[NetScope] WARNING: Failed to enable IPv4 forwarding via netsh.")

    def restore(self) -> None:
        """Restore IPv4 forwarding to its original state (best-effort)."""
        # If it was already enabled, we don't touch it.
        if self.original_state is True:
            return
        if self.original_state is False:
            _set_ip_forwarding(False)
        # If None (unknown), we leave it untouched to avoid guessing.


def build_mitm_plan(
    iface_name: str,
    iface_ip: str,
    target_ip: str,
    gateway_ip: str,
) -> MitmSafetyPlan:
    """Construct a dry-run MITM safety plan.

    - Takes a snapshot of current ARP entries
    - Looks up MACs for target and gateway if present
    - Notes current IP forwarding status

    This function is *read-only*: it does not change ARP tables
    or any system settings.
    """
    arp_snapshot = _parse_arp_table()
    target_mac = arp_snapshot.get(target_ip).mac if target_ip in arp_snapshot else None
    gateway_mac = (
        arp_snapshot.get(gateway_ip).mac if gateway_ip in arp_snapshot else None
    )
    ip_forwarding = _get_ip_forwarding_enabled()

    return MitmSafetyPlan(
        iface_name=iface_name,
        iface_ip=iface_ip,
        target_ip=target_ip,
        target_mac=target_mac,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        ip_forwarding_enabled=ip_forwarding,
        arp_table_snapshot=arp_snapshot,
    )
