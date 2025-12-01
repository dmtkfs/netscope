from __future__ import annotations

import ipaddress
import socket
import subprocess
import time
import json
import os
from dataclasses import dataclass
from typing import Optional, Dict, List

import psutil
from scapy.all import ARP, Ether, srp  # type: ignore[import-untyped]
from manuf import manuf


@dataclass
class InterfaceIPv4:
    """Simple description of an IPv4 interface we can scan."""

    name: str
    ip: str
    netmask: str


@dataclass
class DeviceInfo:
    ip: str
    mac: Optional[str]
    hostname: Optional[str]
    is_local: bool
    alive: bool  # responded to ARP and/or ping
    vendor: Optional[str] = None


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
CACHE_PATH = os.path.join(PROJECT_ROOT, ".netscope_inventory.json")


def _iface_cache_key(iface: InterfaceIPv4) -> str:
    # key includes name+IP+netmask so Ethernet/Wi-Fi etc. don’t collide
    return f"{iface.name}|{iface.ip}|{iface.netmask}"


def save_inventory_snapshot(iface: InterfaceIPv4, devices: list[DeviceInfo]) -> None:
    """Save an inventory snapshot to a simple JSON cache.

    This is just for convenience (reused by mitm-plan); no sensitive
    info beyond what inventory already shows.
    """
    data: dict = {}
    try:
        if os.path.exists(CACHE_PATH):
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
    except Exception:
        data = {}

    key = _iface_cache_key(iface)
    data[key] = {
        "iface": {
            "name": iface.name,
            "ip": iface.ip,
            "netmask": iface.netmask,
        },
        "timestamp": time.time(),
        "devices": [
            {
                "ip": d.ip,
                "mac": d.mac,
                "hostname": d.hostname,
                "is_local": d.is_local,
                "alive": d.alive,
                "vendor": d.vendor,
            }
            for d in devices
        ],
    }

    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        # Cache failure is non-fatal
        pass


def load_inventory_snapshot_for_iface(
    iface: InterfaceIPv4,
) -> tuple[list[DeviceInfo], float | None]:
    """Load a previously-saved snapshot for this interface, if any."""
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return [], None

    key = _iface_cache_key(iface)
    entry = data.get(key)
    if not entry:
        return [], None

    ts = entry.get("timestamp")
    devices_data = entry.get("devices", []) or []

    devices: list[DeviceInfo] = []
    for obj in devices_data:
        devices.append(
            DeviceInfo(
                ip=obj.get("ip", ""),
                mac=obj.get("mac"),
                hostname=obj.get("hostname"),
                is_local=bool(obj.get("is_local", False)),
                alive=bool(obj.get("alive", False)),
                vendor=obj.get("vendor"),
            )
        )
    return devices, ts


_mac_parser = manuf.MacParser()


def list_candidate_interfaces() -> List[InterfaceIPv4]:
    """List IPv4 interfaces that look like real LAN NICs.

    - must be UP
    - must have an IPv4
    - skip obvious loopback/virtual/npcap/tunnel adapters
    """
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    candidates: List[InterfaceIPv4] = []
    skip_keywords = [
        "loopback",
        "npcap",
        "virtual",
        "vmware",
        "hyper-v",
        "vbox",
        "tunnel",
        "miniport",
    ]

    for if_name, if_addrs in addrs.items():
        st = stats.get(if_name)
        if not st or not st.isup:
            continue

        lname = if_name.lower()
        if any(k in lname for k in skip_keywords):
            continue

        ipv4_addr = None
        ipv4_netmask = None
        for a in if_addrs:
            if a.family == socket.AF_INET:
                if a.address.startswith("127."):
                    continue
                ipv4_addr = a.address
                ipv4_netmask = a.netmask or "255.255.255.0"
                break

        if ipv4_addr and ipv4_netmask:
            candidates.append(
                InterfaceIPv4(name=if_name, ip=ipv4_addr, netmask=ipv4_netmask)
            )

    return candidates


def _guess_network(ip: str, netmask: str) -> Optional[ipaddress.IPv4Network]:
    """Use the actual netmask to derive the local IPv4 network."""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return network
    except Exception:
        return None


def _ping(ip: str, timeout_ms: int = 300) -> bool:
    """Ping an IP once, Windows-style. Returns True if host responds.

    Purely observational: just calls 'ping'; no firewall/routing changes.
    Timeouts kept low so a /24 finishes quickly.
    """
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _parse_arp_table() -> Dict[str, str]:
    """Parse 'arp -a' output into a mapping of ip -> mac.

    Read-only: 'arp -a' just shows current ARP cache.
    """
    mapping: Dict[str, str] = {}
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
        if line.lower().startswith("interface:") or "internet address" in line.lower():
            continue

        parts = line.split()
        if len(parts) >= 2:
            ip, mac = parts[0], parts[1]
            mapping[ip] = mac
    return mapping


def _reverse_dns(ip: str) -> Optional[str]:
    """Best-effort reverse DNS; never raises."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def _netbios_name(ip: str, timeout: int = 2) -> Optional[str]:
    """Best-effort NetBIOS name lookup via 'nbtstat -A'.

    Windows-specific and purely observational: it sends a NetBIOS
    query to the host and parses the response. If anything goes wrong,
    we just return None.
    """
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return None

    name: Optional[str] = None
    for line in result.stdout.splitlines():
        line = line.strip()
        # Typical line:
        # "MYPC           <00>  UNIQUE      Registered"
        if "<00>" in line and "UNIQUE" in line:
            parts = line.split()
            if parts:
                name = parts[0]
                break

    return name


def _resolve_hostname(ip: str) -> Optional[str]:
    """Try multiple ways to resolve a human-friendly name for an IP.

    Order:
    - reverse DNS (PTR)
    - NetBIOS name via nbtstat

    All methods are best-effort and safe; failures just return None.
    """
    name = _reverse_dns(ip)
    if name:
        return name

    return _netbios_name(ip)


def _mac_vendor(mac: str) -> Optional[str]:
    """Best-effort MAC vendor lookup using OUI.

    Normalizes Windows-style MAC (aa-bb-cc-dd-ee-ff) to aa:bb:cc:dd:ee:ff.
    Returns a short vendor name or None.
    """
    if not mac:
        return None
    try:
        norm = mac.replace("-", ":").replace(".", ":").lower()
        vendor = _mac_parser.get_manuf(norm)
        if vendor:
            return vendor.strip()
    except Exception:
        return None
    return None


def _arp_scan(
    net: ipaddress.IPv4Network,
    iface_name: str,
    max_hosts: int,
    timeout: float = 1.0,
) -> Dict[str, str]:
    """Active ARP who-has scan over part of the local network on a given iface.

    This sends standard ARP requests (who-has) and records replies.
    It does NOT spoof or poison ARP; it only asks "who has IP X?".

    Requires Npcap/admin for raw access; on failure returns an empty mapping.
    """
    hosts_list = list(net.hosts())
    if len(hosts_list) > max_hosts:
        hosts_list = hosts_list[:max_hosts]

    if not hosts_list:
        return {}

    pdst = " ".join(str(h) for h in hosts_list)

    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst)
        answered, _ = srp(pkt, timeout=timeout, iface=iface_name, verbose=False)
    except Exception:
        # If sniff/send is not available (no Npcap or permissions), just fall back.
        return {}

    mapping: Dict[str, str] = {}
    for _, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc
        mapping[ip] = mac

    return mapping


def discover_devices_on_interface(
    iface: InterfaceIPv4,
    max_hosts: int = 256,
    slow_mode: bool = False,
) -> List[DeviceInfo]:
    """Discover devices on the IPv4 network of a specific interface.

    Pipeline (all safe):

    - derive the network from iface.ip + iface.netmask
    - ARP who-has scan on that iface (layer 2, no spoofing)
    - ping to augment "alive" status
    - read ARP cache
    - reverse DNS / NetBIOS for hostnames
    - MAC vendor lookup

    This function:
    - ONLY sends ARP requests, pings, and name queries
    - NEVER performs ARP spoofing/poisoning
    - NEVER changes firewall or routing
    """
    local_ip = iface.ip
    net = _guess_network(iface.ip, iface.netmask)
    if not net:
        return []

    try:
        local_addr = ipaddress.IPv4Address(local_ip)
    except ipaddress.AddressValueError:
        local_addr = None

    # 1) ARP scan on the chosen interface
    arp_scan_map = _arp_scan(
        net, iface_name=iface.name, max_hosts=max_hosts, timeout=1.0
    )

    # 2) Ping sweep (helps mark "alive" even if ARP scan fails)
    alive_map: Dict[str, bool] = {}
    hosts_iter = list(net.hosts())
    hosts: List[ipaddress.IPv4Address] = []
    for h in hosts_iter:
        hosts.append(h)
        if len(hosts) >= max_hosts:
            break

    # Ensure our own IP is included even on large subnets
    if local_addr is not None and local_addr not in hosts:
        hosts.insert(0, local_addr)

    for h in hosts:
        ip_str = str(h)
        # Don't spam ping if we already saw an ARP reply
        if ip_str in arp_scan_map:
            alive_map[ip_str] = True
            continue
        alive = _ping(ip_str)
        alive_map[ip_str] = alive
        if slow_mode:
            time.sleep(0.05)

    # 3) ARP table after activity
    arp_table_map = _parse_arp_table()

    # Merge ARP sources: scan + OS table
    mac_by_ip: Dict[str, str] = {}
    mac_by_ip.update(arp_table_map)
    mac_by_ip.update(arp_scan_map)

    devices: List[DeviceInfo] = []
    seen_ips: set[str] = set()

    # Collect candidate IPs: any host in net that appears in ARP or is alive or is local
    candidates: List[str] = []
    for h in hosts:
        ip_str = str(h)
        if ip_str in mac_by_ip or alive_map.get(ip_str, False) or ip_str == local_ip:
            candidates.append(ip_str)

    for ip_str in candidates:
        if ip_str in seen_ips:
            continue
        seen_ips.add(ip_str)

        mac = mac_by_ip.get(ip_str)
        alive = bool(
            alive_map.get(ip_str, False) or ip_str in arp_scan_map or ip_str == local_ip
        )
        hostname = _resolve_hostname(ip_str) if alive else None
        is_local = ip_str == local_ip
        vendor = _mac_vendor(mac) if mac else None

        devices.append(
            DeviceInfo(
                ip=ip_str,
                mac=mac,
                hostname=hostname,
                is_local=is_local,
                alive=alive,
                vendor=vendor,
            )
        )

    # Sort by IP
    try:
        devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    except Exception:
        devices.sort(key=lambda d: d.ip)

    return devices


def discover_devices(max_hosts: int = 256, slow_mode: bool = False) -> List[DeviceInfo]:
    """Best-effort discovery on the first suitable interface, if any."""
    interfaces = list_candidate_interfaces()
    if not interfaces:
        return []
    return discover_devices_on_interface(
        interfaces[0], max_hosts=max_hosts, slow_mode=slow_mode
    )
