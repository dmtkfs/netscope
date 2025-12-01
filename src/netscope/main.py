import argparse
import time
import threading
from typing import Sequence, List

from .host_insight import HostInsight, ConnectionInfo
from .inventory import (
    list_candidate_interfaces,
    DeviceInfo,
    discover_devices_on_interface,
)
from .dnsmap import DnsMapper
from .capture import start_dns_sniffer
from .whois_enrich import WhoisEnricher
from .mitm import run_mitm_plan, run_mitm_active


def print_connections(
    conns: List[ConnectionInfo], whois: WhoisEnricher | None = None
) -> None:
    if not conns:
        print("No active connections found (ESTABLISHED).")
        return

    # Pre-enrich IPs once per snapshot to avoid N lookups
    org_by_ip: dict[str, str | None] = {}
    if whois is not None:
        unique_ips = {c.raddr_ip for c in conns if c.raddr_ip}
        for ip in unique_ips:
            org_by_ip[ip] = whois.lookup_org(ip)  # may be None

    rows: list[tuple[str, str, str, str, str, str]] = []

    for c in conns:
        pid = str(c.pid) if c.pid is not None else "-"
        proc_name = c.process_name or "unknown"
        local = f"{c.laddr_ip}:{c.laddr_port}"

        if c.raddr_ip and c.raddr_port:
            remote_ip_port = f"{c.raddr_ip}:{c.raddr_port}"
        else:
            remote_ip_port = "-"

        hostname = c.hostname
        if hostname:
            remote = f"{remote_ip_port} ({hostname})"
        else:
            remote = remote_ip_port

        status = c.status or "-"
        org = ""
        if whois is not None and c.raddr_ip:
            org = org_by_ip.get(c.raddr_ip) or ""
        if not org:
            org = "-"

        rows.append((pid, proc_name, local, remote, status, org))

    headers = ("PID", "Process", "Local", "Remote", "Status", "Org")

    # (min, max) per column
    col_limits = [
        (3, 8),  # PID
        (7, 25),  # Process
        (5, 30),  # Local
        (6, 80),  # Remote
        (6, 15),  # Status
        (3, 30),  # Org
    ]

    def compute_width(idx: int, header: str) -> int:
        min_w, max_w = col_limits[idx]
        max_len = len(header)
        for row in rows:
            max_len = max(max_len, len(row[idx]))
        return max(min_w, min(max_len, max_w))

    widths = [compute_width(i, h) for i, h in enumerate(headers)]

    fmt_header = (
        f"{{:>{widths[0]}}}  "
        f"{{:<{widths[1]}}}  "
        f"{{:<{widths[2]}}}  "
        f"{{:<{widths[3]}}}  "
        f"{{:<{widths[4]}}}  "
        f"{{:<{widths[5]}}}"
    )
    fmt_row = (
        f"{{:>{widths[0]}}}  "
        f"{{:<{widths[1]}.{widths[1]}}}  "
        f"{{:<{widths[2]}.{widths[2]}}}  "
        f"{{:<{widths[3]}.{widths[3]}}}  "
        f"{{:<{widths[4]}.{widths[4]}}}  "
        f"{{:<{widths[5]}.{widths[5]}}}"
    )

    header_line = fmt_header.format(*headers)
    print(header_line)
    print("-" * len(header_line))

    for pid, proc, local, remote, status, org in rows:
        print(fmt_row.format(pid, proc, local, remote, status, org))


def print_connections_live(
    conns: list[ConnectionInfo],
    dns_mapper: DnsMapper,
    whois: WhoisEnricher | None = None,
) -> None:
    if not conns:
        print("No active connections (including UDP where applicable).")
        return

    # Pre-enrich org names once per snapshot
    org_by_ip: dict[str, str | None] = {}
    if whois is not None:
        unique_ips = {c.raddr_ip for c in conns if c.raddr_ip}
        for ip in unique_ips:
            org_by_ip[ip] = whois.lookup_org(ip)  # may be None

    # Build rows
    rows: list[tuple[str, str, str, str, str, str]] = []

    for c in conns:
        pid = str(c.pid) if c.pid is not None else "-"
        proc_name = c.process_name or "unknown"
        local = f"{c.laddr_ip}:{c.laddr_port}"

        remote_ip = c.raddr_ip or "-"
        remote_port = c.raddr_port or 0

        # Prefer DNS/SNI mapper over reverse DNS
        mapped = dns_mapper.lookup(c.raddr_ip) if c.raddr_ip else None

        if mapped:
            remote = f"{remote_ip}:{remote_port} ({mapped})"
        elif c.hostname:
            remote = f"{remote_ip}:{remote_port} ({c.hostname})"
        else:
            remote = f"{remote_ip}:{remote_port}"

        status = c.status or "-"

        org = "-"
        if whois is not None and c.raddr_ip:
            org = org_by_ip.get(c.raddr_ip) or "-"

        rows.append((pid, proc_name, local, remote, status, org))

    headers = ("PID", "Process", "Local", "Remote", "Status", "Org")

    col_limits = [
        (3, 8),  # PID
        (7, 25),  # Process
        (5, 30),  # Local
        (6, 80),  # Remote
        (6, 15),  # Status
        (3, 30),  # Org
    ]

    def compute_width(idx: int, header: str) -> int:
        min_w, max_w = col_limits[idx]
        max_len = len(header)
        for row in rows:
            max_len = max(max_len, len(row[idx]))
        return max(min_w, min(max_len, max_w))

    widths = [compute_width(i, h) for i, h in enumerate(headers)]

    fmt_header = (
        f"{{:>{widths[0]}}}  "
        f"{{:<{widths[1]}}}  "
        f"{{:<{widths[2]}}}  "
        f"{{:<{widths[3]}}}  "
        f"{{:<{widths[4]}}}  "
        f"{{:<{widths[5]}}}"
    )
    fmt_row = (
        f"{{:>{widths[0]}}}  "
        f"{{:<{widths[1]}.{widths[1]}}}  "
        f"{{:<{widths[2]}.{widths[2]}}}  "
        f"{{:<{widths[3]}.{widths[3]}}}  "
        f"{{:<{widths[4]}.{widths[4]}}}  "
        f"{{:<{widths[5]}.{widths[5]}}}"
    )

    header_line = fmt_header.format(*headers)
    print(header_line)
    print("-" * len(header_line))

    for pid, proc, local, remote, status, org in rows:
        print(fmt_row.format(pid, proc, local, remote, status, org))


def run_host_live(poll_interval: float = 3.0) -> None:
    """
    Live view: start DNS/SNI sniffer and periodically show host connections.

    This is still read-only:
    - uses Npcap/Scapy to capture DNS/TLS metadata
    - uses WHOIS/RDAP to enrich IPs with org names
    - does not send packets or change system configuration
    """
    dns_mapper = DnsMapper()
    whois = WhoisEnricher()
    stop_event = threading.Event()

    print("Starting DNS sniffer (requires Npcap and admin privileges)...")
    print(
        "If packet sniffing is unavailable, NetScope will fall back to reverse DNS + WHOIS only.\n"
    )
    start_dns_sniffer(dns_mapper=dns_mapper, iface=None, stop_event=stop_event)

    hi = HostInsight()

    try:
        while True:
            conns = hi.get_connections()
            print("\n=== Host connections (live view) ===")
            print_connections_live(conns, dns_mapper, whois)
            print(f"\n(Next update in {poll_interval:.1f}s, Ctrl+C to stop)")
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print("\nStopping live view...")
    finally:
        stop_event.set()
        time.sleep(0.5)


def print_devices(devices: list[DeviceInfo]) -> None:
    if not devices:
        print("No devices discovered on the local network (or detection failed).")
        return

    rows: list[tuple[str, str, str, str, str, str]] = []

    for d in devices:
        ip = d.ip
        mac = d.mac or "-"
        # Prefer hostname, then vendor as a secondary label
        if d.hostname:
            name = d.hostname
        elif d.vendor:
            name = f"[{d.vendor}]"
        else:
            name = "-"

        is_local = "yes" if d.is_local else "no"
        alive = "yes" if d.alive else "no"
        vendor = d.vendor or "-"

        rows.append((ip, mac, name, is_local, alive, vendor))

    headers = ("IP", "MAC", "Hostname", "Is local", "Alive", "Vendor")

    col_limits = [
        (7, 15),  # IP
        (3, 20),  # MAC
        (3, 40),  # Hostname
        (7, 8),  # Is local
        (5, 8),  # Alive
        (3, 30),  # Vendor
    ]

    def compute_width(idx: int, header: str) -> int:
        min_w, max_w = col_limits[idx]
        max_len = len(header)
        for row in rows:
            max_len = max(max_len, len(row[idx]))
        return max(min_w, min(max_len, max_w))

    widths = [compute_width(i, h) for i, h in enumerate(headers)]

    fmt_header = (
        f"{{:<{widths[0]}}}  "
        f"{{:<{widths[1]}}}  "
        f"{{:<{widths[2]}}}  "
        f"{{:<{widths[3]}}}  "
        f"{{:<{widths[4]}}}  "
        f"{{:<{widths[5]}}}"
    )
    fmt_row = (
        f"{{:<{widths[0]}.{widths[0]}}}  "
        f"{{:<{widths[1]}.{widths[1]}}}  "
        f"{{:<{widths[2]}.{widths[2]}}}  "
        f"{{:<{widths[3]}.{widths[3]}}}  "
        f"{{:<{widths[4]}.{widths[4]}}}  "
        f"{{:<{widths[5]}.{widths[5]}}}"
    )

    header_line = fmt_header.format(*headers)
    print(header_line)
    print("-" * len(header_line))

    for ip, mac, name, is_local, alive, vendor in rows:
        print(fmt_row.format(ip, mac, name, is_local, alive, vendor))


def run_host_insight() -> None:
    hi = HostInsight()
    whois = WhoisEnricher()
    conns = hi.get_connections()
    print_connections(conns, whois)


def run_inventory() -> None:
    interfaces = list_candidate_interfaces()
    if not interfaces:
        print("No suitable IPv4 network interfaces found (Wi-Fi/Ethernet that are up).")
        return

    # If there's only one, just use it.
    if len(interfaces) == 1:
        iface = interfaces[0]
        print(f"Using interface: {iface.name} ({iface.ip}/{iface.netmask})")
    else:
        print("Interfaces found")
        print("----------------")
        for idx, iface in enumerate(interfaces, start=1):
            print(f"{idx}. {iface.name}  ({iface.ip}/{iface.netmask})")

        while True:
            choice = input(
                f"\nChoose interface [1-{len(interfaces)}] (or 'q' to cancel): "
            ).strip()
            if choice.lower() in {"q", "quit", "exit"}:
                print("Inventory cancelled.")
                return
            try:
                idx = int(choice)
                if 1 <= idx <= len(interfaces):
                    iface = interfaces[idx - 1]
                    break
            except ValueError:
                pass
            print("Invalid choice, try again.")

        print(f"\nUsing interface: {iface.name} ({iface.ip}/{iface.netmask})")

    print("Discovering devices on local network (safe ARP + ping scan)...")
    devices = discover_devices_on_interface(iface)
    print_devices(devices)

    from .inventory import save_inventory_snapshot

    save_inventory_snapshot(iface, devices)
    # Optional: tiny UX note
    print("Saved inventory snapshot for this interface for use by 'mitm-plan'.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope - home host/network visibility tool.",
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    # host command
    host_parser = subparsers.add_parser(
        "host",
        help="Show active connections for this host (snapshot).",
    )
    host_parser.set_defaults(func=lambda args: run_host_insight())

    # host-live command
    host_live_parser = subparsers.add_parser(
        "host-live",
        help="Live view of this host's connections (uses DNS sniffing).",
    )
    host_live_parser.set_defaults(func=lambda args: run_host_live())

    # inventory command
    inv_parser = subparsers.add_parser(
        "inventory",
        help="Discover devices on the local network (safe ping + ARP read).",
    )
    inv_parser.set_defaults(func=lambda args: run_inventory())

    sp_mitm_plan = subparsers.add_parser(
        "mitm-plan",
        help="Plan a safe ARP MITM session (dry run only, no changes).",
    )
    sp_mitm_plan.set_defaults(func=lambda args: run_mitm_plan())

    sp_mitm = subparsers.add_parser(
        "mitm",
        help="Run active ARP MITM on a chosen target (with automatic cleanup).",
    )
    sp_mitm.set_defaults(func=lambda args: run_mitm_active())

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # default to "host" if no subcommand
    if not getattr(args, "command", None):
        run_host_insight()
        return

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
    else:
        func(args)


if __name__ == "__main__":
    main()
