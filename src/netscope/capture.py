from __future__ import annotations

import threading
from typing import Optional

from scapy.all import sniff, DNS, DNSRR, TCP, IP, Raw  # type: ignore[import-untyped]

from .dnsmap import DnsMapper


def _handle_dns_packet(pkt, dns_mapper: DnsMapper) -> None:
    """Extract DNS responses (A records) and update the mapper."""
    if not pkt.haslayer(DNS):
        return

    dns = pkt[DNS]

    # We care about responses (qr=1)
    if dns.qr != 1:
        return

    qname = None
    if dns.qd is not None:
        try:
            qname = dns.qd.qname.decode(errors="ignore")
        except Exception:
            qname = None
    if not qname:
        return

    # Collect A records (type 1)
    ips: list[str] = []
    ancount = dns.ancount or 0
    for i in range(ancount):
        rr = dns.an[i]
        if isinstance(rr, DNSRR) and rr.type == 1 and rr.rdata:
            ip_str = str(rr.rdata)
            ips.append(ip_str)

    if ips:
        dns_mapper.update_from_dns_response(qname, ips)


def _extract_sni_from_tls_client_hello(data: bytes) -> Optional[str]:
    """Very small, best-effort TLS ClientHello SNI parser.

    This does NOT decrypt anything; it just parses the cleartext ClientHello.
    If parsing fails at any point, we return None.
    """
    try:
        # TLS record header: 5 bytes
        if len(data) < 5:
            return None
        content_type = data[0]
        if content_type != 0x16:  # Handshake
            return None

        # bytes 1-2: version, 3-4: length (we can mostly ignore here)
        # Handshake header starts at offset 5
        if len(data) < 9:
            return None

        handshake_type = data[5]
        if handshake_type != 0x01:  # ClientHello
            return None

        # Skip: Handshake length (3 bytes), version (2), random (32)
        # 5(handshake hdr) + 4(len+version) + 32(random) = 41 so far
        # But to be safe, parse properly with offsets.
        offset = 5
        # handshake length (3 bytes)
        offset += 3
        # client version (2)
        offset += 2
        # random (32)
        offset += 32

        if len(data) < offset + 1:
            return None

        # session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        if len(data) < offset + 2:
            return None

        # cipher suites
        cipher_suites_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2 + cipher_suites_len

        if len(data) < offset + 1:
            return None

        # compression methods
        compression_methods_len = data[offset]
        offset += 1 + compression_methods_len

        if len(data) < offset + 2:
            return None

        # extensions length
        extensions_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2

        end_extensions = offset + extensions_len
        if end_extensions > len(data):
            return None

        # Parse extensions
        while offset + 4 <= end_extensions:
            ext_type = int.from_bytes(data[offset : offset + 2], "big")
            ext_len = int.from_bytes(data[offset + 2 : offset + 4], "big")
            offset += 4
            if offset + ext_len > end_extensions:
                break

            if ext_type == 0x0000:  # SNI
                # Structure: list length (2) + [name_type(1), name_len(2), name_bytes]
                sni_data = data[offset : offset + ext_len]
                if len(sni_data) < 5:
                    return None
                # skip list length
                sni_offset = 2
                if len(sni_data) < sni_offset + 3:
                    return None
                name_type = sni_data[sni_offset]
                if name_type != 0:  # host_name
                    return None
                sni_offset += 1
                name_len = int.from_bytes(sni_data[sni_offset : sni_offset + 2], "big")
                sni_offset += 2
                if len(sni_data) < sni_offset + name_len:
                    return None
                host_bytes = sni_data[sni_offset : sni_offset + name_len]
                try:
                    hostname = host_bytes.decode("utf-8", errors="ignore")
                    return hostname
                except Exception:
                    return None

            offset += ext_len

        return None
    except Exception:
        return None


def _handle_tls_packet(pkt, dns_mapper: DnsMapper) -> None:
    """Look at TLS ClientHello on TCP/443 and extract SNI if present."""
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]

    # We only care about port 443 traffic, typically the client -> server direction
    if tcp_layer.dport != 443:
        return

    if not pkt.haslayer(Raw):
        return

    payload: bytes = bytes(pkt[Raw].load)
    hostname = _extract_sni_from_tls_client_hello(payload)
    if not hostname:
        return

    dst_ip = ip_layer.dst
    dns_mapper.update_from_sni(dst_ip, hostname)


def start_dns_sniffer(
    dns_mapper: DnsMapper,
    iface: Optional[str] = None,
    stop_event: Optional[threading.Event] = None,
) -> threading.Thread:
    """Start a background thread sniffing DNS traffic and TLS SNI.

    If Npcap/WinPcap is not available or sniffing fails, the thread will
    print a warning once and exit cleanly. The rest of NetScope will
    continue to work, just without live mapping.
    """

    def _sniff_loop() -> None:
        def _prn(pkt):
            # DNS mapping
            _handle_dns_packet(pkt, dns_mapper)
            # TLS SNI mapping
            _handle_tls_packet(pkt, dns_mapper)

        def _stop_filter(_pkt) -> bool:
            return stop_event.is_set() if stop_event is not None else False

        try:
            # Capture DNS (port 53) and HTTPS (tcp port 443)
            sniff(
                filter="udp port 53 or tcp port 53 or tcp port 443",
                prn=_prn,
                store=False,
                iface=iface,
                stop_filter=_stop_filter,
            )
        except RuntimeError as e:
            print(f"[NetScope] Packet sniffing is not available: {e}")
            print("[NetScope] Continuing without live mapping.")
        except Exception as e:
            print(f"[NetScope] Packet sniffing failed: {e}")
            print("[NetScope] Continuing without live mapping.")

    t = threading.Thread(target=_sniff_loop, name="NetScopeSniffer", daemon=True)
    t.start()
    return t
