#!/usr/bin/env python3
"""
SniffDogg — educational network packet sniffer.

Capture and log network traffic to a plain-text file for authorized lab use only.
Only run on networks you own or have explicit written permission to monitor.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import socket
import struct
import sys
from pathlib import Path
from typing import NamedTuple, Optional


ETH_P_ALL = 0x0003
ETH_HEADER_LEN = 14
IP_HEADER_MIN_LEN = 20
TCP_HEADER_MIN_LEN = 20
UDP_HEADER_LEN = 8

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


class ParsedPacket(NamedTuple):
    number: int
    timestamp: dt.datetime
    interface: str
    length: int
    summary: str
    details: list[str]
    payload_hex: str


def print_banner() -> None:
    print("SniffDogg — educational packet capture for authorized testing")


def list_interfaces() -> list[str]:
    net_path = Path("/sys/class/net")
    if not net_path.is_dir():
        return []
    return sorted(
        entry.name
        for entry in net_path.iterdir()
        if entry.is_dir() and entry.name != "lo"
    )


def mac_address(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def parse_ethernet(packet: bytes) -> tuple[dict[str, str], int, bytes]:
    if len(packet) < ETH_HEADER_LEN:
        raise ValueError("packet shorter than Ethernet header")

    destination, source, ethertype = struct.unpack("!6s6sH", packet[:ETH_HEADER_LEN])
    ethertype_name = {
        ETHERTYPE_IPV4: "IPv4",
        ETHERTYPE_IPV6: "IPv6",
        ETHERTYPE_ARP: "ARP",
    }.get(ethertype, f"0x{ethertype:04x}")

    info = {
        "dst_mac": mac_address(destination),
        "src_mac": mac_address(source),
        "ethertype": ethertype_name,
        "ethertype_raw": str(ethertype),
    }
    return info, ethertype, packet[ETH_HEADER_LEN:]


def parse_ipv4(packet: bytes) -> tuple[dict[str, str], int, int, bytes]:
    if len(packet) < IP_HEADER_MIN_LEN:
        raise ValueError("packet shorter than IPv4 header")

    version_ihl, dscp_ecn, total_length, identification, flags_fragment, ttl, protocol, checksum = struct.unpack(
        "!BBHHHBBH", packet[:12]
    )
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(packet) < ihl:
        raise ValueError("invalid IPv4 header")

    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    flags = flags_fragment >> 13
    fragment_offset = flags_fragment & 0x1FFF
    flag_names = []
    if flags & 0x4:
        flag_names.append("DF")
    if flags & 0x2:
        flag_names.append("MF")
    if flags & 0x1:
        flag_names.append("RB")

    info = {
        "version": str(version),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol_name(protocol),
        "protocol_raw": str(protocol),
        "ttl": str(ttl),
        "length": str(total_length),
        "id": str(identification),
        "flags": ",".join(flag_names) if flag_names else "none",
        "fragment_offset": str(fragment_offset),
    }
    return info, protocol, ihl, packet[ihl:]


def protocol_name(number: int) -> str:
    return {
        IP_PROTO_ICMP: "ICMP",
        IP_PROTO_TCP: "TCP",
        IP_PROTO_UDP: "UDP",
    }.get(number, f"PROTO-{number}")


def parse_tcp(packet: bytes) -> tuple[dict[str, str], bytes]:
    if len(packet) < TCP_HEADER_MIN_LEN:
        raise ValueError("packet shorter than TCP header")

    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urgent = struct.unpack(
        "!HHLLHHHH", packet[:20]
    )
    data_offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF
    flag_names = []
    for bit, name in (
        (0x020, "URG"),
        (0x010, "ACK"),
        (0x008, "PSH"),
        (0x004, "RST"),
        (0x002, "SYN"),
        (0x001, "FIN"),
    ):
        if flags & bit:
            flag_names.append(name)

    info = {
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "seq": str(seq),
        "ack": str(ack),
        "flags": ",".join(flag_names) if flag_names else "none",
        "window": str(window),
        "header_len": str(data_offset),
    }
    return info, packet[data_offset:]


def parse_udp(packet: bytes) -> tuple[dict[str, str], bytes]:
    if len(packet) < UDP_HEADER_LEN:
        raise ValueError("packet shorter than UDP header")

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", packet[:UDP_HEADER_LEN])
    info = {
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "length": str(length),
        "checksum": f"0x{checksum:04x}",
    }
    return info, packet[UDP_HEADER_LEN:]


def parse_icmp(packet: bytes) -> tuple[dict[str, str], bytes]:
    if len(packet) < 4:
        raise ValueError("packet shorter than ICMP header")

    icmp_type, code, checksum = struct.unpack("!BBH", packet[:4])
    type_name = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        8: "Echo Request",
        11: "Time Exceeded",
    }.get(icmp_type, "Other")

    info = {
        "type": str(icmp_type),
        "type_name": type_name,
        "code": str(code),
        "checksum": f"0x{checksum:04x}",
    }
    return info, packet[4:]


def payload_preview(payload: bytes, limit: int = 64) -> str:
    if not payload:
        return "(empty)"
    shown = payload[:limit]
    hex_text = " ".join(f"{byte:02x}" for byte in shown)
    if len(payload) > limit:
        hex_text += f" ... (+{len(payload) - limit} bytes)"
    return hex_text


def parse_packet(packet: bytes, number: int, interface: str, protocol_filter: Optional[str]) -> Optional[ParsedPacket]:
    timestamp = dt.datetime.now()
    details: list[str] = []
    summary = f"{interface} len={len(packet)}"

    try:
        eth, ethertype, payload = parse_ethernet(packet)
        details.append(
            f"Ethernet: {eth['src_mac']} -> {eth['dst_mac']} type={eth['ethertype']}"
        )
        summary = f"{eth['src_mac']} -> {eth['dst_mac']} {eth['ethertype']}"

        if ethertype != ETHERTYPE_IPV4:
            if protocol_filter:
                return None
            return ParsedPacket(
                number=number,
                timestamp=timestamp,
                interface=interface,
                length=len(packet),
                summary=summary,
                details=details,
                payload_hex=payload_preview(payload),
            )

        ip_info, protocol, ip_header_len, transport_payload = parse_ipv4(payload)
        details.append(
            f"IPv4: {ip_info['src_ip']} -> {ip_info['dst_ip']} "
            f"proto={ip_info['protocol']} ttl={ip_info['ttl']} len={ip_info['length']}"
        )
        summary = (
            f"{ip_info['src_ip']}:{'?'} -> {ip_info['dst_ip']}:{'?'} "
            f"{ip_info['protocol']}"
        )

        if protocol_filter and ip_info["protocol"].lower() != protocol_filter.lower():
            return None

        app_payload = transport_payload
        if protocol == IP_PROTO_TCP:
            tcp_info, app_payload = parse_tcp(transport_payload)
            details.append(
                f"TCP: {tcp_info['src_port']} -> {tcp_info['dst_port']} "
                f"flags=[{tcp_info['flags']}] seq={tcp_info['seq']} ack={tcp_info['ack']}"
            )
            summary = (
                f"{ip_info['src_ip']}:{tcp_info['src_port']} -> "
                f"{ip_info['dst_ip']}:{tcp_info['dst_port']} TCP [{tcp_info['flags']}]"
            )
        elif protocol == IP_PROTO_UDP:
            udp_info, app_payload = parse_udp(transport_payload)
            details.append(
                f"UDP: {udp_info['src_port']} -> {udp_info['dst_port']} len={udp_info['length']}"
            )
            summary = (
                f"{ip_info['src_ip']}:{udp_info['src_port']} -> "
                f"{ip_info['dst_ip']}:{udp_info['dst_port']} UDP"
            )
        elif protocol == IP_PROTO_ICMP:
            icmp_info, app_payload = parse_icmp(transport_payload)
            details.append(
                f"ICMP: type={icmp_info['type']} ({icmp_info['type_name']}) code={icmp_info['code']}"
            )
            summary = f"{ip_info['src_ip']} -> {ip_info['dst_ip']} ICMP {icmp_info['type_name']}"
        else:
            details.append(f"Transport: unsupported protocol {protocol}")

        return ParsedPacket(
            number=number,
            timestamp=timestamp,
            interface=interface,
            length=len(packet),
            summary=summary,
            details=details,
            payload_hex=payload_preview(app_payload),
        )
    except ValueError as exc:
        if protocol_filter:
            return None
        details.append(f"Parse error: {exc}")
        return ParsedPacket(
            number=number,
            timestamp=timestamp,
            interface=interface,
            length=len(packet),
            summary=f"{interface} unparsed frame",
            details=details,
            payload_hex=payload_preview(packet),
        )


def format_packet_record(parsed: ParsedPacket) -> str:
    lines = [
        f"[{parsed.timestamp.isoformat(sep=' ', timespec='microseconds')}] Packet #{parsed.number}",
        f"  Interface : {parsed.interface}",
        f"  Length    : {parsed.length} bytes",
        f"  Summary   : {parsed.summary}",
    ]
    for detail in parsed.details:
        lines.append(f"  {detail}")
    lines.append(f"  Payload   : {parsed.payload_hex}")
    lines.append("-" * 72)
    return "\n".join(lines)


def write_session_header(handle, interface: str, count: Optional[int], protocol_filter: Optional[str]) -> None:
    handle.write("=" * 72 + "\n")
    handle.write("SniffDogg capture log\n")
    handle.write(f"Started : {dt.datetime.now().isoformat(sep=' ', timespec='seconds')}\n")
    handle.write(f"Interface: {interface}\n")
    handle.write(f"Limit   : {count if count else 'unlimited'}\n")
    handle.write(f"Filter  : {protocol_filter or 'all protocols'}\n")
    handle.write("=" * 72 + "\n\n")


def open_capture_socket(interface: str) -> socket.socket:
    if os.geteuid() != 0:
        raise PermissionError(
            "Packet capture requires root privileges. Run with: sudo python3 SniffDogg.py ..."
        )

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    sock.bind((interface, 0))
    return sock


def sniff(
    interface: str,
    output_path: Path,
    count: Optional[int],
    timeout: Optional[float],
    protocol_filter: Optional[str],
    verbose: bool,
) -> int:
    captured = 0
    written = 0
    sock = open_capture_socket(interface)

    if timeout:
        sock.settimeout(timeout)

    print(f"[*] Listening on {interface}")
    print(f"[*] Writing capture log to {output_path}")
    if protocol_filter:
        print(f"[*] Protocol filter: {protocol_filter.upper()}")

    with output_path.open("w", encoding="utf-8") as handle:
        write_session_header(handle, interface, count, protocol_filter)

        try:
            while count is None or captured < count:
                try:
                    packet, _addr = sock.recvfrom(65535)
                except socket.timeout:
                    print("[*] Capture timeout reached")
                    break

                captured += 1
                parsed = parse_packet(packet, captured, interface, protocol_filter)
                if parsed is None:
                    continue

                written += 1
                record = format_packet_record(parsed)
                handle.write(record + "\n")
                handle.flush()

                if verbose:
                    print(parsed.summary)

                if count is not None and captured >= count:
                    break
        except KeyboardInterrupt:
            print("\n[*] Capture stopped by user")

    sock.close()
    print(f"[+] Examined {captured} packet(s), logged {written} to {output_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffdogg",
        description="SniffDogg: educational packet sniffer for authorized network testing.",
        epilog="Only capture traffic on networks you are permitted to monitor.",
    )
    parser.add_argument(
        "--interface",
        "-i",
        help="Network interface to capture on (default: first non-loopback interface)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output .txt log file (default: capture_YYYYMMDD_HHMMSS.txt)",
    )
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        help="Stop after capturing this many packets (default: unlimited)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        help="Stop after this many seconds",
    )
    parser.add_argument(
        "--protocol",
        "-p",
        choices=["tcp", "udp", "icmp"],
        help="Only log packets for this IP protocol",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available interfaces and exit",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print one-line packet summaries to the terminal",
    )
    return parser


def default_output_path() -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"capture_{stamp}.txt")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_interfaces:
        print_banner()
        interfaces = list_interfaces()
        if not interfaces:
            print("No interfaces found.")
            return 1
        print("Available interfaces:")
        for name in interfaces:
            print(f"  - {name}")
        return 0

    print_banner()

    interface = args.interface
    if not interface:
        interfaces = list_interfaces()
        if not interfaces:
            print("Error: no capture interface found. Use --interface.", file=sys.stderr)
            return 1
        interface = interfaces[0]
        print(f"[*] No interface specified, using {interface}")

    output_path = args.output or default_output_path()

    try:
        return sniff(
            interface=interface,
            output_path=output_path,
            count=args.count,
            timeout=args.timeout,
            protocol_filter=args.protocol,
            verbose=args.verbose,
        )
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: could not open interface '{interface}': {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())