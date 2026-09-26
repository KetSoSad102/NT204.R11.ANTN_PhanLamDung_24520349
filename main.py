from __future__ import annotations

import argparse
import json
from pathlib import Path

from scapy.layers.inet import IP

from ids_parser.capture import CapturedPacket, iter_packets
from ids_parser.http_parser import parse_http
from ids_parser.models import NormalizedEvent
from ids_parser.normalizer import normalize_event
from ids_parser.parser import parse_ipv4, parse_tcp, parse_udp
from ids_parser.protocols import detect_application_protocol
from ids_parser.dns_parser import parse_dns
from ids_parser.smtp_parser import parse_smtp


def build_event(packet_id: int, captured: CapturedPacket) -> NormalizedEvent:
    """
    Run one captured packet through the parsing pipeline.
    """

    # -----------------------------
    # Network layer
    # -----------------------------
    try:
        network = parse_ipv4(captured)
    except ValueError as exc:
        return NormalizedEvent(
            packet_id=packet_id,
            timestamp=captured.timestamp,
            parser_status=f"error: {exc}",
        )

    packet = captured.packet

    # -----------------------------
    # Transport layer
    # -----------------------------
    transport = None
    transport_protocol = None

    if packet[IP].proto == 6:
        try:
            transport = parse_tcp(captured)
            transport_protocol = "TCP"
        except ValueError as exc:
            return normalize_event(
                packet_id,
                network,
                transport_protocol="TCP",
                parser_status=f"error: {exc}",
            )

    elif packet[IP].proto == 17:
        try:
            transport = parse_udp(captured)
            transport_protocol = "UDP"
        except ValueError as exc:
            return normalize_event(
                packet_id,
                network,
                transport_protocol="UDP",
                parser_status=f"error: {exc}",
            )

    else:
        return normalize_event(
            packet_id,
            network,
            transport_protocol=None,
            application_protocol="UNKNOWN",
            parser_status="unsupported transport protocol",
        )

    # -----------------------------
    # Application protocol detection
    # -----------------------------
    payload = transport.get("payload", b"")

    application_protocol = detect_application_protocol(
        packet,
        transport_protocol=transport_protocol,
        src_port=transport.get("src_port"),
        dst_port=transport.get("dst_port"),
        payload=payload,
    )

    application_data: dict = {}
    parser_status = "ok"

    # -----------------------------
    # Application parser
    # -----------------------------
    if application_protocol == "HTTP":
        try:
            application_data = parse_http(payload)
        except ValueError as exc:
            parser_status = f"application parse error: {exc}"
    elif application_protocol == "DNS":
        try:
            application_data = parse_dns(payload)
        except ValueError as exc:
            parser_status = f"application parse error: {exc}"
    elif application_protocol == "SMTP":
        try:
            application_data = parse_smtp(payload)
        except ValueError as exc:
            parser_status = f"application parse error: {exc}"

    return normalize_event(
        packet_id,
        network,
        transport,
        transport_protocol=transport_protocol,
        application_protocol=application_protocol,
        application_data=application_data,
        parser_status=parser_status,
    )


def run_pipeline(
    *,
    pcap: str | None,
    interface: str | None,
    output: str,
    count: int | None,
) -> None:
    """
    Capture packets, parse them and write normalized IDS
    events as JSON Lines.
    """

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packet_count = 0

    with output_path.open("w", encoding="utf-8") as output_file:
        for captured in iter_packets(
            pcap=pcap,
            interface=interface,
            count=count,
        ):
            packet_count += 1

            event = build_event(
                packet_id=packet_count,
                captured=captured,
            )

            output_file.write(
                json.dumps(
                    event.to_dict(),
                    ensure_ascii=False,
                )
                + "\n"
            )

            output_file.flush()

            if count is not None and packet_count >= count:
                break

    print(f"Processed {packet_count} packet(s)")
    print(f"Output: {output_path}")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Packet Capture & Parser for IDS"
    )

    source = parser.add_mutually_exclusive_group(required=True)

    source.add_argument(
        "--pcap",
        help="Read packets from a PCAP file",
    )

    source.add_argument(
        "--interface",
        help="Capture packets from a network interface",
    )

    parser.add_argument(
        "--output",
        default="output/events.jsonl",
        help="Output JSON Lines file",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Maximum number of packets to process",
    )

    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    run_pipeline(
        pcap=args.pcap,
        interface=args.interface,
        output=args.output,
        count=args.count,
    )


if __name__ == "__main__":
    main()