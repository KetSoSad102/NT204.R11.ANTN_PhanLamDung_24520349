from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Iterator, Optional

from scapy.all import AsyncSniffer, PcapReader
from scapy.packet import Packet


@dataclass
class CapturedPacket:
    packet: Packet
    timestamp: float


def iter_pcap(pcap_path: str | Path) -> Iterator[CapturedPacket]:
    """
    Read packets from a PCAP file and yield them one by one.
    """
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            timestamp = float(packet.time)
            yield CapturedPacket(
                packet=packet,
                timestamp=timestamp,
            )


def iter_live(
    interface: str,
    count: Optional[int] = None,
    bpf_filter: str | None = None,
) -> Iterator[CapturedPacket]:
    """
    Capture packets from a live network interface.

    Packets are pushed into a queue by Scapy and then yielded
    immediately to the next stage of the pipeline.
    """
    packet_queue: Queue[Packet] = Queue()

    def on_packet(packet: Packet) -> None:
        packet_queue.put(packet)

    sniffer = AsyncSniffer(
        iface=interface,
        prn=on_packet,
        store=False,
        filter=bpf_filter,
    )

    sniffer.start()
    captured = 0

    try:
        while count is None or captured < count:
            try:
                packet = packet_queue.get(timeout=1.0)
            except Empty:
                continue

            timestamp = float(packet.time)

            yield CapturedPacket(
                packet=packet,
                timestamp=timestamp,
            )

            captured += 1
    finally:
        if sniffer.running:
            sniffer.stop()


def iter_packets(
    *,
    pcap: str | Path | None = None,
    interface: str | None = None,
    count: int | None = None,
    bpf_filter: str | None = None,
) -> Iterator[CapturedPacket]:
    """
    Common packet source interface.

    Exactly one source must be selected:
    - pcap
    - interface

    Both sources produce the same CapturedPacket structure,
    so later parser stages do not need to care where the
    packet came from.
    """
    if (pcap is None) == (interface is None):
        raise ValueError(
            "Specify exactly one packet source: pcap or interface"
        )

    if pcap is not None:
        yield from iter_pcap(pcap)
        return

    yield from iter_live(
        interface,
        count=count,
        bpf_filter=bpf_filter,
    )
