from pathlib import Path

from scapy.all import ICMP, IP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/unknown_protocol.pcap")

    packet = (
        IP(
            src="10.0.0.10",
            dst="10.0.0.20",
        )
        / ICMP(
            type=8,
            code=0,
        )
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), [packet])

    print(f"Created {output}")
    print("Packets: 1")


if __name__ == "__main__":
    main()
