from pathlib import Path

from scapy.all import IP, UDP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/udp.pcap")

    payload = b"Hello IDS UDP payload"

    packet = (
        IP(
            src="10.0.0.10",
            dst="10.0.0.20",
        )
        / UDP(
            sport=40000,
            dport=9999,
        )
        / payload
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), [packet])

    print(f"Created {output}")
    print("Packets: 1")


if __name__ == "__main__":
    main()
