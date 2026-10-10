from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t06_missing_fields.pcap")

    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2", proto=1)
            / b"\x08\x00\xf7\xff\x00\x01\x00\x01test"
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="A")
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

