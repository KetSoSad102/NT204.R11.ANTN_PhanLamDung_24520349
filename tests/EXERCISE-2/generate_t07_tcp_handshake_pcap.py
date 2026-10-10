from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t07_tcp_handshake.pcap")

    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=80, flags="S", seq=1000)
        ),
        (
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=50000, flags="SA", seq=2000, ack=1001)
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=80, flags="A", seq=1001, ack=2001)
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

