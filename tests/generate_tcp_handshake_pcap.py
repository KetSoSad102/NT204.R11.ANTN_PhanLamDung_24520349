from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/pcap/tcp_handshake.pcap")

    client_ip = "10.0.0.10"
    server_ip = "10.0.0.20"

    packets = [
        (
            IP(src=client_ip, dst=server_ip)
            / TCP(
                sport=50000,
                dport=80,
                seq=1000,
                flags="S",
            )
        ),
        (
            IP(src=server_ip, dst=client_ip)
            / TCP(
                sport=80,
                dport=50000,
                seq=2000,
                ack=1001,
                flags="SA",
            )
        ),
        (
            IP(src=client_ip, dst=server_ip)
            / TCP(
                sport=50000,
                dport=80,
                seq=1001,
                ack=2001,
                flags="A",
            )
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()
