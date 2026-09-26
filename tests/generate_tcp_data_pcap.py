from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/tcp_data.pcap")

    payload = b"Hello IDS TCP payload"

    packet = (
        IP(
            src="10.0.0.10",
            dst="10.0.0.20",
        )
        / TCP(
            sport=50001,
            dport=8080,
            seq=1000,
            ack=2000,
            flags="PA",
            window=4096,
        )
        / payload
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), [packet])

    print(f"Created {output}")
    print("Packets: 1")


if __name__ == "__main__":
    main()
