from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t04_invalid_bytes.pcap")

    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="PA")
            / b"GET /data?raw=\x80\xff\xfe HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12346, dport=9999, flags="PA")
            / b"\xff\xfe\xfa\x80\x90\xaa\xbb\xcc"
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

