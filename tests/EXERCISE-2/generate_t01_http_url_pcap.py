from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t01_http_url.pcap")

    packets = [
        # Packet 1: HTTP GET chứa percent-encoding trong URI
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="PA")
            / (
                b"GET /search?query=%27%20OR%201%3D1 HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: test-client\r\n"
                b"\r\n"
            )
        ),
        # Packet 2: HTTP POST chứa percent-encoding trong cả target lẫn body
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12346, dport=80, flags="PA")
            / (
                b"POST /login?ref=%2Fadmin HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: 35\r\n"
                b"\r\n"
                b"username=admin%27%20OR%201%3D1&pass=123"
            )
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

