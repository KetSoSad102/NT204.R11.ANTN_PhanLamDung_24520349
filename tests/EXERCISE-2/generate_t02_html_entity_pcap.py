from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t02_html_entity.pcap")

    packets = [
        # Packet 1: HTTP POST với body chứa HTML entity &lt;script&gt;
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="PA")
            / (
                b"POST /comment HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: 46\r\n"
                b"\r\n"
                b"comment=&lt;script&gt;alert(1)&lt;/script&gt;"
            )
        ),
        # Packet 2: HTTP GET với URI chứa HTML entity
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12346, dport=80, flags="PA")
            / (
                b"GET /view?title=&lt;h1&gt;Hello&amp;World&lt;/h1&gt; HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: test-client\r\n"
                b"\r\n"
            )
        ),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

