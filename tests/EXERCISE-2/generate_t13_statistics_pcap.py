from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap


def main() -> None:
    output = Path("TEST/EXERCISE-2/pcap/t13_statistics.pcap")

    client_ip = "192.168.1.50"
    server_ip = "192.168.1.10"
    client_port = 49152
    server_port = 80

    p1 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=1000)
    p1.time = 1700000000.0

    p2 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001)
    p2.time = 1700000000.01

    p3 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001)
    p3.time = 1700000000.02

    http_req = b"GET /stats HTTP/1.1\r\nHost: example.com\r\n\r\n"
    p4 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=1001, ack=2001) / Raw(load=http_req)
    p4.time = 1700000000.05

    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nStats Payload"
    p5 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=2001, ack=1001 + len(http_req)) / Raw(load=http_resp)
    p5.time = 1700000000.10

    p6 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="FA", seq=1001 + len(http_req), ack=2001 + len(http_resp))
    p6.time = 1700000000.20

    p7 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="FA", seq=2001 + len(http_resp), ack=1002 + len(http_req))
    p7.time = 1700000000.25

    p8 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1002 + len(http_req), ack=2002 + len(http_resp))
    p8.time = 1700000000.26

    packets = [p1, p2, p3, p4, p5, p6, p7, p8]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"Created {output}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()

