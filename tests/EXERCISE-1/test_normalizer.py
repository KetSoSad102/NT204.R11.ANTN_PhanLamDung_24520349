import json

from ids_parser.models import NormalizedEvent
from ids_parser.normalizer import normalize_event


def test_normalize_tcp_event() -> None:
    network = {
        "timestamp": 1234567890.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": 6,
        "ttl": 64,
    }

    transport = {
        "src_port": 12345,
        "dst_port": 80,
        "seq": 100,
        "ack": 200,
        "flags": "PA",
        "window": 4096,
        "payload": b"GET / HTTP/1.1\r\n\r\n",
    }

    event = normalize_event(
        packet_id=1,
        network=network,
        transport=transport,
        transport_protocol="TCP",
        application_protocol="HTTP",
        application_data={
            "method": "GET",
            "path": "/",
        },
    )

    assert isinstance(event, NormalizedEvent)

    assert event.packet_id == 1
    assert event.timestamp == 1234567890.0

    assert event.src_ip == "10.0.0.1"
    assert event.dst_ip == "10.0.0.2"

    assert event.network_protocol == "IPv4"

    assert event.transport_protocol == "TCP"
    assert event.src_port == 12345
    assert event.dst_port == 80
    assert event.tcp_flags == "PA"

    assert event.application_protocol == "HTTP"
    assert event.application_data["method"] == "GET"
    assert event.application_data["path"] == "/"

    assert event.payload_b64 == "R0VUIC8gSFRUUC8xLjENCg0K"
    assert event.parser_status == "ok"


def test_normalized_event_is_json_serializable() -> None:
    network = {
        "timestamp": 123.0,
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "protocol": 17,
        "ttl": 64,
    }

    event = normalize_event(
        packet_id=2,
        network=network,
        transport_protocol="UDP",
    )

    data = event.to_dict()

    serialized = json.dumps(data)

    assert isinstance(serialized, str)
    assert data["application_protocol"] == "UNKNOWN"
