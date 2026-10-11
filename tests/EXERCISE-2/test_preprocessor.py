from __future__ import annotations

from ids_parser.models import NormalizedEvent
from ids_parser.preprocessor import (
    normalize_domain,
    normalize_headers,
    normalize_uri_path,
    preprocess_event,
)


def test_t05_normalize_domain():
    assert normalize_domain("EXAMPLE.COM.") == "example.com"
    assert normalize_domain("Sub.Domain.Net.") == "sub.domain.net"


def test_t05_normalize_uri_path():
    assert normalize_uri_path("//api///v1//login") == "/api/v1/login"
    assert normalize_uri_path("index.html") == "/index.html"


def test_t05_normalize_headers():
    raw_headers = {
        "Host": "Example.com",
        "Content-Type": "text/html",
        "USER-AGENT": "Mozilla/5.0",
    }
    normalized = normalize_headers(raw_headers)
    assert "host" in normalized
    assert "content-type" in normalized
    assert "user-agent" in normalized
    assert normalized["host"] == "Example.com"


def test_t05_normalize_http_event():
    event = NormalizedEvent(
        packet_id=1,
        timestamp=1700000000.123,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        network_protocol="ipv4",
        transport_protocol="tcp",
        src_port=50000,
        dst_port=80,
        application_protocol="http",
        application_data={
            "headers": {"Host": "EXAMPLE.COM", "ACCEPT": "*/*"},
            "target": "//search///items",
            "decoded_uri": "//search///items",
        },
    )

    processed = preprocess_event(event)

    assert processed.network_protocol == "IPv4"
    assert processed.transport_protocol == "TCP"
    assert processed.application_protocol == "HTTP"
    assert processed.application_data["headers"] == {"host": "EXAMPLE.COM", "accept": "*/*"}
    assert processed.application_data["target"] == "/search/items"
    assert processed.application_data["decoded_uri"] == "/search/items"


def test_t05_normalize_dns_event():
    event = NormalizedEvent(
        packet_id=2,
        timestamp=1700000001.0,
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        network_protocol="IPv4",
        transport_protocol="udp",
        src_port=53000,
        dst_port=53,
        application_protocol="dns",
        application_data={
            "domain": "WWW.GOOGLE.COM.",
            "answers": [{"name": "WWW.GOOGLE.COM.", "type": "A"}],
        },
    )

    processed = preprocess_event(event)

    assert processed.transport_protocol == "UDP"
    assert processed.application_protocol == "DNS"
    assert processed.application_data["domain"] == "www.google.com"
    assert processed.application_data["answers"][0]["name"] == "www.google.com"


def test_t06_missing_optional_fields_event():
    event = NormalizedEvent(
        packet_id=3,
        timestamp=1700000002.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        transport_protocol=None,
        src_port=None,
        dst_port=None,
        tcp_flags=None,
        payload_b64=None,
        application_data=None,
    )

    processed = preprocess_event(event)

    assert processed.application_data == {}
    assert processed.src_port is None
    assert processed.dst_port is None
    assert processed.tcp_flags is None
    assert processed.application_protocol == "UNKNOWN"


def test_t06_missing_http_and_dns_fields():
    http_event = NormalizedEvent(
        packet_id=4,
        timestamp=1700000003.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        transport_protocol="TCP",
        application_protocol="HTTP",
        application_data={},
    )
    processed_http = preprocess_event(http_event)
    assert processed_http.application_data["headers"] == {}
    assert processed_http.application_data["body"] == ""

    dns_event = NormalizedEvent(
        packet_id=5,
        timestamp=1700000004.0,
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        transport_protocol="UDP",
        application_protocol="DNS",
        application_data={},
    )
    processed_dns = preprocess_event(dns_event)
    assert processed_dns.application_data["answers"] == []
    assert processed_dns.application_data["domain"] is None


def test_t14_malformed_event_invalid_port():
    event = NormalizedEvent(
        packet_id=6,
        timestamp=1700000005.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        transport_protocol="TCP",
        src_port=70000,
        dst_port=80,
    )
    processed = preprocess_event(event)
    assert processed.preprocess_status == "invalid"
    assert processed.processing_action == "drop"
    assert "invalid src_port" in str(processed.reason)


def test_t14_malformed_event_invalid_timestamp():
    event = NormalizedEvent(
        packet_id=7,
        timestamp=-50.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        transport_protocol="TCP",
        src_port=12345,
        dst_port=80,
    )
    processed = preprocess_event(event)
    assert processed.preprocess_status == "invalid"
    assert processed.processing_action == "drop"
    assert "timestamp" in str(processed.reason)


def test_t14_malformed_event_parser_error():
    event = NormalizedEvent(
        packet_id=8,
        timestamp=1700000007.0,
        parser_status="error: corrupted IP header length",
    )
    processed = preprocess_event(event)
    assert processed.preprocess_status == "invalid"
    assert processed.processing_action == "drop"
    assert "error:" in str(processed.reason)


def test_t14_malformed_event_flow_tracker_safe():
    from ids_parser.flow_tracker import FlowTracker

    tracker = FlowTracker()
    event = NormalizedEvent(
        packet_id=9,
        timestamp=1700000008.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        transport_protocol="TCP",
        src_port=99999,
        dst_port=80,
    )
    processed = preprocess_event(event)
    flow = tracker.track_packet(processed)
    assert flow is None
    assert len(tracker.flows) == 0


