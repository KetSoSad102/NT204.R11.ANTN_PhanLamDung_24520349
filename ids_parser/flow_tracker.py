from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from typing import Any

from ids_parser.models import NormalizedEvent


@dataclass
class Flow:
    flow_id: str
    protocol: str
    application_protocol: str = "UNKNOWN"
    endpoint_a: str = ""
    endpoint_b: str = ""
    start_time: float = 0.0
    last_seen: float = 0.0
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    forward_byte_count: int = 0
    backward_packet_count: int = 0
    backward_byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: str = "NEW/HANDSHAKE"
    initiator: str = ""
    handshake_syn: bool = False
    handshake_syn_ack: bool = False

    @property
    def SYN_count(self) -> int:
        return self.syn_count

    @property
    def ACK_count(self) -> int:
        return self.ack_count

    @property
    def FIN_count(self) -> int:
        return self.fin_count

    @property
    def RST_count(self) -> int:
        return self.rst_count

    def get_statistics(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "endpoint_a": self.endpoint_a,
            "endpoint_b": self.endpoint_b,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward_packet_count": self.forward_packet_count,
            "forward_byte_count": self.forward_byte_count,
            "backward_packet_count": self.backward_packet_count,
            "backward_byte_count": self.backward_byte_count,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "SYN_count": self.syn_count,
            "ACK_count": self.ack_count,
            "FIN_count": self.fin_count,
            "RST_count": self.rst_count,
            "state": self.state,
        }

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["SYN_count"] = self.syn_count
        d["ACK_count"] = self.ack_count
        d["FIN_count"] = self.fin_count
        d["RST_count"] = self.rst_count
        return d


def generate_flow_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
    proto = (protocol or "UNKNOWN").upper()
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    if ep1 <= ep2:
        return f"{proto}_{src_ip}:{src_port}_{dst_ip}:{dst_port}"
    return f"{proto}_{dst_ip}:{dst_port}_{src_ip}:{src_port}"


class FlowTracker:
    def __init__(self, tcp_timeout: float = 300.0, udp_timeout: float = 60.0):
        self.flows: dict[str, Flow] = {}
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout

    def get_flow(self, flow_id: str) -> Flow | None:
        return self.flows.get(flow_id)

    def get_statistics(self, flow_id: str) -> dict[str, Any] | None:
        flow = self.get_flow(flow_id)
        if flow:
            return flow.get_statistics()
        return None

    def check_timeouts(self, current_time: float) -> list[Flow]:
        expired = []
        for flow_id, flow in list(self.flows.items()):
            timeout = self.tcp_timeout if flow.protocol == "TCP" else self.udp_timeout
            if current_time - flow.last_seen > timeout:
                expired.append(flow)
                del self.flows[flow_id]
        return expired

    def track_packet(self, event: NormalizedEvent, payload_len: int | None = None) -> Flow | None:
        try:
            curr_time = float(event.timestamp)
        except (ValueError, TypeError):
            curr_time = 0.0

        self.check_timeouts(curr_time)

        if event.preprocess_status == "invalid":
            return None

        proto = (event.transport_protocol or "UNKNOWN").upper()
        if proto not in ("TCP", "UDP"):
            return None

        src_ip = event.src_ip or "0.0.0.0"
        dst_ip = event.dst_ip or "0.0.0.0"
        src_port = event.src_port or 0
        dst_port = event.dst_port or 0

        if payload_len is None:
            if event.payload_b64:
                try:
                    payload_len = len(base64.b64decode(event.payload_b64))
                except Exception:
                    payload_len = 0
            else:
                payload_len = 0

        flow_id = generate_flow_id(src_ip, dst_ip, src_port, dst_port, proto)
        src_ep = f"{src_ip}:{src_port}"
        dst_ep = f"{dst_ip}:{dst_port}"

        if flow_id not in self.flows:
            flow = Flow(
                flow_id=flow_id,
                protocol=proto,
                application_protocol=event.application_protocol or "UNKNOWN",
                endpoint_a=src_ep,
                endpoint_b=dst_ep,
                start_time=curr_time,
                last_seen=curr_time,
                initiator=src_ep,
                state="NEW/HANDSHAKE" if proto == "TCP" else "ESTABLISHED",
            )
            self.flows[flow_id] = flow
        else:
            flow = self.flows[flow_id]

        flow.last_seen = curr_time
        flow.duration = max(0.0, round(flow.last_seen - flow.start_time, 6))
        flow.packet_count += 1
        flow.byte_count += payload_len

        if event.application_protocol and event.application_protocol != "UNKNOWN":
            flow.application_protocol = event.application_protocol

        is_forward = (src_ep == flow.initiator)
        if is_forward:
            flow.forward_packet_count += 1
            flow.forward_byte_count += payload_len
            direction = "forward"
        else:
            flow.backward_packet_count += 1
            flow.backward_byte_count += payload_len
            direction = "backward"

        if proto == "TCP":
            flags = (event.tcp_flags or "").upper()
            if "S" in flags:
                flow.syn_count += 1
            if "A" in flags:
                flow.ack_count += 1
            if "F" in flags:
                flow.fin_count += 1
            if "R" in flags:
                flow.rst_count += 1

            if "R" in flags:
                flow.state = "CLOSED/RESET"
            elif "F" in flags:
                if flow.state == "CLOSING" or flow.fin_count >= 2:
                    flow.state = "CLOSED/RESET"
                else:
                    flow.state = "CLOSING"
            elif "S" in flags and "A" not in flags:
                flow.handshake_syn = True
                flow.state = "NEW/HANDSHAKE"
            elif "S" in flags and "A" in flags:
                flow.handshake_syn_ack = True
                flow.state = "NEW/HANDSHAKE"
            elif "A" in flags:
                if flow.state == "CLOSING":
                    flow.state = "CLOSED/RESET"
                elif flow.handshake_syn and flow.handshake_syn_ack and flow.state == "NEW/HANDSHAKE":
                    flow.state = "ESTABLISHED"

        event.flow_id = flow.flow_id
        event.flow_state = flow.state
        event.flow_direction = direction

        return flow

