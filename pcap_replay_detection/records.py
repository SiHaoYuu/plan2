from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PacketRecord:
    packet_id: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    payload: bytes
    length: int
    status: str
    status_reason: str

    @property
    def flow_id(self) -> str:
        return make_flow_id(
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.protocol,
        )


@dataclass(frozen=True)
class Prediction:
    label: str
    confidence: float
    scores: dict[str, float]


@dataclass(frozen=True)
class FlowRecord:
    flow_id: str
    packets: tuple[PacketRecord, ...]

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def first_seen(self) -> float:
        return self.packets[0].timestamp

    @property
    def last_seen(self) -> float:
        return self.packets[-1].timestamp

    @property
    def src_ip(self) -> str:
        return self.packets[0].src_ip

    @property
    def dst_ip(self) -> str:
        return self.packets[0].dst_ip

    @property
    def src_port(self) -> int | None:
        return self.packets[0].src_port

    @property
    def dst_port(self) -> int | None:
        return self.packets[0].dst_port

    @property
    def protocol(self) -> str:
        return self.packets[0].protocol


def make_flow_id(
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    protocol: str,
) -> str:
    src_port_text = "" if src_port is None else str(src_port)
    dst_port_text = "" if dst_port is None else str(dst_port)
    return f"{src_ip}:{src_port_text}->{dst_ip}:{dst_port_text}/{protocol}"
