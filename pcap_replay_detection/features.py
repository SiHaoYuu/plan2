from __future__ import annotations

from .records import FlowRecord, PacketRecord


def encode_packet(record: PacketRecord, max_bytes: int) -> list[int]:
    return _pad_or_truncate(record.payload, max_bytes)


def encode_flow(
    flow: FlowRecord,
    max_bytes: int,
    max_packets: int | None = None,
) -> list[int]:
    payload = bytearray()
    packets = flow.packets if max_packets is None else flow.packets[:max_packets]

    for packet in packets:
        remaining = max_bytes - len(payload)
        if remaining <= 0:
            break
        payload.extend(packet.payload[:remaining])

    return _pad_or_truncate(bytes(payload), max_bytes)


def _pad_or_truncate(payload: bytes, max_bytes: int) -> list[int]:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    encoded = list(payload[:max_bytes])
    if len(encoded) < max_bytes:
        encoded.extend([0] * (max_bytes - len(encoded)))
    return encoded
