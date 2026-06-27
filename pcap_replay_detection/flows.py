from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable

from .records import FlowRecord, PacketRecord


def build_flows(
    packets: Iterable[PacketRecord],
    max_packets_per_flow: int | None = None,
) -> list[FlowRecord]:
    grouped: OrderedDict[str, list[PacketRecord]] = OrderedDict()

    for packet in packets:
        if packet.status != "ok":
            continue

        bucket = grouped.setdefault(packet.flow_id, [])
        if max_packets_per_flow is None or len(bucket) < max_packets_per_flow:
            bucket.append(packet)

    return [
        FlowRecord(flow_id=flow_id, packets=tuple(flow_packets))
        for flow_id, flow_packets in grouped.items()
        if flow_packets
    ]
