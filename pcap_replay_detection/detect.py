from __future__ import annotations

import argparse
import time
from collections.abc import Iterable
from typing import Any

from .backends import create_backend
from .features import encode_flow, encode_packet
from .flows import build_flows
from .output import write_rows
from .parser import iter_packet_records
from .records import FlowRecord, PacketRecord


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    packets = replay_packets(args.pcap, args.limit, args.realtime)
    backend = create_backend(args.backend)

    if args.mode == "packet":
        rows = detect_packets(packets, backend, args.max_packet_bytes)
    else:
        flows = build_flows(packets, args.max_flow_packets)
        rows = detect_flows(flows, backend, args.max_flow_bytes, args.max_flow_packets)

    write_rows(rows, args.output, args.output_format)
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay a pcap file into packet-level or flow-level detection."
    )
    parser.add_argument("--pcap", required=True, help="Input .pcap or .pcapng path.")
    parser.add_argument("--mode", choices=("packet", "flow"), required=True)
    parser.add_argument("--backend", default="mock", choices=("mock", "torch", "onnx"))
    parser.add_argument(
        "--output",
        required=True,
        help="Output CSV/JSONL path, or '-' for stdout.",
    )
    parser.add_argument(
        "--output-format",
        default="auto",
        choices=("auto", "csv", "jsonl"),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum packets to process.",
    )
    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Sleep between packets according to original pcap timestamp gaps.",
    )
    parser.add_argument("--max-packet-bytes", type=int, default=256)
    parser.add_argument("--max-flow-bytes", type=int, default=2048)
    parser.add_argument("--max-flow-packets", type=int, default=32)
    return parser.parse_args(argv)


def replay_packets(
    pcap_path: str,
    limit: int | None = None,
    realtime: bool = False,
) -> list[PacketRecord]:
    packets: list[PacketRecord] = []
    previous_timestamp: float | None = None

    for packet in iter_packet_records(pcap_path, limit):
        if realtime and previous_timestamp is not None:
            delay = max(0.0, packet.timestamp - previous_timestamp)
            time.sleep(delay)
        packets.append(packet)
        previous_timestamp = packet.timestamp

    return packets


def detect_packets(
    packets: Iterable[PacketRecord],
    backend: Any,
    max_packet_bytes: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for packet in packets:
        row = _packet_base_row(packet)
        if packet.status == "ok":
            prediction = backend.predict(encode_packet(packet, max_packet_bytes))
            row.update(
                {
                    "label": prediction.label,
                    "confidence": prediction.confidence,
                    "scores": prediction.scores,
                }
            )
        else:
            row.update({"label": "", "confidence": "", "scores": {}})
        rows.append(row)

    return rows


def detect_flows(
    flows: Iterable[FlowRecord],
    backend: Any,
    max_flow_bytes: int,
    max_flow_packets: int | None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for flow in flows:
        prediction = backend.predict(encode_flow(flow, max_flow_bytes, max_flow_packets))
        rows.append(
            {
                "flow_id": flow.flow_id,
                "packet_count": flow.packet_count,
                "first_seen": flow.first_seen,
                "last_seen": flow.last_seen,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": _empty_if_none(flow.src_port),
                "dst_port": _empty_if_none(flow.dst_port),
                "protocol": flow.protocol,
                "status": "ok",
                "label": prediction.label,
                "confidence": prediction.confidence,
                "scores": prediction.scores,
            }
        )

    return rows


def _packet_base_row(packet: PacketRecord) -> dict[str, Any]:
    return {
        "packet_id": packet.packet_id,
        "timestamp": packet.timestamp,
        "flow_id": packet.flow_id,
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": _empty_if_none(packet.src_port),
        "dst_port": _empty_if_none(packet.dst_port),
        "protocol": packet.protocol,
        "length": packet.length,
        "payload_len": len(packet.payload),
        "status": packet.status,
        "status_reason": packet.status_reason,
    }


def _empty_if_none(value: int | None) -> int | str:
    return "" if value is None else value


if __name__ == "__main__":
    raise SystemExit(main())
