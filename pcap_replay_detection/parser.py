from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from .records import PacketRecord

try:
    from scapy.all import ICMP, IP, TCP, UDP, PcapReader, Raw
except ImportError as exc:  # pragma: no cover - covered by runtime message
    raise RuntimeError(
        "pcap_replay_detection requires scapy. Install it with: pip install scapy"
    ) from exc


def iter_packet_records(
    pcap_path: str | Path,
    limit: int | None = None,
) -> Iterator[PacketRecord]:
    """Yield PacketRecord objects in the original pcap order."""
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"pcap file not found: {path}")

    with PcapReader(str(path)) as reader:
        for packet_index, packet in enumerate(reader):
            if limit is not None and packet_index >= limit:
                break
            yield _packet_to_record(packet_index, packet)


def _packet_to_record(packet_id: int, packet: object) -> PacketRecord:
    timestamp = float(getattr(packet, "time", 0.0))
    length = len(bytes(packet))

    if IP not in packet:
        return PacketRecord(
            packet_id=packet_id,
            timestamp=timestamp,
            src_ip="",
            dst_ip="",
            src_port=None,
            dst_port=None,
            protocol="NON_IP",
            payload=b"",
            length=length,
            status="skipped",
            status_reason="non_ip_packet",
        )

    ip_layer = packet[IP]
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    src_port: int | None = None
    dst_port: int | None = None
    protocol = str(ip_layer.proto)

    if TCP in packet:
        tcp_layer = packet[TCP]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        protocol = "TCP"
    elif UDP in packet:
        udp_layer = packet[UDP]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"

    payload = bytes(packet[Raw].load) if Raw in packet else b""
    status = "ok" if payload else "skipped"
    status_reason = "" if payload else "empty_payload"

    return PacketRecord(
        packet_id=packet_id,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        payload=payload,
        length=length,
        status=status,
        status_reason=status_reason,
    )
