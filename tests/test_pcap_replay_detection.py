from __future__ import annotations

import csv

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

from pcap_replay_detection.backends import MockBackend
from pcap_replay_detection.detect import (
    detect_flows,
    detect_packets,
    main,
    replay_packets,
)
from pcap_replay_detection.features import encode_packet
from pcap_replay_detection.flows import build_flows


def _write_sample_pcap(path):
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
        / Raw(b"GET /"),
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
        / Raw(b" HTTP"),
        Ether()
        / IP(src="10.0.0.3", dst="10.0.0.4")
        / UDP(sport=5353, dport=53)
        / Raw(b"dns"),
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.6")
        / TCP(sport=1111, dport=443),
    ]
    for offset, packet in enumerate(packets):
        packet.time = 1.0 + offset
    wrpcap(str(path), packets)


def test_replay_packets_preserves_order_and_status(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    _write_sample_pcap(pcap_path)

    packets = replay_packets(str(pcap_path))

    assert [packet.packet_id for packet in packets] == [0, 1, 2, 3]
    assert packets[0].src_ip == "10.0.0.1"
    assert packets[0].dst_port == 80
    assert packets[0].status == "ok"
    assert packets[3].status == "skipped"
    assert packets[3].status_reason == "empty_payload"


def test_build_flows_groups_detectable_packets_by_five_tuple(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    _write_sample_pcap(pcap_path)

    flows = build_flows(replay_packets(str(pcap_path)))

    assert len(flows) == 2
    assert flows[0].packet_count == 2
    assert flows[0].flow_id == "10.0.0.1:1234->10.0.0.2:80/TCP"
    assert flows[1].packet_count == 1


def test_encode_packet_pads_and_truncates(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    _write_sample_pcap(pcap_path)
    packet = replay_packets(str(pcap_path))[0]

    assert encode_packet(packet, 3) == [71, 69, 84]
    assert encode_packet(packet, 8) == [71, 69, 84, 32, 47, 0, 0, 0]


def test_packet_detection_outputs_rows_for_skipped_packets(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    _write_sample_pcap(pcap_path)

    rows = detect_packets(replay_packets(str(pcap_path)), MockBackend(), max_packet_bytes=16)

    assert len(rows) == 4
    assert rows[0]["label"]
    assert rows[0]["confidence"]
    assert rows[3]["status"] == "skipped"
    assert rows[3]["label"] == ""


def test_flow_detection_outputs_one_row_per_flow(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    _write_sample_pcap(pcap_path)
    flows = build_flows(replay_packets(str(pcap_path)))

    rows = detect_flows(flows, MockBackend(), max_flow_bytes=32, max_flow_packets=32)

    assert len(rows) == 2
    assert rows[0]["packet_count"] == 2
    assert rows[0]["label"]


def test_cli_writes_packet_csv(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    output_path = tmp_path / "packet_results.csv"
    _write_sample_pcap(pcap_path)

    exit_code = main(
        [
            "--pcap",
            str(pcap_path),
            "--mode",
            "packet",
            "--backend",
            "mock",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    with output_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 4
    assert rows[0]["packet_id"] == "0"
    assert rows[0]["label"]


def test_cli_writes_flow_jsonl(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    output_path = tmp_path / "flow_results.jsonl"
    _write_sample_pcap(pcap_path)

    exit_code = main(
        [
            "--pcap",
            str(pcap_path),
            "--mode",
            "flow",
            "--backend",
            "mock",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert "flow_id" in lines[0]
