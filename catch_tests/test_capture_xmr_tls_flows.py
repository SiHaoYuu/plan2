import json

from tools.capture_xmr_tls_flows import (
    CaptureConfig,
    CaptureSession,
    Endpoint,
    FlowKey,
    FlowState,
    PoolConfig,
    TlsPacket,
    parse_tshark_tls_fields,
    sanitize_pool_name,
)


class FakeRunner:
    def __init__(self, responses=None):
        self.commands = []
        self.responses = responses or []

    def run(self, cmd, capture_text=False):
        self.commands.append(list(cmd))
        if capture_text:
            return self.responses.pop(0)
        return ""


def test_parse_tshark_fields_counts_only_tls_rows_from_tshark_output(tmp_path):
    output = "\n".join(
        [
            "7\t1700000000.1\t10.0.0.2\t\t53124\t198.51.100.10\t\t443",
            "9\t1700000000.5\t198.51.100.10\t\t443\t10.0.0.2\t\t53124",
        ]
    )

    packets = parse_tshark_tls_fields(output, tmp_path / "chunk.pcapng")

    assert [packet.frame_number for packet in packets] == [7, 9]
    assert len({packet.flow_key for packet in packets}) == 1
    assert all(packet.is_tls for packet in packets)


def test_parse_tshark_fields_tracks_initial_syn_for_complete_flow(tmp_path):
    output = "\n".join(
        [
            "1\t1700000000.0\t10.0.0.2\t\t53124\t198.51.100.10\t\t443\t1\t0\teth:ip:tcp",
            "7\t1700000000.1\t10.0.0.2\t\t53124\t198.51.100.10\t\t443\t0\t1\teth:ip:tcp:tls",
        ]
    )

    packets = parse_tshark_tls_fields(output, tmp_path / "chunk.pcapng")

    assert packets[0].is_initial_syn
    assert not packets[0].is_tls
    assert packets[1].is_tls


def test_flow_key_is_bidirectional_for_client_and_pool_packets():
    client_to_pool = FlowKey.from_packet("10.0.0.2", 53124, "198.51.100.10", 443)
    pool_to_client = FlowKey.from_packet("198.51.100.10", 443, "10.0.0.2", 53124)

    assert client_to_pool == pool_to_client


def test_display_filter_uses_ipv6_fields_for_ipv6_endpoints():
    flow_key = FlowKey.from_packet("2001:db8::10", 53124, "2001:db8::20", 443)

    display_filter = flow_key.display_filter("tls")

    assert "ipv6.src == 2001:db8::10" in display_filter
    assert "ipv6.dst == 2001:db8::20" in display_filter


def test_pool_name_sanitization_and_sequence_manifest(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "support_xmr_000007.pcap").write_bytes(b"old")
    (out_dir / "nanopool_000099.pcap").write_bytes(b"other-pool")

    config = CaptureConfig(
        interface="en1",
        pools_path=tmp_path / "pools.csv",
        out_dir=out_dir,
        target_flows=1,
        tls_packets_per_flow=2,
    )
    session = CaptureSession(config, runner=FakeRunner())
    output_path = out_dir / "support_xmr_000008.pcap"
    output_path.write_bytes(b"new-flow")
    flow_key = FlowKey.from_packet("10.0.0.2", 53124, "198.51.100.10", 443)
    state = FlowState(
        key=flow_key,
        packets=[
            TlsPacket(
                tmp_path / "chunk.pcapng",
                1,
                1700000000.0,
                flow_key,
                is_tls=False,
                is_initial_syn=True,
            ),
            TlsPacket(tmp_path / "chunk.pcapng", 2, 1700000001.0, flow_key),
            TlsPacket(tmp_path / "chunk.pcapng", 3, 1700000002.0, flow_key),
        ],
    )

    session.write_manifest(
        PoolConfig("Support XMR!", "pool.supportxmr.com", 443), state, output_path
    )

    manifest_text = (out_dir / "capture_manifest.jsonl").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text.splitlines()[0])
    assert session.pool_sequence(
        PoolConfig("Support XMR!", "pool.supportxmr.com", 443)
    ) == 9
    assert sanitize_pool_name("Support XMR!") == "support_xmr"
    assert manifest["pool"] == "Support XMR!"
    assert manifest["tls_packets"] == 2
    assert manifest["complete_tcp_start"] is True
    assert manifest["initial_syn_frame"] == 1
    assert manifest["last_tls_frame"] == 3
    assert manifest["sha256"]
    assert manifest["flow"]["left"]["host"] == "10.0.0.2"


def test_export_flow_uses_mergecap_and_editcap_with_first_tls_frames(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    chunk1 = tmp_path / "chunk1.pcapng"
    chunk2 = tmp_path / "chunk2.pcapng"
    chunk1.write_bytes(b"chunk1")
    chunk2.write_bytes(b"chunk2")
    flow_key = FlowKey.from_packet("10.0.0.2", 53124, "198.51.100.10", 443)
    state = FlowState(
        key=flow_key,
        packets=[
            TlsPacket(
                chunk1,
                1,
                1700000000.0,
                flow_key,
                is_tls=False,
                is_initial_syn=True,
            ),
            TlsPacket(chunk1, 3, 1700000001.0, flow_key),
            TlsPacket(chunk2, 5, 1700000002.0, flow_key),
        ],
    )
    runner = FakeRunner(responses=["1\n2\n3\n4\n5\n"])
    config = CaptureConfig(
        interface="en1",
        pools_path=tmp_path / "pools.csv",
        out_dir=out_dir,
        target_flows=1,
        tls_packets_per_flow=2,
    )
    session = CaptureSession(config, runner=runner)
    pool = PoolConfig("supportxmr", "pool.supportxmr.com", 443)

    output_path = session.export_flow(pool, state, tmp_path)

    assert output_path == out_dir / "supportxmr_000001.pcap"
    assert runner.commands[0][:3] == [
        "mergecap",
        "-w",
        str(tmp_path / "supportxmr_000001_merged.pcapng"),
    ]
    assert runner.commands[2][:5] == [
        "editcap",
        "-F",
        "pcap",
        "-r",
        str(tmp_path / "supportxmr_000001_merged.pcapng"),
    ]
    assert "frame.number >= 1" in runner.commands[1][4]
    assert "frame.number <= 5" in runner.commands[1][4]
    assert runner.commands[2][-5:] == ["1", "2", "3", "4", "5"]


def test_add_packets_tracks_target_and_sequence_per_pool(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "supportxmr_000002.pcap").write_bytes(b"old")
    (out_dir / "nanopool_000004.pcap").write_bytes(b"old")
    chunk = tmp_path / "chunk.pcapng"
    chunk.write_bytes(b"chunk")
    support_key = FlowKey.from_packet("10.0.0.2", 53124, "198.51.100.10", 443)
    nanopool_key = FlowKey.from_packet("10.0.0.2", 53125, "198.51.100.20", 443)
    runner = FakeRunner(responses=["1\n2\n3\n", "4\n5\n6\n"])
    config = CaptureConfig(
        interface="en1",
        pools_path=tmp_path / "pools.csv",
        out_dir=out_dir,
        target_flows=1,
        tls_packets_per_flow=2,
    )
    session = CaptureSession(config, runner=runner)

    session.add_packets(
        PoolConfig("supportxmr", "pool.supportxmr.com", 443),
        [
            TlsPacket(
                chunk,
                1,
                1700000000.0,
                support_key,
                is_tls=False,
                is_initial_syn=True,
            ),
            TlsPacket(chunk, 2, 1700000001.0, support_key),
            TlsPacket(chunk, 3, 1700000002.0, support_key),
        ],
        tmp_path,
    )
    session.add_packets(
        PoolConfig("nanopool", "xmr-eu1.nanopool.org", 10343),
        [
            TlsPacket(
                chunk,
                4,
                1700000003.0,
                nanopool_key,
                is_tls=False,
                is_initial_syn=True,
            ),
            TlsPacket(chunk, 5, 1700000004.0, nanopool_key),
            TlsPacket(chunk, 6, 1700000005.0, nanopool_key),
        ],
        tmp_path,
    )

    editcap_outputs = [command[5] for command in runner.commands if command[0] == "editcap"]
    assert str(out_dir / "supportxmr_000003.pcap") in editcap_outputs
    assert str(out_dir / "nanopool_000005.pcap") in editcap_outputs
    assert session.exported_counts_by_pool == {"supportxmr": 1, "nanopool": 1}
    assert session.exported_count == 2


def test_add_packets_does_not_export_without_initial_syn(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    chunk = tmp_path / "chunk.pcapng"
    chunk.write_bytes(b"chunk")
    flow_key = FlowKey.from_packet("10.0.0.2", 53124, "198.51.100.10", 443)
    runner = FakeRunner()
    config = CaptureConfig(
        interface="en1",
        pools_path=tmp_path / "pools.csv",
        out_dir=out_dir,
        target_flows=1,
        tls_packets_per_flow=2,
    )
    session = CaptureSession(config, runner=runner)

    session.add_packets(
        PoolConfig("supportxmr", "pool.supportxmr.com", 443),
        [
            TlsPacket(chunk, 2, 1700000001.0, flow_key),
            TlsPacket(chunk, 3, 1700000002.0, flow_key),
        ],
        tmp_path,
    )

    assert session.exported_count == 0
    assert not any(command[0] == "editcap" for command in runner.commands)
