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


def test_flow_key_is_bidirectional_for_client_and_pool_packets():
    client_to_pool = FlowKey.from_packet("10.0.0.2", 53124, "198.51.100.10", 443)
    pool_to_client = FlowKey.from_packet("198.51.100.10", 443, "10.0.0.2", 53124)

    assert client_to_pool == pool_to_client


def test_pool_name_sanitization_and_sequence_manifest(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "supportxmr_000007.pcap").write_bytes(b"old")

    config = CaptureConfig(
        interface="en1",
        pools_path=tmp_path / "pools.csv",
        out_dir=out_dir,
        target_flows=1,
        tls_packets_per_flow=2,
    )
    session = CaptureSession(config, runner=FakeRunner())
    output_path = out_dir / "supportxmr_000008.pcap"
    output_path.write_bytes(b"new-flow")
    flow_key = FlowKey.from_packet("10.0.0.2", 53124, "198.51.100.10", 443)
    state = FlowState(
        key=flow_key,
        packets=[
            TlsPacket(tmp_path / "chunk.pcapng", 1, 1700000000.0, flow_key),
            TlsPacket(tmp_path / "chunk.pcapng", 2, 1700000001.0, flow_key),
        ],
    )

    session.write_manifest(
        PoolConfig("Support XMR!", "pool.supportxmr.com", 443), state, output_path
    )

    manifest_text = (out_dir / "capture_manifest.jsonl").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text.splitlines()[0])
    assert session.sequence == 8
    assert sanitize_pool_name("Support XMR!") == "support_xmr"
    assert manifest["pool"] == "Support XMR!"
    assert manifest["tls_packets"] == 2
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
            TlsPacket(chunk1, 3, 1700000000.0, flow_key),
            TlsPacket(chunk2, 5, 1700000001.0, flow_key),
        ],
    )
    runner = FakeRunner(responses=["11\n12\n"])
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
    assert runner.commands[2][-2:] == ["11", "12"]
