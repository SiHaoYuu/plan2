#!/usr/bin/env python3
"""Capture XMR pool TLS flows and export fixed-size per-flow pcap files."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


TRUE_VALUES = {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class PoolConfig:
    name: str
    host: str
    port: int
    enabled: bool = True
    notes: str = ""


@dataclass(frozen=True, order=True)
class Endpoint:
    host: str
    port: int

    def as_display_filter(self, src: bool) -> str:
        host_field = "ip.src" if src else "ip.dst"
        port_field = "tcp.srcport" if src else "tcp.dstport"
        return f"({host_field} == {self.host} and {port_field} == {self.port})"


@dataclass(frozen=True)
class FlowKey:
    left: Endpoint
    right: Endpoint

    @classmethod
    def from_packet(
        cls, src_host: str, src_port: int, dst_host: str, dst_port: int
    ) -> "FlowKey":
        endpoints = sorted(
            (Endpoint(src_host, src_port), Endpoint(dst_host, dst_port))
        )
        return cls(endpoints[0], endpoints[1])

    def display_filter(self, tls_filter: str) -> str:
        left_to_right = (
            f"{self.left.as_display_filter(src=True)} and "
            f"{self.right.as_display_filter(src=False)}"
        )
        right_to_left = (
            f"{self.right.as_display_filter(src=True)} and "
            f"{self.left.as_display_filter(src=False)}"
        )
        return f"{tls_filter} and (({left_to_right}) or ({right_to_left}))"

    def to_json(self) -> dict[str, object]:
        return {
            "left": {"host": self.left.host, "port": self.left.port},
            "right": {"host": self.right.host, "port": self.right.port},
        }


@dataclass(frozen=True)
class TlsPacket:
    chunk_path: Path
    frame_number: int
    time_epoch: float
    flow_key: FlowKey


@dataclass
class FlowState:
    key: FlowKey
    packets: list[TlsPacket] = field(default_factory=list)
    exported: bool = False

    @property
    def chunks(self) -> list[Path]:
        seen: set[Path] = set()
        paths: list[Path] = []
        for packet in self.packets:
            if packet.chunk_path not in seen:
                paths.append(packet.chunk_path)
                seen.add(packet.chunk_path)
        return paths

    @property
    def start_time_epoch(self) -> float | None:
        if not self.packets:
            return None
        return self.packets[0].time_epoch

    @property
    def end_time_epoch(self) -> float | None:
        if not self.packets:
            return None
        return self.packets[-1].time_epoch


@dataclass
class CaptureConfig:
    interface: str
    pools_path: Path
    out_dir: Path
    target_flows: int = 1000
    tls_packets_per_flow: int = 100
    tls_display_filter: str = "tls"
    chunk_seconds: int = 30
    max_idle_seconds_per_pool: int = 180
    temp_dir: Path | None = None
    dry_run: bool = False


class CommandRunner:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def run(self, cmd: Sequence[str], capture_text: bool = False) -> str:
        print("+ " + shlex.join(str(part) for part in cmd))
        if self.dry_run:
            return ""
        result = subprocess.run(
            list(cmd),
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture_text else None,
            stderr=subprocess.PIPE if capture_text else None,
        )
        return result.stdout if capture_text else ""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def epoch_to_iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def read_pools(path: Path) -> list[PoolConfig]:
    pools: list[PoolConfig] = []
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"name", "host", "port", "enabled", "notes"}
        if set(reader.fieldnames or []) != required:
            missing = required - set(reader.fieldnames or [])
            extra = set(reader.fieldnames or []) - required
            raise ValueError(
                f"{path} must have columns name,host,port,enabled,notes; "
                f"missing={sorted(missing)} extra={sorted(extra)}"
            )
        for row in reader:
            enabled = row["enabled"].strip().lower() in TRUE_VALUES
            pools.append(
                PoolConfig(
                    name=row["name"].strip(),
                    host=row["host"].strip(),
                    port=int(row["port"].strip()),
                    enabled=enabled,
                    notes=row["notes"].strip(),
                )
            )
    return pools


def resolve_host(host: str) -> list[str]:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    }
    return sorted(addresses)


def sanitize_pool_name(name: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip().lower())
    value = value.strip("._-")
    return value or "pool"


def next_global_sequence(out_dir: Path) -> int:
    pattern = re.compile(r".*_(\d{6})\.pcap$")
    highest = 0
    if not out_dir.exists():
        return 1
    for path in out_dir.glob("*.pcap"):
        match = pattern.match(path.name)
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_tshark_tls_fields(output: str, chunk_path: Path) -> list[TlsPacket]:
    packets: list[TlsPacket] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.rstrip("\n").split("\t")
        if len(fields) == 6:
            frame, time_epoch, src_host, src_port, dst_host, dst_port = fields
        elif len(fields) >= 8:
            frame, time_epoch, ip_src, ipv6_src, src_port, ip_dst, ipv6_dst, dst_port = (
                fields[:8]
            )
            src_host = ip_src or ipv6_src
            dst_host = ip_dst or ipv6_dst
        else:
            raise ValueError(f"unexpected tshark TLS field row: {line!r}")
        if not src_host or not dst_host or not src_port or not dst_port:
            continue
        flow_key = FlowKey.from_packet(src_host, int(src_port), dst_host, int(dst_port))
        packets.append(
            TlsPacket(
                chunk_path=chunk_path,
                frame_number=int(frame),
                time_epoch=float(time_epoch),
                flow_key=flow_key,
            )
        )
    return packets


def tshark_tls_field_command(pcap_path: Path, display_filter: str) -> list[str]:
    return [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.dst",
        "-e",
        "tcp.dstport",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]


def frame_number_command(
    pcap_path: Path, display_filter: str, limit: int
) -> list[str]:
    del limit
    return [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]


def parse_frame_numbers(output: str, limit: int) -> list[str]:
    numbers = [line.strip() for line in output.splitlines() if line.strip()]
    return numbers[:limit]


class CaptureSession:
    def __init__(self, config: CaptureConfig, runner: CommandRunner | None = None) -> None:
        self.config = config
        self.runner = runner or CommandRunner(dry_run=config.dry_run)
        self.flows: dict[FlowKey, FlowState] = {}
        self.exported_count = 0
        self.sequence = next_global_sequence(config.out_dir)

    def run(self) -> None:
        pools = [pool for pool in read_pools(self.config.pools_path) if pool.enabled]
        if not pools:
            raise ValueError(f"no enabled pools in {self.config.pools_path}")
        print(f"loaded {len(pools)} enabled pools")
        if self.config.dry_run:
            self._print_dry_run_preview(pools)
            return

        self.config.out_dir.mkdir(parents=True, exist_ok=True)
        temp_root = self.config.temp_dir or self.config.out_dir / ".capture_tmp"
        temp_root.mkdir(parents=True, exist_ok=True)

        while self.exported_count < self.config.target_flows:
            made_progress = False
            for pool in pools:
                exported_before = self.exported_count
                self.capture_pool(pool, temp_root)
                made_progress = made_progress or self.exported_count > exported_before
                if self.exported_count >= self.config.target_flows:
                    break
            if not made_progress:
                print("completed one polling pass without new exported flows")

    def _print_dry_run_preview(self, pools: Sequence[PoolConfig]) -> None:
        print(f"out_dir={self.config.out_dir}")
        print(f"target_flows={self.config.target_flows}")
        print(f"tls_packets_per_flow={self.config.tls_packets_per_flow}")
        for pool in pools:
            print(f"pool={pool.name} host={pool.host} port={pool.port}")

    def capture_pool(self, pool: PoolConfig, temp_root: Path) -> None:
        try:
            addresses = resolve_host(pool.host)
        except socket.gaierror as exc:
            print(f"skip {pool.name}: cannot resolve {pool.host}: {exc}", file=sys.stderr)
            return
        if not addresses:
            print(f"skip {pool.name}: no addresses resolved for {pool.host}", file=sys.stderr)
            return

        idle_seconds = 0
        address_index = 0
        while idle_seconds < self.config.max_idle_seconds_per_pool:
            address = addresses[address_index % len(addresses)]
            address_index += 1
            chunk_path = self.capture_chunk(pool, address, temp_root)
            packets = self.read_tls_packets(chunk_path)
            if packets:
                idle_seconds = 0
            else:
                idle_seconds += self.config.chunk_seconds
            self.add_packets(pool, packets, temp_root)
            if self.exported_count >= self.config.target_flows:
                break

    def capture_chunk(self, pool: PoolConfig, address: str, temp_root: Path) -> Path:
        safe_name = sanitize_pool_name(pool.name)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fd, raw_path = tempfile.mkstemp(
            prefix=f"{safe_name}_{timestamp}_",
            suffix=".pcapng",
            dir=temp_root,
        )
        os.close(fd)
        chunk_path = Path(raw_path)
        capture_filter = f"tcp and host {address} and port {pool.port}"
        cmd = [
            "dumpcap",
            "-i",
            self.config.interface,
            "-f",
            capture_filter,
            "-a",
            f"duration:{self.config.chunk_seconds}",
            "-w",
            str(chunk_path),
        ]
        self.runner.run(cmd)
        return chunk_path

    def read_tls_packets(self, chunk_path: Path) -> list[TlsPacket]:
        cmd = tshark_tls_field_command(chunk_path, self.config.tls_display_filter)
        output = self.runner.run(cmd, capture_text=True)
        return parse_tshark_tls_fields(output, chunk_path)

    def add_packets(
        self, pool: PoolConfig, packets: Iterable[TlsPacket], temp_root: Path
    ) -> None:
        for packet in packets:
            state = self.flows.setdefault(packet.flow_key, FlowState(packet.flow_key))
            if state.exported:
                continue
            state.packets.append(packet)
            if len(state.packets) >= self.config.tls_packets_per_flow:
                self.export_flow(pool, state, temp_root)
                state.exported = True
                self.exported_count += 1
                self.sequence += 1
                if self.exported_count >= self.config.target_flows:
                    break

    def export_flow(self, pool: PoolConfig, state: FlowState, temp_root: Path) -> Path:
        safe_name = sanitize_pool_name(pool.name)
        output_path = self.config.out_dir / f"{safe_name}_{self.sequence:06d}.pcap"
        merged_path = temp_root / f"{safe_name}_{self.sequence:06d}_merged.pcapng"

        chunks = state.chunks
        if len(chunks) == 1:
            merged_path = chunks[0]
        else:
            self.runner.run(["mergecap", "-w", str(merged_path), *map(str, chunks)])

        display_filter = state.key.display_filter(self.config.tls_display_filter)
        frame_output = self.runner.run(
            frame_number_command(
                merged_path, display_filter, self.config.tls_packets_per_flow
            ),
            capture_text=True,
        )
        frames = parse_frame_numbers(frame_output, self.config.tls_packets_per_flow)
        if len(frames) < self.config.tls_packets_per_flow:
            raise RuntimeError(
                f"only found {len(frames)} TLS frames after merge for {state.key}"
            )

        self.runner.run(
            [
                "editcap",
                "-F",
                "pcap",
                "-r",
                str(merged_path),
                str(output_path),
                *frames,
            ]
        )
        self.write_manifest(pool, state, output_path)
        print(f"exported {output_path}")
        return output_path

    def write_manifest(self, pool: PoolConfig, state: FlowState, output_path: Path) -> None:
        manifest_path = self.config.out_dir / "capture_manifest.jsonl"
        record = {
            "pool": pool.name,
            "host": pool.host,
            "port": pool.port,
            "flow": state.key.to_json(),
            "tls_packets": self.config.tls_packets_per_flow,
            "output_file": str(output_path),
            "sha256": sha256_file(output_path) if output_path.exists() else None,
            "start_time": epoch_to_iso(state.start_time_epoch),
            "end_time": epoch_to_iso(state.end_time_epoch),
            "recorded_at": utc_now_iso(),
        }
        with manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture XMR pool TLS flows into fixed-size per-flow pcap files."
    )
    parser.add_argument("--interface", required=True, help="capture interface, e.g. en1")
    parser.add_argument(
        "--pools",
        type=Path,
        default=Path("configs/xmr_pools.csv"),
        help="CSV with name,host,port,enabled,notes",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("shy_data_apple_m4"),
        help="output directory for pcap files and capture_manifest.jsonl",
    )
    parser.add_argument("--target-flows", type=int, default=1000)
    parser.add_argument("--tls-packets-per-flow", type=int, default=100)
    parser.add_argument("--tls-display-filter", default="tls")
    parser.add_argument("--chunk-seconds", type=int, default=30)
    parser.add_argument("--max-idle-seconds-per-pool", type=int, default=180)
    parser.add_argument("--temp-dir", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    config = CaptureConfig(
        interface=args.interface,
        pools_path=args.pools,
        out_dir=args.out_dir,
        target_flows=args.target_flows,
        tls_packets_per_flow=args.tls_packets_per_flow,
        tls_display_filter=args.tls_display_filter,
        chunk_seconds=args.chunk_seconds,
        max_idle_seconds_per_pool=args.max_idle_seconds_per_pool,
        temp_dir=args.temp_dir,
        dry_run=args.dry_run,
    )
    CaptureSession(config).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
