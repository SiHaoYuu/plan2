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
        ip_prefix = "ipv6" if ":" in self.host else "ip"
        host_field = f"{ip_prefix}.src" if src else f"{ip_prefix}.dst"
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
        return f"{tls_filter} and ({self.tcp_display_filter()})"

    def tcp_display_filter(self) -> str:
        left_to_right = (
            f"{self.left.as_display_filter(src=True)} and "
            f"{self.right.as_display_filter(src=False)}"
        )
        right_to_left = (
            f"{self.right.as_display_filter(src=True)} and "
            f"{self.left.as_display_filter(src=False)}"
        )
        return f"(({left_to_right}) or ({right_to_left}))"

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
    is_tls: bool = True
    is_initial_syn: bool = False


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
        tls_packets = self.tls_packets
        if not tls_packets:
            return None
        return tls_packets[-1].time_epoch

    @property
    def initial_syn_packet(self) -> TlsPacket | None:
        for packet in self.packets:
            if packet.is_initial_syn:
                return packet
        return None

    @property
    def tls_packets(self) -> list[TlsPacket]:
        return [packet for packet in self.packets if packet.is_tls]


@dataclass
class CaptureConfig:
    interface: str
    pools_path: Path
    out_dir: Path
    target_flows: int = 1000
    tls_packets_per_flow: int = 100
    tls_display_filter: str = "tls"
    chunk_seconds: int = 30
    max_idle_seconds_per_pool: int = 1800
    temp_dir: Path | None = None
    dry_run: bool = False


class CommandRunner:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def run(self, cmd: Sequence[str], capture_text: bool = False) -> str:
        print("执行命令: " + shlex.join(str(part) for part in cmd))
        if self.dry_run:
            return ""
        result = subprocess.run(
            list(cmd),
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if capture_text:
            return result.stdout
        for line in result.stdout.splitlines():
            print(f"工具输出: {line}")
        return ""


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
                f"{path} 必须包含列 name,host,port,enabled,notes；"
                f"缺失={sorted(missing)} 多余={sorted(extra)}"
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


def validate_unique_pool_slugs(pools: Sequence[PoolConfig]) -> None:
    seen: dict[str, str] = {}
    for pool in pools:
        slug = sanitize_pool_name(pool.name)
        if slug in seen:
            raise ValueError(
                f"矿池名称会生成重复文件名前缀 {slug!r}: "
                f"{seen[slug]!r} 和 {pool.name!r}"
            )
        seen[slug] = pool.name


def next_pool_sequence(out_dir: Path, pool_slug: str) -> int:
    pattern = re.compile(rf"{re.escape(pool_slug)}_(\d{{6}})\.pcap$")
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


def tshark_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true"}


def parse_tshark_tls_fields(output: str, chunk_path: Path) -> list[TlsPacket]:
    packets: list[TlsPacket] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.rstrip("\n").split("\t")
        if len(fields) == 6:
            frame, time_epoch, src_host, src_port, dst_host, dst_port = fields
            is_tls = True
            is_initial_syn = False
        elif len(fields) >= 8:
            frame, time_epoch, ip_src, ipv6_src, src_port, ip_dst, ipv6_dst, dst_port = (
                fields[:8]
            )
            src_host = ip_src or ipv6_src
            dst_host = ip_dst or ipv6_dst
            syn_value = fields[8] if len(fields) > 8 else ""
            ack_value = fields[9] if len(fields) > 9 else ""
            protocols = fields[10] if len(fields) > 10 else "tls"
            is_initial_syn = tshark_bool(syn_value) and not tshark_bool(ack_value)
            is_tls = ":tls" in protocols or protocols == "tls"
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
                is_tls=is_tls,
                is_initial_syn=is_initial_syn,
            )
        )
    return packets


def tshark_tls_field_command(pcap_path: Path, display_filter: str) -> list[str]:
    tracked_filter = (
        f"tcp and (({display_filter}) or "
        "(tcp.flags.syn == 1 and tcp.flags.ack == 0))"
    )
    return [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        tracked_filter,
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
        "-e",
        "tcp.flags.syn",
        "-e",
        "tcp.flags.ack",
        "-e",
        "frame.protocols",
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


def parse_frame_numbers(output: str, limit: int | None = None) -> list[str]:
    numbers = [line.strip() for line in output.splitlines() if line.strip()]
    if limit is None:
        return numbers
    return numbers[:limit]


class CaptureSession:
    def __init__(self, config: CaptureConfig, runner: CommandRunner | None = None) -> None:
        self.config = config
        self.runner = runner or CommandRunner(dry_run=config.dry_run)
        self.flows: dict[tuple[str, FlowKey], FlowState] = {}
        self.exported_count = 0
        self.exported_counts_by_pool: dict[str, int] = {}
        self.sequences_by_pool: dict[str, int] = {}

    def run(self) -> None:
        pools = [pool for pool in read_pools(self.config.pools_path) if pool.enabled]
        if not pools:
            raise ValueError(f"{self.config.pools_path} 中没有启用的矿池")
        validate_unique_pool_slugs(pools)
        print(f"已读取 {len(pools)} 个启用矿池")
        if self.config.dry_run:
            self._print_dry_run_preview(pools)
            return

        self.config.out_dir.mkdir(parents=True, exist_ok=True)
        temp_root = self.config.temp_dir or self.config.out_dir / ".capture_tmp"
        temp_root.mkdir(parents=True, exist_ok=True)

        for pool in pools:
            if self.pool_exported_count(pool) >= self.config.target_flows:
                continue
            self.capture_pool(pool, temp_root)
            if self.pool_exported_count(pool) < self.config.target_flows:
                print(
                    f"矿池 {pool.name} 当前导出 "
                    f"{self.pool_exported_count(pool)}/{self.config.target_flows} 条 flow，"
                    "已达到空闲上限，切换到下一个矿池"
                )

    def _print_dry_run_preview(self, pools: Sequence[PoolConfig]) -> None:
        print(f"输出目录: {self.config.out_dir}")
        print(f"每个矿池目标 flow 数: {self.config.target_flows}")
        print(f"每条 flow 的 TLS 包数: {self.config.tls_packets_per_flow}")
        for pool in pools:
            print(f"矿池: {pool.name} host={pool.host} port={pool.port}")

    def pool_slug(self, pool: PoolConfig) -> str:
        return sanitize_pool_name(pool.name)

    def pool_exported_count(self, pool: PoolConfig) -> int:
        return self.exported_counts_by_pool.get(self.pool_slug(pool), 0)

    def pool_sequence(self, pool: PoolConfig) -> int:
        slug = self.pool_slug(pool)
        if slug not in self.sequences_by_pool:
            self.sequences_by_pool[slug] = next_pool_sequence(self.config.out_dir, slug)
        return self.sequences_by_pool[slug]

    def incomplete_flow_stats(self, pool: PoolConfig) -> tuple[int, int]:
        pool_slug = self.pool_slug(pool)
        active_states = [
            state
            for (slug, _), state in self.flows.items()
            if slug == pool_slug
            and not state.exported
            and state.initial_syn_packet is not None
        ]
        max_tls_packets = max(
            (len(state.tls_packets) for state in active_states),
            default=0,
        )
        return len(active_states), max_tls_packets

    def capture_pool(self, pool: PoolConfig, temp_root: Path) -> None:
        try:
            addresses = resolve_host(pool.host)
        except socket.gaierror as exc:
            print(
                f"跳过 {pool.name}: 无法解析 {pool.host}: {exc}",
                file=sys.stderr,
            )
            return
        if not addresses:
            print(
                f"跳过 {pool.name}: {pool.host} 没有解析到地址",
                file=sys.stderr,
            )
            return
        print(
            f"开始监听矿池 {pool.name} ({pool.host}:{pool.port})，"
            f"解析地址: {', '.join(addresses)}"
        )

        idle_seconds = 0
        while (
            self.pool_exported_count(pool) < self.config.target_flows
            and idle_seconds < self.config.max_idle_seconds_per_pool
        ):
            chunk_path = self.capture_chunk(pool, addresses, temp_root)
            packets = self.read_tls_packets(chunk_path)
            self.add_packets(pool, packets, temp_root)
            active_flows, max_tls_packets = self.incomplete_flow_stats(pool)
            if packets:
                idle_seconds = 0
                tls_packets = sum(1 for packet in packets if packet.is_tls)
                print(
                    f"本分片识别到 {tls_packets} 个 TLS 包，"
                    f"当前已跟踪 {len(self.flows)} 条双向 flow；"
                    f"未完成完整 flow {active_flows} 条，"
                    f"最多 {max_tls_packets}/{self.config.tls_packets_per_flow} 个 TLS 包"
                )
            else:
                idle_seconds += self.config.chunk_seconds
                print(
                    f"本分片没有 TLS 包，矿池空闲累计 {idle_seconds} 秒；"
                    f"未完成完整 flow {active_flows} 条，"
                    f"最多 {max_tls_packets}/{self.config.tls_packets_per_flow} 个 TLS 包"
                )

    def capture_chunk(
        self, pool: PoolConfig, addresses: Sequence[str], temp_root: Path
    ) -> Path:
        safe_name = sanitize_pool_name(pool.name)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fd, raw_path = tempfile.mkstemp(
            prefix=f"{safe_name}_{timestamp}_",
            suffix=".pcapng",
            dir=temp_root,
        )
        os.close(fd)
        chunk_path = Path(raw_path)
        host_filter = " or ".join(f"host {address}" for address in addresses)
        capture_filter = f"tcp and port {pool.port} and ({host_filter})"
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
        pool_slug = self.pool_slug(pool)
        for packet in packets:
            state = self.flows.setdefault(
                (pool_slug, packet.flow_key), FlowState(packet.flow_key)
            )
            if state.exported:
                continue
            state.packets.append(packet)
            if (
                state.initial_syn_packet is not None
                and len(state.tls_packets) >= self.config.tls_packets_per_flow
            ):
                self.export_flow(pool, state, temp_root)
                state.exported = True
                self.exported_counts_by_pool[pool_slug] = (
                    self.exported_counts_by_pool.get(pool_slug, 0) + 1
                )
                self.exported_count += 1
                self.sequences_by_pool[pool_slug] = self.pool_sequence(pool) + 1
                print(
                    f"{pool.name} 已导出 "
                    f"{self.pool_exported_count(pool)}/{self.config.target_flows} 条 flow"
                )
                if self.pool_exported_count(pool) >= self.config.target_flows:
                    break

    def export_flow(self, pool: PoolConfig, state: FlowState, temp_root: Path) -> Path:
        initial_syn = state.initial_syn_packet
        tls_packets = state.tls_packets
        if initial_syn is None:
            raise RuntimeError(f"flow 缺少初始 TCP SYN，不能导出: {state.key}")
        if len(tls_packets) < self.config.tls_packets_per_flow:
            raise RuntimeError(
                f"flow 只有 {len(tls_packets)} 个 TLS 包，"
                f"不足 {self.config.tls_packets_per_flow}: {state.key}"
            )

        safe_name = sanitize_pool_name(pool.name)
        sequence = self.pool_sequence(pool)
        output_path = self.config.out_dir / f"{safe_name}_{sequence:06d}.pcap"
        merged_path = temp_root / f"{safe_name}_{sequence:06d}_merged.pcapng"

        chunks = state.chunks
        if len(chunks) == 1:
            merged_path = chunks[0]
        else:
            self.runner.run(["mergecap", "-w", str(merged_path), *map(str, chunks)])

        stop_frame = tls_packets[self.config.tls_packets_per_flow - 1].frame_number
        display_filter = (
            f"{state.key.tcp_display_filter()} and "
            f"frame.number >= {initial_syn.frame_number} and "
            f"frame.number <= {stop_frame}"
        )
        frame_output = self.runner.run(
            frame_number_command(
                merged_path, display_filter, self.config.tls_packets_per_flow
            ),
            capture_text=True,
        )
        frames = parse_frame_numbers(frame_output)
        if not frames:
            raise RuntimeError(
                f"合并后没有找到从 SYN 到第 "
                f"{self.config.tls_packets_per_flow} 个 TLS 包的 TCP frame: {state.key}"
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
        print(f"已导出 flow: {output_path}")
        return output_path

    def write_manifest(self, pool: PoolConfig, state: FlowState, output_path: Path) -> None:
        manifest_path = self.config.out_dir / "capture_manifest.jsonl"
        record = {
            "pool": pool.name,
            "host": pool.host,
            "port": pool.port,
            "flow": state.key.to_json(),
            "tls_packets": self.config.tls_packets_per_flow,
            "complete_tcp_start": state.initial_syn_packet is not None,
            "initial_syn_frame": (
                state.initial_syn_packet.frame_number
                if state.initial_syn_packet is not None
                else None
            ),
            "last_tls_frame": (
                state.tls_packets[self.config.tls_packets_per_flow - 1].frame_number
                if len(state.tls_packets) >= self.config.tls_packets_per_flow
                else None
            ),
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
        description="采集 XMR 矿池 TLS flow，并导出固定 TLS 包数的 pcap 文件。"
    )
    parser.add_argument("--interface", required=True, help="抓包网卡，例如 en1")
    parser.add_argument(
        "--pools",
        type=Path,
        default=Path("configs/xmr_pools.csv"),
        help="矿池 CSV，字段为 name,host,port,enabled,notes",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("shy_data_apple_m4"),
        help="pcap 文件和 capture_manifest.jsonl 的输出目录",
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
