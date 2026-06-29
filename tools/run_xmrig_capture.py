#!/usr/bin/env python3
"""Start XMRig from environment variables and capture its TLS pool flow."""

from __future__ import annotations

import argparse
import csv
import os
import platform
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.capture_xmr_tls_flows import (
    CaptureConfig,
    CaptureSession,
    PoolConfig,
    read_pools,
    sanitize_pool_name,
    validate_unique_pool_slugs,
)


DEFAULT_XMRIG_VERSION = "6.26.0"
DEFAULT_XMRIG_DIR = Path(f"xmrig-{DEFAULT_XMRIG_VERSION}")
DEFAULT_XMRIG_PATH = DEFAULT_XMRIG_DIR / "xmrig"
XMRIG_RELEASE_BASE_URL = (
    f"https://github.com/xmrig/xmrig/releases/download/v{DEFAULT_XMRIG_VERSION}"
)
DEFAULT_POOL_URL = "pool.supportxmr.com:443"


def env_value(env: Mapping[str, str], name: str, default: str | None = None) -> str:
    value = env.get(name, default)
    if value is None or not value.strip():
        raise ValueError(f"缺少环境变量 {name}")
    return value.strip()


def parse_pool_url(pool_url: str) -> tuple[str, int]:
    if "://" in pool_url:
        pool_url = pool_url.split("://", 1)[1]
    host_port = pool_url.rsplit("@", 1)[-1]
    host, sep, port_text = host_port.rpartition(":")
    if not sep or not host or not port_text:
        raise ValueError("XMR_POOL_URL 必须类似 pool.supportxmr.com:443")
    return host.strip("[]"), int(port_text)


def mask_wallet(wallet: str) -> str:
    if len(wallet) <= 8:
        return wallet[:4] + "..."
    if len(wallet) <= 16:
        return wallet[:4] + "..." + wallet[-4:]
    return wallet[:8] + "..." + wallet[-6:]


def xmrig_asset_name(
    system: str | None = None, machine: str | None = None
) -> str:
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    if system == "Darwin" and machine in {"arm64", "aarch64"}:
        return f"xmrig-{DEFAULT_XMRIG_VERSION}-macos-arm64.tar.gz"
    if system == "Darwin" and machine in {"x86_64", "amd64"}:
        return f"xmrig-{DEFAULT_XMRIG_VERSION}-macos-x64.tar.gz"
    if system == "Linux" and machine in {"x86_64", "amd64"}:
        return f"xmrig-{DEFAULT_XMRIG_VERSION}-linux-static-x64.tar.gz"
    raise ValueError(
        f"当前平台暂未配置 XMRig 自动下载: system={system} machine={machine}"
    )


def xmrig_download_url(asset_name: str | None = None) -> str:
    return f"{XMRIG_RELEASE_BASE_URL}/{asset_name or xmrig_asset_name()}"


def safe_extract_tar(archive_path: Path, dest_dir: Path) -> None:
    dest_dir = dest_dir.resolve()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            target_path = (dest_dir / member.name).resolve()
            if dest_dir not in target_path.parents and target_path != dest_dir:
                raise ValueError(f"压缩包包含不安全路径: {member.name}")
        archive.extractall(dest_dir)


def download_xmrig(dest_root: Path = REPO_ROOT) -> Path:
    asset_name = xmrig_asset_name()
    url = xmrig_download_url(asset_name)
    archive_path = dest_root / asset_name
    print(f"本地未找到 XMRig，开始下载: {url}")
    try:
        urllib.request.urlretrieve(url, archive_path)
        safe_extract_tar(archive_path, dest_root)
    finally:
        if archive_path.exists():
            archive_path.unlink()
    xmrig_path = dest_root / DEFAULT_XMRIG_PATH
    if not xmrig_path.exists():
        raise FileNotFoundError(f"下载解压后仍未找到 XMRig: {xmrig_path}")
    xmrig_path.chmod(xmrig_path.stat().st_mode | 0o755)
    print(f"XMRig 已准备好: {DEFAULT_XMRIG_PATH}")
    return xmrig_path


def ensure_xmrig_available(env: Mapping[str, str], repo_root: Path = REPO_ROOT) -> str:
    configured = env.get("XMRIG_PATH", str(DEFAULT_XMRIG_PATH)).strip()
    if not configured:
        configured = str(DEFAULT_XMRIG_PATH)
    configured_path = Path(configured).expanduser()
    check_path = configured_path if configured_path.is_absolute() else repo_root / configured_path
    if check_path.exists():
        return configured
    if env.get("XMRIG_PATH", "").strip():
        raise FileNotFoundError(f"XMRIG_PATH 指向的文件不存在: {configured}")
    download_xmrig(repo_root)
    return str(DEFAULT_XMRIG_PATH)


def build_xmrig_command(
    env: Mapping[str, str],
    pool_url_override: str | None = None,
    xmrig_path_override: str | None = None,
) -> list[str]:
    xmrig_path = xmrig_path_override or env_value(
        env, "XMRIG_PATH", str(DEFAULT_XMRIG_PATH)
    )
    wallet = env_value(env, "XMR_WALLET")
    pool_url = pool_url_override or env_value(env, "XMR_POOL_URL", DEFAULT_POOL_URL)
    worker = env_value(env, "XMR_WORKER", "catchtest")
    password = env_value(env, "XMR_PASSWORD", "x")
    threads = env_value(env, "XMR_THREADS", "2")
    print_time = env_value(env, "XMR_PRINT_TIME", "30")
    cpu_priority = env_value(env, "XMR_CPU_PRIORITY", "0")
    tls_enabled = env_value(env, "XMR_TLS", "1").lower() not in {
        "0",
        "false",
        "no",
        "off",
    }

    cmd = [
        xmrig_path,
        "-o",
        pool_url,
        "-u",
        f"{wallet}.{worker}",
        "-p",
        password,
        "--coin",
        "monero",
        "--threads",
        threads,
        "--cpu-priority",
        cpu_priority,
        "--print-time",
        print_time,
    ]
    if tls_enabled:
        cmd.append("--tls")

    extra_args = env.get("XMRIG_EXTRA_ARGS", "").strip()
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    return cmd


def pool_url_source(env: Mapping[str, str]) -> str:
    if env.get("XMR_POOL_URL", "").strip():
        return "环境变量 XMR_POOL_URL"
    return "脚本默认值"


def mask_xmrig_command(cmd: Sequence[str], wallet: str) -> str:
    masked_cmd = list(cmd)
    wallet_user = None
    for index, part in enumerate(masked_cmd):
        if part == "-u" and index + 1 < len(masked_cmd):
            wallet_user = masked_cmd[index + 1]
            break
    if wallet_user:
        suffix = ""
        if wallet_user.startswith(wallet):
            suffix = wallet_user[len(wallet) :]
        masked_cmd[index + 1] = mask_wallet(wallet) + suffix
    return shlex.join(masked_cmd)


def print_required_env() -> None:
    print("需要你配置的环境变量:")
    print("  XMR_WALLET      必填，你自己的 XMR 钱包地址")
    print("  XMRIG_PATH      可选，默认 xmrig-6.26.0/xmrig；缺失时自动下载")
    print("  XMR_POOL_URL    可选，默认 pool.supportxmr.com:443")
    print("  XMR_WORKER      可选，默认 catchtest")
    print("  XMR_PASSWORD    可选，默认 x")
    print("  XMR_THREADS     可选，默认 2")
    print("  XMR_TLS         可选，默认 1")
    print("  XMR_PRINT_TIME  可选，默认 30")
    print("  XMR_CPU_PRIORITY 可选，默认 0")
    print("  XMRIG_EXTRA_ARGS 可选，追加传给 XMRig 的参数")


def write_single_pool_csv(path: Path, pool: PoolConfig) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["name", "host", "port", "enabled", "notes"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "name": pool.name,
                "host": pool.host,
                "port": pool.port,
                "enabled": "true",
                "notes": pool.notes,
            }
        )


def pool_from_url(pool_url: str) -> PoolConfig:
    host, port = parse_pool_url(pool_url)
    return PoolConfig(
        name="xmrig_pool",
        host=host,
        port=port,
        enabled=True,
        notes="Generated by tools/run_xmrig_capture.py",
    )


def prefix_process_output(process: subprocess.Popen[str], label: str) -> threading.Thread:
    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            print(f"{label}: {line.rstrip()}")

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    return thread


def terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    print("正在停止 XMRig...")
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="启动 XMRig 并同步采集当前矿池 TLS flow。"
    )
    parser.add_argument("--interface", help="抓包网卡，例如 en1")
    parser.add_argument(
        "--pools",
        type=Path,
        default=None,
        help="可选：按 CSV 中启用矿池逐个启动 XMRig 并采集",
    )
    parser.add_argument("--out-dir", type=Path, default=Path("shy_data_apple_m4"))
    parser.add_argument("--target-flows", type=int, default=1000)
    parser.add_argument("--tls-packets-per-flow", type=int, default=100)
    parser.add_argument("--chunk-seconds", type=int, default=15)
    parser.add_argument("--max-idle-seconds-per-pool", type=int, default=60)
    parser.add_argument(
        "--capture-warmup-seconds",
        type=float,
        default=1.0,
        help="每条 flow 启动 XMRig 前先让 dumpcap 预热的秒数",
    )
    parser.add_argument("--dry-run", action="store_true", help="只打印配置，不启动矿工")
    parser.add_argument(
        "--print-env-help",
        action="store_true",
        help="打印需要配置的环境变量",
    )
    return parser.parse_args(argv)


def enabled_pools_from_args(args: argparse.Namespace, env: Mapping[str, str]) -> list[PoolConfig]:
    if args.pools is not None:
        pools = [pool for pool in read_pools(args.pools) if pool.enabled]
        if not pools:
            raise ValueError(f"{args.pools} 中没有启用的矿池")
        validate_unique_pool_slugs(pools)
        return pools
    return [pool_from_url(env_value(env, "XMR_POOL_URL", DEFAULT_POOL_URL))]


def capture_one_pool(
    args: argparse.Namespace,
    pool: PoolConfig,
    xmrig_cmd: Sequence[str],
    temp_path: Path,
) -> None:
    pools_path = temp_path / f"{sanitize_pool_name(pool.name)}_{pool.port}.csv"
    write_single_pool_csv(pools_path, pool)

    if args.dry_run:
        config = CaptureConfig(
            interface=args.interface,
            pools_path=pools_path,
            out_dir=args.out_dir,
            target_flows=args.target_flows,
            tls_packets_per_flow=args.tls_packets_per_flow,
            chunk_seconds=args.chunk_seconds,
            max_idle_seconds_per_pool=args.max_idle_seconds_per_pool,
            temp_dir=args.out_dir / ".capture_tmp",
            dry_run=True,
        )
        CaptureSession(config).run()
        return

    exported_for_pool = 0
    while exported_for_pool < args.target_flows:
        print(
            f"准备采集 {pool.name} 第 {exported_for_pool + 1}/"
            f"{args.target_flows} 条完整握手 flow"
        )
        config = CaptureConfig(
            interface=args.interface,
            pools_path=pools_path,
            out_dir=args.out_dir,
            target_flows=1,
            tls_packets_per_flow=args.tls_packets_per_flow,
            chunk_seconds=args.chunk_seconds,
            max_idle_seconds_per_pool=args.max_idle_seconds_per_pool,
            temp_dir=args.out_dir / ".capture_tmp",
            dry_run=False,
        )
        session = CaptureSession(config)
        session_error: list[BaseException] = []

        def run_capture() -> None:
            try:
                session.run()
            except BaseException as exc:
                session_error.append(exc)

        capture_thread = threading.Thread(target=run_capture)
        capture_thread.start()
        time.sleep(args.capture_warmup_seconds)
        if session_error:
            raise session_error[0]

        process = subprocess.Popen(
            list(xmrig_cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path.cwd(),
        )
        prefix_process_output(process, f"{pool.name} 矿工输出")

        try:
            capture_thread.join()
            if session_error:
                raise session_error[0]
        except KeyboardInterrupt:
            print("收到中断，准备停止采集和矿工。")
            raise
        finally:
            terminate_process(process)

        if session.exported_count == 0:
            print(f"{pool.name} 本次没有导出完整 flow，停止该矿池采集")
            break
        exported_for_pool += session.exported_count


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.print_env_help:
        print_required_env()
        return 0
    if not args.interface:
        print("配置错误: 必须传入 --interface，例如 --interface en1", file=sys.stderr)
        return 2

    try:
        pools = enabled_pools_from_args(args, os.environ)
        wallet = env_value(os.environ, "XMR_WALLET")
        xmrig_path = ensure_xmrig_available(os.environ)
    except ValueError as exc:
        print(f"配置错误: {exc}", file=sys.stderr)
        print_required_env()
        return 2
    except FileNotFoundError as exc:
        print(f"配置错误: {exc}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="xmr_capture_") as temp_dir:
        temp_path = Path(temp_dir)
        print(f"矿池数量: {len(pools)}")
        if args.pools is None:
            print(f"矿池来源: {pool_url_source(os.environ)}")
        else:
            print(f"矿池来源: {args.pools}")
        print(f"钱包: {mask_wallet(wallet)}")
        print(f"XMRig 路径: {xmrig_path}")
        print(f"抓包输出目录: {args.out_dir}")
        print(f"每个矿池目标 flow 数: {args.target_flows}")

        for pool in pools:
            pool_url = f"{pool.host}:{pool.port}"
            xmrig_cmd = build_xmrig_command(
                os.environ,
                pool_url_override=pool_url,
                xmrig_path_override=xmrig_path,
            )
            print(f"矿池: {pool.name} {pool_url}")
            print(f"XMRig: {xmrig_cmd[0]}")
            print(f"XMRig 命令: {mask_xmrig_command(xmrig_cmd, wallet)}")
            if args.dry_run:
                print("预演模式：不启动 XMRig，不实际抓包。")
            capture_one_pool(args, pool, xmrig_cmd, temp_path)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
