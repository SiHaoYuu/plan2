import pytest

from tools.run_xmrig_capture import (
    build_xmrig_command,
    enabled_pools_from_args,
    ensure_xmrig_available,
    mask_xmrig_command,
    mask_wallet,
    parse_args,
    parse_pool_url,
    pool_url_source,
    select_pool_by_index,
    xmrig_asset_candidates,
    xmrig_asset_name,
    xmrig_download_url,
)
from tools.capture_xmr_tls_flows import (
    PoolConfig,
    detect_sysfs_active_interface,
    parse_bsd_route_interface,
    parse_linux_route_interface,
    wireshark_cli_install_commands,
)


def test_parse_pool_url_accepts_plain_host_port():
    assert parse_pool_url("pool.supportxmr.com:443") == ("pool.supportxmr.com", 443)


def test_parse_pool_url_rejects_missing_port():
    with pytest.raises(ValueError):
        parse_pool_url("pool.supportxmr.com")


def test_parse_args_defaults_to_task_capture_settings():
    args = parse_args(["--pool-index", "3"])

    assert args.interface is None
    assert str(args.pools) == "configs/xmr_pools.csv"
    assert args.pool_index == 3
    assert args.out_dir.name == "shy_data_apple_m4"
    assert args.target_flows == 1000
    assert args.tls_packets_per_flow == 100
    assert args.max_idle_seconds_per_pool == 1800


def test_parse_linux_route_interface_reads_default_route_device():
    output = "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.10 uid 501"

    assert parse_linux_route_interface(output) == "eth0"


def test_parse_bsd_route_interface_reads_default_route_device():
    output = "\n".join(
        [
            "   route to: default",
            "destination: default",
            "  interface: en0",
        ]
    )

    assert parse_bsd_route_interface(output) == "en0"


def test_detect_sysfs_active_interface_skips_loopback_and_virtual_links(tmp_path):
    for name, state in {
        "lo": "up",
        "docker0": "up",
        "eth0": "down",
        "enp3s0": "up",
    }.items():
        iface_dir = tmp_path / name
        iface_dir.mkdir()
        (iface_dir / "operstate").write_text(state, encoding="utf-8")

    assert detect_sysfs_active_interface(tmp_path) == "enp3s0"


def test_wireshark_cli_install_commands_use_linux_package_name(monkeypatch):
    monkeypatch.setattr(
        "tools.capture_xmr_tls_flows.shutil.which",
        lambda command: "/usr/bin/apt-get" if command == "apt-get" else None,
    )

    commands = wireshark_cli_install_commands("Linux")

    assert commands[0][-2:] == ["apt-get", "update"]
    assert commands[1][-3:] == ["install", "-y", "tshark"]


def test_build_xmrig_command_uses_environment_values():
    cmd = build_xmrig_command(
        {
            "XMRIG_PATH": "xmrig-6.26.0/xmrig",
            "XMR_WALLET": "48abc",
            "XMR_POOL_URL": "pool.supportxmr.com:443",
            "XMR_WORKER": "catchtest",
            "XMR_THREADS": "2",
            "XMRIG_EXTRA_ARGS": "--donate-level 1",
        }
    )

    assert cmd[:5] == [
        "xmrig-6.26.0/xmrig",
        "-o",
        "pool.supportxmr.com:443",
        "-u",
        "48abc.catchtest",
    ]
    assert "--tls" in cmd
    assert "--algo" in cmd
    assert "rx/0" in cmd
    assert "--keepalive" in cmd
    assert "-t" in cmd
    assert cmd[cmd.index("-t") + 1] == "2"
    assert cmd[-2:] == ["--donate-level", "1"]


def test_build_xmrig_command_requires_wallet():
    with pytest.raises(ValueError, match="XMR_WALLET"):
        build_xmrig_command({"XMRIG_PATH": "xmrig-6.26.0/xmrig"})


def test_build_xmrig_command_accepts_pool_override():
    cmd = build_xmrig_command(
        {
            "XMRIG_PATH": "xmrig",
            "XMR_WALLET": "48abc",
            "XMR_POOL_URL": "pool.supportxmr.com:443",
        },
        pool_url_override="xmr.2miners.com:2222",
    )

    assert cmd[2] == "xmr.2miners.com:2222"


def test_build_xmrig_command_accepts_xmrig_path_override():
    cmd = build_xmrig_command(
        {
            "XMRIG_PATH": "missing-xmrig",
            "XMR_WALLET": "48abc",
        },
        xmrig_path_override="xmrig-6.26.0/xmrig",
    )

    assert cmd[0] == "xmrig-6.26.0/xmrig"


def test_xmrig_asset_name_supports_macos_arm64():
    assert xmrig_asset_name("Darwin", "arm64") == "xmrig-6.26.0-macos-arm64.tar.gz"


def test_xmrig_asset_name_supports_linux_x64():
    assert xmrig_asset_name("Linux", "x86_64") == (
        "xmrig-6.26.0-linux-static-x64.tar.gz"
    )


def test_xmrig_asset_candidates_support_linux_arm64():
    assert xmrig_asset_candidates("Linux", "aarch64") == [
        "xmrig-6.26.0-linux-static-arm64.tar.gz",
        "xmrig-6.26.0-linux-arm64.tar.gz",
    ]


def test_xmrig_download_url_points_to_official_release_asset():
    assert xmrig_download_url("xmrig-6.26.0-macos-arm64.tar.gz") == (
        "https://github.com/xmrig/xmrig/releases/download/v6.26.0/"
        "xmrig-6.26.0-macos-arm64.tar.gz"
    )


def test_ensure_xmrig_available_uses_existing_default_path(tmp_path):
    xmrig_path = tmp_path / "xmrig-6.26.0" / "xmrig"
    xmrig_path.parent.mkdir()
    xmrig_path.write_text("fake", encoding="utf-8")

    assert ensure_xmrig_available({}, repo_root=tmp_path) == "xmrig-6.26.0/xmrig"


def test_ensure_xmrig_available_rejects_missing_custom_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        ensure_xmrig_available({"XMRIG_PATH": "custom/xmrig"}, repo_root=tmp_path)


def test_mask_wallet_keeps_address_readable_without_printing_all():
    assert mask_wallet("1234567890abcdef") == "1234...cdef"


def test_pool_url_source_reports_default_or_env():
    assert pool_url_source({}) == "脚本默认值"
    assert pool_url_source({"XMR_POOL_URL": "pool.supportxmr.com:443"}) == (
        "环境变量 XMR_POOL_URL"
    )


def test_mask_xmrig_command_hides_wallet_but_keeps_worker_suffix():
    wallet = "1234567890abcdef"
    cmd = ["xmrig", "-o", "pool.supportxmr.com:443", "-u", f"{wallet}.catchtest"]

    rendered = mask_xmrig_command(cmd, wallet)

    assert "1234567890abcdef" not in rendered
    assert "1234...cdef.catchtest" in rendered


def test_enabled_pools_from_args_reads_enabled_csv_rows(tmp_path):
    pools_path = tmp_path / "pools.csv"
    pools_path.write_text(
        "\n".join(
            [
                "name,host,port,enabled,notes",
                "supportxmr,pool.supportxmr.com,443,true,",
                "disabled,pool.example.com,443,false,",
            ]
        ),
        encoding="utf-8",
    )
    args = type("Args", (), {"pools": pools_path, "pool_index": None})()

    pools = enabled_pools_from_args(args, {"XMR_WALLET": "48abc"})

    assert [pool.name for pool in pools] == ["supportxmr"]


def test_enabled_pools_from_args_selects_one_based_pool_index(tmp_path):
    pools_path = tmp_path / "pools.csv"
    pools_path.write_text(
        "\n".join(
            [
                "name,host,port,enabled,notes",
                "supportxmr,pool.supportxmr.com,443,true,",
                "nanopool,xmr-eu1.nanopool.org,10343,true,",
            ]
        ),
        encoding="utf-8",
    )
    args = type("Args", (), {"pools": pools_path, "pool_index": 2})()

    pools = enabled_pools_from_args(args, {"XMR_WALLET": "48abc"})

    assert [pool.name for pool in pools] == ["nanopool"]


def test_select_pool_by_index_rejects_out_of_range_index():
    pools = [PoolConfig("supportxmr", "pool.supportxmr.com", 443)]

    with pytest.raises(ValueError):
        select_pool_by_index(pools, 2)


def test_enabled_pools_from_args_rejects_pool_index_without_csv():
    args = type("Args", (), {"pools": None, "pool_index": 2})()

    with pytest.raises(ValueError):
        enabled_pools_from_args(args, {"XMR_WALLET": "48abc"})
