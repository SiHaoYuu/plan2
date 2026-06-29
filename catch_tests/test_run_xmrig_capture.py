import pytest

from tools.run_xmrig_capture import (
    build_xmrig_command,
    enabled_pools_from_args,
    mask_xmrig_command,
    mask_wallet,
    parse_pool_url,
    pool_url_source,
)


def test_parse_pool_url_accepts_plain_host_port():
    assert parse_pool_url("pool.supportxmr.com:443") == ("pool.supportxmr.com", 443)


def test_parse_pool_url_rejects_missing_port():
    with pytest.raises(ValueError):
        parse_pool_url("pool.supportxmr.com")


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
    assert cmd[-2:] == ["--donate-level", "1"]


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
    args = type("Args", (), {"pools": pools_path})()

    pools = enabled_pools_from_args(args, {"XMR_WALLET": "48abc"})

    assert [pool.name for pool in pools] == ["supportxmr"]
