# XMRig Capture systemd 服务注册说明

本说明对应以下模板文件：

- `systemd/plan2-xmrig-capture.service.template`
- `systemd/xmrig-capture.env.template`

## 1. 准备环境变量文件

```sh
sudo mkdir -p /etc/plan2

sudo cp /root/plan2/systemd/xmrig-capture.env.template /etc/plan2/xmrig-capture.env
sudo nano /etc/plan2/xmrig-capture.env
```

把里面的：

```sh
XMR_WALLET=PUT_YOUR_XMR_WALLET_HERE
```

改成你的真实环境变量值。你原来需要 `export` 的变量，都写到这个文件里，例如：

```sh
XMR_WALLET=你的钱包地址
XMR_THREADS=2
```

## 2. 安装并启动 service

```sh
sudo cp /root/plan2/systemd/plan2-xmrig-capture.service.template /etc/systemd/system/plan2-xmrig-capture.service
sudo systemctl daemon-reload
sudo systemctl start plan2-xmrig-capture.service
```

## 3. 实时查看输出 log

```sh
journalctl -u plan2-xmrig-capture.service -f
```

## 4. 查看状态

```sh
sudo systemctl status plan2-xmrig-capture.service
```

## 5. 停止服务

```sh
sudo systemctl stop plan2-xmrig-capture.service
```

## 说明

这个模板里没有真的 `source .venv/bin/activate`，而是直接用了虚拟环境里的 Python：

```sh
/root/plan2/.venv/bin/python3
```

效果等价，而且更适合 `systemd`。

如果你的 venv 里只有 `python` 没有 `python3`，把 service 里的 `ExecStart` 改成：

```ini
ExecStart=/root/plan2/.venv/bin/python /root/plan2/tools/run_xmrig_capture.py --pool-index 2 --out-dir /tmp/shy_data_apple_m4 --target-flows 1 --tls-packets-per-flow 100
```
