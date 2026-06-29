# feature/catch 分支说明

## 分支目标

本分支实现 XMR 矿池 TLS flow 在线采集方案。`tools/capture_xmr_tls_flows.py` 只负责抓包；`tools/run_xmrig_capture.py` 可以先启动抓包、再逐条启动 XMRig，保证每个导出的 flow 尽量包含完整 TCP 握手。

采集脚本按启用矿池逐个监听。每条双向 TCP flow 必须先看到初始 TCP SYN；该 flow 满 `100` 个 Wireshark 识别到的 TLS 包后，导出从 SYN 到第 `100` 个 TLS 包之间的该 TCP flow 全部包到一个独立 pcap 文件。默认目标为每个启用矿池 `1000` 条 flow，下一阶段只需要把参数改为 `--target-flows 5000`。

## 与 pcap.md / feature/pcap 的区别

- `catch_pcap.md` / `feature/catch`：在线抓包采集 XMR TLS flow 数据，关注真实连接过程中的 TLS flow 保存。
- `pcap.md` / `feature/pcap`：离线 pcap 回放检测原型，关注已有 pcap 的回放、解析或检测。

两者关注点不同，脚本、配置和测试应保持分离，避免把在线采集逻辑和离线回放检测逻辑混在一起。

## 任务口径

采集单位为双向 TCP flow，而不是单向五元组。客户端到矿池、矿池到客户端的两个方向会归入同一个 flow。

每条 flow 满 `100` 个 TLS 数据包后保存。这里的 `100` 个 TLS 数据包不同于 `100` 个数据包：

- `100` 个数据包：可能包含 TCP ACK、重传、DNS、握手和其他被捕获包。
- `100` 个 TLS 数据包：只统计 Wireshark display filter 命中 `tls` 的包。

本分支以后者为准。导出的 flow 文件默认只包含该 flow 的前 `100` 个 TLS frame，用于严格满足数据口径。

## 文件与目录

- `tools/capture_xmr_tls_flows.py`：在线采集脚本。
- `tools/run_xmrig_capture.py`：自动准备 XMRig、启动矿池连接并同步采集完整 flow 的辅助脚本。
- `configs/xmr_pools.csv`：矿池入口配置，字段为 `name,host,port,enabled,notes`。
- `catch_tests/test_capture_xmr_tls_flows.py`：采集脚本的轻量单元测试，和 `feature/pcap` 的 `tests/` 目录分离。
- `shy_data_apple_m4/`：默认输出目录，不应提交实际采集数据。

## CLI 示例

手动模式适合已有连接程序可控启动顺序的情况。必须先运行抓包脚本，再建立新的矿池连接，否则可能看不到初始 SYN，脚本会拒绝导出该连接：

```sh
python3 tools/capture_xmr_tls_flows.py \
  --interface en1 \
  --pools configs/xmr_pools.csv \
  --out-dir shy_data_apple_m4 \
  --target-flows 1000 \
  --tls-packets-per-flow 100
```

下一阶段扩大规模时：

```sh
python3 tools/capture_xmr_tls_flows.py \
  --interface en1 \
  --pools configs/xmr_pools.csv \
  --out-dir shy_data_apple_m4 \
  --target-flows 5000 \
  --tls-packets-per-flow 100
```

推荐模式是让脚本自动逐个启动 XMRig 连接 CSV 中的矿池并采集。脚本会每导出一条完整 flow 后停止 XMRig，再启动下一次连接：

```sh
XMR_WALLET=<你的钱包地址> \
python3 tools/run_xmrig_capture.py \
  --interface en1 \
  --pools configs/xmr_pools.csv \
  --out-dir shy_data_apple_m4 \
  --target-flows 1000 \
  --tls-packets-per-flow 100
```

如果本地没有默认路径 `xmrig-6.26.0/xmrig`，脚本会按当前平台从 XMRig GitHub release 下载 v6.26.0 并解压到本地。也可以用 `XMRIG_PATH` 指向已经安装好的 XMRig。

## 实现方式

脚本使用 PATH 中的 Wireshark CLI 工具：

- `dumpcap`：按接口、矿池 IP 和端口分段捕获临时 pcapng。
- `tshark`：用 display filter 解析 TLS 包，并提取 frame、时间、IP、端口字段。
- `mergecap`：当一个 flow 跨多个分段时，合并相关临时分段。
- `editcap`：导出从初始 TCP SYN 到第 `100` 个 TLS 包之间的该 TCP flow 全部 frame。

采集流程：

1. 从 `configs/xmr_pools.csv` 读取 `enabled=true` 的矿池。
2. 解析矿池 host 到 IP。
3. 对每个 IP 使用 capture filter：`tcp and host <ip> and port <port>`。
4. 按 `--chunk-seconds` 分段捕获临时 pcapng。
5. 对分段运行 `tshark`，跟踪 TLS 包和初始 TCP SYN。
6. 按双向 TCP conversation 聚合 flow；没有初始 SYN 的连接不导出。
7. 某 flow 达到 `--tls-packets-per-flow` 后，导出从 SYN 到第 `100` 个 TLS 包之间的全部 TCP frame，并把该 flow 标记为完成。
8. 当前矿池达到 `--target-flows` 后，切换到下一个启用矿池；如果长时间无 TLS 包，则达到空闲上限后切换。

## 输出约定

默认输出目录：

```text
shy_data_apple_m4/
```

文件名格式：

```text
安全化矿池名_该矿池序号.pcap
```

示例：

```text
supportxmr_000001.pcap
nanopool_000001.pcap
```

同一输出目录内序号按矿池名分别递增。脚本启动时会扫描已有同名 pcap，继续使用下一个序号，避免覆盖已有采集结果。

脚本同步写入：

```text
shy_data_apple_m4/capture_manifest.jsonl
```

每行记录一个导出 flow，包含矿池名、host、port、双向 flow tuple、TLS 包数、输出文件、sha256、开始时间、结束时间和记录时间。

## 主要参数

- `--target-flows`：每个启用矿池的目标导出 flow 数，默认 `1000`。
- `--tls-packets-per-flow`：每条 flow 导出的 TLS 包数，默认 `100`。
- `--tls-display-filter`：TLS display filter，默认 `tls`。
- `--chunk-seconds`：分段捕获时长，默认 `30`。
- `--max-idle-seconds-per-pool`：某矿池长时间无新 flow 时切到下一个。
- `--dry-run`：打印配置和计划，不实际抓包。

## 使用前提

- Wireshark CLI 已安装，`dumpcap`、`tshark`、`editcap`、`mergecap` 均在 `PATH` 中。
- macOS 抓包权限由用户通过 Wireshark 权限配置或 `sudo` 解决，脚本不绕过系统权限。
- 用户负责启动矿工或连接程序来产生 XMR 矿池 TLS 流量。
- `configs/xmr_pools.csv` 中的矿池入口在采集前需要复核，因为公开矿池地址和端口可能变化。
- 输出目录 `shy_data_apple_m4/` 可写。
- `xmrig-6.26.0/` 为本地工具目录，当前通过 `.gitignore` 排除，不随本仓库提交；缺失时由运行脚本从官方 GitHub release 下载。若以后要分发 XMRig 二进制，需要一并保留 GPLv3 许可证文本，并提供对应源码获取说明。

## 测试计划

- 测试 `tshark -T fields` 输出解析，确认只统计 TLS 行，不统计普通 TCP 包。
- 测试双向 flow key，确认客户端到矿池、矿池到客户端归为同一 flow。
- 测试文件名安全化、按矿池独立续号、manifest JSONL 写入字段。
- 用 fake subprocess runner 测试达到 `100` 个 TLS frame 后生成正确的 `mergecap` / `editcap` 命令。
- 检查本文档清楚区分在线采集和离线回放检测。

运行：

```sh
python3 -m pytest catch_tests
git diff --check
```
