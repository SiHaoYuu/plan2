# Plan2: 静态嵌入与知识蒸馏

本项目用于执行“研究计划二：静态嵌入、学生结构与知识蒸馏”。研究目标是在当前 LPD-Miner/CMD 实验基础上，通过受控消融明确三类因素的独立贡献：

- 静态嵌入方式：Random、Word2Vec-CBOW、ET-BERT/PCA 等。
- 学生模型结构：MLP、1D-CNN、GRU、BiLSTM。
- 蒸馏目标：CE only、logits MSE、temperature KL。

项目重点是可复现、公平比较和实验边界控制。所有实验应使用同一冻结 train/val/test 划分，不能根据测试集表现调整模型或重新划分数据。

## 当前已完成

- 已建立 Git 仓库并配置远端 `origin`。
- 已创建中文 contributor guide：[AGENTS.md](./AGENTS.md)。
- 已生成当前 Python 环境依赖锁定文件：[requirements-lock.txt](./requirements-lock.txt)。
- 本地保留研究计划 Word 文档：`研究计划二_静态嵌入与知识蒸馏.docx`。
- 已明确后续实验目录、命名规范、测试要求和研究边界。

当前尚未完成实验代码、数据冻结索引、教师 logits 缓存、模型训练结果、表格和图。

## feature/pcap 分支说明

当前 `feature/pcap` 分支是独立工程原型，用于研究“如何通过 pcap 文件做回放式输入，并让模型进行包级和流级检测”。该分支暂不合并 `main`，实现上与原训练消融任务剥离，不修改冻结数据划分、模型选择规则或论文结果表。

新增模块位于 `pcap_replay_detection/`，第一版支持：

- 从 `.pcap` / `.pcapng` 文件按原始顺序读取 packet。
- `packet` 模式：每个可检测 packet 输出一次预测。
- `flow` 模式：按五元组 `src_ip, dst_ip, src_port, dst_port, protocol` 聚合后输出预测。
- `mock` 推理后端：在真实 PyTorch/ONNX 模型接入前验证完整管线。

运行示例：

```sh
python -m pcap_replay_detection.detect --pcap sample.pcap --mode packet --backend mock --output packet_results.csv
python -m pcap_replay_detection.detect --pcap sample.pcap --mode flow --backend mock --output flow_results.jsonl
```

常用参数：

- `--limit N`：只处理前 N 个 packet，便于调试。
- `--realtime`：按 pcap 时间戳间隔睡眠，模拟实时回放。
- `--max-packet-bytes`：包级输入的最大 byte token 长度。
- `--max-flow-packets` / `--max-flow-bytes`：流级聚合上限。

## 建议目录结构

后续开发按以下结构组织：

```text
plan2/
├── frozen_data/      # 固定数据划分与 sample_id
├── teacher/          # ET-BERT 教师与 logits 缓存
├── embeddings/       # Word2Vec、Random、ET-BERT/PCA 嵌入
├── student_models/   # MLP、1D-CNN、GRU、BiLSTM
├── configs/          # 实验配置
├── checkpoints/      # 模型权重
├── logs/             # 训练日志
├── results_tables/   # CSV 结果表
├── figures/          # Pareto 图、学习曲线
└── report/           # 最终报告
```

## 环境准备

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-lock.txt
```

如果需要重新锁定依赖：

```sh
pip freeze > requirements-lock.txt
```

## 实验原则

- 所有实验必须记录配置、seed、指标、运行日志和输出文件 hash。
- teacher logits 必须保存 `sample_id`、`logits`、`labels`、`class_names`，并校验类别顺序。
- 模型规模统计必须区分 `total_params`、`trainable_params` 和 `embedding_params`。
- 少样本实验必须按类别分层抽样，并在 D0/D1/D2 之间复用同一组 sample_id。
- 测试集只能用于最终固定配置评估，不能参与模型选择。

## 预期产出

最终应产出 8 张核心表格，包括复现结果、学生结构、嵌入消融、蒸馏比较、少样本结果、复杂度、量化和 Pareto 汇总；同时提交关键配置、权重、日志、图和最终报告。
