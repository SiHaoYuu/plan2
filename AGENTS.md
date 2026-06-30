# Repository Guidelines

## 项目结构与模块组织

本仓库服务于 `研究计划二_静态嵌入与知识蒸馏.docx` 中的 4 周研究计划，目标是在当前 LPD-Miner/CMD 设置下，受控比较静态嵌入、学生模型结构和知识蒸馏方法。

后续添加代码和实验产物时，按以下目录组织：

- `frozen_data/`：固定的 CMD train/val/test 索引和 sample_id。
- `teacher/`：ET-BERT 教师代码、logits 缓存和类别顺序校验。
- `embeddings/`：Word2Vec、Random、ET-BERT/PCA 嵌入文件。
- `student_models/`：MLP、1D-CNN、GRU、BiLSTM 实现。
- `configs/`、`checkpoints/`、`logs/`：可复现实验配置、权重和日志。
- `results_tables/`、`figures/`、`report/`：CSV 表格、图和最终报告。

禁止为了改善结果而更换冻结划分。生成 teacher logits 或嵌入文件时必须记录 hash。

## 构建、测试与开发命令

从仓库根目录创建环境：

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install torch torchvision torchaudio
pip install gensim scikit-learn pandas numpy matplotlib thop onnx onnxruntime
pip freeze > requirements-lock.txt
```

实验脚本应通过提交到仓库的配置运行，例如 `python train.py --config configs/base.yaml`。避免把关键参数只写在 notebook 或临时命令中。

## 编码风格与命名约定

实验代码优先使用 Python。遵循 PEP 8、4 空格缩进、显式 import 和描述性 `snake_case` 命名。MLP、CNN、GRU、BiLSTM 应保持统一模型 API：输入 shape、输出 logits shape 和参数统计方式一致。

结果文件按计划中的表格命名，例如 `embedding_ablation.csv`、`distillation.csv`、`fewshot.csv`、`complexity.csv`。

## 测试规范

长时间训练前先补轻量测试。至少覆盖模型 forward shape、标签与类别顺序一致性、参数统计、teacher-logit 缓存读取。测试放在 `tests/`，文件名使用 `test_*.py`。

加入 pytest 后使用 `python -m pytest` 运行。测试数据应使用小型 fixture 或固定 sample_id，不能重新随机划分数据。

## 提交与 Pull Request 规范

当前仓库尚无既有提交规范。提交信息使用简洁祈使句，建议采用 Conventional Commits，并优先使用中文祈使短句，例如 `feat: 添加gru学生模型`、`test: 校验teacher logits顺序`、`docs: 更新实验指南`。

修改代码后，在相关校验和代码审查均通过的前提下，自动提交到当前 git 分支。提交前只暂存本次任务涉及的文件，避免混入无关工作区改动；提交信息沿用本仓库最近提交的风格。

PR 应说明实验改动、运行命令、影响的表格或图，并提供验证证据：seed、配置路径、指标和输出 hash。涉及结果变更时，必须说明测试集是否只用于最终固定评估。

## 研究边界

允许范围：冻结 CMD-Base 实验、可选 CMD-CrossPool 附加测试、4 种学生结构、3 种蒸馏损失、嵌入消融、少样本比例、FLOPs/MACs、文件大小、离线延迟、ONNX 和动态 INT8 检查。

禁止范围：新增网络流量数据集、Flow-disjoint/Capture-disjoint 研究、tcpreplay、Docker 网络系统，以及任何基于测试集结果的模型选择。
