# V-APF Model Training Documentation

`core/train_model.py` 是 V-APF 的 AI 引擎训练模块。它负责读取标注数据、执行特征工程、训练随机森林分类器并导出模型与标准化器。当前配置：浅层树、最小叶子限制、略偏向正类的 class_weight，并自带多阈值评估（含 0.65）。可通过 `main.py train` 触发完整流水线（特征提取→合并→打标→训练）。

## 核心流程

### 1. 数据加载 (Data Loading)
- 从 CSV 文件加载数据集 (默认 `data/train_dataset.csv`)。
- 提取特征列 (`v1` - `v13`) 和标签列 (`label`)。

### 2. 特征工程 (Feature Engineering)
在送入模型之前进行两步预处理：

- **对数缩放**：`v1` 和 `v3` 先取绝对值，再做 $\log(1 + x)$ 压缩长尾，减弱极端值影响。
- **标准化**：使用 `StandardScaler` 对全部 13 维特征做 Z-score 变换（训练/推理均以 numpy 输入，避免特征名告警）。

### 3. 模型训练 (Model Training)
使用 **Random Forest Classifier (随机森林)**：
- `n_estimators=100`
- `max_depth=8`
- `min_samples_leaf=2`
- `class_weight={0:1.3, 1:1.7}`（正类权重略高，兼顾召回）
- `random_state=42`, `n_jobs=-1`

### 4. 模型评估 (Evaluation)
训练完成后，在 20% 测试集上评估：
- Classification Report（阈值 0.5）。
- 混淆矩阵。
- 阈值调优：0.2/0.3/0.4/0.5/0.55/0.6/0.65/0.7 输出 Recall/Precision/FP，便于选择推理阈值（推理侧默认 0.65）。
- 特征重要性排名打印到控制台。

### 5. 模型持久化 (Serialization)
训练好的模型和预处理器会被保存为二进制文件：
- `models/safs_rf_model.pkl`: 随机森林模型。
- `models/scaler.pkl`: 标准化器（推理侧同样以 numpy 输入，避免特征名告警）。

## 使用方法
有两种方式：

1) 直接训练脚本（数据已就绪）：
```bash
python3 core/train_model.py
```
脚本会自动读取 `data/train_dataset.csv`，完成训练后将模型保存至 `models/` 目录。

2) 一键流水线（从 targets_*.json 开始）：
```bash
python main.py train
```
该命令会执行：特征提取（对各 targets）、合并 `data/features_all.json`、自动打标到 `data/train_dataset.csv`、训练并产出模型与 scaler。

## 依赖关系

- **Input**: `data/train_dataset.csv` (由 `auto_labeler.py` 生成)。
- **Output**: `models/safs_rf_model.pkl`, `models/scaler.pkl`.
- **Libraries**: `scikit-learn`, `pandas`, `numpy`, `joblib`.


## 概要与核心功能（与现实现一致）

- **数据加载**：读取 `data/train_dataset.csv`，使用 `label` 与 `v1`~`v13`。
- **特征工程**：`v1/v3` 做 $\log(1+|x|)$，然后全量 13 维做 StandardScaler。
- **数据划分**：`train_test_split` 8:2，`stratify=y`。
- **模型训练**：随机森林超参如上；偏向提升召回但控制树深/叶子数。
- **评估**：输出默认阈值 0.5 报告与混淆矩阵，并对 0.2~0.7 多阈值打印 Recall/Precision/FP；打印特征重要性。
- **持久化**：保存模型与 scaler 到 `models/`，推理端直接加载并使用 numpy 输入。

## 命令行使用

**直接训练（数据已就绪）**
```bash
python3 core/train_model.py
```

**一键流水线**（从 targets_*.json 开始到训练完模型）
```bash
python main.py train
```
