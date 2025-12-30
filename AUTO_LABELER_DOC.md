# V-APF Auto Labeler Documentation

`core/auto_labeler.py` 是 V-APF 的核心数据处理模块，负责将爬虫和提取器生成的原始特征数据转化为可用于机器学习模型训练的有监督数据集。当前版本已调优为偏高召回、适度控制误报的风格，默认判定阈值为 0.65。

## 功能概览

由于在无监督或弱监督环境下，我们缺乏明确的“漏洞/非漏洞”标签，Auto Labeler 利用一套精心设计的**启发式规则 (Heuristic Rules)**，结合靶场上下文（如 URL 是否包含 `impossible`、Payload 是否攻击性强等），自动为每个探测样本打上标签（Label: 0 或 1）。

## 核心逻辑

打标器通过 `heuristic_label` 方法计算每个样本的**风险评分 (Risk Score)**，并根据阈值判定标签。

### 评分规则

1.  **强特征判定 (Strong Indicators)**:
    -   报错注入: `v4 (Keyword Score)` > 0 → +1.7 分。
    -   时间盲注: `v3 (Time Delay)` 归一化 > 0.7 → +1.3 分。
    -   状态异常: `v2 (Status Change)` 发生变化 → +0.8 分。

2.  **结构异变判定 (Structure Mutation)**:
    -   DOM 剧变: `v5 (DOM Sim)` 在 0.2 ~ 0.98 → +0.4 分。
    -   长度突变: `|v1 (Length Diff)|` > 15% → +0.3 分。
    -   组合弱信号: `v5 > 0` 且 `|v1| > 5%` → +0.5；`|v1| > 5%` 且 `0.2 < v5 < 0.99` → +0.25。

3.  **反射型 XSS 判定**:
    -   只要有回显 (`v6 > 0`) → +0.9 分。

4.  **环境上下文修正 (Context Correction)**:
    -   “impossible” 页面不再强制扣分（目前扣 0）。
    -   风险参数: `risk_level == high` → +0.2 分。
    -   变异 Payload 偏好: 含 `/**/`, `sElEcT`, `%00`, `||`, `&&` 且页面有波动 → +0.5 分。
    -   简单 payload（如 1/0/test_safe）不再额外扣分。

5.  **保底打标逻辑 (Safety Net)**:
    -   Payload 含攻击性片段（如 `'`, `<script`, `sleep`, `whoami`, `alert`）且出现任意微小波动（长度/DOM/回显/报错）→ +0.4 分。

### 判定阈值

阈值调整为 **0.65**。
-   强特征和组合特征更容易越过阈值，正样本占比相对提升；若需减少误报，可在代码中将阈值调高（如 0.7）。

### 无害 Payload 白名单
- 白名单来源：`data/payloads.txt`，忽略以 `#` 开头的行。
- 只接受“安全格式”的值才会入白名单：纯字母数字/`_`/`-`/`.` 组合（如 `hello_world-1.0`），或日期 `YYYY-MM-DD`。
- 命中白名单时强制标记为 0。白名单越多，负样本越多；越少，正样本占比会提升。
- 如需固定少量无害样本，可将该文件精简为少数安全字符串；如需扩充也可直接追加。

## 使用方法

通常在 `extractor.py` 运行完成后，手动或自动调用此脚本生成训练集。

```bash
python3 core/auto_labeler.py --input data/features.json --output data/train_dataset.csv
```

### 参数说明

| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `--input` | 输入的特征向量 JSON 文件路径 | `data/features.json` |
| `--output` | 输出的 CSV 训练数据集路径 | `data/train_dataset.csv` |

## 输出格式 (CSV)

生成的 CSV 文件包含以下字段：

-   `label`: **目标变量** (1=Vulnerable, 0=Safe)
-   `url`: 目标 URL
-   `param`: 测试参数名
-   `payload`: 使用的 Payload
-   `risk_level`: 参数风险等级
-   `v1` - `v13`: 13 维特征向量数值

该 CSV 文件可直接被 `core/train_model.py` 读取用于训练随机森林模型。
