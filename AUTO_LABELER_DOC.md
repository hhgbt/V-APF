# `core/auto_labeler.py` 模块文档

## 概述

`core/auto_labeler.py` 是 **ML-AdaptPentest** 框架中的自动打标组件。它的作用是为 `fuzzer_feature_extractor.py` 生成的原始特征数据集（CSV）自动添加准确的 `label`（0 代表安全，1 代表有漏洞），从而构建出可用于监督学习的高质量训练集。

该模块采用**“双重验证打标策略” (Double Verification Labeling)**，即结合**安全等级 (Security Level)** 上下文和**漏洞特征反馈 (Feature Feedback)** 进行综合判断，以确保标签的高准确度，有效区分“无效攻击”与“防御成功”。

## 功能特性

1.  **双重验证逻辑**：
    *   **Level 1: 上下文验证**：利用 DVWA 的 `security_level`（low/medium/high/impossible）作为先验知识。例如，在 `impossible` 等级下，系统默认是安全的。
    *   **Level 2: 特征验证**：检查具体的响应特征（如 SQL 报错、XSS 反射、时间延迟）是否表明攻击成功。只有当特征确实发生“有害”变化时，才标记为漏洞。

2.  **异常特征检测**：
    自动识别以下关键异常指标：
    *   **SQL 注入**：`has_sql_error_probe` 为 1 且 `has_sql_error_base` 为 0（新增报错）。
    *   **XSS 攻击**：Payload 被反射 (`probe_reflected`) 或出现 `<script>` 标签。
    *   **状态异常**：HTTP 状态码发生突变 (`status_changed`)。
    *   **时间盲注**：响应时间显著增加 (`resp_time_diff > 0.5s`)。
    *   **内容差异**：响应长度或文本内容发生变化。

3.  **负样本清洗**：
    *   即使在 `low`（易受攻击）等级下，如果攻击 Payload 投递后没有任何反应（无报错、无反射、无延迟），该样本也会被修正为 **0 (安全)**。这消除了“无效攻击”造成的标签噪声。

## 实现细节

### 核心函数 `logic_label(row)`

这是打标逻辑的大脑，处理流程如下：

1.  **数据提取**：从 CSV 行中读取 `security_level`, `payload_type` 以及各类数值特征。
2.  **特征判定**：计算 `is_sql_error`, `is_xss_sign`, `is_time_delayed` 等布尔标志。
3.  **场景分流**：
    *   **场景 A (Impossible/High)**：
        *   **策略**：信任防御。默认标记为 `0`。
        *   **例外**：如果检测到确凿的 SQL 语法报错（`is_sql_error`），强制标记为 `1`（虽然极罕见）。
    *   **场景 B (Low/Medium)**：
        *   **策略**：实证主义。
        *   **判定**：
            *   如果有明显异常 (`has_anomaly`) -> 标记为 `1`。
            *   如果有内容变化 (`is_content_changed`) 且符合 Payload 类型（如 XSS 必须有反射） -> 标记为 `1`。
            *   如果毫无反应（死水微澜） -> 标记为 `0`。

### 命令行接口 (`main` 函数)

```bash
python3 core/auto_labeler.py [选项]
```

**参数说明**：
*   `-i`, `--in`: 输入的原始 CSV 文件路径 (默认: `data/training_data.csv`)。
*   `-o`, `--out`: 输出的已打标 CSV 文件路径 (默认覆盖输入文件)。
*   `--preserve`: 保留输入文件中已有的非空标签（不覆盖），用于人工修正后的增量打标。

## 依赖库

*   `pandas`: CSV 读取与数据处理。
*   `argparse`: 命令行参数解析。

## 使用示例

**基本用法：**
```bash
python3 core/auto_labeler.py -i data/training_features_raw.csv -o data/training_data_final.csv
```

**输出统计：**
脚本运行结束后会打印正负样本的分布情况，例如：
```text
[+] Wrote data/training_data_final.csv — total=273, label=1:143, label=0:130
```
这有助于快速评估数据集的平衡性。
