# `core/fuzzer_feature_extractor.py` 模块文档

## 概述

`core/fuzzer_feature_extractor.py` 是 **ML-AdaptPentest** 框架中的特征提取引擎。它的核心任务是将爬虫（`spider.py`）收集到的静态目标信息（`targets.json`），转化为机器学习模型可理解的数值化特征向量（`training_features_raw.csv`）。

该模块通过主动向目标 URL 发送预定义的探测 Payload（Fuzzing），并对比“基准请求”（正常请求）与“探测请求”（攻击请求）之间的响应差异，提取出 13 个维度的关键特征，用于后续的模型训练或漏洞预测。

## 功能特性

1.  **基于差异的特征提取 (Differential Feature Extraction)**：
    *   通过对比 `Base Response`（基准响应）和 `Probe Response`（探测响应），计算长度差异、时间差异、状态码变化等动态特征。
    *   支持利用爬虫阶段采集的精准基准指标（`base_resp_length`, `base_resp_time`），消除网络波动带来的误差。

2.  **多维特征向量生成**：
    为每个样本生成包含以下 13 个核心特征的向量：
    *   `probe_reflected`: Payload 是否在响应中被反射（针对 XSS）。
    *   `len_diff`: 响应长度差异（绝对值）。
    *   `has_text_diff`: 响应文本内容是否有差异（0/1）。
    *   `status_changed`: HTTP 状态码是否改变（0/1）。
    *   `resp_time_diff`: 响应时间差（探测时间 - 基准时间）。
    *   `resp_time_base/probe`: 基准/探测响应时间。
    *   `resp_length_base/probe`: 基准/探测响应长度。
    *   `has_sql_error_base/probe`: 是否包含 SQL 报错信息。
    *   `has_script_tag_base/probe`: 是否包含 `<script>` 标签。

3.  **智能 Payload 注入**：
    *   内置针对 SQL 注入、XSS 和 LFI（本地文件包含）的典型测试 Payload。
    *   自动处理表单中的隐藏字段（如 CSRF Token），确保请求合法性。

4.  **上下文保留**：
    *   在输出的 CSV 中保留 `page_url`, `payload_type`, `security_level` 等元数据，方便后续的自动打标（Auto Labeling）和人工审计。

## 实现细节

### 1. `FeatureExtractor` 类

*   `__init__(self, targets_file, output_csv)`:
    *   加载 `targets.json`。
    *   初始化 HTTP 会话 (`requests.Session`)，支持从环境变量读取 `PHPSESSID` 和 `security` Cookie，实现认证状态维持。
    *   定义 SQL 报错指纹 (`sql_error_signs`) 和探测 Payload 列表。

*   `_fetch_form_tokens(self, page_url, action)`:
    *   在提交表单前，先访问页面解析 `<input type="hidden">`，获取 CSRF Token 等反爬虫/安全验证字段。

*   `get_feature_vector(self, url, method, payload_data, ...)`:
    *   发送实际 HTTP 请求（GET/POST）。
    *   计算响应时间、长度。
    *   使用 `_is_sql_error` 和 `_has_script_tag` 进行正则/DOM 匹配，提取布尔特征。

*   `extract_features(self, ..., base_resp_metrics)`:
    *   **核心逻辑**：执行两次请求逻辑（逻辑上）。
        1.  **Base Request**: 发送填充了 `test` 的无害数据。
            *   *优化*：如果提供了 `base_resp_metrics`（来自爬虫），则直接使用其中的长度和时间作为基准，极大提高 `len_diff` 和 `resp_time_diff` 的准确性。
        2.  **Probe Request**: 发送带有攻击 Payload 的数据。
    *   计算两者之间的差值（Diff），构建并返回特征字典。

*   `run(self)`:
    *   遍历 `targets.json` 中的每个页面和表单。
    *   为每个表单构建 `base_payload` 和 `probe_payload`。
    *   调用 `extract_features` 生成样本。
    *   将结果追加到列表，最终保存为 CSV 文件。

### 2. 命令行接口 (`main` 函数)

```bash
python3 core/fuzzer_feature_extractor.py [选项]
```

**参数说明**：
*   `--targets`, `-t`: 爬虫生成的 JSON 目标文件路径 (默认: `data/targets.json`)。
*   `--out`, `-o`: 输出的原始特征 CSV 文件路径 (默认: `data/training_features_raw.csv`)。

## 依赖库

*   `requests`: 发送 HTTP 请求。
*   `pandas`: 数据结构化与 CSV 导出。
*   `beautifulsoup4` (`bs4`): HTML 解析与 Token 提取。
*   `urllib.parse`: URL 拼接与处理。

## 使用示例

**基本用法（使用默认路径）：**
```bash
python3 core/fuzzer_feature_extractor.py
```

**指定输入输出文件：**
```bash
python3 core/fuzzer_feature_extractor.py -t my_targets.json -o my_features.csv
```
