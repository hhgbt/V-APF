# V-APF Extractor Documentation

`core/extractor.py` 是 V-APF 的核心特征提取模块，负责执行具体的攻击探测、数据采集以及将响应转化为 AI 模型可理解的 13 维特征向量。当前版本要点：
- 载入 `data/payloads.txt` 全量非注释行（当前 38 条，其中 4 条无害基准），对前 5 条（含 4 条无害与 1 条 `'` 基础 SQL）各生成 3 个变异样本并去重合并，实际总量约 53 条，随文件内容动态变动。
- 如果目标页数 > 50，会随机采样 50 页参与训练采集，避免长时间运行。
- 每条记录包含 `url / param / payload / risk_level / security_level / vector`，便于后续打标与训练。

## 模块架构

`FeatureExtractor` 类是该模块的核心，它整合了 Payload 管理、变异引擎 (Mutator)、浏览器控制 (Playwright) 以及特征计算逻辑。

### 核心流程

1.  **Payload 初始化与变异**:
    - 加载基础 Payload (`data/payloads.txt`)，当前 38 条（含 4 条无害基准）。
    - 对前 5 条（4 条无害 + 1 条基础 SQL `'`）各生成 3 个变异样本并去重合并，最终约 53 条，随文件内容动态变化。
2.  **数据采集 (Data Collection)**:
    - 读取 `targets_*.json` 中的注入点信息。
    - 初始化浏览器并执行自动登录（复用 `Spider` 逻辑，支持 DVWA/bWAPP/Pikachu），采集基线使用 Playwright。
    - 若页面数量 > 50，随机采样 50 页。
    - 针对每个注入点：
        - 获取 **Baseline** (基准响应)：发送正常请求。
        - 发送 **Probe** (探测请求)：将 Payload 注入到参数中，XSS 类 Payload 使用 Playwright，其他使用 httpx 以提升吞吐。
        - 实时获取响应状态、长度、时间、文本内容及 Headers，并记录 `security_level`。
3.  **特征工程 (Feature Engineering)**:
    - 对比 Baseline 和 Probe 的差异。
    - 计算并生成标准的 13 维特征向量（含 Length/Status/Time/Keyword/DOM/Reflection/Header 等）。
4.  **结果持久化**:
    - 将生成的特征向量集保存为 JSON 文件，供模型训练或实时预测使用。

## 13 维特征向量详解 (The 13-Dim Vector)

这是 V-APF 的核心创新点，通过多维度的语义差异来量化漏洞特征：

| 维度 | 特征名称 | 描述 | 计算逻辑 | 归一化范围 |
| :--- | :--- | :--- | :--- | :--- |
| **v1** | **Length Diff** | 响应长度变化率 | `(len_probe - len_base) / len_base` | -1.0 ~ 1.0 |
| **v2** | **Status Change** | 状态码是否改变 | `1.0` if changed else `0.0` | 0.0 / 1.0 |
| **v3** | **Time Delay** | 响应时间延迟 | `probe_time - base_time` (seconds) | 0.0 ~ 1.0 (capped at 5s) |
| **v4** | **Keyword Score** | 错误关键词匹配度 | 匹配 SQL/PHP 报错关键字的数量 | 0.0 ~ 1.0 (weighted) |
| **v5** | **DOM Similarity** | DOM 结构相似度 | `difflib.SequenceMatcher` 对比 HTML 结构 | 0.0 ~ 1.0 |
| **v6** | **Reflection** | Payload 反射性 | Payload 是否出现在响应中 | 0.0 / 1.0 |
| **v7** | **Header Change** | 关键 Header 变动 | 检测 `Set-Cookie`, `Location` 等变化 | 0.0 ~ 1.0 |
| **v8** | *Reserved* | 预留维度 | 暂定为 0.0 | 0.0 |
| **v9** | *Reserved* | 预留维度 | 暂定为 0.0 | 0.0 |
| **v10** | *Reserved* | 预留维度 | 暂定为 0.0 | 0.0 |
| **v11** | *Reserved* | 预留维度 | 暂定为 0.0 | 0.0 |
| **v12** | *Reserved* | 预留维度 | 暂定为 0.0 | 0.0 |
| **v13** | **Content-Type** | 内容类型一致性 | 检测 `Content-Type` Header 是否改变 | 0.0 / 1.0 |

> **注意**: 特征值均经过归一化处理（Normalization），以确保模型训练的稳定性。

## 关键类与方法

### `FeatureExtractor`

-   **`__init__(payloads_file)`**:
    -   加载 Payload，初始化 `SAFSMutator`，并执行 Payload 扩充。
-   **`fetch_page_features(page, url, method, data)`**:
    -   核心网络请求方法。
    -   使用 Playwright 发送请求（自动处理 GET Query 参数）。
    -   提取 `status`, `length`, `time`, `text`, `headers` 等原始数据。
-   **`compute_13_vector(base_data, probe_data, payload)`**:
    -   输入基准数据和探测数据，计算上述 13 维特征向量。
-   **`process_file(json_path)`**:
    -   处理单个 Target JSON 文件。
    -   自动识别目标类型 (DVWA/bWAPP/Pikachu) 并执行相应的自动登录。
    -   遍历页面和注入点，执行 Fuzzing 探测循环。

## 使用方法

通常通过 `main` 函数调用，或被 `predict_scanner.py` 引用。

**命令行运行 (用于采集训练数据):**

```bash
# 采集 DVWA 和 bWAPP 的特征数据
python3 core/extractor.py --targets data/targets_dvwa.json data/targets_bwapp.json --output data/features_train.json
```

**参数说明:**

-   `--targets`: **[必选]** 目标 JSON 文件路径列表（由 `spider.py` 生成）。
-   `--output`: 输出的特征向量 JSON 文件路径（默认 `data/features.json`）。

## 依赖关系

-   **Input**: `data/targets_*.json` (由 Spider 生成), `data/payloads.txt`.
-   **Output**: `data/features_*.json`（如 `features_1/2/3.json` 或合并前的中间文件，最终可汇总为 `data/features_all.json`）。
-   **Modules**: `core.spider` (复用登录逻辑), `core.mutator` (Payload 变异).
