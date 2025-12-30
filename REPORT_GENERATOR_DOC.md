# V-APF Report Generator Documentation

`core/report_generator.py` 是 V-APF 的报告生成模块。它负责将 `predict_scanner.py` 输出的扫描结果转换为 HTML 与 PDF 报告（默认输出：`report.html` / `VAPF_Penetration_Report.pdf`，调用方可自定义路径）。

## 功能概览

该模块包含两个核心类：
1.  **`VAPFReportGenerator`**: 交互式 HTML 报告。
2.  **`VAPFPDFGenerator`**: 基于 Playwright 的 PDF 报告（Chromium 打印，需可访问 Chart.js CDN）。

## 核心特性

### 1. 交互式数据可视化
报告首页包含一个由 **Chart.js** 驱动的环形图（Doughnut Chart），直观展示风险分布，基于“有效置信度 prob_effective”分桶：
-   **Critical**: prob_effective ≥ 0.65（可调 `critical_threshold`）。
-   **Suspicious**: 0.4 ≤ prob_effective < 阈值。
-   **Safe**: prob_effective < 0.4。

### 2. 智能修复建议 (Remediation)
采用 **特征向量优先 + 工具证据 + 关键词回退** 的策略生成修复建议：
-   特征优先：延迟/报错/反射信号直接驱动 SQLi/XSS/盲注建议。
-   证据增强：sqlmap/xsstrike/beef 等利用成功会覆盖为对应修复提示。
-   关键词回退：仅在缺乏信号时按 payload 形态兜底。

### 3. 智能快照截取 (Smart Snapshot)
报告中的 **Probe Snapshot** 具有智能截取：
-   若探测响应含原始 payload，则高亮并截取前后 100 字符。
-   如未反射但出现错误关键词，优先截取包含错误片段并高亮命中词；否则截取前 500 字符。
-   无可用文本时显示回退提示 `FALLBACK_SNAPSHOT_MSG`。

### 4. AI 判定依据解释 (Explainability)
报告通过 `_analyze_reason` 基于 13 维向量输出判定理由（延迟>2s、报错关键词、反射信号等），避免“无反射却声称 XSS”类误导。

### 4. 响应快照对比 (Snapshot)
HTML 报告内含 Base/Probe 片段与证据、利用尝试摘要，PDF 版本同样汇总成功/失败利用并保留特征指纹与修复建议。

## 报告格式详解

### HTML 报告
-   **文件**: 默认 `report.html`（调用方可传自定义路径）
-   **技术栈**: Jinja2 + CSS3 + Chart.js
-   **特点**:
    -   支持响应式布局。
    -   包含完整的特征向量数据。
    -   漏洞卡片支持 hover 效果。

### PDF 报告
-   **文件**: 默认 `VAPF_Penetration_Report.pdf`（可自定义路径）
-   **技术栈**: Playwright (Headless Chromium) 打印 PDF，依赖在线 Chart.js
-   **特点**:
    -   完美的排版和分页。
    -   保留了 Chart.js 图表（通过 Playwright 渲染）。
    -   去除不必要的交互元素，适合存档。

## 关键类与方法

### `VAPFReportGenerator` / `VAPFPDFGenerator`

-   **`__init__(scan_results, critical_threshold=0.65)`**: 保存结果并设置阈值。
-   **去重与有效置信度**: 按 `url+param+归一化payload` 去重，同键仅保留更高 prob；弱信号（反射-only、低延迟、低报错、DOM 高相似）会下调至最多 0.55。
-   **`_analyze_reason(vector)`**: 基于特征（延迟/报错/反射）生成自然语言理由。
-   **`_smart_remediation(payload, vector, evidence_text, exploit_entries)`**: 结合特征、工具成功与关键词生成修复建议。
-   **`generate_html(path)` / `generate(output_pdf)`**: 渲染 Jinja2 模板，HTML 直写文件；PDF 通过 Playwright 渲染 Chart.js 后打印。

## 使用示例

通常被 `predict_scanner.py` 调用：

```python
from core.report_generator import VAPFReportGenerator, VAPFPDFGenerator

results = [...] # 扫描结果列表

# 生成 HTML
html_reporter = VAPFReportGenerator(results)
html_reporter.generate_html("reports/vapf_report.html")

# 生成 PDF (异步)
pdf_reporter = VAPFPDFGenerator(results)
await pdf_reporter.generate("reports/VAPF_Final_Report.pdf")
```

## 依赖关系

-   **Libraries**: `jinja2`, `playwright`。
-   **External Assets**: `Chart.js` (CDN 加载；PDF 生成需可访问 CDN)。
