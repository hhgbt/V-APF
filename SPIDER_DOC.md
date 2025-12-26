# `core/spider.py` 模块文档

## 概述

`core/spider.py` 是 **ML-AdaptPentest** 框架的爬虫组件，专门设计用于自动化遍历 DVWA (Damn Vulnerable Web App) 风格的靶场应用。该脚本利用 **Playwright** 浏览器自动化工具，模拟用户登录、设置安全等级、抓取导航菜单，并深度解析每个页面的表单和链接信息，最终将收集到的目标信息结构化保存为 JSON 文件，供后续的漏洞扫描和特征提取使用。

## 功能特性

1.  **自动化登录**：
    *   自动访问登录页面 (`/login.php`)。
    *   填写用户名和密码（默认 `admin:password`）并提交。
    *   验证登录状态（等待网络空闲）。

2.  **安全等级管理**：
    *   自动识别当前 DVWA 的安全等级 (`security.php`)。
    *   **多等级支持**：支持传入多个目标等级（如 `low,impossible`），脚本会依次切换到每个等级进行完整抓取，从而收集同一页面在不同防护状态下的表现。

3.  **智能导航抓取**：
    *   自动定位左侧主菜单 (`#main_menu` 或包含 `menu` 的 `div`)。
    *   提取菜单中的所有导航链接，并进行去重和 URL 标准化处理。

4.  **深度页面解析与指纹记录**：
    *   遍历每一个发现的导航链接。
    *   **基准响应指纹 (Base Fingerprint)**：在访问页面时，自动记录无注入攻击时的**页面响应长度** (`base_resp_length`) 和**响应时间** (`base_resp_time`)。这为后续特征提取（如计算响应长度差异 `len_diff`）提供了精准的对照基准。
    *   **链接提取**：提取页面内所有 `<a>` 标签的 `href` 属性。
    *   **表单提取**：详细解析页面内的 `<form>` 元素。

5.  **结构化输出**：
    *   将所有抓取到的页面信息（URL、安全等级、表单详情、内部链接、基准指纹）保存为标准的 JSON 格式文件。

## 实现细节

该脚本基于 `playwright.async_api` 实现异步浏览器控制，核心类为 `DVWASpider`。

### 1. `DVWASpider` 类

*   `__init__(self, base_url, username, password)`: 初始化爬虫，设置基础 URL 和认证信息。

*   `login(self, page)`:
    *   导航至登录页。
    *   使用 `page.fill` 填充凭据。
    *   使用 `page.click` 点击登录按钮。
    *   使用 `page.wait_for_load_state("networkidle")` 确保页面加载完成。

*   `get_security_level(self, page)` / `set_security_level(self, page, level)`:
    *   访问安全设置页面。
    *   读取或修改 `select[name="security"]` 下拉框的值。
    *   点击提交按钮以应用更改。

*   `_extract_forms_from_page(page)` (静态方法):
    *   查询页面所有 `form` 元素。
    *   遍历表单内的输入控件，构建包含 `name`, `type`, `value` 等字段的字典。
    *   特别处理 `select` 元素，解析其子 `option` 选项。

*   `crawl_targets(self, page, nav_links, target_level)`:
    *   迭代访问导航链接列表中的每个 URL。
    *   **指纹采集**：记录页面加载耗时 (`base_resp_time`) 和 HTML 内容长度 (`base_resp_length`)。
    *   调用 `_extract_anchors_from_page` 和 `_extract_forms_from_page` 获取详情。
    *   将结果追加到 `self.results["pages"]` 列表。

*   `run(self, target_levels, headless, output)`:
    *   主执行流：启动浏览器 -> 登录 -> 抓取导航链接。
    *   **多等级循环**：遍历 `target_levels` 列表（如 `["low", "impossible"]`），依次切换安全等级并重复执行爬取逻辑。
    *   包含针对菜单加载的优化等待逻辑 (`wait_for_selector`)。

### 2. 命令行接口 (`main` 函数)

脚本支持丰富的命令行参数配置：

```bash
python3 core/spider.py [选项]
```

**参数说明**：
*   `--base`, `-b`: 目标 DVWA 的基础 URL (默认: `http://127.0.0.1/dvwa`)。
*   `--user`, `-u`: 登录用户名 (默认: `admin`)。
*   `--pass`, `-p`: 登录密码 (默认: `password`)。
*   `--levels`, `-l`: 目标安全等级列表，逗号分隔 (默认: `low,medium,high,impossible`)。
*   `--output`, `-o`: 结果输出文件路径 (默认: `data/targets.json`)。
*   `--no-headless`: 禁用无头模式（显示浏览器界面），用于调试。

## 依赖库

*   `playwright`: 强大的浏览器自动化库。
*   `asyncio`: Python 标准异步库。
*   `json`: JSON 数据处理。
*   `argparse`: 命令行参数解析。

## 使用示例

**基本用法（针对本地 DVWA）：**
```bash
python3 core/spider.py
```

**指定目标和安全等级：**
```bash
python3 core/spider.py -b http://192.168.1.100/dvwa -l medium -o data/targets_medium.json
```

**可视化调试模式运行：**
```bash
python3 core/spider.py --no-headless
```
