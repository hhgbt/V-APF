# V-APF Spider Documentation

`core/spider.py` 是 V-APF 的爬虫模块，基于 Playwright 发现潜在注入点并输出 `targets_*.json`。当前版本要点：
- 通用模式 + DVWA/bWAPP/Pikachu 专用模式（自动登录或 A.I.M.）；bWAPP 在 A.I.M. 下直接使用内置漏洞列表，无需 portal 下拉。
- 表单与 URL 参数均标注 `risk_level`（命中敏感词置 high）。
- 采集页面基线指纹：`resp_length_base`/`status_base`/`dom_hash`/`resp_time_base`；安全等级仅在 DVWA/bWAPP 批量模式下追加。
- 默认无头，可用 `--no-headless` 调试；无图形环境建议保持无头。
- 产物可直接供 `main.py train` 使用；首次运行需 `python -m playwright install`。
- BFS 爬取，默认最大深度 3；自动添加常见入口种子（index.php/admin/login/help 等），仅同域、非静态资源会入队。

## 功能概览

该模块包含一个通用爬虫类 `UniversalSpider` 和三个针对特定靶场的专用爬虫类：
- `UniversalSpider`: 通用爬虫，支持 Cookie 注入、表单/Query 发现与指纹采集。
- `DVWASpider`: 自动登录 admin/password，遍历 low/medium/high/impossible，按等级写回 `security_level`。
- `BWAPPSpider`: 自动登录 bee/bug，遍历等级 0/1/2（low/medium/high）；A.I.M. 模式直接用内置漏洞页列表生成队列。
- `PikachuSpider`: 通过 OverPermission 登录模块获取 Session 后全站 BFS。

## 核心特性

### 1. 智能输入点发现 (Input Discovery)
爬虫会自动识别页面中的以下注入点：
- **HTML 表单**: 解析 `<form>`，提取 `action`/`method` 与 `input`/`textarea`/`select` 字段，缺省值为空时填充占位符 `SAFS_TEST_PAYLOAD`。
- **URL 参数**: 解析当前页面的 Query 参数，识别潜在 GET 注入点。

### 2. 风险启发式分析 (Risk Heuristics)
在提取注入点时，爬虫会对表单和参数进行初步的风险评估：
- **High Risk**: form action 或字段/路径命中敏感关键词（login/admin/cmd/sql/id/file/url/path 等）。
- **Normal Risk**: 其他参数。

### 3. 页面指纹采集 (Fingerprinting)
爬虫会采集页面的基准指纹：`resp_length_base`、`status_base`、`dom_hash`、`resp_time_base`（秒）。

### 4. 自动认证与 Cookie 注入
支持通过命令行传入 Cookie 注入通用登录；特定靶场自动登录在新上下文内执行，DVWA/bWAPP 按等级循环，Pikachu 使用默认账号获取 Session。

### 5. 爬取策略与过滤
- 默认最大深度 3（Pikachu 同样 3），同域过滤，忽略常见静态资源后缀（jpg/png/css/js/pdf/ico/svg/woff）。
- 起始 URL 支持绝对或相对路径，未带协议时自动拼接 `base_url`。

## 使用方法

### 通用模式
适用于任意目标网站。

```bash
python3 core/spider.py --base "http://target.com" --cookie "PHPSESSID=xxx" --output "data/targets.json"
```

### DVWA 专用模式
自动遍历 `low`, `medium`, `high`, `impossible` 四个安全等级，并分别爬取。

```bash
python3 core/spider.py --base "http://127.0.0.1/dvwa" --dvwa --output "data/targets_dvwa.json"
```

### bWAPP 专用模式 (A.I.M.)
使用 A.I.M. (Authentication Is Missing) 模式，无需登录即可遍历漏洞页面。

```bash
python3 core/spider.py --base "http://127.0.0.1/bWAPP" --start "/aim.php" --bwapp --output "data/targets_bwapp.json"
```

### Pikachu 专用模式
自动执行登录流程并全站爬取。

```bash
python3 core/spider.py --base "http://127.0.0.1/pikachu" --pikachu --output "data/targets_pikachu.json"
```

## 参数说明

| 参数 | 简写 | 说明 | 默认值 |
| :--- | :--- | :--- | :--- |
| `--base` | `-b` | **[必选]** 目标基础 URL | 无 |
| `--cookie` | `-c` | 登录 Cookie 字符串 (分号分隔) | "" |
| `--start` | `-s` | 起始爬取路径 | "/" |
| `--output` | `-o` | 结果输出 JSON 文件路径 | "data/targets.json" |
| `--no-headless` | | 禁用无头模式（显示浏览器界面），调试用 | False (默认启用 Headless) |
| `--dvwa` | | 启用 DVWA 批量爬取模式 | False |
| `--bwapp` | | 启用 bWAPP 批量爬取模式 | False |
| `--pikachu` | | 启用 Pikachu 专用模式 | False |

## 输出格式 (JSON)

生成的 JSON 文件包含以下结构（DVWA/bWAPP 批量模式会额外在页面级标记 `security_level`）：

```json
{
  "base_url": "http://target.com",
  "pages": [
    {
      "url": "http://target.com/login.php",
      "baseline": {
        "resp_length_base": 1234,
        "status_base": 200,
        "dom_hash": 987654321,
        "resp_time_base": 0.15
      },
      "injection_points": [
        {
          "type": "form",
          "method": "POST",
          "action": "login.php",
          "inputs": [
            {
              "name": "username",
              "default": "",
              "type": "text",
              "risk_level": "high"
            },
            {
              "name": "password",
              "default": "",
              "type": "password",
              "risk_level": "high"
            }
          ]
        }
      ]
    }
  ]
}
```

## 与一键流水线（main.py）的协作

- 训练模式：先按上述任一模式生成 `data/targets_*.json`，然后直接运行：

```bash
python main.py train 
```

- 扫描模式：如无需预爬，可直接使用预测扫描器或一键 CLI：

```bash
python main.py scan \
  --url "http://target/vuln.php?name=test" \
  --method GET \
  --scan_mode single \
  --threshold 0.65 \
  --max-payloads 10 \
  --headless
```

提示：在服务器/CI 无桌面环境时请保持无头；`--no-headless` 仅在本地调试。爬取生成的 targets_*.json 会被 `main.py train` 消费，扫描可用 `main.py scan`，报告文件名按 URL 自动安全化+时间戳（可自定义基名）。
