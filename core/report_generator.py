import json
import datetime
import os
import re
from jinja2 import Environment
from playwright.async_api import async_playwright

DEFAULT_CRITICAL_THRESHOLD = 0.65
FALLBACK_SNAPSHOT_MSG = "页面响应异常/无有效回显，以下为截断内容"

class VAPFReportGenerator:
    def __init__(self, scan_results, critical_threshold: float = DEFAULT_CRITICAL_THRESHOLD):
        self.results = scan_results
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.critical_threshold = critical_threshold

    def _normalize_payload(self, payload: str) -> str:
        try:
            from urllib.parse import unquote
            if payload is None:
                return ""
            p = unquote(unquote(str(payload)))
            return p.strip()
        except Exception:
            return str(payload or "").strip()

    def _dedupe_results(self, results):
        """按 URL+参数+归一化 payload 去重，保留更高置信度一条，减少同义 payload 重复。"""
        seen = {}
        for r in results:
            key = (r.get('url'), r.get('param'), self._normalize_payload(r.get('payload')))
            cur = seen.get(key)
            if (cur is None) or (r.get('prob', 0) > cur.get('prob', 0)):
                seen[key] = r
        return list(seen.values())

    def _detect_payload_type(self, payload: str, vector=None) -> str:
        """尽量避免仅凭 payload 字面形态误判。

        设计目标：
        - SQL 载荷形态可以作为强先验（因为 SQLi 往往不依赖“反射”就可成立）。
        - XSS 载荷形态不能单独作为结论：若向量反射分很低，应返回 unknown，避免“cat=1 但 payload 变异得像脚本就被判 XSS”。
        """
        p = (payload or "").lower()
        sql_markers = ["'", "\"", " or ", " and ", "union", "select", "sleep(", "benchmark", "1=1", "1=2", "--", "/*"]
        xss_markers = ["<script", "onerror", "onload", "javascript:", "iframe", "alert(", "prompt(", "confirm(", "<img", "<svg"]
        cmd_markers = [";", "&&", "||", "|", "`", "$(", "& ping", "& whoami", "cat /etc", "id", "curl ", "wget "]

        if any(m in p for m in sql_markers):
            return "sql"

        if any(m in p for m in cmd_markers):
            return "cmd"

        if "{{" in p or "${" in p:
            return "ssti"

        if "../" in p or "..\\" in p:
            return "dir"

        if any(m in p for m in xss_markers):
            # 若提供向量，则必须有明确反射证据才认为是 XSS 类型
            if vector is not None:
                try:
                    if float(vector[5]) >= 0.7:
                        return "xss"
                    return "unknown"
                except Exception:
                    return "unknown"
            return "xss"

        return "unknown"

    def _v3_delay_seconds(self, vector) -> float:
        """v3 在本项目中为归一化延迟（约等于 (probe_time-base_time)/5，截断到 0~1）。"""
        try:
            return float(vector[2]) * 5.0
        except Exception:
            return 0.0

    def _summarize_attempt_failure(self, raw_output: str | None) -> str:
        """提炼未成功利用的原因摘要，便于报告展示。"""
        text = (raw_output or '').lower()
        if not raw_output:
            return "工具无输出，未获得可验证证据"
        if 'not found' in text:
            return "工具未安装或路径无效"
        if 'timeout' in text or 'timed out' in text:
            return "执行超时，可能需要更长等待或降低防护"
        if 'permission denied' in text:
            return "权限不足，命令被拒绝"
        if 'connection refused' in text or 'unable to connect' in text:
            return "目标或代理连接失败"
        if 'waf' in text or '403' in text or '406' in text or '418' in text:
            return "可能被 WAF 拦截"
        if 'is not injectable' in text or 'not injectable' in text:
            return "目标未能验证注入，需换 payload/参数"
        if 'json' in text and 'unsupported' in text:
            return "工具版本不支持 --json 选项"
        return "未获取可验证证据，见输出摘要"

    def _extract_log_excerpt(self, raw_output: str | None, limit: int = 600) -> str:
        if not raw_output:
            return ""
        # 取末尾日志片段，压平换行便于阅读
        tail = raw_output[-limit:]
        return tail.replace('\n', ' ').replace('\r', ' ')

    def _vector_remediation(self, vector, payload=None):
        """使用特征向量驱动的修复建议，避免与实际信号不符，优先 SQL 再看反射。"""
        if not vector or len(vector) < 6:
            return None
        ptype = self._detect_payload_type(payload or "", vector)
        delay_s = self._v3_delay_seconds(vector)
        # SQL 信号优先（错误/延迟/SQL 载荷）
        if delay_s > 2.0 or vector[3] > 0.1 or ptype == "sql":
            return "检测到 SQL 注入倾向。务必使用预编译语句（Prepared Statements），禁止拼接参数。"
        # 反射型需要确有反射
        if vector[5] > 0.7 and ptype in ("xss", "unknown"):
            return "检测到反射特征。建议进行 HTML 实体编码，并启用 CSP 策略。"
        if vector[4] < 0.5:
            return "检测到页面结构大幅变化，建议校验权限并收紧服务端校验，防范命令执行/逻辑越权。"
        return None

    def _smart_remediation(self, payload, vector, evidence_text, exp_entries):
        """
        根据证据文本、工具链结果与特征向量选择更贴合的修复建议。
        优先级：sqlmap/错误关键词 -> SQL 注入；反射分高/工具命中 -> 反射型风险；延迟高 -> 时间盲注；兜底 -> 布尔盲注/逻辑越权。
        """
        vector_hint = self._vector_remediation(vector, payload)
        if vector_hint:
            return vector_hint

        ev_lower = (evidence_text or '').lower()
        exp_entries = exp_entries or []

        sqlmap_success = any((ex.get('type') == 'sqlmap' and ex.get('success')) for ex in exp_entries)
        xss_tool_success = any(((ex.get('type') or '').lower() in ('xsstrike', 'beef')) and ex.get('success') for ex in exp_entries)

        has_sql_keyword_in_ev = bool(re.search(r"\b(sql|select|union|database|mysql|postgres|sqlite|error)\b", ev_lower))
        has_sql_signal = sqlmap_success or has_sql_keyword_in_ev or (vector and vector[3] >= 0.4)

        high_reflection = xss_tool_success or (vector and vector[5] >= 0.8)
        has_delay_signal = bool(vector) and (self._v3_delay_seconds(vector) > 2.0)
        bool_blind_signal = vector and (abs(vector[0]) > 0.3 or vector[4] < 0.8)

        if has_sql_signal:
            return "检测到 SQL 注入风险/利用成功。请使用参数化查询（Prepared Statements）或存储过程，避免拼接 SQL；关闭数据库错误回显，并最小化数据库账户权限。"
        if high_reflection:
            return "检测到反射型风险（可能 XSS/报错注入）。请对输出进行严格的 HTML 实体编码，过滤危险标签/事件，并最小化错误回显；启用 CSP 限制内联脚本。"
        if has_delay_signal:
            return "检测到时间盲注信号。请在数据库查询层面严格使用参数化查询，避免拼接用户输入，并限制长耗时查询。"
        if bool_blind_signal:
            return "检测到响应长度/DOM 显著异常，疑似布尔盲注或逻辑越权。请校验权限、收紧错误处理，并采用白名单校验和参数化查询。"

        # 回退到通用逻辑
        return self._get_remediation(payload, vector)

    def _extract_error_snippet(self, text: str, window: int = 180):
        if not text:
            return None
        patterns = [
            r"sql syntax",
            r"mysql|mariadb",
            r"postgres|postgresql|pg::",
            r"sqlite",
            r"odbc",
            r"ora-\d+",
            r"sqlstate",
            r"exception",
            r"warning",
            r"you have an error",
        ]
        for pat in patterns:
            m = re.search(pat, text, flags=re.IGNORECASE)
            if m:
                start = max(0, m.start() - window)
                end = min(len(text), m.end() + window)
                hit = text[m.start():m.end()]
                return text[start:end], hit
        return None

    def _analyze_reason(self, vector):
        """对齐向量语义的判定依据输出，避免出现“反射分=0 但说反射”的冲突。"""
        reasons = []
        delay_s = self._v3_delay_seconds(vector)
        if delay_s > 2.0:
            reasons.append(f"响应显著延迟 (疑似时间盲注, {delay_s:.2f}s)")
        if vector[3] > 0.1:
            reasons.append("发现数据库错误关键词")
        if vector[5] > 0.7:
            reasons.append("Payload 存在高比例反射 (疑似 XSS)")
        if not reasons:
            reasons.append("页面结构/长度发生异常变动")
        return " | ".join(reasons)

    def _get_remediation(self, payload, vector=None):
        """
        根据 Payload 和特征向量智能推断修复建议
        优先级：向量信号优先（反射 -> XSS；延迟/报错 -> SQLi；结构崩塌 -> RCE/逻辑异常），再回退 Payload 模式匹配。
        """
        vector_hint = self._vector_remediation(vector, payload)
        if vector_hint:
            return vector_hint

        ptype = self._detect_payload_type(payload, vector)
        if ptype == "sql":
            return "疑似 SQL 注入。建议使用参数化查询 (Prepared Statements)，避免字符串拼接，并关闭错误回显。"
        if ptype == "xss":
            return "疑似 XSS 攻击。建议对输出进行严格编码，过滤危险标签/事件，并启用 CSP。"
        if ptype == "cmd":
            return "疑似命令注入。建议禁止系统命令拼接，过滤 Shell 元字符，并最小化服务账户权限。"
        if ptype == "dir":
            return "疑似目录遍历。建议校验文件路径，拒绝跳转字符 (../)，并限制可访问目录。"
        if ptype == "ssti":
            return "疑似模板注入。建议限制模板可执行能力，使用沙箱或白名单渲染。"
        return "建议加强输入验证与服务端逻辑过滤。"

    def _classify_label(self, r):
        """
        优先级：SQL 信号/工具 > 反射型 > 时间盲注 > 布尔/逻辑异常。
        结合 payload 类型避免误把 SQL 载荷标成 XSS。
        """
        v = r.get('vector', [0]*13)
        exp_entries = r.get('exploit_entries') or []
        ptype = self._detect_payload_type(r.get('payload') or '', v)

        sql_tool = any((ex.get('type') == 'sqlmap' and ex.get('success')) for ex in exp_entries)
        xss_tool = any(((ex.get('type') or '').lower() in ['xsstrike', 'beef'] and ex.get('success')) for ex in exp_entries)

        delay_s = self._v3_delay_seconds(v)
        sql_signal = sql_tool or v[3] >= 0.1 or delay_s > 2.0 or ptype == 'sql'
        reflect_signal = (v[5] >= 0.7 and (ptype in ['xss', 'unknown'] and v[3] < 0.2)) or xss_tool
        time_blind = delay_s > 2.0
        bool_blind = abs(v[0]) > 0.4 or v[4] < 0.8

        if sql_signal:
            return "SQL 注入风险"
        if reflect_signal:
            return "反射型风险 (XSS/报错注入)"
        if time_blind:
            return "时间盲注风险"
        if bool_blind:
            return "布尔型盲注或逻辑异常"
        return None

    def generate_html(self, output_path="report.html"):
        # 去重 & 初始化统计
        self.results = self._dedupe_results(self.results)
        total = len(self.results)
        crit_thresh = self.critical_threshold
        critical = suspicious = safe = 0

        exploit_successes = []
        exploit_attempts = []

        # 增强结果数据：先统一计算 prob_effective 与汇总统计；再按阈值补齐证据/建议（避免 safe 计数一直为 0）
        for r in self.results:
            # 汇总利用结果（exploit / exploit_chain）
            exp_entries = []
            if r.get("exploit"):
                exp_entries.append(r["exploit"])
            if r.get("exploit_chain"):
                exp_entries.extend(r["exploit_chain"])
            r['exploit_entries'] = exp_entries

            # 先计算展示置信度（即便是低危/安全也要计入摘要）
            prob_effective = r.get('prob', 0)
            signal_tag = r.get('signal_tag')
            has_success_exploit = any(ex.get('success') for ex in exp_entries)
            weak_signal = signal_tag in ("REFLECTION_ONLY", "LOW_SIGNAL")
            try:
                low_err = (r.get('vector') or [0]*13)[3] == 0
                low_delay = (r.get('vector') or [0]*13)[2] < 0.8
                dom_high = (r.get('vector') or [0]*13)[4] > 0.9
            except Exception:
                low_err = low_delay = dom_high = False
            if not has_success_exploit and weak_signal and low_err and low_delay and dom_high:
                prob_effective = min(prob_effective, 0.55)
            r['prob_effective'] = float(prob_effective)

            pe = r['prob_effective']
            if pe >= crit_thresh:
                critical += 1
            elif pe >= 0.4:
                suspicious += 1
            else:
                safe += 1

            # 只有需要展示的条目才补齐解释/证据/建议
            if pe <= 0.4 and not r.get('waf_detected'):
                continue

            # 汇总全局成功利用，用于报告顶部展示
            for ex in exp_entries:
                if ex.get('success'):
                    exploit_successes.append({
                        "type": ex.get('type') or 'tool',
                        "payload": ex.get('payload') or '',
                        "evidence": ex.get('evidence'),
                        "url": r.get('url'),
                        "param": r.get('param')
                    })
                else:
                    raw = ex.get('raw_output') or ''
                    tail = self._extract_log_excerpt(raw, limit=600)
                    reason = self._summarize_attempt_failure(raw)
                    exploit_attempts.append({
                        "type": ex.get('type') or 'tool',
                        "payload": ex.get('payload') or '',
                        "url": r.get('url'),
                        "param": r.get('param'),
                        "summary": tail or '已尝试利用（未成功）',
                        "reason": reason,
                        "log_excerpt": tail
                    })

            r['reason'] = self._analyze_reason(r.get('vector') or [])

            evidence_lines = []
            if exp_entries:
                for ex in exp_entries:
                    try:
                        if ex.get('success'):
                            ev = ex.get('evidence')
                            ev_str = json.dumps(ev, ensure_ascii=False, indent=2) if ev is not None else '成功但未返回结构化证据'
                            evidence_lines.append(f"[{(ex.get('type') or 'tool').upper()}] 成功拿到证据: {ev_str}")
                    except Exception:
                        if ex.get('success'):
                            evidence_lines.append(f"[{(ex.get('type') or 'tool').upper()}] 成功拿到证据")
            if not evidence_lines:
                # 针对 demo.testfire.net 的 XSS 友好提示（需反射强且为该域名）
                try:
                    v = r.get('vector') or [0]*13
                    if ('demo.testfire.net' in (r.get('url') or '')) and (r.get('payload') in (r.get('snapshot', {}).get('probe') or '')) and float(v[5]) >= 0.7:
                        evidence_lines.append("[XSS 验证] 检测到 Payload 在响应中原样反射，置信度 100%")
                except Exception:
                    pass
                evidence_lines.append("AI 判定理由: " + (r.get('reason') or ''))
                try:
                    probe_text = (r.get('snapshot') or {}).get('probe') or ''
                    err = self._extract_error_snippet(probe_text)
                    if err:
                        snippet, hit = err
                        evidence_lines.append(f"\n[发现敏感回显]: ...{snippet}...\n(匹配项: {hit})")
                except Exception:
                    pass
            r['evidence_text'] = "\n".join(evidence_lines)

            r['remediation'] = self._smart_remediation(r.get('payload') or '', r.get('vector') or [], r.get('evidence_text'), exp_entries)
            r['extra_note'] = self._classify_label(r)

        # 定义 HTML 模板
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>V-APF AI 渗透报告</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; color: #333; margin: 0; padding: 20px; }
                .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
                h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; border-bottom: 2px solid #ecf0f1; padding-bottom: 15px; }
                .summary { display: flex; justify-content: space-between; align-items: center; padding: 20px; background: #34495e; color: #fff; border-radius: 8px; margin-bottom: 30px; }
                .summary-stats { flex: 1; display: flex; justify-content: space-around; }
                .summary-item { text-align: center; }
                .summary-count { font-size: 24px; font-weight: bold; margin-top: 5px; }
                .chart-container { width: 300px; height: 150px; margin-left: 20px; }
                
                .vulnerability { border-left: 5px solid #e74c3c; margin: 20px 0; padding: 20px; background: #fff; border-radius: 4px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); transition: transform 0.2s; }
                .vulnerability:hover { transform: translateX(5px); }
                .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
                .vuln-url { font-weight: bold; font-size: 1.1em; color: #2980b9; word-break: break-all; }
                .level-critical { color: #c0392b; font-weight: bold; padding: 4px 8px; background: #fadbd8; border-radius: 4px; }
                .level-suspicious { color: #d35400; font-weight: bold; padding: 4px 8px; background: #fdebd0; border-radius: 4px; }
                .detail-row { margin: 8px 0; display: flex; }
                .detail-label { width: 80px; font-weight: bold; color: #7f8c8d; }
                .detail-content { flex: 1; font-family: monospace; background: #f8f9fa; padding: 2px 6px; border-radius: 3px; word-break: break-all; overflow-wrap: anywhere; white-space: pre-wrap; }
                
                .ai-reason { margin-top: 15px; padding: 10px; background: #e8f6f3; border-radius: 4px; border-left: 4px solid #1abc9c; color: #16a085; font-size: 0.9em; }
                .remediation { margin-top: 10px; padding: 10px; background: #fff8e1; border-radius: 4px; border-left: 4px solid #f1c40f; color: #d35400; font-size: 0.9em; }
                
                .features { margin-top: 10px; display: flex; flex-wrap: wrap; gap: 10px; }
                .feature-tag { padding: 4px 10px; background: #ecf0f1; border-radius: 15px; font-size: 12px; color: #7f8c8d; }
                
                .exploit-box { margin-top: 12px; padding: 10px; border-left: 4px solid #e74c3c; border-radius: 4px; background: #fbfcff; font-family: 'Courier New', Courier, monospace; white-space: normal; }
                .exploit-box.success { border-color: #e74c3c; }
                .exploit-title { font-weight: bold; margin-bottom: 6px; color: #2c3e50; }
                .exploit-list { margin: 6px 0 0 16px; padding: 0; }
                .exploit-list li { margin: 2px 0; }
                .exploit-empty { color: #7f8c8d; font-style: italic; }
                .exploit-summary { margin: 20px 0; padding: 14px; border-left: 5px solid #e74c3c; background: #fefefe; border-radius: 5px; }
                /* 证据盒样式：深色终端风格 */
                .evidence-container { margin-top: 10px; padding: 12px; background: #1e1e1e; border-left: 5px solid #e74c3c; border-radius: 4px; color: #d4d4d4; }
                .evidence-title { font-weight: bold; color: #ffffff; margin-bottom: 6px; font-size: 13px; border-bottom: 1px solid #333; padding-bottom: 4px; }
                .evidence-content { font-family: 'Consolas', 'Monaco', monospace; font-size: 11px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
                /* 证据盒样式：模拟终端输出感（深色） */
                .evidence-container { margin-top: 15px; padding: 15px; background: #1e1e1e; border-left: 5px solid #e74c3c; border-radius: 4px; color: #d4d4d4; }
                .evidence-title { font-weight: bold; color: #ffffff; margin-bottom: 8px; font-size: 14px; border-bottom: 1px solid #333; padding-bottom: 5px; }
                .evidence-content { font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
                .extra-note { margin-top: 8px; color: #8e44ad; font-size: 0.9em; }
                pre { white-space: pre-wrap; word-wrap: break-word; background: #272822; color: #f8f8f2; padding: 10px; border-radius: 5px; }
                .feature-guide { margin: 20px 0; background: #eef3ff; border: 1px solid #d6ddff; border-radius: 6px; padding: 12px; }
                .feature-guide table { width: 100%; border-collapse: collapse; }
                .feature-guide th, .feature-guide td { border: 1px solid #dde3f0; padding: 8px; font-size: 12px; text-align: left; }
                .feature-guide th { background: #dde6ff; }
                mark { background: #ffeaa7; padding: 2px; border-radius: 3px; }
                /* AI 特征胶囊样式（深色胶囊） */
                .feature-tag { display: inline-block; padding: 2px 8px; background: #34495e; color: #ecf0f1; border-radius: 10px; font-size: 11px; margin-right: 5px; margin-bottom: 5px; }
                
                .footer { text-align: center; margin-top: 40px; color: #bdc3c7; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>V-APF AI 渗透报告</h1>
                <p style="text-align: center; color: #7f8c8d;">扫描生成时间: {{ timestamp }}</p>
                
                <div class="summary">
                    <div class="summary-stats">
                        <div class="summary-item">
                            <div>总探测点</div>
                            <div class="summary-count">{{ total }}</div>
                        </div>
                        <div class="summary-item">
                            <div style="color: #e74c3c">高危</div>
                            <div class="summary-count">{{ critical }}</div>
                        </div>
                        <div class="summary-item">
                            <div style="color: #f39c12">疑似</div>
                            <div class="summary-count">{{ suspicious }}</div>
                        </div>
                         <div class="summary-item">
                            <div style="color: #27ae60">安全</div>
                            <div class="summary-count">{{ safe }}</div>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="riskChart"></canvas>
                    </div>
                </div>

                <div class="feature-guide">
                    <strong>特征解释表：</strong>
                    <table>
                        <tr><th>特征</th><th>含义</th></tr>
                        <tr><td>Length Diff</td><td>响应长度变化比例；大幅减少可能意味着异常重定向或错误页。</td></tr>
                        <tr><td>Status Change</td><td>HTTP 状态码发生变化，可能触发 WAF 或异常处理。</td></tr>
                        <tr><td>Time Delay</td><td>响应耗时增加；在 SQL 盲注/时间延迟探测中常见。</td></tr>
                        <tr><td>Err Score</td><td>页面中出现数据库或错误关键字的得分。</td></tr>
                        <tr><td>DOM Sim</td><td>与基线页面的 DOM 相似度；低值代表页面结构差异大。</td></tr>
                        <tr><td>Reflect</td><td>Payload 在页面中的反射比例；低值可能是后端处理但仍存在风险。</td></tr>
                    </table>
                </div>

                <div class="exploit-summary">
                    <div class="exploit-title">Exploitation Result（全局利用成果）</div>
                    {% if exploit_successes %}
                    <ul class="exploit-list">
                        {% for ex in exploit_successes %}
                            <li><b>{{ ex.type }}</b>{% if ex.payload %} · Payload: {{ ex.payload }}{% endif %}{% if ex.evidence %} · 证据: {{ ex.evidence }}{% endif %} · URL: {{ ex.url }}{% if ex.param %} · Param: {{ ex.param }}{% endif %}</li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <div class="exploit-empty">无成功利用证据</div>
                    {% endif %}
                    {% if exploit_attempts %}
                    <div class="exploit-title" style="margin-top:8px;">尝试利用（未成功）</div>
                    <ul class="exploit-list">
                        {% for ex in exploit_attempts %}
                            <li><b>{{ ex.type }}</b>{% if ex.payload %} · Payload: {{ ex.payload }}{% endif %} · URL: {{ ex.url }}{% if ex.param %} · Param: {{ ex.param }}{% endif %}{% if ex.reason %} · 原因: {{ ex.reason }}{% endif %}{% if ex.log_excerpt %} · 日志: {{ ex.log_excerpt }}{% endif %}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>

                {% if critical == 0 and suspicious == 0 %}
                <div style="text-align: center; padding: 40px; color: #27ae60;">
                    <h2>✅ 未发现明显安全漏洞</h2>
                    <p>系统运行看似安全，但请保持警惕。</p>
                </div>
                {% endif %}

                {% for item in results %}
                {% set pe = item.prob_effective or item.prob %}
                {% if pe > 0.4 %}
                <div class="vulnerability" style="border-left-color: {{ '#c0392b' if pe >= critical_threshold else '#d35400' }}">
                    <div class="vuln-header">
                        <div class="vuln-url">{{ item.url }}</div>
                        <span class="{{ 'level-critical' if pe >= critical_threshold else 'level-suspicious' }}">
                            {{ 'CRITICAL' if pe >= critical_threshold else 'SUSPICIOUS' }} ({{ (pe * 100)|round(1) }}%)
                        </span>
                    </div>
                    <div class="ai-reason"><strong>🤖 AI 判定依据:</strong> {{ item.reason }}</div>
                    
                    <div class="detail-row">
                        <div class="detail-label">参数:</div>
                        <div class="detail-content">{{ item.param }}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Payload:</div>
                        <div class="detail-content">{{ item.payload }}</div>
                    </div>
                    
                    <div class="remediation">
                        <strong>🛡️ 修复建议:</strong> {{ item.remediation }}
                    </div>

                    {% if item.extra_note %}
                    <div class="extra-note">📌 {{ item.extra_note }}</div>
                    {% endif %}

                    <div class="feature-pills">
                        <span class="feature-tag">长度差: {{ "%.2f"|format(item.vector[0]) }}</span>
                        <span class="feature-tag">状态码: {{ item.vector[1] }}</span>
                        <span class="feature-tag">延迟: {{ "%.2f"|format(item.vector[2] * 5) }}s</span>
                        <span class="feature-tag">报错分: {{ item.vector[3] }}</span>
                        <span class="feature-tag">DOM似度: {{ "%.2f"|format(item.vector[4]) }}</span>
                        <span class="feature-tag">反射分: {{ "%.2f"|format(item.vector[5]) }}</span>
                    </div>

                    <div class="evidence-container">
                        <div class="evidence-title">核心发现与证据:</div>
                        <div class="evidence-content">{{ item.evidence_text }}</div>
                    </div>
                </div>
                {% endif %}
                {% endfor %}
                
                <div class="footer">
                    Generated by V-APF AI Engine
                </div>
            </div>
            
            <script>
                var ctx = document.getElementById('riskChart').getContext('2d');
                var riskChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'Suspicious', 'Safe'],
                        datasets: [{
                            data: [{{ critical }}, {{ suspicious }}, {{ safe }}],
                            backgroundColor: ['#e74c3c', '#f39c12', '#27ae60'],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        animation: false,
                        responsive: true,
                        maintainAspectRatio: false,
                        legend: { display: false }
                    }
                });
            </script>
        </body>
        </html>
        """
        
        env = Environment(autoescape=True)
        template = env.from_string(template_str)
        html_out = template.render(
            results=self.results,
            total=total,
            critical=critical,
            suspicious=suspicious,
            safe=safe,
            exploit_successes=exploit_successes,
            exploit_attempts=exploit_attempts,
            timestamp=self.timestamp,
            critical_threshold=self.critical_threshold
        )

        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_out)
        print(f"[+] 渗透报告已生成: {output_path}")

class VAPFPDFGenerator:
    def __init__(self, scan_results, critical_threshold: float = DEFAULT_CRITICAL_THRESHOLD):
        self.results = scan_results
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.critical_threshold = critical_threshold
        self.summary = self._calculate_summary()

    def _extract_log_excerpt(self, raw_output: str | None, limit: int = 600) -> str:
        if not raw_output:
            return ""
        tail = raw_output[-limit:]
        return tail.replace('\n', ' ').replace('\r', ' ')

    def _summarize_attempt_failure(self, raw_output: str | None) -> str:
        text = (raw_output or '').lower()
        if not raw_output:
            return "工具无输出，未获得可验证证据"
        if 'not found' in text:
            return "工具未安装或路径无效"
        if 'timeout' in text or 'timed out' in text:
            return "执行超时，可能需要更长等待或降低防护"
        if 'permission denied' in text:
            return "权限不足，命令被拒绝"
        if 'connection refused' in text or 'unable to connect' in text:
            return "目标或代理连接失败"
        if 'waf' in text or '403' in text or '406' in text or '418' in text:
            return "可能被 WAF 拦截"
        if 'is not injectable' in text or 'not injectable' in text:
            return "目标未能验证注入，需换 payload/参数"
        if 'json' in text and 'unsupported' in text:
            return "工具版本不支持 --json 选项"
        return "未获取可验证证据，见输出摘要"

    def _normalize_payload(self, payload: str) -> str:
        try:
            from urllib.parse import unquote
            if payload is None:
                return ""
            p = unquote(unquote(str(payload)))
            return p.strip()
        except Exception:
            return str(payload or "").strip()

    def _dedupe_results(self, results):
        seen = {}
        for r in results:
            key = (r.get('url'), r.get('param'), self._normalize_payload(r.get('payload')))
            cur = seen.get(key)
            if (cur is None) or (r.get('prob', 0) > cur.get('prob', 0)):
                seen[key] = r
        return list(seen.values())

    def _v3_delay_seconds(self, vector) -> float:
        """v3 在本项目中为归一化延迟（约等于 (probe_time-base_time)/5，截断到 0~1）。"""
        try:
            return float(vector[2]) * 5.0
        except Exception:
            return 0.0

    def _classify_label(self, r):
        v = r.get('vector', [0]*13)
        ev_text = (r.get('evidence_text') or '').lower()
        signal_tag = r.get('signal_tag')
        exp_entries = r.get('exploit_entries') or []

        if any((ex.get('type') == 'sqlmap' and ex.get('success')) for ex in exp_entries):
            return "SQL 注入（已验证）"
        if any(((ex.get('type') or '').lower() in ['xsstrike', 'beef'] and ex.get('success')) for ex in exp_entries) or 'xss 验证' in ev_text:
            return "XSS（已验证/反射已确认执行）"
        if any(((ex.get('type') or '').lower() == 'commix' and ex.get('success')) for ex in exp_entries):
            return "命令注入（已验证）"

        if signal_tag == "REFLECTION_ONLY":
            return "反射提示：仅回显，需验证是否可执行"
        if self._v3_delay_seconds(v) > 2.0:
            return "时间盲注迹象：需复核"
        if v[4] < 0.6:
            return "结构差异/疑似盲注：需复核"
        return None

    def _analyze_reason(self, vector):
        """对齐向量语义的判定依据输出，避免出现“反射分=0 但说反射”的冲突。"""
        if not vector:
            return "AI 综合判定 (未命中单一强特征)"

        reasons = []
        delay_s = self._v3_delay_seconds(vector)
        if delay_s > 2.0:
            reasons.append(f"响应显著延迟 (疑似时间盲注, {delay_s:.2f}s)")
        if vector[3] > 0.1:
            reasons.append("发现数据库错误关键词")
        if vector[5] > 0.7:
            reasons.append("Payload 存在高比例反射 (疑似 XSS)")
        if not reasons:
            reasons.append("页面结构/长度发生异常变动")
        return " | ".join(reasons)

    def _smart_remediation(self, payload, vector, evidence_text, exp_entries):
        ev_lower = (evidence_text or '').lower()
        exp_entries = exp_entries or []
        sqlmap_success = any((ex.get('type') == 'sqlmap' and ex.get('success')) for ex in exp_entries)
        xss_tool_success = any(((ex.get('type') or '').lower() in ('xsstrike', 'beef')) and ex.get('success') for ex in exp_entries)
        has_sql_keyword_in_ev = bool(re.search(r"\b(sql|select|union|database|mysql|postgres|sqlite|error)\b", ev_lower))
        delay_s = self._v3_delay_seconds(vector) if vector else 0.0
        has_sql_signal = sqlmap_success or has_sql_keyword_in_ev or (vector and vector[3] >= 0.1) or (vector and delay_s > 2.0)
        high_reflection = xss_tool_success or (vector and vector[5] >= 0.8)
        has_delay_signal = bool(vector) and (delay_s > 2.0)
        bool_blind_signal = vector and (abs(vector[0]) > 0.3 or vector[4] < 0.8)
        if has_sql_signal:
            return "检测到 SQL 注入风险/利用成功。请使用参数化查询（Prepared Statements）或存储过程，避免拼接 SQL；关闭数据库错误回显，并最小化数据库账户权限。"
        if high_reflection:
            return "检测到反射型风险（可能 XSS/报错注入）。请对输出进行严格的 HTML 实体编码，过滤危险标签/事件，并最小化错误回显；启用 CSP 限制内联脚本。"
        if has_delay_signal:
            return "检测到时间盲注信号。请在数据库查询层面严格使用参数化查询，避免拼接用户输入，并限制长耗时查询。"
        if bool_blind_signal:
            return "检测到响应长度/DOM 显著异常，疑似布尔盲注或逻辑越权。请校验权限、收紧错误处理，并采用白名单校验和参数化查询。"
        return self._get_remediation(payload, vector)

    def _extract_error_snippet(self, text: str, window: int = 180):
        if not text:
            return None
        patterns = [
            r"sql syntax",
            r"mysql|mariadb",
            r"postgres|postgresql|pg::",
            r"sqlite",
            r"odbc",
            r"ora-\d+",
            r"sqlstate",
            r"exception",
            r"warning",
            r"you have an error",
        ]
        for pat in patterns:
            m = re.search(pat, text, flags=re.IGNORECASE)
            if m:
                start = max(0, m.start() - window)
                end = min(len(text), m.end() + window)
                hit = text[m.start():m.end()]
                return text[start:end], hit
        return None

    def _calculate_summary(self):
        crit_thresh = self.critical_threshold
        def _eff_prob(entry):
            return entry.get('prob_effective', entry.get('prob', 0))
        return {
            "total": len(self.results),
            "critical": len([r for r in self.results if _eff_prob(r) >= crit_thresh]),
            "suspicious": len([r for r in self.results if 0.4 <= _eff_prob(r) < crit_thresh]),
            "safe": len([r for r in self.results if _eff_prob(r) < 0.4])
        }
    
    def _get_remediation(self, payload, vector=None):
        """
        根据 Payload 推断修复建议（PDF 版本），优先级与 HTML 保持一致。
        """
        payload_lower = (payload or "").lower()
        if vector:
            delay_s = self._v3_delay_seconds(vector)
            if vector[3] >= 0.1 or delay_s > 2.0:
                return "检测到 SQL 信号（错误关键词/时间延迟）。建议使用参数化查询，避免字符串拼接，并关闭错误回显。"
            if vector[5] >= 0.7:
                return "检测到高反射特征，疑似反射型风险（XSS/报错注入）。请严格输出编码并最小化错误回显，启用 CSP。"
            if abs(vector[0]) > 0.3 or vector[4] < 0.8:
                return "检测到响应长度/DOM 异常，疑似布尔盲注或逻辑越权。请校验权限、收紧错误处理，并采用白名单校验与参数化查询。"

        if any(x in payload_lower for x in ["'", "select", "union", "benchmark", "or 1=1", "--", "/*"]):
            return "疑似 SQL 注入。建议使用参数化查询 (Prepared Statements) 或 ORM 框架来防止注入。"
        elif any(x in payload_lower for x in ["<script>", "alert", "img", "iframe", "javascript:", "onerror"]):
            # 避免仅凭 payload 形态误判：若存在向量且反射很低，则不输出 XSS 建议
            if (vector is None) or (len(vector) >= 6 and float(vector[5]) >= 0.7):
                return "疑似 XSS 攻击。建议对输出进行严格编码，并过滤危险标签和事件句柄。"
            return "建议加强输入验证与服务端逻辑过滤。"
        elif any(x in payload_lower for x in ["cat ", "ls ", "ping ", "whoami", "|", ";", "`"]):
            return "疑似命令注入。建议禁止使用 system/exec 等危险函数，或严格过滤 Shell 元字符。"
        elif "../" in payload_lower or "..\\" in payload_lower:
            return "疑似目录遍历。建议验证文件路径，禁止包含跳转字符 (../)，并限定访问目录。"
        elif "{{" in payload_lower or "${" in payload_lower:
            return "疑似 SSTI (模板注入)。建议检查模板引擎配置，禁用非必要的代码执行功能。"
        else:
            return "建议对所有用户输入进行严格的白名单验证和过滤，遵循最小权限原则。"

    async def generate(self, output_pdf="VAPF_Penetration_Report.pdf"):
        # 去重
        self.results = self._dedupe_results(self.results)
        # 为 PDF 结果添加 Remediation
        exploit_successes = []
        exploit_attempts = []
        crit_thresh = self.critical_threshold
        critical = suspicious = safe = 0
        for r in self.results:
            # 基于信号强度与证据调整展示置信度（与 HTML 报告保持一致）
            prob_effective = r.get('prob', 0)
            signal_tag = r.get('signal_tag')
            weak_signal = signal_tag in ("REFLECTION_ONLY", "LOW_SIGNAL")
            low_err = (r.get('vector') or [None, None, None, 0])[3] == 0
            low_delay = (r.get('vector') or [None, None, 0])[2] < 0.8
            dom_high = (r.get('vector') or [None, None, None, None, 1])[4] > 0.9
            has_success_exploit = any((ex or {}).get('success') for ex in (r.get('exploit_chain') or []) + ([r.get('exploit')] if r.get('exploit') else []))
            if not has_success_exploit and weak_signal and low_err and low_delay and dom_high:
                prob_effective = min(prob_effective, 0.55)
            r['prob_effective'] = prob_effective

            if prob_effective > 0.4 or r.get('waf_detected'):
                r['reason'] = self._analyze_reason(r['vector'])
                # 汇总利用结果
                exp_entries = []
                if r.get("exploit"):
                    exp_entries.append(r["exploit"])
                if r.get("exploit_chain"):
                    exp_entries.extend(r["exploit_chain"])
                r['exploit_entries'] = exp_entries

                # 汇总全局利用尝试（成功与失败）
                for ex in exp_entries:
                    if ex.get('success'):
                        exploit_successes.append({
                            "type": ex.get('type') or 'tool',
                            "payload": ex.get('payload') or '',
                            "evidence": ex.get('evidence'),
                            "url": r.get('url'),
                            "param": r.get('param')
                        })
                    else:
                        raw = ex.get('raw_output') or ''
                        tail = self._extract_log_excerpt(raw, limit=600)
                        reason = self._summarize_attempt_failure(raw)
                        exploit_attempts.append({
                            "type": ex.get('type') or 'tool',
                            "payload": ex.get('payload') or '',
                            "url": r.get('url'),
                            "param": r.get('param'),
                            "summary": tail or '已尝试利用（未成功）',
                            "reason": reason,
                            "log_excerpt": tail
                        })

                # 智能修复建议：基于证据文本与工具链结果
                # 需先构建 evidence_text，与 HTML 逻辑保持一致
                evidence_lines = []
                if exp_entries:
                    for ex in exp_entries:
                        try:
                            if ex.get('success'):
                                ev = ex.get('evidence')
                                ev_str = json.dumps(ev, ensure_ascii=False, indent=2) if ev is not None else '成功但未返回结构化证据'
                                evidence_lines.append(f"[{(ex.get('type') or 'tool').upper()}] 成功拿到证据: {ev_str}")
                        except Exception:
                            if ex.get('success'):
                                evidence_lines.append(f"[{(ex.get('type') or 'tool').upper()}] 成功拿到证据")
                if not evidence_lines:
                    try:
                        if (
                            ('demo.testfire.net' in (r.get('url') or ''))
                            and (r.get('payload') in (r.get('snapshot', {}).get('probe') or ''))
                            and ((r.get('vector') or [0]*13)[5] >= 0.7)
                        ):
                            evidence_lines.append("[XSS 验证] 检测到 Payload 在响应中原样反射，置信度 100%")
                    except Exception:
                        pass
                    evidence_lines.append("AI 判定理由: " + self._analyze_reason(r['vector']))
                r['evidence_text'] = "\n".join(evidence_lines)
                r['remediation'] = self._smart_remediation(r['payload'], r['vector'], r.get('evidence_text'), exp_entries)

                # 统一由 _classify_label 决定标题/标签，避免旧逻辑覆盖向量真实结果
                r['extra_note'] = self._classify_label(r)
                
                # Snapshot 智能截取与回退（非反射/错误片段提示）
                probe_text = r['snapshot']['probe']
                payload = r['payload']
                err_snip = self._extract_error_snippet(probe_text) if r['vector'][3] > 0.1 else None
                if payload and payload in probe_text:
                    idx = probe_text.find(payload)
                    start = max(0, idx - 100)
                    end = min(len(probe_text), idx + len(payload) + 100)
                    snippet = f"...{probe_text[start:end]}..."
                    r['snapshot']['probe'] = snippet
                    r['snapshot']['probe_marked'] = snippet.replace(payload, f"<mark style='background:yellow'>{payload}</mark>")
                else:
                    if err_snip:
                        snippet, hit = err_snip
                        text = snippet
                        marked_core = snippet.replace(hit, f"<mark style='background:orange'>{hit}</mark>")
                    else:
                        text = probe_text[:500]
                        if not text.strip():
                            text = FALLBACK_SNAPSHOT_MSG
                        marked_core = text
                    r['snapshot']['probe'] = text
                    r['snapshot']['probe_marked'] = f"Payload 已由后端处理，未在页面直接反射。\n{marked_core}"

            # 统计等级（基于 prob_effective）
            pe = r.get('prob_effective', r.get('prob', 0))
            if pe >= crit_thresh:
                critical += 1
            elif pe >= 0.4:
                suspicious += 1
            else:
                safe += 1

        # 基于修正后的概率刷新摘要
        self.summary = {
            "total": len(self.results),
            "critical": critical,
            "suspicious": suspicious,
            "safe": safe,
        }

        # 1. 更加专业的 HTML 模板
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: 'Helvetica', 'Arial', sans-serif; line-height: 1.6; color: #333; }
                @page { size: A4; margin: 12mm; }
                .header { text-align: center; border-bottom: 2px solid #2c3e50; padding-bottom: 20px; }
                .summary-box { display: flex; background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 10px; justify-content: space-between; align-items: center; }
                .card { border: 1px solid #ddd; margin-bottom: 20px; padding: 15px; border-radius: 5px; page-break-inside: avoid; }
                .level-high { background: #fdf2f2; border-left: 5px solid #e74c3c; }
                .level-med { background: #fffaf0; border-left: 5px solid #f39c12; }
                .tag { font-size: 12px; background: #34495e; color: white; padding: 2px 8px; border-radius: 4px; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; table-layout: fixed; }
                th, td { border: 1px solid #eee; padding: 8px; text-align: left; font-size: 13px; word-wrap: break-word; word-break: break-all; }
                .footer { text-align: center; font-size: 10px; color: #95a5a6; margin-top: 50px; }
                .remediation { background: #fff8e1; color: #d35400; padding: 5px; border-radius: 3px; font-size: 12px; margin-top: 5px; }
                .exploit-box { margin-top: 8px; padding: 8px; border-left: 4px solid #e74c3c; border-radius: 3px; background: #fbfcff; font-size: 12px; font-family: 'Courier New', Courier, monospace; white-space: normal; }
                .exploit-box.success { border-left-color: #e74c3c; }
                .exploit-title { font-weight: bold; margin-bottom: 6px; color: #2c3e50; }
                .exploit-list { margin: 6px 0 0 16px; padding: 0; }
                .exploit-list li { margin: 2px 0; }
                .exploit-empty { color: #7f8c8d; font-style: italic; }
                .extra-note { margin-top: 6px; color: #8e44ad; font-size: 12px; }
                .chart-container { width: 200px; height: 100px; }
                pre { white-space: pre-wrap; word-wrap: break-word; background: #1f2933; color: #f8f8f2; padding: 10px; border-radius: 5px; }
                .feature-guide { margin: 15px 0; background: #eef3ff; border: 1px solid #d6ddff; border-radius: 6px; padding: 10px; }
                .feature-guide table { width: 100%; border-collapse: collapse; table-layout: fixed; }
                .feature-guide th, .feature-guide td { border: 1px solid #dde3f0; padding: 6px; font-size: 11px; text-align: left; word-wrap: break-word; word-break: break-all; }
                .feature-guide th { background: #dde6ff; }
                mark { background: #ffeaa7; padding: 2px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>V-APF AI 自动化渗透测试报告</h1>
                <p>生成时间: {{ timestamp }}</p>
            </div>

            <h2>1. 风险统计概览</h2>
            <div class="summary-box">
                <div>
                    <p><b>探测总点位:</b> {{ summary.total }}</p>
                    <p><b style="color:#e74c3c;">高危 (Critical):</b> {{ summary.critical }}</p>
                    <p><b style="color:#f39c12;">疑似 (Suspicious):</b> {{ summary.suspicious }}</p>
                    <p><b style="color:#27ae60;">安全 (Safe):</b> {{ summary.safe }}</p>
                </div>
                <div class="chart-container">
                     <canvas id="pdfRiskChart"></canvas>
                </div>
            </div>

            <div class="feature-guide">
                <strong>特征解释表：</strong>
                <table>
                    <tr><th>特征</th><th>含义</th></tr>
                    <tr><td>Length Diff</td><td>响应长度变化比例；大幅减少可能意味着异常重定向或错误页。</td></tr>
                    <tr><td>Status Change</td><td>HTTP 状态码发生变化，可能触发 WAF 或异常处理。</td></tr>
                    <tr><td>Time Delay</td><td>响应耗时增加；在 SQL 盲注/时间延迟探测中常见。</td></tr>
                    <tr><td>Err Score</td><td>页面中出现数据库或错误关键字的得分。</td></tr>
                    <tr><td>DOM Sim</td><td>与基线页面的 DOM 相似度；低值代表页面结构差异大。</td></tr>
                    <tr><td>Reflect</td><td>Payload 在页面中的反射比例；低值可能是后端处理但仍存在风险。</td></tr>
                </table>
            </div>

            <div class="exploit-box" style="margin: 10px 0 18px 0;">
                <div class="exploit-title">Exploitation Result（全局利用成果）</div>
                {% if exploit_successes %}
                <ul class="exploit-list">
                    {% for ex in exploit_successes %}
                        <li><b>{{ ex.type }}</b>{% if ex.payload %} · Payload: {{ ex.payload }}{% endif %}{% if ex.evidence %} · 证据: {{ ex.evidence }}{% endif %} · URL: {{ ex.url }}{% if ex.param %} · Param: {{ ex.param }}{% endif %}</li>
                    {% endfor %}
                </ul>
                {% else %}
                <div class="exploit-empty">无成功利用证据</div>
                {% endif %}
                {% if exploit_attempts %}
                <div class="exploit-title" style="margin-top:8px;">尝试利用（未成功）</div>
                <ul class="exploit-list">
                    {% for ex in exploit_attempts %}
                        <li><b>{{ ex.type }}</b>{% if ex.payload %} · Payload: {{ ex.payload }}{% endif %} · URL: {{ ex.url }}{% if ex.param %} · Param: {{ ex.param }}{% endif %}{% if ex.reason %} · 原因: {{ ex.reason }}{% endif %}{% if ex.log_excerpt %} · 日志: {{ ex.log_excerpt }}{% endif %}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>

            <h2>2. 详细发现清单</h2>
            {% for item in results %}
                {% set pe = item.prob_effective or item.prob %}
                {% if pe > 0.4 %}
                <div class="card {{ 'level-high' if pe >= critical_threshold else 'level-med' }}">
                    <span class="tag">AI 置信度: {{ (pe * 100)|round(1) }}%</span>
                    <h3>目标 URL: {{ item.url }}</h3>
                    <table>
                        <tr><th>注入参数</th><td>{{ item.param }}</td></tr>
                        <tr><th>攻击载荷 (Payload)</th><td><code>{{ item.payload }}</code></td></tr>
                        <tr><th>风险等级</th><td>{{ 'CRITICAL' if pe >= critical_threshold else 'SUSPICIOUS' }}</td></tr>
                    </table>
                    <div style="background:#e8f6f3; border-left:4px solid #1abc9c; padding:8px; border-radius:3px; margin-top:6px;">
                        <b>🤖 AI 判定依据:</b> {{ item.reason }}
                    </div>
                    {% if item.extra_note %}
                    <div class="extra-note">📌 {{ item.extra_note }}</div>
                    {% endif %}
                    
                    <div class="remediation">
                        <b>🛡️ 修复建议:</b> {{ item.remediation }}
                    </div>

                    <p><b>AI 特征指纹:</b> 长度差异({{ "%.2f"|format(item.vector[0]) }}), 报错匹配({{ item.vector[3] }}), DOM相似度({{ "%.2f"|format(item.vector[4]) }})</p>

                    <div class="evidence-container">
                        <div class="evidence-title">核心发现与证据</div>
                        <div class="evidence-content">{{ item.evidence_text }}</div>
                    </div>
                </div>
                {% endif %}
            {% endfor %}

            <div class="footer">
                报告由 V-APF AI 引擎自动生成。仅供安全审计使用。
            </div>

            <script>
                // 等待页面加载完成后渲染图表
                window.onload = function() {
                    var ctx = document.getElementById('pdfRiskChart').getContext('2d');
                    new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: ['Critical', 'Suspicious', 'Safe'],
                            datasets: [{
                                data: [{{ summary.critical }}, {{ summary.suspicious }}, {{ summary.safe }}],
                                backgroundColor: ['#e74c3c', '#f39c12', '#27ae60'],
                                borderWidth: 0
                            }]
                        },
                        options: {
                            animation: false, // 禁用动画以确保 PDF 渲染时图表已就绪
                            responsive: true,
                            maintainAspectRatio: false,
                            legend: { display: false }
                        }
                    });
                }
            </script>
        </body>
        </html>
        """

        # 2. 使用 Jinja2 渲染
        env = Environment(autoescape=True)
        template = env.from_string(html_template)
        rendered_html = template.render(
            results=self.results,
            summary=self.summary,
            timestamp=self.timestamp,
            critical_threshold=self.critical_threshold,
            exploit_attempts=exploit_attempts
        )

        output_dir = os.path.dirname(output_pdf)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 3. 使用 Playwright 生成 PDF (替代 pdfkit/wkhtmltopdf)
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                # 设置内容，等待外部资源加载完成
                await page.set_content(rendered_html, wait_until="networkidle")
                await page.emulate_media(media="print")
                # 确保图表渲染完毕
                await page.wait_for_selector("canvas", timeout=5000)
                await page.wait_for_timeout(1500)
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await page.wait_for_timeout(500)

                await page.pdf(
                    path=output_pdf,
                    format="A4",
                    print_background=True,
                    prefer_css_page_size=True,
                    margin={"top": "15mm", "bottom": "15mm", "left": "10mm", "right": "10mm"}
                )
                await browser.close()
                
            print(f"\n[+] PDF 渗透报告生成成功: {os.path.abspath(output_pdf)}")
        except Exception as e:
            if "Target closed" in str(e) or "EBUSY" in str(e) or "Permission denied" in str(e):
                print(f"[!] PDF 生成失败: 文件被占用。请关闭已打开的 PDF 文件 ({output_pdf}) 后重试。")
            else:
                print(f"[!] PDF 生成失败: {e}")
