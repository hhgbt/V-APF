import argparse
import asyncio
import datetime
import joblib
import numpy as np
import os
import random
import re
import sys
import pandas as pd
from urllib.parse import urlparse, parse_qs

# Ensure core is in path if running from root
sys.path.append(os.getcwd())

from core.extractor import FeatureExtractor
from core.mutator import SAFSMutator
from core.exploit_engine import run_sqlmap, run_beef_xss, run_commix, run_msfconsole_cmd
from playwright.async_api import async_playwright
from sklearn.preprocessing import MinMaxScaler

DEFAULT_THRESHOLD = 0.65
FEATURE_NAMES = [f"v{i+1}" for i in range(13)]

class SAFSPredictScanner:
    def __init__(self, model_path="models/safs_rf_model.pkl", scaler_path="models/scaler.pkl", default_headers=None):
        print("[*] 正在加载 V-APF AI 引擎...")
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        # 实例化提取器，仅用于复用它的 compute_13_vector 逻辑
        self.extractor = FeatureExtractor(default_headers=default_headers)
        self.mutator = SAFSMutator() # 实例化变异引擎
        self.final_results = [] # 新增：用于存储所有探测结果
        # 运行期配置在 scan_url 中设置
        self.sem = None
        self.exploit_sem = asyncio.Semaphore(1)  # 自动利用串行队列，避免并发踩踏
        self.current_critical_threshold = DEFAULT_THRESHOLD
        self.mutation_count = 1
        self.waf_hits = 0
        self.total_tests = 0
        self.baseline_status = None

    def _detect_payload_prior(self, payload: str | None) -> str:
        p = (payload or "").lower()
        sql_markers = ["union", "select", "sleep(", "benchmark(", " or ", " and ", "'", "\"", "--", "#", "/*"]
        cmd_markers = ["&&", "||", "|", "`", "$(", ";", "whoami", "id", "uname", "cat ", "wget ", "curl ", "nc "]
        xss_markers = ["<script", "onerror=", "onload=", "javascript:", "<img", "<svg", "<iframe", "alert("]
        if any(m in p for m in sql_markers):
            return "sql"
        if any(m in p for m in cmd_markers):
            return "cmd"
        if any(m in p for m in xss_markers):
            return "xss"
        return "unknown"

    def _apply_signal_sanity(self, prob: float, vector, status: int | None, payload: str | None = None):
        """
        中间方案：对仅反射/弱信号的结果做概率降噪，避免“回显即高危”。
        - 反射且无错误/无延时/长度变化微弱且状态未变：上限 0.50，标记 REFLECTION_ONLY。
        - 无错误/无延时/长度微弱且 DOM 高度相似：上限 0.55，标记 LOW_SIGNAL。

        激进模式（默认启用）：对明显 SQL/命令注入形态的 payload 不做封顶，避免高危被错误降噪。
        """
        prior = self._detect_payload_prior(payload)
        if prior in ("sql", "cmd", "xss"):
            return prob, f"BYPASS_SANITY_{prior.upper()}"
        try:
            reflect = vector[5]
            err = vector[3]
            dom = vector[4]
            delay = vector[2]
            length_delta = vector[0]
            status_same = (status is None) or (self.baseline_status is None) or (status == self.baseline_status)
        except Exception:
            return prob, None

        # 反射但无执行证据、无错误、无延时、状态未变
        if reflect > 0.2 and err == 0 and delay < 0.8 and abs(length_delta) < 0.2 and status_same:
            return min(prob, 0.50), "REFLECTION_ONLY"

        # 全局弱信号：无错误、无延时、长度微弱、DOM 相似
        if err == 0 and delay < 0.8 and abs(length_delta) < 0.2 and dom > 0.9 and status_same:
            return min(prob, 0.55), "LOW_SIGNAL"

        return prob, None

    def _sanitize_name(self, name: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
        return safe or "report"

    def _url_to_name(self, target_url: str) -> str:
        parsed = urlparse(target_url)
        host = parsed.hostname or "report"
        path = (parsed.path or "").strip("/")
        base = f"{host}_{path}" if path else host
        return self._sanitize_name(base)[:120]

    def _build_report_paths(self, target_url: str, report_name=None, report_dir="reports", suffix=None):
        base = self._sanitize_name(report_name) if report_name else self._url_to_name(target_url)
        if suffix:
            base = f"{base}_{self._sanitize_name(suffix)}"
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{base}_{timestamp}"
        html_path = os.path.join(report_dir, f"{base}.html")
        pdf_path = os.path.join(report_dir, f"{base}.pdf")
        return html_path, pdf_path

    def _apply_feature_engineering(self, vector):
        """特征工程处理：对原始 13 维向量进行转换，适配模型输入"""
        if isinstance(vector, dict):
            ordered = [vector.get(name, 0.0) for name in FEATURE_NAMES]
        else:
            if len(vector) != len(FEATURE_NAMES):
                raise ValueError(f"Feature vector length mismatch: expected {len(FEATURE_NAMES)}, got {len(vector)}")
            ordered = list(vector)

        v_df = pd.DataFrame([ordered], columns=FEATURE_NAMES)
        v_scaled = self.scaler.transform(v_df.values)
        return v_scaled

    async def _scan_single_payload(self, page, target_url, method, params, param_name, payload, base_data, threshold=DEFAULT_THRESHOLD):
        async with self.sem:
            probe_page = await page.context.new_page()
            # 自动处理 JS 弹窗（alert/confirm/prompt），避免阻塞探测
            probe_page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
            try:
                # 防止页面长期 pending 导致“卡死”：对单次探测加硬超时
                current_vector, probe_data = await asyncio.wait_for(
                    self.extractor.probe_and_get_vector(
                        probe_page, target_url, method, params, param_name, payload, base_data
                    ),
                    timeout=25,
                )
                self.total_tests += 1

                v_processed = self._apply_feature_engineering(current_vector)
                prob = self.model.predict_proba(v_processed)[0][1]

                is_waf = False
                waf_reason = ""
                status = probe_data.get('status')
                if status in [403, 406, 418, 429]:
                    is_waf = True
                    waf_reason = f"状态码异常 ({status})"
                    self.waf_hits += 1
                    prob = prob * 0.5

                prob_adj, signal_tag = self._apply_signal_sanity(prob, current_vector, status, payload)
                result = {
                    "url": target_url,
                    "param": param_name,
                    "payload": payload,
                    "prob_raw": float(prob),
                    "prob": float(prob_adj),
                    "vector": current_vector,
                    "waf_detected": is_waf,
                    "waf_reason": waf_reason,
                    "response_status": probe_data.get("status"),
                    "response_headers": probe_data.get("headers", {}),
                    "signal_tag": signal_tag,
                    "snapshot": {
                        "base": base_data.get("text", "")[:2000],
                        "probe": probe_data.get("text", "")[:2000]
                    }
                }
                self.final_results.append(result)

                # 告警展示以 prob_effective 为准（与自动利用/报告一致）；若原始分数更高则额外提示降噪原因
                if prob_adj > threshold or is_waf or prob > threshold:
                    self._print_alert(
                        prob_adj,
                        payload,
                        param=param_name,
                        waf_info=waf_reason,
                        prob_raw=prob,
                        signal_tag=signal_tag,
                    )
            except Exception:
                pass
            finally:
                try:
                    await probe_page.close()
                except Exception:
                    pass

    async def scan_url(self, target_url, method="GET", params=None, scan_mode="single", threshold=DEFAULT_THRESHOLD,
                      headless=True, max_payloads=None, report_name=None, report_dir="reports", report_suffix=None,
                      report_format="both",
                      sqlmap_path="sqlmap", exploit_timeout=600, exploit_max=1,
                      beef_xss_path="beef-xss", msfconsole_path="msfconsole", commix_path="commix",
                      critical_threshold=None, concurrency=3, mutation_count=1, headers=None):
        """
        对单个 URL 进行深度探测与 AI 评分
        :param scan_mode: "single" (逐个参数探测), "all" (全参数同时探测), "combo" (智能组合探测)
        :param threshold: 判定阈值 (0.0 - 1.0)，默认 0.4
        """
        # 每次 scan_url 都应是一次完整流水线：扫描 -> 自动利用 -> 报告。
        # 避免跨多次调用累积结果导致“报告已出但仍在跑 sqlmap”的错觉与重复利用。
        self.final_results = []
        self.waf_hits = 0
        self.total_tests = 0
        self.baseline_status = None

        html_path, pdf_path = self._build_report_paths(target_url, report_name, report_dir, suffix=report_suffix)
        print(f"\n[+] 开始 AI 扫描: {target_url} [{method}] [Mode: {scan_mode}] [Threshold: {threshold}] [Headless: {headless}]")
        # 对齐关键阈值与可重复性/稳定性参数
        self.current_critical_threshold = critical_threshold if critical_threshold is not None else threshold
        self.mutation_count = max(1, mutation_count)
        self.sem = asyncio.Semaphore(max(1, concurrency))
        
        # Ensure params is a dict
        if params is None:
            params = {}
            # Try to parse query params from URL if GET
            if method == "GET":
                parsed = urlparse(target_url)
                query = parse_qs(parsed.query)
                # parse_qs returns list for values, take first
                params = {k: v[0] for k, v in query.items()}
        
        if not params:
            print("    [!] 无参数可注入，将生成空报告以记录本次扫描。")
            from core.report_generator import VAPFReportGenerator, VAPFPDFGenerator
            html_reporter = VAPFReportGenerator(self.final_results, critical_threshold=self.current_critical_threshold)
            html_reporter.generate_html(html_path)
            print("\n[*] 正在生成空 PDF 报告...")
            pdf_reporter = VAPFPDFGenerator(self.final_results, critical_threshold=self.current_critical_threshold)
            await pdf_reporter.generate(pdf_path)
            return

        async with async_playwright() as p:
            browser = None
            context = None
            page = None
            try:
                # 在无图形环境下（如服务器/CI）若用户误用了有头模式，自动降级为无头，避免崩溃
                if not headless and sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
                    print("    [!] 未检测到 XServer，已自动切换为无头模式运行。可用 --no-headless 在本地桌面调试。")
                    headless = True
                browser = await p.chromium.launch(headless=headless)
                if headers:
                    self.extractor.set_default_headers(headers)
                context = await browser.new_context(extra_http_headers=headers or {})
                page = await context.new_page()
                # 自动处理 JS 弹窗（alert/confirm/prompt），避免阻塞基准页/组合探测页
                page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

                # 1. 获取 Baseline (基准响应)
                print("    [*] 正在建立语义基准...")
                # Fetch baseline once
                base_data = await self.extractor.fetch_page_features(page, target_url, method, params)
                self.baseline_status = base_data.get("status")

                # Define injectable parameters
                injectable_params = [k for k in params.keys() if k not in ['submit', 'Login', 'btn', 'action']]
                
                if not injectable_params:
                    print("    [!] 没有发现可注入参数")
                else:
                    # 控制 payload 数量，避免一次性任务过多
                    seeds = self.extractor.payloads
                    if isinstance(max_payloads, int) and max_payloads > 0:
                        seeds = seeds[:max_payloads]

                    if scan_mode == "single":
                        # Mode 1: Single Parameter Injection
                        for param_name in injectable_params:
                            print(f"    -> 测试参数: {param_name}")
                            
                            tasks = []
                            for seed_payload in seeds:
                                # 针对每一个基础 Payload，根据配置生成变异版本，减少随机性可设为 1
                                test_variants = self.mutator.mutate(seed_payload, count=self.mutation_count)
                                
                                for payload in test_variants:
                                    tasks.append(
                                        self._scan_single_payload(page, target_url, method, params, param_name, payload, base_data, threshold)
                                    )
                            
                            print(f"    -> 计划探测任务数: {len(tasks)}（并发={max(1, concurrency)}）")
                            # 并发执行所有探测任务
                            await asyncio.gather(*tasks)
                    
                    elif scan_mode == "combo":
                        # Mode 3: Combination Mutation Injection
                        # 随机挑选 2-3 个核心参数进行注入，保持其他参数为原始值
                        print(f"    -> 启用组合变异探测 (Combo Mode)")
                        
                        # 如果参数少于 2 个，退化为 single 模式
                        if len(injectable_params) < 2:
                            # 禁止递归调用 scan_url：会导致外层 finally 再跑一遍自动利用与报告
                            print("    [!] 参数过少，退化为 Single 模式（同一流程内执行）")
                            scan_mode = "single"
                            for param_name in injectable_params:
                                print(f"    -> 测试参数: {param_name}")

                                tasks = []
                                for seed_payload in seeds:
                                    test_variants = self.mutator.mutate(seed_payload, count=self.mutation_count)
                                    for payload in test_variants:
                                        tasks.append(
                                            self._scan_single_payload(page, target_url, method, params, param_name, payload, base_data, threshold)
                                        )
                                await asyncio.gather(*tasks)
                        else:
                            # 生成组合：生成 min(5, len) 个随机组合
                            num_combos = min(5, len(injectable_params))
                            combinations_to_test = []
                            
                            for _ in range(num_combos):
                                # 随机决定取 2 个还是 3 个 (不超过实际参数量)
                                k = random.randint(2, min(3, len(injectable_params)))
                                subset = random.sample(injectable_params, k)
                                combinations_to_test.append(subset)
                            
                            # 去重
                            combinations_to_test = [list(x) for x in set(tuple(sorted(x)) for x in combinations_to_test)]
                            print(f"    -> 将测试以下参数组合: {combinations_to_test}")

                            for combo in combinations_to_test:
                                print(f"    -> 正在测试组合: {combo}")
                                for payload in seeds:
                                    try:
                                        probe_params = params.copy()
                                        for k in combo:
                                            probe_params[k] = payload
                                        
                                        # Manually fetch and compute vector
                                        probe_data = await self.extractor.fetch_page_features(page, target_url, method, probe_params)
                                        current_vector = self.extractor.compute_13_vector(base_data, probe_data, payload)
                                        
                                        # AI Reasoning
                                        v_processed = self._apply_feature_engineering(current_vector)
                                        prob = self.model.predict_proba(v_processed)[0][1]

                                        # 记录每一条结果（先做反射/弱信号降噪）
                                        prob_adj, signal_tag = self._apply_signal_sanity(prob, current_vector, probe_data.get("status"), payload)
                                        self.final_results.append({
                                            "url": target_url,
                                            "param": f"Combo:{combo}",
                                            "payload": payload,
                                            "prob_raw": float(prob),
                                            "prob": float(prob_adj),
                                            "vector": current_vector,
                                            "response_status": probe_data.get("status"),
                                            "response_headers": probe_data.get("headers", {}),
                                            "signal_tag": signal_tag,
                                            "snapshot": {
                                                "base": base_data.get("text", "")[:2000],
                                                "probe": probe_data.get("text", "")[:2000]
                                            }
                                        })

                                        if prob_adj > threshold or prob > threshold:
                                            self._print_alert(prob_adj, payload, param=f"Combo:{combo}", prob_raw=prob, signal_tag=signal_tag)
                                    except Exception as e:
                                        print(f"    [!] 组合 {combo} 探测异常: {e}")
                                        continue

                    elif scan_mode == "all":
                        # Mode 2: All Parameters Injection (Simultaneous)
                        print(f"    -> 测试全参数同时注入: {injectable_params}")
                        
                        for payload in seeds:
                            try:
                                probe_params = params.copy()
                                for k in injectable_params:
                                    probe_params[k] = payload
                                
                                # Manually fetch and compute vector since probe_and_get_vector is for single param
                                probe_data = await self.extractor.fetch_page_features(page, target_url, method, probe_params)
                                current_vector = self.extractor.compute_13_vector(base_data, probe_data, payload)
                                
                                # AI Reasoning
                                v_processed = self._apply_feature_engineering(current_vector)
                                prob = self.model.predict_proba(v_processed)[0][1]

                                prob_adj, signal_tag = self._apply_signal_sanity(prob, current_vector, probe_data.get("status"), payload)
                                self.final_results.append({
                                    "url": target_url,
                                    "param": "ALL",
                                    "payload": payload,
                                    "prob_raw": float(prob),
                                    "prob": float(prob_adj),
                                    "vector": current_vector,
                                    "response_status": probe_data.get("status"),
                                    "response_headers": probe_data.get("headers", {}),
                                    "signal_tag": signal_tag,
                                    "snapshot": {
                                        "base": base_data.get("text", "")[:2000],
                                        "probe": probe_data.get("text", "")[:2000]
                                    }
                                })

                                if prob_adj > threshold or prob > threshold:
                                    self._print_alert(prob_adj, payload, param="ALL", prob_raw=prob, signal_tag=signal_tag)
                            except Exception as e:
                                print(f"    [!] 全参数探测异常: {e}")
                                continue

            except Exception as e:
                print(f"[!] 扫描流程发生异常：{e}")
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass
                if browser:
                    try:
                        await browser.close()
                    except Exception:
                        pass

                # 若 WAF 拦截占比高，给出提示
                if self.total_tests > 0 and self.waf_hits / self.total_tests > 0.3:
                    print(f"    [!] 检测到可能的防火墙拦截：{self.waf_hits}/{self.total_tests} 次返回 403/429/406/418，结果置信度已降低。")

                # 自动利用（扫描结束后必定尝试，预算由 exploit_max 控制）
                await self._auto_exploit(target_url, threshold, sqlmap_path, exploit_timeout, exploit_max,
                                          beef_xss_path, msfconsole_path, commix_path)

                # 生成报告（即便发生异常也尽力生成可用报告）
                from core.report_generator import VAPFReportGenerator, VAPFPDFGenerator
                fmt = (report_format or "both").lower()
                if fmt in ("both", "html"):
                    html_reporter = VAPFReportGenerator(self.final_results, critical_threshold=self.current_critical_threshold)
                    html_reporter.generate_html(html_path)
                if fmt in ("both", "pdf"):
                    print("\n[*] 正在汇总数据并生成 PDF 报告...")
                    pdf_reporter = VAPFPDFGenerator(self.final_results, critical_threshold=self.current_critical_threshold)
                    await pdf_reporter.generate(pdf_path)

    async def _auto_exploit_logic(self, url, param, payload, vector, score, sqlmap_path, exploit_timeout, beef_xss_path, commix_path):
        """基于 13 维向量的分诊中心，按特征触发唯一工具并可提前结束。

        关键原则：
        - SQL 信号一旦出现（错误关键词/时间延迟/SQL 载荷形态），必须绝对优先 sqlmap。
        - 只有在“无 SQL 信号”且“高反射 + 明显 XSS 载荷形态”时才允许触发 BeEF。
        """
        exploit_results = []

        V_TIME_DELAY = 2  # v3 (归一化延迟: time_diff/5, 截断 0~1)
        V_ERR_SCORE = 3   # v4
        V_DOM_SIM = 4     # v5
        V_REFLECT = 5     # v6

        payload_l = (payload or "").lower()

        try:
            delay_s = float(vector[V_TIME_DELAY]) * 5.0
        except Exception:
            delay_s = 0.0

        try:
            err_score = float(vector[V_ERR_SCORE])
        except Exception:
            err_score = 0.0

        try:
            reflect = float(vector[V_REFLECT])
        except Exception:
            reflect = 0.0

        try:
            dom_sim = float(vector[V_DOM_SIM])
        except Exception:
            dom_sim = 1.0

        # 注意：不要把单引号/双引号当作 SQL 强信号（会导致 XSS 靶场也几乎总走 sqlmap）
        payload_has_sql = any(k in payload_l for k in [
            "union select",
            "union all",
            "information_schema",
            "@@version",
            "sleep(",
            "benchmark(",
            "extractvalue(",
            "updatexml(",
            " or 1=1",
            " and 1=1",
            "--",
            "/*",
        ])
        payload_has_xss = any(k in payload_l for k in [
            "<script", "</script", "onerror=", "onload=", "javascript:", "<img", "<svg", "<iframe", "alert("
        ])
        payload_has_cmd = any(k in payload_l for k in [
            "&&", "||", "`", "$(", "|", "wget ", "curl ", "nc ", "bash", "sh "
        ])

        sql_signal = (delay_s > 2.0) or (err_score > 0.1) or payload_has_sql
        # XSS 触发条件：反射强 + payload 像 XSS，且没有明显 SQL 信号（避免 SQLi 被 BeEF 抢跑）
        xss_signal = (reflect >= 0.6) and payload_has_xss and (delay_s <= 2.0) and (err_score <= 0.1) and (not payload_has_sql)
        rce_signal = (not sql_signal) and (not xss_signal) and ((dom_sim < 0.5) or payload_has_cmd)

        async with self.exploit_sem:
            # 1) SQL 信号优先：先跑 sqlmap
            if sql_signal:
                print(f"[!] SQL 信号优先 (Score: {score:.2f})：触发 sqlmap (delay={delay_s:.2f}s, err={err_score:.2f})")
                res = await run_sqlmap(url, param, sqlmap_path=sqlmap_path, timeout=exploit_timeout)
                exploit_results.append(res)
                if res.get('success'):
                    return exploit_results, True
                # sqlmap 失败时不直接结束：允许在同一高危点位继续尝试 XSS/RCE（避免“永远只跑 sqlmap”）

            # 2) XSS：只有满足反射强 + payload 像 XSS 且无明显 SQL 信号时才触发 BeEF
            if xss_signal:
                print(f"[!] 反射强且无明显 SQL 信号 (v6={reflect:.2f})：触发 BeEF...")
                res = await run_beef_xss(beef_path=beef_xss_path, timeout=10)
                exploit_results.append(res)
                if res.get('success'):
                    return exploit_results, True

            # 3) RCE
            if rce_signal:
                print(f"[!] 页面结构变化/命令形态载荷：尝试 Commix 验证 RCE...")
                res = await run_commix(url, commix_path=commix_path, timeout=exploit_timeout)
                exploit_results.append(res)
                if res.get('success'):
                    return exploit_results, True
                return exploit_results, True

        return exploit_results, bool(exploit_results)

    async def _auto_exploit(self, target_url: str, threshold: float, sqlmap_path: str, exploit_timeout: int, exploit_max: int,
                            beef_xss_path: str, msfconsole_path: str, commix_path: str):
        crit_thresh = max(0.0, min(1.0, self.current_critical_threshold))

        def _eff_prob(r):
            return r.get("prob_effective", r.get("prob", 0.0))

        criticals = [r for r in self.final_results if _eff_prob(r) >= crit_thresh]
        if not criticals:
            try:
                max_eff = max((_eff_prob(r) for r in self.final_results), default=0.0)
                max_raw = max((r.get("prob_raw", r.get("prob", 0.0)) for r in self.final_results), default=0.0)
            except Exception:
                max_eff = 0.0
                max_raw = 0.0
            print(f"    [*] 自动利用跳过：无结果达到阈值 {crit_thresh:.2f}（最高有效分 {max_eff:.2f}，最高原始分 {max_raw:.2f}）")
            return

        # 按分诊逻辑 + 置信度排序（高分先试），每个高危只触发一个最匹配工具
        decisions = sorted(criticals, key=lambda r: _eff_prob(r), reverse=True)

        budget = max(1, exploit_max)
        used = 0

        attempted_keys: set[tuple[str, str]] = set()
        successful_keys: set[tuple[str, str]] = set()

        for r in decisions:
            if used >= budget:
                break
            vector = r.get("vector") or [0]*13
            score = _eff_prob(r)
            param = r.get("param") or ""
            payload = r.get("payload")

            # 点位去重：同一个 URL+param（包括 ALL/Combo）最多触发一次自动利用；若已成功，更不再重复
            key = (str(target_url), str(param))
            if key in successful_keys:
                continue
            if key in attempted_keys:
                continue

            results, attempted = await self._auto_exploit_logic(
                target_url, param, payload, vector, score,
                sqlmap_path, exploit_timeout, beef_xss_path, commix_path
            )

            if attempted:
                attempted_keys.add(key)
                used += 1
                for res in results:
                    if res.get("type") == "sqlmap":
                        r["exploit"] = res
                    else:
                        r.setdefault("exploit_chain", []).append(res)
                    if res.get("success"):
                        successful_keys.add(key)

        if used < budget:
            async with self.exploit_sem:
                res = await run_msfconsole_cmd("version; exit", msfconsole_path=msfconsole_path, timeout=30)
            for r in criticals:
                r.setdefault("exploit_chain", []).append(res)

    def _print_alert(self, prob, payload, param, waf_info="", prob_raw=None, signal_tag=None):
        if waf_info:
            print(f"    [!] 警报: WAF 拦截! ({waf_info})")
        else:
            print(f"    [!] 警报: 发现高度可疑漏洞!")
            
        print(f"        - Param: {param}")
        print(f"        - Payload: {payload}")
        print(f"        - AI 评分(有效): {prob:.2%}")
        try:
            if prob_raw is not None and abs(float(prob_raw) - float(prob)) > 1e-6:
                print(f"        - AI 评分(原始): {float(prob_raw):.2%}")
                if signal_tag:
                    print(f"        - 降噪标记: {signal_tag}（自动利用/报告按有效分判定）")
        except Exception:
            pass

        conclusion = 'CRITICAL' if prob >= self.current_critical_threshold else 'SUSPICIOUS'
        print(f"        - 判定结论: {conclusion}")

if __name__ == "__main__":
    def parse_params(param_list):
        params = {}
        for item in param_list or []:
            if "=" not in item:
                continue
            k, v = item.split("=", 1)
            params[k] = v
        return params

    parser = argparse.ArgumentParser(description="V-APF 预测扫描器")
    parser.add_argument("--url", required=True, help="目标 URL，GET 可直接包含查询参数")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP 方法")
    parser.add_argument("--param", action="append", help="参数对，格式 key=value，可重复传入")
    parser.add_argument("--scan_mode", default="single", choices=["single", "all", "combo"], help="扫描模式")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="告警阈值，默认 0.65")
    parser.add_argument("--max-payloads", type=int, default=None, help="限制基础 payload 数量（变异数量由 --mutation-count 控制），用于快速扫描")
    parser.add_argument("--critical-threshold", type=float, default=None, help="自定义 CRITICAL 判定阈值（默认与 threshold 相同）")
    parser.add_argument("--concurrency", type=int, default=3, help="并发探测数（默认 3）")
    parser.add_argument("--mutation-count", type=int, default=1, help="每个基础 payload 的变异数量（默认 1）")
    parser.add_argument("--sqlmap-path", default="sqlmap", help="sqlmap 可执行路径（默认 sqlmap）")
    parser.add_argument("--exploit-timeout", type=int, default=600, help="利用步骤超时秒数（默认 600，时间盲注更稳）")
    parser.add_argument("--exploit-max", type=int, default=1, help="最多触发的高危条目数量（默认 1）")
    parser.add_argument("--beef-xss-path", default="beef-xss", help="BeEF-XSS 可执行路径（默认 beef-xss）")
    parser.add_argument("--msfconsole-path", default="msfconsole", help="Metasploit msfconsole 可执行路径（默认 msfconsole）")
    parser.add_argument("--commix-path", default="commix", help="Commix 可执行路径（默认 commix）")
    parser.add_argument("--header", action="append", help="自定义 Header，格式 'Key: Value'，可重复指定")
    parser.add_argument("--report-name", default=None, help="自定义报告基名（将自动附加时间戳）；默认按 URL 生成")
    parser.add_argument("--report-dir", default="reports", help="报告输出目录（默认 reports）")
    # 互斥的 headless 控制，默认无头
    headless_group = parser.add_mutually_exclusive_group()
    headless_group.add_argument("--headless", dest="headless", action="store_true", help="启用无头模式（默认）")
    headless_group.add_argument("--no-headless", dest="headless", action="store_false", help="关闭无头模式，便于调试")
    parser.set_defaults(headless=True)

    args = parser.parse_args()

    user_params = parse_params(args.param)

    headers_dict = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers_dict[k.strip()] = v.strip()
    headers_dict = headers_dict or None

    scanner = SAFSPredictScanner(default_headers=headers_dict)
    asyncio.run(
        scanner.scan_url(
            args.url,
            method=args.method,
            params=user_params if user_params else None,
            scan_mode=args.scan_mode,
            threshold=args.threshold,
            headless=args.headless,
            max_payloads=args.max_payloads,
            report_name=args.report_name,
            report_dir=args.report_dir,
            sqlmap_path=args.sqlmap_path,
            exploit_timeout=args.exploit_timeout,
            exploit_max=args.exploit_max,
            beef_xss_path=args.beef_xss_path,
            msfconsole_path=args.msfconsole_path,
            commix_path=args.commix_path,
            critical_threshold=args.critical_threshold,
            concurrency=args.concurrency,
            mutation_count=args.mutation_count,
            headers=headers_dict,
        )
    )
