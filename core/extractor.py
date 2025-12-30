import asyncio
import json
import math
import time
import re
import argparse
import difflib
import numpy as np
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any
from playwright.async_api import async_playwright, Page, BrowserContext

# Import Spiders for Auto-Login Logic
# Ensure core is in path if running from root
import sys
import os
import difflib
import re
import asyncio
import httpx
import random
sys.path.append(os.getcwd())
from playwright.async_api import async_playwright, Page, BrowserContext
from core.spider import DVWASpider, BWAPPSpider, PikachuSpider, UniversalSpider
from core.mutator import SAFSMutator

class FeatureExtractor:
    """
    语义特征提取器 (Semantic Feature Extractor)
    
    功能:
    1. 读取 targets_*.json 中的注入点
    2. 对每个注入点发送 Payload (Probe)
    3. 实时重新获取 Baseline (以应对 Session 变化)
    4. 对比 Probe 与 Baseline，生成 13 维特征向量
    """

    def __init__(self, payloads_file: str = "data/payloads.txt", cookies: str = "", default_headers: Dict[str, str] | None = None):
        self.payloads = self._load_payloads(payloads_file)
        self.mutator = SAFSMutator()
        self.cookies = cookies
        self.default_headers = default_headers or {}
        # [Optimization] 预先生成变异 Payload，扩充攻击向量库
        # 为了避免数量爆炸，我们这里只对前 5 个基础 Payload 进行变异演示
        # 实际生产中可以全量变异
        mutated_payloads = []
        for p in self.payloads[:5]:
            mutated_payloads.extend(self.mutator.mutate(p, count=3))
        
        # 将变异后的 Payload 加入到主列表（去重）
        self.payloads = sorted(list(set(self.payloads + mutated_payloads)))
        print(f"[*] Payload 库加载完成: 基础 {len(self.payloads)-len(mutated_payloads)} + 变异 {len(mutated_payloads)} -> 总计 {len(self.payloads)}")

        self.vectors = []
        self.error_keywords = [
            "SQL syntax", "mysql_fetch", "syntax error", "Warning", "Fatal error",
            "Unclosed quotation", "not found", "404", "denied", "root:", "admin"
        ]
        
        # [Optimization] HTTP Client for Fast Probing
        self.http_client = httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True, headers=self.default_headers)
        # [Optimization] Concurrency Semaphore
        self.sem = asyncio.Semaphore(5)

    def set_default_headers(self, headers: Dict[str, str] | None):
        """更新默认请求头，应用于 httpx 与后续 Playwright 创建的上下文。"""
        self.default_headers = headers or {}
        try:
            self.http_client.headers.update(self.default_headers)
        except Exception:
            pass

    def _load_payloads(self, path: str) -> List[str]:
        if not os.path.exists(path):
            print(f"[!] Payload 文件不存在: {path}")
            return ["' OR 1=1 --"] # Fallback
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def _calculate_entropy(self, text: str) -> float:
        """计算文本的香农熵"""
        if not text:
            return 0.0
        prob = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)

    def _extract_nlp_features(self, html_content: str):
        """提取 NLP/结构化特征"""
        soup = BeautifulSoup(html_content, "html.parser")
        text = soup.get_text()
        
        return {
            "tag_count": len(soup.find_all()),
            "text_len": len(text),
            "entropy": self._calculate_entropy(text),
            "special_chars": len(re.findall(r'[^\w\s]', text)),
            "lines": len(text.splitlines()),
            "words": len(text.split())
        }

    def compute_13_vector(self, base_data: Dict, probe_data: Dict, payload: str) -> List[float]:
        """
        计算 13 维特征向量 (优化版)
        """
        vector = []

        # 1. 响应长度变化 (归一化到 -1 ~ 1)
        len_base = base_data.get('length', 0)
        len_probe = probe_data.get('length', 0)
        # 避免除以零
        len_diff = (len_probe - len_base) / max(len_base, 1)
        # 截断极端值
        vector.append(max(min(len_diff, 1.0), -1.0)) 

        # 2. 状态码变化 (0 或 1)
        vector.append(1.0 if base_data.get('status') != probe_data.get('status') else 0.0)

        # 3. 响应时间延迟 (秒, 归一化)
        time_diff = probe_data.get('time', 0) - base_data.get('time', 0)
        # 假设超过 5 秒为严重延迟
        vector.append(max(min(time_diff / 5.0, 1.0), 0.0))

        # 4. 关键词匹配评分 (归一化)
        error_score = 0
        p_text_lower = probe_data.get('text', '').lower()
        for kw in self.error_keywords:
            if kw in p_text_lower:
                error_score += 1
        # 假设匹配 5 个关键词即为满分
        vector.append(min(error_score / 5.0, 1.0))

        # 5. DOM 结构相似度 (0 ~ 1)
        sim = difflib.SequenceMatcher(None, base_data.get('text', ''), probe_data.get('text', '')).quick_ratio()
        vector.append(sim)

        # 6. 反射性 (0 或 1)
        # 简单判断 Payload 是否在响应中出现
        # 注意：Payload 可能被编码，这里只做简单字符串匹配
        is_reflected = payload in probe_data.get('text', '')
        vector.append(1.0 if is_reflected else 0.0)

        # 7. Header 变化 (Set-Cookie / Server / Location)
        # 重点关注安全相关的 Header 变动
        header_diff_score = 0
        base_headers = base_data.get('headers', {})
        probe_headers = probe_data.get('headers', {})
        
        def _count_set_cookie(val):
            if isinstance(val, list):
                return len(val)
            return 1 if val else 0
        if _count_set_cookie(base_headers.get('set-cookie')) != _count_set_cookie(probe_headers.get('set-cookie')):
            header_diff_score += 0.5
            
        # 检查 Location 跳转变化
        if base_headers.get('location') != probe_headers.get('location'):
             header_diff_score += 0.5
             
        vector.append(min(header_diff_score, 1.0))

        # 8-12. 占位符 (保留给未来特征，如 TF-IDF 距离等)
        # 暂时填充 0.0
        for _ in range(5):
            vector.append(0.0)

        # 13. Content_Type 变化
        ct_base = base_headers.get('content-type', '').split(';')[0]
        ct_probe = probe_headers.get('content-type', '').split(';')[0]
        vector.append(1.0 if ct_base != ct_probe else 0.0)

        return vector

    async def fetch_page_features(self, page: Page, url: str, method: str = "GET", data: Dict = None, use_playwright: bool = True) -> Dict:
        """
        [Core] 发送请求并提取原始特征 (Raw Features)
        支持 Playwright (全功能) 和 httpx (快速) 混合模式
        """
        try:
            # 记录请求开始时间
            start_time = time.time()
            
            response = None
            method_upper = method.upper()
            if use_playwright and page:
                # 对 prompt.ml / xss-game 这类页面：networkidle 可能永远不满足（长连接/轮询）
                # 采用更宽容的策略：domcontentloaded(20s) -> 尝试等待 networkidle(20s, 可超时忽略) -> 短暂停留给 JS 渲染
                async def _goto_then_settle(target: str):
                    resp = await page.goto(target, wait_until="domcontentloaded", timeout=20000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=20000)
                    except Exception:
                        pass
                    await asyncio.sleep(1)
                    return resp

                if method_upper == "GET":
                    if data:
                        from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
                        parts = list(urlparse(url))
                        query = dict(parse_qsl(parts[4]))
                        query.update(data)
                        parts[4] = urlencode(query)
                        final_url = urlunparse(parts)
                        response = await _goto_then_settle(final_url)
                    else:
                        response = await _goto_then_settle(url)
                elif method_upper == "POST":
                    response = await _goto_then_settle(url)
            else:
                # 使用 httpx 进行快速协议层探测（不渲染 DOM）
                if method_upper == "GET":
                    r = await self.http_client.get(url, params=data or {}, headers=self.default_headers or None)
                else:
                    r = await self.http_client.post(url, data=data or {}, headers=self.default_headers or None)
                # 仿造 Playwright 返回结构
                end_time = time.time()
                text = r.text
                # 保留 set-cookie 的列表计数能力
                try:
                    set_cookie_list = r.headers.get_list('set-cookie')
                except Exception:
                    set_cookie_list = []
                headers = {k.lower(): v for k, v in r.headers.items()}
                if set_cookie_list:
                    headers['set-cookie'] = set_cookie_list
                return {
                    "status": r.status_code,
                    "length": len(text),
                    "time": end_time - start_time,
                    "text": text,
                    "headers": headers
                }

            end_time = time.time()
            
            if not response:
                return {"status": 0, "length": 0, "time": 0, "text": "", "headers": {}}

            # 提取基础数据
            text = await response.text()
            headers = response.headers
            # 将 headers key 转为小写，且规范化 set-cookie 为计数友好的形式
            headers = {k.lower(): v for k, v in headers.items()}
            if 'set-cookie' in headers and not isinstance(headers['set-cookie'], list):
                headers['set-cookie'] = [headers['set-cookie']]
            
            return {
                "status": response.status,
                "length": len(text),
                "time": end_time - start_time,
                "text": text,
                "headers": headers
            }
            
        except Exception as e:
            # print(f"[Debug] Fetch Error: {e}")
            return {"status": 0, "length": 0, "time": 0, "text": "", "headers": {}}

        # Fallback: 如果 Playwright 返回空响应，补打一发 httpx 获取原始文本，避免报告空白
        try:
            if result := locals().get("response"):
                pass
        except Exception:
            result = None
        # 如果 text 为空或 status 为 0，则尝试 httpx 再取一次
        try:
            need_fallback = False
            if 'text' in locals() and (not text or len(text.strip()) == 0):
                need_fallback = True
            if 'response' in locals() and response and getattr(response, 'status', 0) == 0:
                need_fallback = True
            if need_fallback:
                method_upper = (method or "GET").upper()
                start_time_fb = time.time()
                if method_upper == "GET":
                    r_fb = await self.http_client.get(url, params=data or {})
                else:
                    r_fb = await self.http_client.post(url, data=data or {})
                end_time_fb = time.time()
                try:
                    set_cookie_list = r_fb.headers.get_list('set-cookie')
                except Exception:
                    set_cookie_list = []
                headers_fb = {k.lower(): v for k, v in r_fb.headers.items()}
                if set_cookie_list:
                    headers_fb['set-cookie'] = set_cookie_list
                return {
                    "status": r_fb.status_code,
                    "length": len(r_fb.text),
                    "time": end_time_fb - start_time_fb,
                    "text": r_fb.text,
                    "headers": headers_fb,
                }
        except Exception:
            pass

    async def probe_and_get_vector(self, page: Page, url: str, method: str, base_params: Dict, param_name: str, payload: str, base_data: Dict = None, use_playwright: bool = True) -> tuple[List[float], Dict]:
        """
        单次探测并获取 (13 维向量, Probe Data)
        """
        if base_data is None:
             base_data = await self.fetch_page_features(page, url, method, base_params, use_playwright=use_playwright)
        
        probe_params = base_params.copy()
        probe_params[param_name] = payload
        
        probe_data = await self.fetch_page_features(page, url, method, probe_params, use_playwright=use_playwright)
        
        vector = self.compute_13_vector(base_data, probe_data, payload)
        return vector, probe_data

    async def _process_page_concurrent(self, context: BrowserContext, page_info: Dict):
        """
        并发处理单个页面的所有注入点
        """
        async with self.sem: # 限制页面级并发
            page = await context.new_page()
            try:
                url = page_info['url']
                print(f"[+] Processing: {url}")
                
                # 获取基准数据 (使用 Playwright 确保准确性)
                base_data = await self.fetch_page_features(page, url, method="GET", use_playwright=True)
                if not base_data['text']:
                    return

                injection_points = page_info.get('injection_points', [])
                # [Debug]
                print(f"    [Debug] Injection Points for {url}: {len(injection_points)}")
                
                for point in injection_points:
                    # [Debug]
                    print(f"        [Debug] Point Type: {point['type']}, Method: {point.get('method')}")
                    
                    if point['type'] == 'query' or point['type'] == 'form': # 支持 URL 参数和 Form 表单
                        # 注意：Form 表单的参数列表 key 是 'inputs'，Query 是 'params'
                        # 需要做适配
                        params_list = point.get('params') or point.get('inputs') or []
                        
                        for param in params_list:
                            p_name = param['name']
                            print(f"            [Debug] Testing Param: {p_name}")
                            
                            # [Optimization] 快速筛选 (Quick Check)
                            # 先用一个简单的单引号探测
                            seed = "'"
                            v_seed, _ = await self.probe_and_get_vector(
                                None, url, "GET", {p_name: ""}, p_name, seed, base_data, use_playwright=False
                            )
                            # 如果 V1(长度), V2(状态), V5(DOM) 几乎无变化，且 V4(报错) 为 0
                            # 则认为该参数可能是死参数，跳过后续重型探测
                            # [Debug] 暂时禁用快速筛选，并打印调试信息
                            # print(f"    [Debug] Quick Check ({p_name}): v_seed={v_seed}")
                            # if abs(v_seed[0]) < 0.05 and v_seed[1] == 0 and v_seed[4] > 0.99 and v_seed[3] == 0:
                            #    # print(f"    [-] Skipping dead param: {p_name}")
                            #    continue

                            # 否则进行全量探测
                            for payload in self.payloads:
                                # [Optimization] 混合模式：XSS 用 Playwright，其他用 httpx
                                use_pw = "<script" in payload or "javascript:" in payload
                                
                                # 同步 Cookie (简单实现：从 context 获取)
                                # cookies = await context.cookies()
                                # httpx_cookies = {c['name']: c['value'] for c in cookies}
                                # self.http_client.cookies.update(httpx_cookies)
                                
                                # 注意：probe_and_get_vector 参数顺序需要调整，因为之前签名改了
                                vector, _ = await self.probe_and_get_vector(
                                    page if use_pw else None, 
                                    url, "GET", {p_name: ""}, p_name, payload, base_data, 
                                    use_playwright=use_pw
                                )
                                
                                self.vectors.append({
                                    "url": url,
                                    "param": p_name,
                                    "payload": payload,
                                    "security_level": page_info.get('security_level', ''),
                                    "risk_level": param.get('risk_level', 'normal'),
                                    "vector": vector
                                })
            except Exception as e:
                print(f"[!] Error processing {page_info['url']}: {e}")
            finally:
                await page.close()

    async def process_file(self, json_path: str, headless: bool = True):
        """
        处理单个 Target JSON 文件 (并发版)
        """
        with open(json_path, 'r') as f:
            data = json.load(f)
            
        base_url = data['base_url']
        pages = data['pages']
        
        # [Optimization] 数据采样 (针对训练阶段)
        # 如果页面过多，随机抽取 50 个进行训练数据采集
        if len(pages) > 50:
            print(f"[*] Pages count {len(pages)} > 50, sampling 50 pages for training...")
            pages = random.sample(pages, 50)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            # 创建 Context 并执行自动登录 (复用 Spider 逻辑或手动登录)
            context = await browser.new_context()
            
            # 简单起见，这里针对 DVWA/Pikachu 做简单登录
            page = await context.new_page()
            if "dvwa" in base_url:
                await DVWASpider(base_url, "").auto_login(page)
            elif "pikachu" in base_url:
                await PikachuSpider(base_url, "").auto_login(page)
            # --- 新增 bWAPP A.I.M 激活逻辑 ---
            elif "bwapp" in base_url.lower():
                print("[*] 检测到 bWAPP 目标，正在通过 A.I.M. 模式激活上下文...")
                spider = BWAPPSpider(base_url, getattr(self, "cookies", ""))
                await spider.init_browser(context)
                # 即使不需要登录，也必须访问一次 aim.php 以确保后续页面可以直接访问
                aim_url = f"{base_url}/aim.php" if not base_url.endswith("aim.php") else base_url
                try:
                    await page.goto(aim_url, wait_until="domcontentloaded", timeout=20000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=20000)
                    except Exception:
                        pass
                    await asyncio.sleep(1)
                except Exception as e:
                    print(f"[!] bWAPP A.I.M 激活失败: {e}")
            # ------------------------------
            await page.close()
            
            cookies = await context.cookies()
            httpx_cookies = {c['name']: c['value'] for c in cookies}
            self.http_client.cookies.update(httpx_cookies)
            
            # 并发执行页面探测
            tasks = [self._process_page_concurrent(context, page_info) for page_info in pages]
            await asyncio.gather(*tasks)
            
            await browser.close()
        
        await self.http_client.aclose()

    def save_vectors(self, output_file: str = "data/features.json"):
        with open(output_file, 'w') as f:
            json.dump(self.vectors, f, indent=2)
        print(f"\n[+] 特征提取完成，共生成 {len(self.vectors)} 条向量数据")
        print(f"[+] 结果已保存至: {output_file}")

async def main():
    parser = argparse.ArgumentParser(description="SAFS-Scanner 特征提取器")
    parser.add_argument("--targets", nargs="+", help="目标 JSON 文件列表", required=True)
    parser.add_argument("--output", default="data/features.json", help="输出特征文件")
    parser.add_argument("--cookie", default="", help="登录 Cookie 字符串")
    parser.add_argument("--no-headless", dest="headless", action="store_false", default=True, help="运行可见浏览器")
    args = parser.parse_args()

    extractor = FeatureExtractor(cookies=args.cookie)
    
    # 也可以自动扫描 data/ 目录下的所有 targets_*.json
    targets = args.targets
    
    for target_file in targets:
        await extractor.process_file(target_file, headless=args.headless)
        
    extractor.save_vectors(args.output)

if __name__ == "__main__":
    asyncio.run(main())
