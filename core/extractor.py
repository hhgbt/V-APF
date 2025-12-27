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
sys.path.append(os.getcwd())
from core.spider import DVWASpider, BWAPPSpider, PikachuSpider, UniversalSpider

class FeatureExtractor:
    """
    语义特征提取器 (Semantic Feature Extractor)
    
    功能:
    1. 读取 targets_*.json 中的注入点
    2. 对每个注入点发送 Payload (Probe)
    3. 实时重新获取 Baseline (以应对 Session 变化)
    4. 对比 Probe 与 Baseline，生成 13 维特征向量
    """

    def __init__(self, payloads_file: str = "data/payloads.txt"):
        self.payloads = self._load_payloads(payloads_file)
        self.vectors = []
        self.error_keywords = [
            "SQL syntax", "mysql_fetch", "syntax error", "Warning", "Fatal error",
            "Unclosed quotation", "not found", "404", "denied", "root:", "admin"
        ]

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
        """核心：计算 13 维特征向量"""
        # 1. Length_Diff
        len_base = base_data.get("length", 1)
        len_probe = probe_data.get("length", 0)
        v1 = (len_probe - len_base) / len_base

        # 2. Status_Change
        v2 = 1.0 if base_data.get("status") != probe_data.get("status") else 0.0

        # 3. Time_Delay (seconds) - [Fix] 修复负值问题
        v3 = max(0.0, probe_data.get("time", 0) - base_data.get("time", 0))

        # 4. Keyword_Match (Error Keywords) - [Fix] 改为加权评分
        probe_text = probe_data.get("text", "")
        # v4 = sum(1.0 for k in self.error_keywords if k.lower() in probe_text.lower())
        # 权重表: 强特征给高分
        keyword_scores = {
            "SQL syntax": 1.0, "mysql_fetch": 1.0, "Unclosed quotation": 1.0,
            "syntax error": 0.8, "Fatal error": 0.8, 
            "Warning": 0.5, "denied": 0.3, "404": 0.1, "not found": 0.1
        }
        v4 = 0.0
        lower_text = probe_text.lower()
        for k, score in keyword_scores.items():
            if k.lower() in lower_text:
                v4 += score
        # 简单的归一化，避免无限大
        v4 = min(5.0, v4) 

        # 5. DOM_Sim (Similarity Ratio) - [Fix] 使用 difflib.SequenceMatcher 计算编辑距离相似度
        # 注意：这里对比的是 probe 和 base 的相似度
        # 如果页面崩了，相似度会降低
        base_text = base_data.get("text", "")
        v5 = difflib.SequenceMatcher(None, base_text, probe_text).quick_ratio()

        # 6. Reflection_Score (Payload Reflection) - [Fix] Normalization
        v6 = float(probe_text.count(payload))
        if len(payload) > 0:
             v6 = v6 / len(payload) # 简单的归一化尝试，或者使用反射比例
        # 更好的归一化：count / (len(text) / len(payload)) ? 
        # 暂时使用相对值： count / 10 (假设很少超过 10 次)
        v6 = min(1.0, v6 / 10.0)

        # 7. Header_Change (Placeholder -> Implemented if headers available)
        # 目前 _fetch 返回结果还没包含 headers，暂时保留为 0.0 或改为随机微扰动以避免全0
        # 为了让模型能跑通，我们这里暂时先填 0，后续优化 _fetch 返回 headers
        v7 = 0.0 

        # --- NLP / Semantic Features (Difference) ---
        base_nlp = base_data.get("nlp", {})
        probe_nlp = probe_data.get("nlp", {})

        # 8. Tag Count Diff (Normalized)
        base_tags = base_nlp.get("tag_count", 1)
        if base_tags == 0: base_tags = 1
        v8 = abs(probe_nlp.get("tag_count", 0) - base_nlp.get("tag_count", 0)) / base_tags

        # 9. Text Length Diff (Normalized)
        base_txt_len = base_nlp.get("text_len", 1)
        if base_txt_len == 0: base_txt_len = 1
        v9 = abs(probe_nlp.get("text_len", 0) - base_nlp.get("text_len", 0)) / base_txt_len

        # 10. Entropy Diff
        v10 = abs(probe_nlp.get("entropy", 0) - base_nlp.get("entropy", 0))

        # 11. Tag_Count_Change (Ratio Diff)
        # 计算比率变化：abs(probe / base - 1.0)
        base_tags = base_nlp.get("tag_count", 1)
        if base_tags == 0: base_tags = 1
        probe_tags = probe_nlp.get("tag_count", 0)
        v11 = abs(probe_tags / base_tags - 1.0)

        # 12. Hidden_Field_Consistency (Currently Proxy by Special Char Ratio)
        # 如果未来有专门的 hidden field count，这里替换为 abs(probe_hidden - base_hidden)
        # 暂时保持 Special Char Ratio 逻辑，因为这也能反映结构一致性
        base_spec = base_nlp.get("special_chars", 1)
        if base_spec == 0: base_spec = 1
        v12 = abs(probe_nlp.get("special_chars", 0) - base_nlp.get("special_chars", 0)) / base_spec

        # 13. Content_Type_Consistency (Placeholder -> Check Headers)
        # 暂时用 Line Count 变化率填充
        base_lines = base_nlp.get("lines", 1)
        if base_lines == 0: base_lines = 1
        v13 = abs(probe_nlp.get("lines", 0) - base_nlp.get("lines", 0)) / base_lines

        return [v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13]

    async def _fetch(self, page: Page, url: str, method: str = "GET", data: Dict = None) -> Dict:
        """发送请求并获取完整特征数据"""
        start = time.time()
        try:
            if method == "POST":
                # Playwright POST 需要使用 page.request 或者 form fill
                # 这里为了模拟真实表单，我们尽量用 page.goto (GET) 或 page.request (POST)
                # 为了保持 session，最好用 page 里的上下文
                # 简单起见，对于 POST，我们使用 page.evaluate fetch 或者 requests
                # 但 page.evaluate fetch 受同源策略限制，且难以获取 full response
                # 最佳方案：使用 page.request (APIRequestContext)
                response = await page.request.post(url, form=data)
                content = await response.text() # bytes to string
                status = response.status
            else:
                # GET: 构造 URL Query
                full_url = url
                if data:
                    sep = "&" if "?" in url else "?"
                    full_url = f"{url}{sep}{urlencode(data)}"
                response = await page.goto(full_url)
                # page.goto 返回的是 Response 对象
                content = await page.content() # 获取渲染后的 DOM
                status = response.status if response else 0

            duration = time.time() - start
            
            return {
                "length": len(content),
                "status": status,
                "time": duration,
                "text": content,
                "nlp": self._extract_nlp_features(content)
            }
        except Exception as e:
            print(f"[-] 请求失败 {url}: {e}")
            return {
                "length": 0, "status": 0, "time": 0, "text": "", "nlp": {}
            }

    async def process_file(self, json_path: str):
        """处理单个 targets.json 文件"""
        print(f"\n[*] 正在处理目标文件: {json_path}")
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        base_url = data.get("base_url", "")
        pages = data.get("pages", [])

        # 1. 确定 Target 类型并初始化 Spider 以获取 Session
        spider = None
        if "dvwa" in base_url.lower():
            spider = DVWASpider(base_url, "")
        elif "pikachu" in base_url.lower():
            spider = PikachuSpider(base_url, "")
        elif "bwapp" in base_url.lower():
            spider = BWAPPSpider(base_url, "")
        else:
            spider = UniversalSpider(base_url, "")

        async with async_playwright() as p:
            # [Optimization] 使用 asyncio.Semaphore 限制并发 (例如同时只处理 5 个)
            # 但这里我们是单页面顺序处理，实际上瓶颈在于页面加载
            # 这里的改进是：不在每个 process_file 里都开浏览器，而是如果能复用更好
            # 不过目前的架构是每个文件一个 Context，这对于隔离 Session 比较安全
            
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # 2. 执行自动登录 (复用 Spider 逻辑)
            # 注意：Spider 的 auto_login 可能需要调整，因为它通常不接受参数
            # 这里我们尝试尽力而为
            if hasattr(spider, 'auto_login'):
                print(f"[+] 执行自动登录 ({type(spider).__name__})...")
                # 对于 bWAPP A.I.M. 模式，我们需要先访问 aim.php
                if isinstance(spider, BWAPPSpider):
                     await page.goto(f"{base_url}/aim.php")
                     if await page.query_selector('button[type="submit"]'):
                         await page.click('button[type="submit"]')
                else:
                    await spider.auto_login(page)
            
            # [Optimization] 增加并发控制
            sem = asyncio.Semaphore(5)

            async def process_page_entry(page_entry):
                url = page_entry['url']
                points = page_entry.get('injection_points', [])
                if not points: return

                # print(f"[+] 分析页面: {url} ({len(points)} 个注入点)")
                
                # 为了并发安全，我们不能共享同一个 page 对象进行 fetch
                # 因为 page.goto 是会改变当前页面状态的
                # 所以必须：要么顺序执行，要么每个任务开一个新的 page
                # 开新 page 开销大，所以这里我们在文件内部还是保持顺序，
                # 但对于 points 循环可以尝试并发？不行，同一个 Context 下并发操作 page 会冲突。
                # 结论：Playwright 单 Context 下必须串行操作 Page。
                # 只有多 Context 才能并发。
                
                # 因此，针对 Session 重用风险，我们已经在上面复用了 browser/context/page
                # 只要不 close，就能一直用。
                # 这里的瓶颈是：每次 fetch 都要 goto，这很慢。
                # 唯一的优化是：减少不必要的 fetch。
                
                # 下面的代码保持串行即可，无需 Semaphore，因为我们只有一个 Page
                
                for point in points:
                    method = point['method']
                    inputs = point['inputs']
                    
                    # 构造 Base Data (使用默认值)
                    base_params = {i['name']: i['default'] for i in inputs}
                    
                    # print(f"    -> 获取基准 ({method})...")
                    base_resp = await self._fetch(page, url, method, base_params)
                    
                    # 3.2 Fuzzing: 对每个参数轮询测试
                    for inp in inputs:
                        param_name = inp['name']
                        risk = inp.get('risk_level', 'normal')
                        
                        if inp['type'] == 'hidden' or 'token' in param_name.lower():
                            continue

                        # 选取 Payload (这里简单选取前 2 个作为演示，以免太慢)
                        # 实际生产中应根据 risk_level 动态调整 payload 数量
                        # [Optimized] 使用全部新 Payloads (约 20 个)，虽然慢但数据质量高
                        test_payloads = self.payloads 
                        
                        for payload in test_payloads:
                            probe_params = base_params.copy()
                            probe_params[param_name] = payload
                            
                            probe_resp = await self._fetch(page, url, method, probe_params)
                            vector = self.compute_13_vector(base_resp, probe_resp, payload)
                            
                            record = {
                                "url": url,
                                "param": param_name,
                                "payload": payload,
                                "method": method,
                                "risk_level": risk,
                                "vector": vector
                            }
                            self.vectors.append(record)

            # 3. 遍历每个页面和注入点
            # 鉴于 Playwright 单 Page 限制，我们只能顺序执行
            # 这里的优化点：已经复用了 Context 和 Page，避免了重复登录
            total_points = sum(len(p.get('injection_points', [])) for p in pages)
            print(f"[+] 开始扫描 {len(pages)} 个页面，共 {total_points} 个注入点...")
            
            for i, page_entry in enumerate(pages):
                if i % 5 == 0:
                    print(f"    -> 进度: {i}/{len(pages)}")
                await process_page_entry(page_entry)
            
            await browser.close()

    def save_vectors(self, output_file: str = "data/features.json"):
        with open(output_file, 'w') as f:
            json.dump(self.vectors, f, indent=2)
        print(f"\n[+] 特征提取完成，共生成 {len(self.vectors)} 条向量数据")
        print(f"[+] 结果已保存至: {output_file}")

async def main():
    parser = argparse.ArgumentParser(description="SAFS-Scanner 特征提取器")
    parser.add_argument("--targets", nargs="+", help="目标 JSON 文件列表", required=True)
    parser.add_argument("--output", default="data/features.json", help="输出特征文件")
    args = parser.parse_args()

    extractor = FeatureExtractor()
    
    # 也可以自动扫描 data/ 目录下的所有 targets_*.json
    targets = args.targets
    
    for target_file in targets:
        await extractor.process_file(target_file)
        
    extractor.save_vectors(args.output)

if __name__ == "__main__":
    asyncio.run(main())
