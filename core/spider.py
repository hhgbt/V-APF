import argparse
import asyncio
import json
import sys
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

from playwright.async_api import async_playwright, Page, Browser, BrowserContext


class UniversalSpider:
    """通用 Web 爬虫 (SAFS-Scanner)，专为 bWAPP、DVWA、Pikachu 等多靶场设计。

    功能特性:
    - 通用 Cookie 注入 (替代硬编码登录)
    - 自动发现注入点 (Input Discovery)
    - 指纹基准采集 (Baseline Fingerprinting)
    """

    def __init__(self, base_url: str, cookies: str = ""):
        self.base_url = base_url.rstrip("/")
        self.cookies = cookies
        self.results: Dict[str, Any] = {"base_url": self.base_url, "pages": []}

    async def init_browser(self, context: BrowserContext):
        """将格式化的 Cookie 注入浏览器，实现通用登录"""
        if not self.cookies:
            return

        cookie_list = []
        # 优化：过滤空字符串，处理末尾可能存在的分号
        for pair in [p.strip() for p in self.cookies.split(";") if p.strip()]:
            if "=" in pair:
                key, val = pair.split("=", 1)
                cookie_list.append({
                    "name": key.strip(), 
                    "value": val.strip(), 
                    "url": self.base_url  # 必须指定 URL 或 domain
                })
        
        if cookie_list:
            await context.add_cookies(cookie_list)
            print(f"[+] 已注入 {len(cookie_list)} 个 Cookie")

    async def find_injection_points(self, page: Page) -> List[Dict[str, Any]]:
        """输入点提取 (The Input Hunter): 扫描页面中所有的潜在注入点"""
        points = []
        # 1. 抓取所有表单及其字段
        forms = await page.query_selector_all("form")
        for form in forms:
            action = await form.get_attribute("action") or ""
            inputs = await form.query_selector_all("input, textarea, select")
            input_details = []
            
            # [Risk Analysis] 简单的风险启发式分析
            form_risk = "normal"
            sensitive_keywords = ["login", "admin", "delete", "update", "password", "upload", "exec"]
            if any(k in action.lower() for k in sensitive_keywords):
                form_risk = "high"

            for i in inputs:
                name = await i.get_attribute("name")
                if name:
                    # 获取更多元数据以便 extractor 使用
                    default_val = await i.get_attribute("value")
                    i_type = await i.get_attribute("type") or "text"
                    
                    # 策略：如果 default 为空，填入通用测试字符作为占位符
                    if not default_val:
                        # 简单的占位符，后续 Extractor 可识别并替换
                        default_val = "SAFS_TEST_PAYLOAD"
                    
                    # 字段级别的风险分析
                    field_risk = form_risk
                    if any(k in name.lower() for k in sensitive_keywords):
                        field_risk = "high"
                        
                    input_details.append({
                        "name": name,
                        "default": default_val,
                        "type": i_type,
                        "risk_level": field_risk # [New] 增加风险等级标记
                    })
            
            if input_details: # 只记录有输入项的表单
                points.append({
                    "type": "form",
                    "method": (await form.get_attribute("method") or "GET").upper(),
                    "action": action,
                    "inputs": input_details
                })
        
        # 2. 抓取 URL 参数作为注入点 (针对 GET 参数注入)
        parsed = urlparse(page.url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            inputs = []
            
            # URL 级别的风险分析
            url_risk = "normal"
            if any(k in parsed.path.lower() for k in ["admin", "login", "api", "cmd", "shell"]):
                url_risk = "high"

            for k, v in query_params.items():
                # v is a list of values, taking the first one
                
                # 参数名风险分析
                param_risk = url_risk
                if any(kw in k.lower() for kw in ["id", "file", "cmd", "url", "path"]):
                     # 这些参数名常用于 SQLi, LFI, RCE, SSRF
                     param_risk = "high"

                inputs.append({
                    "name": k,
                    "default": v[0] if v else "",
                    "type": "query",
                    "risk_level": param_risk # [New]
                })
            
            if inputs:
                points.append({
                    "type": "query",
                    "method": "GET",
                    "action": parsed.path,
                    "inputs": inputs
                })

        return points

    async def get_page_fingerprint(self, page: Page, response) -> Dict[str, Any]:
        """获取当前页面的指纹 (复用已加载的页面)"""
        try:
            content = await page.content()
            return {
                "resp_length_base": len(content),
                # 注意：这里的时间可能不准确，因为是爬虫过程中的加载。
                # 但为了效率，暂时使用粗略估计或由 crawl 传入
                "status_base": response.status if response else 0,
                "dom_hash": hash(content)
            }
        except Exception as e:
            print(f"[-] 指纹采集失败: {e}")
            return {}

    async def crawl(self, page: Page, start_urls: List[str], max_depth: int = 3):
        """递归爬取 (BFS)"""
        queue = []
        for url in start_urls:
            queue.append((url, 0))
            
        visited = set()
        
        # 增加一些常见路径作为种子，以确保覆盖（Heuristics）
        # 尤其是 /admin, /index.php 等可能未直接链接但存在的页面
        common_paths = ["index.php", "admin/", "login.php", "help.php"]
        base_path = self.base_url.rstrip("/")
        for p in common_paths:
            full_p = f"{base_path}/{p}"
            # 只有当这些路径在目标域下时才添加
            queue.append((full_p, 0))

        # 确保 base_url 在 visited 中，避免重复 (如果 start_url 就是 base_url)
        # 但这里依靠 queue 处理即可。

        while queue:
            url, depth = queue.pop(0)
            
            # 规范化 URL 以去重 (简单去除 fragment)
            url = url.split('#')[0]
            
            if url in visited:
                continue
            visited.add(url)

            # 只爬取目标范围内的 URL (除了 start_url 可能是入口)
            if not url.startswith(self.base_url) and url not in start_urls:
                continue
            
            # 静态资源过滤
            lower_href = url.lower()
            if any(lower_href.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".pdf", ".ico", ".svg", ".woff", ".woff2"]):
                continue

            print(f"[+] 正在分析 (Depth {depth}): {url}")
            
            try:
                start_time = time.time()
                response = await page.goto(url)
                await page.wait_for_load_state("networkidle")
                resp_time = time.time() - start_time
                
                # 1. 采集指纹与注入点
                # 只有当 URL 属于目标域时才记录结果
                if url.startswith(self.base_url):
                    baseline = await self.get_page_fingerprint(page, response)
                    if baseline:
                        baseline["resp_time_base"] = resp_time
                        
                        injection_points = await self.find_injection_points(page)
                        
                        # [Baseline 有效性检查]
                        # 简单的启发式检查：如果页面长度极短且包含 "login" 关键字，可能需要警告
                        # 但我们不在这里中断，而是记录下来
                        
                        self.results["pages"].append({
                            "url": url,
                            "baseline": baseline,
                            "injection_points": injection_points
                        })
                
                # 2. 提取新链接 (如果未达到最大深度)
                # 优化：对于看起来像是列表页的，鼓励更深一层
                if depth < max_depth:
                    hrefs = await page.evaluate('''() => {
                        return Array.from(document.querySelectorAll('a, area')).map(a => a.href)
                    }''')
                    
                    # 尝试发现 iframe 中的链接 (针对 Pikachu 等)
                    iframe_srcs = await page.evaluate('''() => {
                         return Array.from(document.querySelectorAll('iframe')).map(i => i.src)
                    }''')
                    hrefs.extend(iframe_srcs)
                    
                    count_new = 0
                    for href in hrefs:
                        # 简单的过滤
                        if not href or href.startswith('javascript:'):
                            continue
                        
                        # 必须是同域链接才加入队列 (防止爬出站)
                        if href.startswith(self.base_url):
                            # 预先检查 visited 减少队列膨胀 (虽然 pop 时也会检查)
                            clean_href = href.split('#')[0]
                            if clean_href not in visited:
                                queue.append((href, depth + 1))
                                count_new += 1
                    
                    # print(f"    -> 发现 {count_new} 个新链接")

            except Exception as e:
                print(f"[-] 爬取失败 {url}: {e}")

    async def run(self, start_path: str = "/", headless: bool = True, output: str = "targets.json"):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context()
            
            # A. 初始化与会话注入
            await self.init_browser(context)
            
            page = await context.new_page()
            
            # 开始爬取
            full_start_url = f"{self.base_url}{start_path}" if start_path.startswith("/") else start_path
            if not full_start_url.startswith("http"):
                 full_start_url = f"{self.base_url}/{start_path.lstrip('/')}"

            await self.crawl(page, full_start_url)

            # 保存结果
            # 如果 output 包含目录，先创建目录
            import os
            if os.path.dirname(output):
                os.makedirs(os.path.dirname(output), exist_ok=True)
                
            with open(output, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"[+] 结果已写入 {output}")
            
            await browser.close()


class DVWASpider(UniversalSpider):
    """DVWA 专用批量爬虫：自动遍历 low, medium, high, impossible 等级"""
    
    def __init__(self, base_url: str, cookies: str):
        super().__init__(base_url, cookies)
        self.levels = ['low', 'medium', 'high', 'impossible']
        self.all_results = {"base_url": base_url, "pages": []}

    async def auto_login(self, page: Page):
        """自动登录 DVWA"""
        login_url = f"{self.base_url}/login.php"
        print(f"[+] 尝试自动登录 DVWA: {login_url}")
        try:
            await page.goto(login_url)
            await page.wait_for_load_state("networkidle")
            
            # 检查是否处于登录页
            if await page.query_selector('input[name="username"]'):
                await page.fill('input[name="username"]', 'admin')
                await page.fill('input[name="password"]', 'password')
                await page.click('input[name="Login"]') # 注意按钮 value 是 Login，name 也是 Login
                await page.wait_for_load_state("networkidle")
                print("[+] DVWA 登录表单提交完成")
            else:
                print("[!] 未找到登录表单，可能已登录")
        except Exception as e:
            print(f"[-] DVWA 自动登录失败: {e}")

    async def run_batch(self, start_path: str = "/", headless: bool = True, output: str = "data/targets_dvwa.json"):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            
            # 从原始 cookies 中移除 security 字段，避免冲突
            base_cookies_parts = []
            for pair in self.cookies.split(";"):
                if "=" in pair:
                    key, _ = pair.strip().split("=", 1)
                    if key.strip() != "security":
                        base_cookies_parts.append(pair.strip())
            base_cookie_str = "; ".join(base_cookies_parts)

            for level in self.levels:
                print(f"\n[+] === 开始爬取 DVWA Level: {level} ===")
                # 构造当前等级的 Cookie
                current_cookie = f"{base_cookie_str}; security={level}"
                
                # 创建新的 Context 以隔离 Cookie
                context = await browser.new_context()
                
                # 临时更新 self.cookies 供 init_browser 使用
                self.cookies = current_cookie
                await self.init_browser(context)
                
                page = await context.new_page()
                
                # [新增] 在每个安全等级开始前，都尝试确保登录态
                # 实际上 DVWA 的 Session 在 Context 内是共享的，但 Cookie 可能会覆盖
                # 最好在每次 new_context 后都检查登录
                await self.auto_login(page)

                # 重置 self.results 以便通过 crawl 收集当前等级的数据
                # 注意：这里需要清空 pages 列表，否则会累积之前的等级数据
                self.results = {"base_url": self.base_url, "pages": []}
                
                # 构造完整的 start_url
                full_start_url = f"{self.base_url}{start_path}" if start_path.startswith("/") else start_path
                if not full_start_url.startswith("http"):
                     full_start_url = f"{self.base_url}/{start_path.lstrip('/')}"

                # 调用父类的 crawl
                await self.crawl(page, full_start_url)
                
                # 将结果标记等级并合并
                for page_entry in self.results["pages"]:
                    page_entry["security_level"] = level
                    self.all_results["pages"].append(page_entry)
                
                await context.close()
            
            # 保存总结果
            import os
            if os.path.dirname(output):
                os.makedirs(os.path.dirname(output), exist_ok=True)
                
            with open(output, "w", encoding="utf-8") as f:
                json.dump(self.all_results, f, indent=2, ensure_ascii=False)
            print(f"\n[+] DVWA 所有等级爬取完成，结果已写入 {output}")
            
            await browser.close()


class BWAPPSpider(UniversalSpider):
    """bWAPP 专用批量爬虫：自动遍历 low, medium, high 等级"""
    
    def __init__(self, base_url: str, cookies: str):
        super().__init__(base_url, cookies)
        self.levels = ['0', '1', '2']  # 0=low, 1=medium, 2=high
        self.level_names = {'0': 'low', '1': 'medium', '2': 'high'}
        self.all_results = {"base_url": base_url, "pages": []}

    async def fetch_bwapp_entries(self, page: Page, portal_url: str) -> List[str]:
        """从 bWAPP portal.php 或内置列表获取漏洞入口 (A.I.M. 模式优化版)"""
        urls = []
        
        # [Fallback] A.I.M. 模式下，直接加载内置的常用漏洞列表，因为我们已经免认证了
        # 不再尝试从 portal.php 提取，因为 aim.php 不会显示那个下拉菜单
        print("[+] A.I.M. 模式生效: 直接加载内置漏洞页面列表...")
        fallback_pages = [
            "sqli_1.php", "sqli_2.php", "sqli_6.php", "sqli_16.php", # SQLi
            "xss_get.php", "xss_post.php", "xss_stored_1.php", # XSS
            "commandi.php", "commandi_blind.php", # Command Injection
            "fi_local.php", "fi_remote.php", # File Inclusion
            "unrestricted_file_upload.php", # Upload
            "xmli_1.php", "xmli_2.php", # XML
            "phpi.php", # PHP Injection
            "csrf_1.php", "csrf_2.php", # CSRF
            "ssrf_1.php", # SSRF
            "htmli_get.php", "htmli_post.php", # HTML Injection
            "portal.php" # 同时也把 portal 加进去
        ]
        
        # 修正 base_dir 逻辑：如果 portal_url 是 /aim.php，则 base_dir 应该是 /bWAPP/app
        # 假设 portal_url 已经是指向 app 目录下的某个文件
        if portal_url.endswith(".php"):
            base_dir = portal_url.rsplit('/', 1)[0]
        else:
            base_dir = portal_url.rstrip("/")

        for page_name in fallback_pages:
            urls.append(f"{base_dir}/{page_name}")
        
        print(f"[+] 已加载 {len(urls)} 个目标页面")
        return urls

    async def run_batch(self, start_path: str = "/", headless: bool = True, output: str = "data/targets_bwapp.json"):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            
            # A.I.M. 模式不需要 Cookie 中的 security_level，因为 A.I.M. 会接管
            # 但为了兼容性还是保留 Cookie 注入逻辑
            
            # A.I.M. 模式下只需要跑一次即可，因为安全等级在 A.I.M. 下可能无效或固定
            # 但为了保持数据格式一致性，我们还是保留循环，或者只跑一次并标记
            # 这里为了不破坏原有结构，依然循环，但其实每次访问都是 A.I.M. 授权后的结果
            
            for level in self.levels:
                level_name = self.level_names[level]
                print(f"\n[+] === 开始爬取 bWAPP (A.I.M. Mode) Level: {level_name} ({level}) ===")
                
                context = await browser.new_context()
                await self.init_browser(context)
                
                page = await context.new_page()
                
                # [关键修改] A.I.M. 模式下跳过 auto_login
                # 并且起始页应该是 aim.php (由命令行参数传入)
                # await self.auto_login(page) 
                
                # 重置 self.results 以便通过 crawl 收集当前等级的数据
                self.results = {"base_url": self.base_url, "pages": []}
                
                # 构造完整的 start_url
                full_start_url = f"{self.base_url}{start_path}" if start_path.startswith("/") else start_path
                if not full_start_url.startswith("http"):
                     full_start_url = f"{self.base_url}/{start_path.lstrip('/')}"
                
                # 1. 访问起始页 (通常是 aim.php) 以触发授权
                print(f"[+] 访问 A.I.M. 入口: {full_start_url}")
                try:
                    await page.goto(full_start_url)
                    # 可能需要点击按钮？ bWAPP 的 aim.php 通常有一个 "Set A.I.M." 按钮或自动生效
                    # 检查是否有表单提交
                    if await page.query_selector('form'):
                         print("[+] 发现 A.I.M. 表单，尝试提交...")
                         # 这里的按钮名称可能不同，通常是 update 或 aim
                         # 简单的策略：如果有按钮就点击第一个 submit
                         await page.click('button[type="submit"]')
                         await page.wait_for_load_state("networkidle")
                         print("[+] A.I.M. 授权触发完成")
                except Exception as e:
                    print(f"[-] A.I.M. 入口访问异常: {e}")

                # 2. 直接构造漏洞页面列表
                entry_urls = await self.fetch_bwapp_entries(page, full_start_url)
                
                # 3. 将所有目标页面加入爬取队列
                all_start_urls = entry_urls # 不再包含 start_url 因为 aim.php 本身没漏洞

                # 调用父类的 crawl
                await self.crawl(page, all_start_urls)
                
                # 将结果标记等级并合并
                for page_entry in self.results["pages"]:
                    page_entry["security_level"] = level_name
                    self.all_results["pages"].append(page_entry)
                
                await context.close()
            
            # 保存总结果
            import os
            if os.path.dirname(output):
                os.makedirs(os.path.dirname(output), exist_ok=True)
                
            with open(output, "w", encoding="utf-8") as f:
                json.dump(self.all_results, f, indent=2, ensure_ascii=False)
            print(f"\n[+] bWAPP 所有等级爬取完成，结果已写入 {output}")
            
            await browser.close()


class PikachuSpider(UniversalSpider):
    """Pikachu 专用爬虫：自动执行登录以获取 Session，然后全站爬取"""
    
    async def auto_login(self, page: Page):
        """自动登录 Pikachu 获取 Session"""
        # Pikachu 没有全局登录，但通过 op1_login.php 可以获取有效 Session
        login_url = f"{self.base_url}/vul/overpermission/op1/op1_login.php"
        print(f"[+] 尝试通过 OverPermission 模块登录: {login_url}")
        
        try:
            await page.goto(login_url)
            await page.wait_for_load_state("networkidle")
            
            if await page.query_selector('input[name="username"]'):
                await page.fill('input[name="username"]', 'admin')
                await page.fill('input[name="password"]', '123456')
                await page.click('input[name="submit"]')
                await page.wait_for_load_state("networkidle")
                print("[+] 登录表单提交完成")
                
                # 验证是否登录成功 (检查是否有 "注销" 或 "logout" 字样，或者 url 变化)
                content = await page.content()
                if "注销" in content or "op1_mem.php" in page.url:
                     print("[+] Pikachu 登录成功！Session 已激活")
                else:
                     print("[!] 登录可能失败，请检查账号密码或数据库状态")
            else:
                print("[!] 未找到登录表单，可能已处于登录状态")
                
        except Exception as e:
            print(f"[-] 自动登录失败: {e}")

    async def run_pikachu(self, start_path: str = "/", headless: bool = True, output: str = "data/targets_pikachu.json"):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context()
            
            # 初始化 (如果有额外的 Cookie)
            await self.init_browser(context)
            
            page = await context.new_page()
            
            # 1. 执行自动登录
            await self.auto_login(page)
            
            # 2. 构造起始 URL
            full_start_url = f"{self.base_url}{start_path}" if start_path.startswith("/") else start_path
            if not full_start_url.startswith("http"):
                 full_start_url = f"{self.base_url}/{start_path.lstrip('/')}"
            
            # 3. 开始爬取
            print(f"[+] 开始全站爬取: {full_start_url}")
            # Pikachu 结构比较扁平，但左侧菜单由 iframe 或 JS 加载，
            # 这里我们简单地从 index.php 开始，依赖 crawl 的 BFS 发现链接
            await self.crawl(page, [full_start_url], max_depth=3) # Pikachu 稍微深一点
            
            # 保存结果
            import os
            if os.path.dirname(output):
                os.makedirs(os.path.dirname(output), exist_ok=True)
                
            with open(output, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Pikachu 爬取完成，结果已写入 {output}")
            
            await browser.close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SAFS-Scanner 通用爬虫")
    parser.add_argument("--base", "-b", required=True, help="目标基础 URL (例如 http://127.0.0.1/dvwa)")
    parser.add_argument("--cookie", "-c", default="", help="登录 Cookie 字符串 (例如 'PHPSESSID=xxx; security=low')")
    parser.add_argument("--start", "-s", default="/", help="起始爬取路径 (默认 /)")
    parser.add_argument("--output", "-o", default="data/targets.json", help="输出 JSON 文件")
    parser.add_argument("--no-headless", dest="headless", action="store_false", help="运行可见浏览器")
    parser.add_argument("--dvwa", action="store_true", help="启用 DVWA 批量爬取模式 (自动遍历 low-impossible)")
    parser.add_argument("--bwapp", action="store_true", help="启用 bWAPP 批量爬取模式 (自动遍历 low-high)")
    parser.add_argument("--pikachu", action="store_true", help="启用 Pikachu 专用模式 (自动处理登录)")

    args = parser.parse_args(argv)

    if args.dvwa:
        spider = DVWASpider(args.base, args.cookie)
        try:
            asyncio.run(spider.run_batch(start_path=args.start, headless=args.headless, output=args.output))
        except KeyboardInterrupt:
            print("[!] 用户中断")
            return 1
        except Exception as e:
            print(f"[!] 未处理的错误: {e}")
            return 2
    elif args.bwapp:
        spider = BWAPPSpider(args.base, args.cookie)
        try:
            asyncio.run(spider.run_batch(start_path=args.start, headless=args.headless, output=args.output))
        except KeyboardInterrupt:
            print("[!] 用户中断")
            return 1
        except Exception as e:
            print(f"[!] 未处理的错误: {e}")
            return 2
    elif args.pikachu:
        spider = PikachuSpider(args.base, args.cookie)
        try:
            asyncio.run(spider.run_pikachu(start_path=args.start, headless=args.headless, output=args.output))
        except KeyboardInterrupt:
            print("[!] 用户中断")
            return 1
        except Exception as e:
            print(f"[!] 未处理的错误: {e}")
            return 2
    else:
        spider = UniversalSpider(args.base, args.cookie)
        try:
            asyncio.run(spider.run(start_path=args.start, headless=args.headless, output=args.output))
        except KeyboardInterrupt:
            print("[!] 用户中断")
            return 1
        except Exception as e:
            print(f"[!] 未处理的错误: {e}")
            return 2
            
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

