import argparse
import asyncio
import json
import sys
import time
from typing import List, Dict, Any, Optional

from playwright.async_api import async_playwright, Page, Browser, BrowserContext


class DVWASpider:
    """一个基于 Playwright 的小型爬虫，专为 DVWA 风格的应用设计。

    功能特性:
    - 使用提供的凭据登录 login.php
    - 读取并设置 security.php 上的安全等级
    - 从左侧菜单提取导航目标
    - 针对每个发现的目标页面，提取锚点链接 (href) 和表单定义
    - 将结构化结果保存为 JSON 文件
    """

    def __init__(self, base_url: str, username: str = "admin", password: str = "password"):
        self.base_url = base_url.rstrip("/")
        self.auth = {"user": username, "pass": password}
        self.targets: List[Dict[str, Any]] = []
        self.results: Dict[str, Any] = {"base_url": self.base_url, "pages": []}

    async def login(self, page: Page) -> bool:
        try:
            await page.goto(f"{self.base_url}/login.php")
            # DVWA 登录表单使用 name=username 和 name=password，以及 name=Login 的输入框
            await page.fill('input[name="username"]', self.auth["user"])
            await page.fill('input[name="password"]', self.auth["pass"])
            await page.click('input[name="Login"]')
            # 等待导航完成或登录完成的标志
            await page.wait_for_load_state("networkidle")
            print("[+] 尝试登录")
            return True
        except Exception as e:
            print(f"[-] 登录失败: {e}")
            return False

    async def get_security_level(self, page: Page) -> Optional[str]:
        try:
            await page.goto(f"{self.base_url}/security.php")
            # 从 select[name="security"] 读取选中选项的值或文本
            sel = await page.query_selector('select[name="security"]')
            if not sel:
                return None
            selected = await sel.input_value()
            # input_value 返回选中选项的 value 属性
            return selected
        except Exception as e:
            print(f"[-] 无法读取安全等级: {e}")
            return None

    async def set_security_level(self, page: Page, level: str) -> bool:
        try:
            await page.goto(f"{self.base_url}/security.php")
            # 尝试通过选项值设置。常见的 DVWA 值: low, medium, high, impossible
            await page.select_option('select[name="security"]', level)
            await page.click('input[name="seclev_submit"]')
            await page.wait_for_load_state("networkidle")
            print(f"[+] 安全等级已设置为: {level}")
            return True
        except Exception as e:
            print(f"[-] 无法设置安全等级: {e}")
            return False

    @staticmethod
    async def _extract_forms_from_page(page: Page) -> List[Dict[str, Any]]:
        forms_data: List[Dict[str, Any]] = []
        forms = await page.query_selector_all("form")
        for form in forms:
            try:
                action = await form.get_attribute("action") or ""
                method = (await form.get_attribute("method")) or "GET"
                inputs: List[Dict[str, Any]] = []

                # 收集 input 字段, textarea 和 select
                fields = await form.query_selector_all("input, textarea, select")
                for field in fields:
                    name = await field.get_attribute("name") or ""
                    ftype = await field.get_attribute("type") or ("textarea" if (await field.evaluate("el => el.tagName.toLowerCase()")) == "textarea" else "select")
                    value = await field.get_attribute("value") or ""
                    placeholder = await field.get_attribute("placeholder") or ""

                    field_data: Dict[str, Any] = {
                        "name": name,
                        "type": ftype,
                        "value": value,
                        "placeholder": placeholder,
                    }

                    # 如果是 select，收集选项
                    tag_name = await field.evaluate("el => el.tagName.toLowerCase()")
                    if tag_name == "select":
                        opts = []
                        options = await field.query_selector_all("option")
                        for opt in options:
                            opts.append({
                                "value": await opt.get_attribute("value"),
                                "text": await opt.inner_text(),
                                "selected": await opt.get_attribute("selected") is not None,
                            })
                        field_data["options"] = opts

                    inputs.append(field_data)

                forms_data.append({"action": action, "method": method.upper(), "inputs": inputs})
            except Exception as e:
                # 遇到表单提取错误继续执行
                print(f"[-] 提取表单时出错: {e}")
                continue
        return forms_data

    @staticmethod
    async def _extract_anchors_from_page(page: Page, base_url: str) -> List[str]:
        anchors: List[str] = []
        a_elems = await page.query_selector_all("a")
        for a in a_elems:
            try:
                href = await a.get_attribute("href")
                if not href:
                    continue
                # 标准化相对 URL
                if href.startswith("/"):
                    full = f"{base_url}{href}"
                elif href.startswith("http://") or href.startswith("https://"):
                    full = href
                else:
                    # 相对路径
                    full = f"{base_url}/{href}".replace("//", "/").replace("http:/", "http://").replace("https:/", "https://")
                anchors.append(full)
            except Exception:
                continue
        # 去重并保持顺序
        seen = set()
        uniq = []
        for u in anchors:
            if u not in seen:
                seen.add(u)
                uniq.append(u)
        return uniq

    async def crawl_targets(self, page: Page, nav_links: List[str], target_level: str):
        # 访问每个发现的页面并提取锚点和表单
        for url in nav_links:
            try:
                print(f"[+] 正在访问 {url} (等级: {target_level})")
                
                # 测量基准响应指标
                start_time = time.time()
                resp = await page.goto(url)
                await page.wait_for_load_state("networkidle")
                end_time = time.time()
                
                resp_time = end_time - start_time
                content = await page.content()
                resp_length = len(content)
                
                # 提取锚点和表单
                anchors = await self._extract_anchors_from_page(page, self.base_url)
                forms = await self._extract_forms_from_page(page)
                
                page_entry = {
                    "url": url, 
                    "level": target_level, 
                    "anchors": anchors, 
                    "forms": forms,
                    "base_resp_time": resp_time,
                    "base_resp_length": resp_length
                }
                self.results["pages"].append(page_entry)
            except Exception as e:
                print(f"[-] 爬取 {url} 时出错: {e}")
                continue

    async def run(self, target_levels: List[str] = ["low", "medium", "high", "impossible"], headless: bool = True, output: str = "targets.json"):
        async with async_playwright() as p:
            browser: Browser = await p.chromium.launch(headless=headless)
            context: BrowserContext = await browser.new_context()
            page: Page = await context.new_page()

            # 1. 登录
            ok = await self.login(page)
            if not ok:
                print("[-] 因登录失败中止")
                await browser.close()
                return

            # 收集导航链接一次（假设它们在不同等级间变化不大）
            nav_hrefs_clean = await self._collect_nav_links(page)
            if not nav_hrefs_clean:
                print("[-] 未找到导航链接。中止。")
                await browser.close()
                return

            # 遍历每个请求的安全等级
            for level in target_levels:
                print(f"\n[=] 正在切换到安全等级: {level}")
                
                # 2. 安全等级
                current_level = await self.get_security_level(page)
                if current_level != level:
                    await self.set_security_level(page, level)
                
                # 双重检查
                current_level = await self.get_security_level(page)
                print(f"[+] 当前安全等级: {current_level}")

                # 4. 爬取每个页面并提取锚点和表单
                await self.crawl_targets(page, nav_hrefs_clean, level)

            # 5. 保存结果
            with open(output, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"[+] 结果已写入 {output}")

            await browser.close()

    async def _collect_nav_links(self, page: Page) -> List[str]:
        # 3. 从左侧菜单收集导航链接
        try:
            await page.goto(f"{self.base_url}/index.php")
            # 优化点 1：等待菜单容器出现，增加成功率
            await page.wait_for_selector('#main_menu', timeout=5000)

            # 优化点 2：使用更宽泛的选择器，抓取 id 包含 menu 的 div 下的所有链接
            nav_links_elems = await page.query_selector_all('div[id*="menu"] a')

            nav_hrefs: List[str] = []
            for a in nav_links_elems:
                href = await a.get_attribute("href")
                if not href:
                    continue
                if href.startswith("http://") or href.startswith("https://"):
                    full = href
                else:
                    full = f"{self.base_url}/{href.lstrip('./')}"
                nav_hrefs.append(full)

            # 去重
            seen = set()
            nav_hrefs_clean: List[str] = []
            for n in nav_hrefs:
                if n not in seen:
                    seen.add(n)
                    nav_hrefs_clean.append(n)

            print(f"[+] 找到 {len(nav_hrefs_clean)} 个导航链接")
            return nav_hrefs_clean

        except Exception as e:
            print(f"[-] 收集导航链接时出错: {e}")
            return []


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="使用 Playwright 的 DVWA 爬虫")
    parser.add_argument("--base", "-b", default="http://127.0.0.1/dvwa", help="目标 DVWA 实例的基础 URL")
    parser.add_argument("--user", "-u", default="admin", help="用户名")
    parser.add_argument("--pass", "-p", dest="password", default="password", help="密码")
    parser.add_argument("--levels", "-l", default="low,medium,high,impossible", help="目标安全等级（逗号分隔，例如 low,medium,high,impossible）")
    parser.add_argument("--output", "-o", default="data/targets.json", help="输出 JSON 文件")
    parser.add_argument("--no-headless", dest="headless", action="store_false", help="运行可见浏览器以便调试")

    args = parser.parse_args(argv)

    target_levels = [l.strip() for l in args.levels.split(",")]

    spider = DVWASpider(args.base, args.user, args.password)
    try:
        asyncio.run(spider.run(target_levels=target_levels, headless=args.headless, output=args.output))
    except KeyboardInterrupt:
        print("[!] 用户中断")
        return 1
    except Exception as e:
        print(f"[!] 未处理的错误: {e}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

