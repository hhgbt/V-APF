import os
import json
import time
import argparse
import requests
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class FeatureExtractor:
    def __init__(self, targets_file="targets.json", output_csv="data/training_data.csv"):
        with open(targets_file, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.session = requests.Session()
        # 从环境获取会话信息，优先使用环境变量以避免硬编码
        phpsess = os.environ.get("DVWA_PHPSESSID", os.environ.get("PHPSESSID", ""))
        security = os.environ.get("DVWA_SECURITY", os.environ.get("security", "low"))
        self.cookies = {}
        if phpsess:
            self.cookies["PHPSESSID"] = phpsess
        if security:
            self.cookies["security"] = security
        self.output_csv = output_csv

        # 关键检测关键词
        self.sql_error_signs = ["sql syntax", "mysql", "syntax error", "warning: mysql", "you have an error in your sql"]

        # 预定义的探测 Payload 列表（SQLi, XSS, LFI）
        self.payloads = [
            {"type": "sqli", "payload": "test' OR '1'='1"},
            {"type": "sqli", "payload": "' OR 1=1 -- "},
            {"type": "sqli", "payload": "\" OR \"\"=\"\""},
            {"type": "xss", "payload": "<script>alert(1)</script>"},
            {"type": "xss", "payload": "<img src=1 onerror=alert(1)>"},
            {"type": "lfi", "payload": "../../../../etc/passwd"},
        ]

    def _fetch_form_tokens(self, page_url: str, action: str = "") -> dict:
        """请求表单所在页面并提取隐藏字段（例如 user_token）以防止 CSRF 拦截。"""
        try:
            target = urljoin(page_url, action) if action else page_url
            r = self.session.get(target, cookies=self.cookies, timeout=5)
            text = r.text or ""
            soup = BeautifulSoup(text, "html.parser")
            tokens = {}
            for inp in soup.find_all("input", type="hidden"):
                name = inp.get("name")
                val = inp.get("value", "")
                if name:
                    tokens[name] = val
            return tokens
        except Exception:
            return {}

    def _is_sql_error(self, text: str) -> int:
        if not text:
            return 0
        low = text.lower()
        return 1 if any(k in low for k in self.sql_error_signs) else 0

    def _has_script_tag(self, text: str) -> int:
        if not text:
            return 0
        soup = BeautifulSoup(text, "html.parser")
        return 1 if soup.find("script") else 0

    def get_feature_vector(self, url: str, method: str, payload_data: dict, timeout: float = 5.0):
        start_time = time.time()
        try:
            if method.upper() == "POST":
                resp = self.session.post(url, data=payload_data, cookies=self.cookies, timeout=timeout)
            else:
                resp = self.session.get(url, params=payload_data, cookies=self.cookies, timeout=timeout)

            end_time = time.time()

            text = resp.text or ""
            features = {
                "resp_length": len(text),
                "status_code": resp.status_code,
                "resp_time": end_time - start_time,
                "has_sql_error": self._is_sql_error(text),
                "has_script_tag": self._has_script_tag(text),
            }
            return features, text
        except Exception as e:
            return None, str(e)

    def extract_features(self, request_url: str, method: str, probe_payload: dict, base_payload: dict = None, probe_str: str = None, timeout: float = 5.0, base_resp_metrics: dict = None):
        """通用特征提取器。

        参数:
            request_url: 提交的完整 URL
            method: 请求方法 'GET' 或 'POST'
            probe_payload: 探测请求的参数字典（含要注入的 payload）
            base_payload: 可选的基准请求参数字典；若为 None，会以 probe_payload 的字段名构造默认值 'test'
            probe_str: 可选的探测字符串，用于判断是否反射
            timeout: 请求超时时间
            base_resp_metrics: 可选的基准响应指标（从爬虫阶段获取），包含 base_resp_length 和 base_resp_time

        返回:
            tuple (sample_dict, base_text, probe_text) 或 (None, None, None) 在失败时。
        """
        # 准备 base_payload
        if base_payload is None:
            base_payload = {k: "test" for k in probe_payload.keys()}

        # 合并页面隐藏 token（如果存在）到两个 payload
        try:
            tokens = self._fetch_form_tokens(request_url, "")
        except Exception:
            tokens = {}

        if tokens:
            base_payload.update(tokens)
            probe_payload.update(tokens)

        # 优先使用爬虫阶段获取的基准指标，减少请求次数并提高准确性
        if base_resp_metrics and "base_resp_length" in base_resp_metrics:
            base_feat = {
                "resp_length": base_resp_metrics.get("base_resp_length", 0),
                "resp_time": base_resp_metrics.get("base_resp_time", 0.0),
                "status_code": 200, # 假设爬虫能爬到的页面状态码为 200，或者需要额外传递
                "has_sql_error": 0, # 假设基准页面无报错
                "has_script_tag": 0 # 假设基准页面无注入脚本
            }
            base_text = "" # 如果使用了预先记录的指标，可能无法进行 has_text_diff 的精确比对，这里视情况权衡
            # 为了兼容 has_text_diff，如果必须要对比文本，还是得发请求。
            # 这里策略：如果提供了 metrics，我们仍然发请求以获取 text 用于 diff，但 resp_time_diff 可以参考 metrics
            # 或者：为了效率，如果提供了 metrics，我们就不发 base 请求了？
            # 考虑到 has_text_diff 是强特征，我们还是发一次 base 请求比较稳妥，或者仅在 base_text 确实需要时发。
            # 现阶段为了逻辑统一，我们还是发一次请求，但可以用 metrics 来校准/对比
            
            # 重新思考：爬虫记录的 metrics 是最“纯净”的。现在的 base_payload 是填了 "test" 的，可能已经不算完全的“空载”了。
            # 我们继续执行 get_feature_vector 获取当前环境下的 base_feat，但可以用 metrics 做参考或增强
            pass

        base_feat, base_text = self.get_feature_vector(request_url, method, base_payload, timeout=timeout)
        if not base_feat:
            return None, None, None

        # 如果爬虫提供了基准长度，用它来校准 len_diff 计算可能更准？
        # 实际上，base_payload 填入 "test" 后的响应长度，应该和爬虫记录的原始长度非常接近。
        # 我们这里主要使用 base_resp_metrics 来辅助计算 resp_time_diff，因为爬虫那次请求可能网络更稳定？
        # 或者，直接使用当前的 base_feat 即可，爬虫的数据主要用于 Labeling 阶段的参考？
        # 用户指令是：“提取器在计算 len_diff 时会变得极度精准”。这意味着应该利用 base_resp_length。
        
        if base_resp_metrics:
             # 如果提供了基准指标，覆盖 base_feat 中的关键数值，以爬虫记录的“纯净”状态为准
             if "base_resp_length" in base_resp_metrics:
                 base_feat["resp_length"] = base_resp_metrics["base_resp_length"]
             if "base_resp_time" in base_resp_metrics:
                 base_feat["resp_time"] = base_resp_metrics["base_resp_time"]

        probe_feat, probe_text = self.get_feature_vector(request_url, method, probe_payload, timeout=timeout)
        if not probe_feat:
            return None, None, None

        sample = {
            # 按训练时使用的特征名组织（保证名字完全一致以便对齐）
            "probe_reflected": 1 if probe_str and probe_str in (probe_text or "") else 0,
            "len_diff": abs(probe_feat["resp_length"] - base_feat["resp_length"]),
            "has_text_diff": 1 if (probe_text != base_text) else 0,
            "status_changed": 1 if probe_feat["status_code"] != base_feat["status_code"] else 0,
            "resp_time_diff": probe_feat["resp_time"] - base_feat["resp_time"],
            "resp_time_base": base_feat["resp_time"],
            "resp_time_probe": probe_feat["resp_time"],
            "resp_length_base": base_feat["resp_length"],
            "resp_length_probe": probe_feat["resp_length"],
            "has_sql_error_probe": probe_feat.get("has_sql_error", 0),
            "has_sql_error_base": base_feat.get("has_sql_error", 0),
            "has_script_tag_probe": probe_feat.get("has_script_tag", 0),
            "has_script_tag_base": base_feat.get("has_script_tag", 0),
        }

        return sample, base_text, probe_text

    def run(self):
        os.makedirs(os.path.dirname(self.output_csv) or ".", exist_ok=True)
        dataset = []

        for page in self.data.get("pages", []):
            page_url = page.get("url")
            # 获取爬虫记录的基准指标
            base_metrics = {
                "base_resp_length": page.get("base_resp_length"),
                "base_resp_time": page.get("base_resp_time")
            }
            security_level = page.get("level", "unknown")

            for form in page.get("forms", []):
                # 组合动作 URL（action 可能是相对路径）
                action = form.get("action") or ""
                request_url = urljoin(page_url, action) if action else page_url
                method = form.get("method", "GET").upper()

                inputs = [inp for inp in form.get("inputs", []) if inp.get("name")]
                if not inputs:
                    continue

                # 1) 干净基准请求
                base_payload = {inp["name"]: "test" for inp in inputs}
                # 注意：这里我们依然会发请求以获取 text 用于 diff，但在 extract_features 内部会利用 base_metrics 修正 length/time
                
                # 2) 获取表单页面的隐藏字段（CSRF token 等），以便将它们加入提交
                form_tokens = self._fetch_form_tokens(page_url, form.get("action") or "")

                # 3) 对每种探测 Payload 循环
                for p in self.payloads:
                    probe_str = p["payload"]
                    # 将 token 与探测字符串合并到每个字段（仅对有 name 的字段）
                    probe_payload = {inp["name"]: probe_str for inp in inputs}
                    # 如果 tokens 中包含与 form input 相同的名字（如 user_token），保留真实值
                    probe_payload.update(form_tokens)

                    # 使用通用的特征提取器以保证训练/预测时特征一致
                    sample, base_text, probe_text = self.extract_features(
                        request_url, 
                        method, 
                        probe_payload, 
                        base_payload=base_payload, 
                        probe_str=probe_str,
                        base_resp_metrics=base_metrics
                    )
                    if not sample:
                        continue
                    # 保留一些上下文信息以便人工标注
                    sample.update({
                        "page_url": page_url,
                        "request_url": request_url,
                        "form_method": method,
                        "payload_type": p["type"],
                        "payload": probe_str,
                        "security_level": security_level, # 传递安全等级给 auto_labeler 使用
                        "label": "",
                    })

                    dataset.append(sample)

        if not dataset:
            print("[!] No samples collected.")
            return

        df = pd.DataFrame(dataset)
        df.to_csv(self.output_csv, index=False)
        print(f"[+] Dataset generated: {self.output_csv}")


def main():
    parser = argparse.ArgumentParser(description="Fuzzer feature extractor for targets.json")
    parser.add_argument("--targets", "-t", default="data/targets.json", help="Path to targets.json")
    parser.add_argument("--out", "-o", default="data/training_features_raw.csv", help="Output CSV path")
    args = parser.parse_args()

    extractor = FeatureExtractor(targets_file=args.targets, output_csv=args.out)
    extractor.run()


if __name__ == "__main__":
    main()
