import os
import sys
import pickle
import time
from typing import Optional

import pandas as pd

try:
    import joblib
except Exception:
    joblib = None

# Ensure project root is on sys.path so `core` package imports work when
# running scripts directly (python3 core/predict_scanner.py)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.fuzzer_feature_extractor import FeatureExtractor


class AIScanner:
    def __init__(
        self,
        model_path: str = "models/vulnerability_model_all.pkl",
        feature_list_path: str = "models/feature_list_all.pkl",
    ):
        # 加载模型与特征列表（支持 joblib 或 pickle）
        if joblib is not None:
            self.model = joblib.load(model_path)
            self.feature_list = joblib.load(feature_list_path)
        else:
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            with open(feature_list_path, "rb") as f:
                self.feature_list = pickle.load(f)

        # 初始化提取器（复用 session/cookies），默认使用仓库下的 data/targets.json
        targets_path = os.path.join(ROOT, "data/targets.json")
        if os.path.exists(targets_path):
            self.extractor = FeatureExtractor(targets_file=targets_path)
        else:
            # 回退到相对路径，兼容旧的工作目录用法
            self.extractor = FeatureExtractor()
        print(f"[+] AI 扫描引擎已就绪，识别特征数: {len(self.feature_list)}")

    def scan(self, target_url: str, method: str = "POST", payload_type: str = "sqli", payload_str: str = "' OR '1'='1", adaptive: bool = True):
        print(f"[*] 扫描: {target_url} (payload_type={payload_type})")

        feat = self.get_live_features(target_url, method, payload_type, payload_str)
        if not feat:
            print("[!] 无法提取特征，扫描中止")
            return None

        df = pd.DataFrame([feat])
        # 保证特征顺序一致
        X = df.reindex(columns=self.feature_list, fill_value=0)

        pred = self.model.predict(X)[0]
        prob = None
        try:
            prob = self.model.predict_proba(X)[0]
        except Exception:
            pass

        result = {"prediction": int(pred), "probability": prob, "features": feat}

        if pred == 1:
            if prob is not None:
                print(f"[@] 发现漏洞 (概率 {prob[1]*100:.2f}%)")
            else:
                print("[@] 发现漏洞 (模型给出正例)")
        else:
            if prob is not None:
                print(f"[#] 判定为安全 (安全概率 {prob[0]*100:.2f}%)")
            else:
                print("[#] 判定为安全")

        # 检查是否需要进入自适应变异阶段（只在顶层调用时进行）
        if adaptive and result and result.get("probability") is not None:
            vulnerability_prob = result["probability"][1] * 100
            if 40 <= vulnerability_prob <= 75:
                print("[+] 进入自适应变异阶段...")
                adaptive_payloads = ["' OR SLEEP(5) -- ", "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, (SELECT database()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) -- "]
                for adaptive_payload in adaptive_payloads:
                    print(f"[*] 使用变异 Payload: {adaptive_payload}")
                    # 对变异 payload 执行一次非自适应扫描以避免递归
                    mut_result = self.scan(target_url, method, payload_type, adaptive_payload, adaptive=False)
                    if mut_result and mut_result.get("prediction") == 1:
                        prob = mut_result.get("probability")
                        if prob is not None:
                            print(f"[@] 发现漏洞 (变异 Payload 概率 {prob[1]*100:.2f}%)")
                        else:
                            print("[@] 发现漏洞 (变异 Payload 检测到正例)")
                        result = mut_result
                        break
            else:
                print("[+] 无需变异，扫描结束。")

        return result

    def _find_page_form(self, url: str) -> Optional[dict]:
        # 在 extractor.data 中寻找匹配的 page 和 form
        pages = self.extractor.data.get("pages", [])
        for page in pages:
            p_url = page.get("url")
            if not p_url:
                continue
            if url == p_url or url.startswith(p_url) or p_url.startswith(url):
                forms = page.get("forms", [])
                if forms:
                    return {"page": page, "form": forms[0]}
        return None

    def get_live_features(self, url: str, method: str, p_type: str, p_str: str) -> Optional[dict]:
        # 尝试找到原始表单定义（从 targets.json），没有的话回退到简单提交
        match = self._find_page_form(url)
        if match:
            page = match["page"]
            form = match["form"]
            action = form.get("action") or ""
            request_url = action and (self.extractor._fetch_form_tokens(page["url"], action) and url) or page.get("url", url)
            method = form.get("method", method).upper()
            inputs = [inp for inp in form.get("inputs", []) if inp.get("name")]
            base_payload = {inp["name"]: "test" for inp in inputs}
            # 合入隐藏 token
            tokens = self.extractor._fetch_form_tokens(page.get("url"), form.get("action") or "")
            base_payload.update(tokens)
            probe_payload = {inp["name"]: p_str for inp in inputs}
            probe_payload.update(tokens)
        else:
            # 回退：使用单参数 'input' 和抓取隐藏 token
            request_url = url
            base_payload = {"input": "test"}
            tokens = self.extractor._fetch_form_tokens(url, "")
            base_payload.update(tokens)
            probe_payload = {"input": p_str}
            probe_payload.update(tokens)

        # 使用 FeatureExtractor.extract_features() 以确保训练/预测时特征完全对齐
        sample, base_text, probe_text = self.extractor.extract_features(request_url, method, probe_payload, base_payload=base_payload, probe_str=p_str)
        return sample


def main():
    import argparse

    parser = argparse.ArgumentParser(description="AI 在线扫描器（即时特征提取 + 预测）")
    parser.add_argument("url", help="目标页面 URL")
    parser.add_argument("--method", default="POST", help="请求方法")
    parser.add_argument("--payload", default="' OR '1'='1", help="探测 payload 字符串")
    parser.add_argument("--model", default="models/vulnerability_model_all.pkl", help="模型路径")
    parser.add_argument("--features", default="models/feature_list_all.pkl", help="特征列表路径")
    args = parser.parse_args()

    scanner = AIScanner(model_path=args.model, feature_list_path=args.features)
    scanner.scan(args.url, method=args.method, payload_str=args.payload)


if __name__ == "__main__":
    main()
