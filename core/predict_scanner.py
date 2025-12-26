import os
import sys
import pickle
import time
import json
from typing import Optional

import pandas as pd

try:
    import joblib
except Exception:
    joblib = None

# 确保项目根目录在 sys.path 中，以便直接运行脚本时（python3 core/predict_scanner.py）能正确导入 `core` 包
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.fuzzer_feature_extractor import FeatureExtractor
from core.mutator import Mutator


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
            pos_conf = result["probability"][1]
            # 当正例置信度低于 60% 时，启动变异反馈循环
            if pos_conf < 0.6:
                print(f"[+] 置信度低 ({pos_conf*100:.1f}%)，进入自适应变异反馈循环...")
                mutator = Mutator(max_attempts=10)
                attempts = 0
                best_result = result
                for mutated in mutator.generate(payload_str):
                    attempts += 1
                    print(f"[*] 尝试变异 #{attempts}: {mutated}")
                    # 直接重新提取特征并预测（避免递归调用 scan() 以保留控制）
                    feat = self.get_live_features(target_url, method, payload_type, mutated)
                    if not feat:
                        print("[!] 变异后无法提取到特征，跳过")
                        continue
                    dfm = pd.DataFrame([feat]).reindex(columns=self.feature_list, fill_value=0)
                    try:
                        pm = self.model.predict(dfm)[0]
                        pp = None
                        try:
                            pp = self.model.predict_proba(dfm)[0]
                        except Exception:
                            pass
                    except Exception as e:
                        print(f"[!] 预测失败: {e}")
                        continue

                    mutated_result = {"prediction": int(pm), "probability": pp, "features": feat}
                    # 如果这是更高的正例置信度则替换
                    if pp is not None and best_result.get("probability") is not None:
                        if pp[1] > best_result["probability"][1]:
                            best_result = mutated_result
                    else:
                        # 若无法获得概率信息，但预测为正例，优先使用
                        if mutated_result.get("prediction") == 1 and best_result.get("prediction") == 0:
                            best_result = mutated_result

                    # 终止条件：达到或超过 60% 的正例置信度，或模型直接判定为漏洞
                    conf = (pp[1] if pp is not None else (1.0 if mutated_result.get("prediction") == 1 else 0.0))
                    if mutated_result.get("prediction") == 1 or conf >= 0.6:
                        print(f"[+] 通过变异达成终止条件 (置信度 {conf*100:.2f}%)")
                        result = mutated_result
                        break

                else:
                    # 完成所有尝试仍未达标，使用 best_result（可能仍是原始结果）
                    print("[+] 变异尝试耗尽，使用最佳观测结果")
                    result = best_result
            else:
                print("[+] 置信度足够，无需自适应变异。")

        self._save_result(target_url, payload_str, payload_type, result)
        return result

    def _save_result(self, url: str, payload: str, payload_type: str, result: dict):
        if not result:
            return
        
        output_file = os.path.join(ROOT, "data/scan_results.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # 准备数据条目
        prob = result.get("probability")
        if prob is not None and hasattr(prob, "tolist"):
            prob = prob.tolist()
            
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "url": url,
            "payload": payload,
            "payload_type": payload_type,
            "prediction": int(result.get("prediction", 0)),
            "probability": prob,
            "features": result.get("features")
        }
        
        # 加载现有数据或创建新列表
        data = []
        if os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    content = f.read()
                    if content:
                        data = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                pass
        
        data.append(entry)
        
        # 保存回文件
        with open(output_file, "w") as f:
            json.dump(data, f, indent=4)

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
