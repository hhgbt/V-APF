import json
import pandas as pd
import argparse
import os
import re

class AutoLabeler:
    """
    自动打标器 (Auto Labeler)
    
    功能:
    根据 13 维特征向量和靶场上下文 (Security Level)，利用启发式规则
    自动判定样本是“漏洞” (1) 还是“安全” (0)，生成用于训练的 CSV 数据集。
    """
    
    def __init__(self, features_path):
        if not os.path.exists(features_path):
            raise FileNotFoundError(f"特征文件未找到: {features_path}")
            
        with open(features_path, 'r') as f:
            self.data = json.load(f)

        # 载入无害 Payload 集合，用于强制负样本
        self.benign_payloads = self._load_benign_payloads()

    def _is_benign_format(self, s: str) -> bool:
        s = s.strip()
        if not s:
            return False
        # 仅限字母数字与常见表单安全字符
        if re.fullmatch(r'[A-Za-z0-9_\-.]+', s):
            return True
        # 日期格式 YYYY-MM-DD
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}', s):
            return True
        return False

    def _load_benign_payloads(self, path: str = 'data/payloads.txt'):
        benign = set()
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        t = line.strip()
                        if t and not t.startswith('#') and self._is_benign_format(t):
                            benign.add(t)
        except Exception:
            # 忽略读取失败，保持空集合
            pass
        return benign

    def is_benign_payload(self, payload: str) -> bool:
        if not payload:
            return False
        # 仅对白名单中的 payload 视为无害，不再对任意字母数字格式强制负判
        return payload in self.benign_payloads

    def heuristic_label(self, record):
        """
        核心打标逻辑
        """
        v = record['vector']
        url = record['url'].lower()
        payload = record.get('payload', '')
        risk_level = record.get('risk_level', 'normal')

        # 无害 Payload 强制判定为安全样本
        if self.is_benign_payload(payload):
            return 0
        
        # 提取特征维度 (对应 extractor.py 的顺序)
        # v1: Length Diff, v2: Status Change, v3: Time Delay, v4: Keyword Match
        # v5: DOM Sim, v6: Reflection Score, v7: Header Change
        # v8-v13: Semantic Diffs
        
        # 初始分数
        score = 0.0
        
        # --- Rule 1: 强特征判定 (Strong Indicators) ---
        # 1.1 报错注入特征（提升为更强信号）
        if v[3] > 0: # Keyword Match (任意报错即加分)
            score += 1.7
            
        # 1.2 时间盲注特征（更严格门槛）
        if v[2] > 0.7: # Normalized > 0.7 (~>3.5s)
            score += 1.3
            
        # 1.3 状态码变化 (通常意味着异常)
        if v[1] > 0:
            score += 0.8
            
        # --- Rule 2: 结构异变判定 (Structure Mutation) ---
        # 2.1 DOM 剧烈变化 (但不是全部丢失)
        if 0.2 < v[4] < 0.98: 
            score += 0.4
            
        # 2.2 长度显著变化 (>15%)
        if abs(v[0]) > 0.15:
            score += 0.3
            
        # 2.3 标签数量剧变 (v11 -> Extractor 目前没实现v11，保留逻辑)
        # if v[10] > 0.05: 
        #    score += 0.4
            
        # --- Rule 3: 反射型 XSS 判定 ---
        # 反射比例高且页面结构微变
        if v[5] > 0:
            score += 0.9

        # 反射型且长度明显变化的组合加分
        if v[5] > 0 and abs(v[0]) > 0.05:
            score += 0.5

        # 多弱信号叠加：长度变化且 DOM 有变化时给额外加分
        if abs(v[0]) > 0.05 and 0.2 < v[4] < 0.99:
            score += 0.25
            
        # --- Rule 4: 环境上下文修正 (Context Correction) ---
        # 4.1 安全等级降权
        # 大幅减少对 High 的惩罚，因为我们需要正样本
        if "impossible" in url:
            score -= 0.0 # 不再额外扣分
            
        # 4.2 风险参数加权
        if risk_level == 'high':
            score += 0.2 
            
        # 4.3 Payload 类型修正
        # 对变异 Payload 给予偏好
        if any(c in payload for c in ["/**/", "sElEcT", "%00", "||", "&&"]):
             if v[4] < 0.999 or abs(v[0]) > 0.02 or v[2] > 0.6:
                 score += 0.5

        # 对简单 payload 不再额外扣分
            
        # [New Rule] 针对特定 Payload 的“保底打标逻辑”
        # 只要 Payload 含有特定字符且引起了任何微小波动，就标记为漏洞
        if any(p in payload for p in ["'", "<script", "sleep", "whoami", "alert"]): 
            if abs(v[0]) > 0.02 or v[4] < 0.999 or v[5] > 0 or v[3] > 0:  
                score += 0.4
            
        # --- 最终判定 ---
        # 阈值设定：降到 0.65，进一步提高正样本占比
        return 1 if score >= 0.65 else 0

    def process(self, output_path):
        labeled_data = []
        pos_count = 0
        neg_count = 0
        
        print(f"[*] 开始处理 {len(self.data)} 条特征数据...")
        
        for record in self.data:
            label = self.heuristic_label(record)
            if label == 1:
                pos_count += 1
            else:
                neg_count += 1
                
            # 展平数据用于机器学习
            row = {
                "label": label,
                "url": record['url'],
                "param": record['param'],
                "payload": record.get('payload', ''),
                "risk_level": record.get('risk_level', 'normal')
            }
            # 将 13 维向量展开为 v1-v13
            for i, val in enumerate(record['vector']):
                row[f'v{i+1}'] = val
            labeled_data.append(row)
            
        df = pd.DataFrame(labeled_data)
        
        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        df.to_csv(output_path, index=False)
        print(f"\n[+] 打标完成！")
        print(f"    - 总样本数: {len(labeled_data)}")
        print(f"    - 正样本 (Vulnerable): {pos_count}")
        print(f"    - 负样本 (Safe): {neg_count}")
        print(f"    - 结果已保存至: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="V-APF 自动打标器")
    parser.add_argument("--input", default="data/features.json", help="输入特征文件")
    parser.add_argument("--output", default="data/train_dataset.csv", help="输出 CSV 数据集")
    args = parser.parse_args()

    try:
        labeler = AutoLabeler(args.input)
        labeler.process(args.output)
    except Exception as e:
        print(f"[!] 错误: {e}")

if __name__ == "__main__":
    main()
