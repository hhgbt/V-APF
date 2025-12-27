import json
import pandas as pd
import argparse
import os

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

    def heuristic_label(self, record):
        """
        核心打标逻辑
        """
        v = record['vector']
        url = record['url'].lower()
        payload = record.get('payload', '')
        risk_level = record.get('risk_level', 'normal')
        
        # 提取特征维度 (对应 extractor.py 的顺序)
        # v1: Length Diff, v2: Status Change, v3: Time Delay, v4: Keyword Match
        # v5: DOM Sim, v6: Reflection Score, v7: Header Change
        # v8-v13: Semantic Diffs
        
        # 初始分数
        score = 0.0
        
        # --- Rule 1: 强特征判定 (Strong Indicators) ---
        # 1.1 报错注入特征
        if v[3] > 0.1: # Keyword Match (加权分)
            score += 0.8 * v[3] # 权重越高分数越高
            
        # 1.2 时间盲注特征
        if v[2] > 0.5: # Time Delay > 0.5s (Aggressive)
            score += 0.8
            
        # 1.3 状态码变化 (通常意味着异常)
        if v[1] > 0:
            score += 0.4
            
        # --- Rule 2: 结构异变判定 (Structure Mutation) ---
        # 2.1 DOM 剧烈变化
        if 0.1 < v[4] < 0.99: 
            score += 0.4
            
        # 2.2 长度显著变化 (>10%)
        if abs(v[0]) > 0.1:
            score += 0.4
            
        # 2.3 标签数量剧变 (v11)
        if v[10] > 0.05: # Tag Count Change > 5%
            score += 0.4
            
        # --- Rule 3: 反射型 XSS 判定 ---
        # 反射比例高且页面结构微变
        if v[5] > 0.3: # Reflection Score (Very Relaxed)
            score += 0.5
            
        # --- Rule 4: 环境上下文修正 (Context Correction) ---
        # 4.1 安全等级降权
        # 大幅减少对 High 的惩罚，因为我们需要正样本
        if "impossible" in url:
            score -= 0.5
        # elif "high" in url:
        #    score -= 0.1 
            
        # 4.2 风险参数加权
        if risk_level == 'high':
            score += 0.3 
            
        # 4.3 Payload 类型修正
        if "test_safe" in payload or payload in ["1", "0"]:
            score -= 2.0 
            
        # [New Rule] 针对特定 Payload 的“保底打标逻辑”
        # 只要 Payload 含有特定字符且引起了任何微小波动，就标记为漏洞
        if any(p in payload for p in ["'", "<script", "sleep", "whoami"]): 
            # 长度微变 OR DOM微变 OR 有回显
            if abs(v[0]) > 0.01 or v[4] < 0.999 or v[5] > 0:  
                score += 0.5
            
        # --- 最终判定 ---
        # 阈值设定：0.35 (Extremely Aggressive)
        return 1 if score >= 0.35 else 0

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
    parser = argparse.ArgumentParser(description="SAFS-Scanner 自动打标器")
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
