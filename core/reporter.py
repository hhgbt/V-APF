import json
import os
import time
import math
import numpy as np
import matplotlib
matplotlib.use('Agg') # 非交互式后端
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from matplotlib import font_manager

# 确保核心包导入在直接运行时工作
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 尝试配置中文字体
zh_font = None
# 常见 Linux 中文字体路径
font_candidates = [
    "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/arphic/uming.ttc"
]
for fpath in font_candidates:
    if os.path.exists(fpath):
        # 全局注册字体
        font_manager.fontManager.addfont(fpath)
        # 获取字体名称并设置为全局默认
        prop = font_manager.FontProperties(fname=fpath)
        plt.rcParams['font.family'] = prop.get_name()
        plt.rcParams['font.sans-serif'] = [prop.get_name()]
        zh_font = prop # 保留引用以防万一
        print(f"[+] 发现并注册中文字体: {fpath} ({prop.get_name()})")
        break

if not zh_font:
    print("[!] 未找到系统中文字体，图表中文可能显示异常。")

plt.rcParams['axes.unicode_minus'] = False 

class ReportGenerator:
    def __init__(self, data_file="data/scan_results.json"):
        self.data_file = os.path.join(ROOT, data_file)
        self.results = []
        self._load_data()

    def _load_data(self):
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    self.results = json.load(f)
            except Exception as e:
                print(f"[!] 加载数据错误: {e}")
                self.results = []
        else:
            print(f"[!] 未找到数据文件: {self.data_file}")

    def get_remediation_advice(self, payload_type):
        advice_map = {
            "sqli": "建议使用参数化查询（Prepared Statements）或 ORM 框架，避免直接拼接 SQL 语句。对于存储过程，确保存储过程本身不进行动态 SQL 拼接。",
            "xss": "建议对用户输入进行严格的转义和过滤。输出时使用上下文感知的编码（如 HTML Entity Encoding）。启用 Content Security Policy (CSP) 以限制脚本执行。",
            "cmdi": "建议避免直接调用系统命令。如必须调用，请使用 execFile 等不调用 shell 的 API，并严格验证输入参数。",
            "lfi": "建议严格验证文件名输入，使用白名单机制限制可访问的文件路径。避免直接将用户输入用于文件路径拼接。",
            "generic": "建议对输入进行严格的类型和格式验证，遵循最小权限原则，并定期进行安全审计。"
        }
        return advice_map.get(payload_type, advice_map["generic"])

    def process_results(self):
        # 增强结果：添加置信度、风险等级和修复建议
        processed = []
        for r in self.results:
            # 处理概率
            # probability 是列表 [safe_prob, vuln_prob] 或 None
            prob = r.get("probability")
            pred = r.get("prediction")
            features = r.get("features", {})
            
            confidence = 0.0
            risk_level = "安全"
            
            if prob and isinstance(prob, list) and len(prob) == 2:
                if pred == 1:
                    confidence = prob[1]
                else:
                    confidence = prob[0]
            else:
                # 如果没有概率，则为确定性
                confidence = 1.0 
            
            if pred == 1:
                # 增强的风险评级逻辑
                if confidence > 0.95:
                    risk_level = "严重"
                elif confidence > 0.80:
                    risk_level = "高危"
                else:
                    # 如果置信度一般，但特征偏移巨大，也可以提升风险等级
                    # 这里假设 resp_time_diff > 2.0s 为显著异常
                    resp_diff = features.get("resp_time_diff", 0) if features else 0
                    if resp_diff > 2.0:
                         risk_level = "高危"
                    else:
                        risk_level = "中危"
                
                # 添加修复建议
                payload_type = r.get("payload_type", "generic")
                r["remediation"] = self.get_remediation_advice(payload_type)
            else:
                risk_level = "安全"
            
            r["confidence"] = confidence
            r["risk_level"] = risk_level
            processed.append(r)
        return processed

    def generate_chart(self, output_path="data/stat_chart.png"):
        output_full_path = os.path.join(ROOT, output_path)
        os.makedirs(os.path.dirname(output_full_path), exist_ok=True)
        
        vuln_count = sum(1 for r in self.results if r.get('prediction') == 1)
        safe_count = sum(1 for r in self.results if r.get('prediction') == 0)
        
        if vuln_count + safe_count == 0:
            return None
            
        labels = ['漏洞', '安全']
        counts = [vuln_count, safe_count]
        colors = ['#c0392b', '#2ecc71']
        
        plt.figure(figsize=(6, 4))
        plt.pie(counts, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
        plt.title("AI 漏洞检测分布")
        plt.savefig(output_full_path, bbox_inches='tight')
        plt.close()
        
        return output_full_path

    def generate_radar_chart(self, result, output_path="data/radar_chart.png"):
        # 选择主要特征进行展示，避免拥挤
        # 关注差异特征和敏感特征
        if not result or not result.get("features"):
            return None

        features = result.get("features", {})
        
        # 定义关注的特征及其最大归一化尺度（近似值）
        # 我们使用对数尺度或相对尺度进行可视化
        keys = ['len_diff', 'resp_time_diff', 'sql_error_count', 'tag_count_diff', 'special_char_count', 'keyword_count']
        labels = ['长度差异', '时间差异', 'SQL错误', '标签差异', '特殊字符', '关键字']
        
        values = []
        for k in keys:
            val = features.get(k, 0)
            # 归一化以获得视觉冲击力（简单的上限截断/缩放）
            if k == 'len_diff':
                val = min(val, 500) / 500.0 * 5 # 缩放到 0-5
            elif k == 'resp_time_diff':
                val = min(val, 2.0) / 2.0 * 5
            elif k == 'sql_error_count':
                val = min(val, 5) / 5.0 * 5
            elif k == 'tag_count_diff':
                val = min(abs(val), 20) / 20.0 * 5
            elif k == 'special_char_count':
                val = min(val, 20) / 20.0 * 5
            elif k == 'keyword_count':
                val = min(val, 5) / 5.0 * 5
            values.append(max(0, val)) # 确保无负值
            
        # 闭合圆环
        values += values[:1]
        angles = np.linspace(0, 2*np.pi, len(labels), endpoint=False).tolist()
        angles += angles[:1]
        
        fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
        ax.fill(angles, values, color='#c0392b', alpha=0.25)
        ax.plot(angles, values, color='#c0392b', linewidth=2)
        
        ax.set_yticklabels([])
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels)
        
        plt.title(f"漏洞特征指纹\n(风险: {result.get('risk_level', '未知')})", y=1.08)
        
        output_full_path = os.path.join(ROOT, output_path)
        os.makedirs(os.path.dirname(output_full_path), exist_ok=True)
        plt.savefig(output_full_path, bbox_inches='tight')
        plt.close()
        
        return output_full_path

    def render_pdf(self, output_pdf="reports/scan_report.pdf"):
        output_full_path = os.path.join(ROOT, output_pdf)
        os.makedirs(os.path.dirname(output_full_path), exist_ok=True)
        
        processed_results = self.process_results()
        
        total_scans = len(processed_results)
        total_vulns = sum(1 for r in processed_results if r['prediction'] == 1)
        avg_conf = 0
        if total_scans > 0:
            avg_conf = sum(r['confidence'] for r in processed_results) / total_scans * 100
        
        chart_path = self.generate_chart()
        
        # Generate radar chart for the highest confidence vulnerability
        radar_chart_path = None
        vulns = [r for r in processed_results if r['prediction'] == 1]
        if vulns:
            # Sort by confidence desc
            vulns.sort(key=lambda x: x['confidence'], reverse=True)
            top_vuln = vulns[0]
            radar_chart_path = self.generate_radar_chart(top_vuln)
        
        env = Environment(loader=FileSystemLoader(os.path.join(ROOT, 'templates')))
        template = env.get_template('report_template.html')
        
        html_out = template.render(
            results=processed_results,
            chart_path=chart_path,
            radar_chart_path=radar_chart_path,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            total_scans=total_scans,
            total_vulns=total_vulns,
            avg_confidence=f"{avg_conf:.2f}"
        )
        
        HTML(string=html_out, base_url=ROOT).write_pdf(output_full_path)
        print(f"[+] 报告已成功生成: {output_full_path}")
        return output_full_path

if __name__ == "__main__":
    reporter = ReportGenerator()
    reporter.render_pdf()
