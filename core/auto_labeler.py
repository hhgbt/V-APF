import argparse
import pandas as pd

def logic_label(row):
    sec_level = str(row.get("security_level", "")).lower()
    payload_type = str(row.get("payload_type", "")).lower()

    # 安全转换特征值为数值
    def get_int(key, default=0):
        try:
            return int(row.get(key, default))
        except:
            return default
    
    def get_float(key, default=0.0):
        try:
            return float(row.get(key, default))
        except:
            return default

    # 提取关键特征
    has_sql_error_probe = get_int("has_sql_error_probe")
    has_sql_error_base = get_int("has_sql_error_base")
    probe_reflected = get_int("probe_reflected")
    has_script_tag_probe = get_int("has_script_tag_probe")
    status_changed = get_int("status_changed")
    has_text_diff = get_int("has_text_diff")
    len_diff = get_float("len_diff")
    resp_time_diff = get_float("resp_time_diff")

    # 定义“有明显异常”的条件（特征反馈）
    # 1. SQL 报错出现
    is_sql_error = (has_sql_error_probe == 1 and has_sql_error_base == 0)
    # 2. XSS 关键特征：脚本标签或反射
    is_xss_sign = (probe_reflected == 1) or (has_script_tag_probe == 1 and payload_type == "xss")
    # 3. 状态码突变（如 500）
    is_status_bad = (status_changed == 1)
    # 4. 显著的时间延迟（针对盲注，阈值设为 0.5s）
    is_time_delayed = (resp_time_diff > 0.5)
    # 5. 明显的文本或长度差异（排除微小的动态内容变化）
    # 严格模式：仅在非 impossible/high 时作为主要判断依据，或者差异足够大
    is_content_changed = (has_text_diff == 1) or (len_diff > 0)

    # 综合异常标志
    has_anomaly = is_sql_error or is_xss_sign or is_status_bad or is_time_delayed

    # === 双重验证打标逻辑 ===

    # 场景 A: 高安全等级 (impossible / high)
    if sec_level in ["impossible", "high"]:
        # 信任 DVWA 的防御，默认标为 0 (安全)
        # 但保留底线：如果出现了极度明显的硬伤（如 SQL 语法报错），则必须标为 1
        # 注意：时间延迟或文本差异在 impossible 级别通常被视为正常处理（如过滤后的页面变化），不视为漏洞
        if is_sql_error:
            return 1
        return 0

    # 场景 B: 低/中安全等级 (low / medium)
    if sec_level in ["low", "medium"]:
        # 只有当特征真的发生“有害”变化时，才标为 1
        if has_anomaly:
            return 1
        
        # 对于内容变化，需要更细致的判断
        # 如果仅仅是 len_diff > 0 但没有其他报错/延迟，可能是正常的动态页面（如显示了输入内容但转义了）
        # 但在 Low 级别，DVWA 通常会直接反射 Payload。
        # 如果 probe_reflected == 1，上面 has_anomaly 已经覆盖了。
        # 如果只是 len_diff > 0 但没反射（比如被过滤空了），那也不算利用成功，应标为 0。
        # 这里我们稍微放宽：如果 payload 导致了明显的内容变化（非 0），且处于易感等级，倾向于认为有效
        if is_content_changed:
             # 进一步确认：如果是 XSS payload，必须要有反射或脚本标签才算成功
             if payload_type == "xss" and not is_xss_sign:
                 return 0
             return 1

        # 如果 Payload 丢进去毫无反应（无报错、无延迟、无状态变化、无内容差异），
        # 说明这次注入无效（可能是 Payload 本身不匹配该端点），标为 0
        return 0

    # 默认兜底（未知等级）
    return 1 if has_anomaly else 0

def main():
    parser = argparse.ArgumentParser(description="Auto label training CSV using heuristics")
    parser.add_argument("-i", "--in", dest="infile", default="data/training_data.csv", help="Input CSV path")
    parser.add_argument("-o", "--out", dest="outfile", default=None, help="Output CSV path (default overwrite input)")
    parser.add_argument("--force", action="store_true", help="(deprecated) kept for compatibility")
    parser.add_argument("--preserve", action="store_true", help="Preserve existing non-empty labels (do not overwrite)")
    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile or infile

    df = pd.read_csv(infile)

    def apply_label(row):
        # 默认覆盖所有标签，除非用户指定 --preserve
        if args.preserve:
            cur = str(row.get("label", "")).strip()
            if cur != "":
                return cur
        return logic_label(row)

    df["label"] = df.apply(apply_label, axis=1)

    # 确保输出目录存在
    outdir = "/".join(outfile.split("/")[:-1])
    if outdir:
        import os

        os.makedirs(outdir, exist_ok=True)

    df.to_csv(outfile, index=False)
    total = len(df)
    ones = int((df["label"] == 1).sum())
    zeros = int((df["label"] == 0).sum())
    print(f"[+] Wrote {outfile} — total={total}, label=1:{ones}, label=0:{zeros}")

if __name__ == "__main__":
    main()