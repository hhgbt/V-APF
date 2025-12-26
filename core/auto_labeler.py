import argparse
import pandas as pd

def logic_label(row):
    url = str(row.get("page_url", "")).lower()
    payload_type = str(row.get("payload_type", "")).lower()

    # 1) probe 导致 SQL 错误从无到有
    try:
        if int(row.get("has_sql_error_probe", 0)) == 1 and int(row.get("has_sql_error_base", 0)) == 0:
            return 1
    except Exception:
        pass

    # 2) payload 被反射（潜在 XSS/反射注入），对 XSS 权重更高
    try:
        if int(row.get("probe_reflected", 0)) == 1:
            return 1
    except Exception:
        pass

    # 3) 响应中出现 <script> 且 payload_type 为 xss
    try:
        if int(row.get("has_script_tag_probe", 0)) == 1 and payload_type == "xss":
            return 1
    except Exception:
        pass

    # 4) 状态码变化（例如 403/500）通常表示请求触发了异常或被阻断
    try:
        if int(row.get("status_changed", 0)) == 1:
            return 1
    except Exception:
        pass

    # 5) 文本差异或长度差异（更宽松：len_diff > 0 即可）
    try:
        if int(row.get("has_text_diff", 0)) == 1:
            return 1
        if float(row.get("len_diff", 0)) > 0:
            # 对某些页面 len_diff 微小但有意义，视为可疑
            return 1
    except Exception:
        pass

    # 6) 响应时间显著增加（默认阈值 0.1s）
    try:
        if float(row.get("resp_time_diff", 0)) > 0.1:
            return 1
    except Exception:
        pass

    return 0

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