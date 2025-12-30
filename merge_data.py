import json

# 仅合并标准三个目标的特征输出，避免其它运行结果被重复合并
feature_files = [
    "data/features_1.json",  # DVWA
    "data/features_2.json",  # bWAPP
    "data/features_3.json",  # Pikachu
]

all_vectors = []

for file in feature_files:
    try:
        with open(file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"警告: 未找到 {file}，跳过")
        continue

    if isinstance(data, list):
        all_vectors.extend(data)
        print(f"已加载 {file}: {len(data)} 条向量")
    else:
        print(f"警告: {file} 不是列表，跳过")

with open("data/features_all.json", "w") as f:
    json.dump(all_vectors, f, indent=2)

print(f"--- 合并完成，总计 {len(all_vectors)} 条数据 ---")
