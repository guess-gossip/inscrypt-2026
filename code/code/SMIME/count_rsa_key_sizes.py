#!/usr/bin/env python3
import json
from collections import Counter

input_file = "/home/skl/SMINE/processing_output/weak_keys/rsa_keys.jsonl"
output_file = "/home/skl/SMINE/processing_output/weak_keys/key_size_counts.txt"

key_size_counter = Counter()

# 逐行读取 JSONL 文件，统计 key_size
with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            key_size = data.get("key_size")
            if key_size:
                key_size_counter[key_size] += 1
        except json.JSONDecodeError:
            print("Warning: 无法解析行:", line[:100])

# 写入统计结果
with open(output_file, "w", encoding="utf-8") as f:
    f.write("key_size,count\n")
    for key_size, count in sorted(key_size_counter.items()):
        f.write(f"{key_size},{count}\n")

print(f"统计完成，结果写入 {output_file}")