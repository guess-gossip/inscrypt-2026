#!/usr/bin/env python3
import json
import os
from collections import Counter, defaultdict

# SM2 参数
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93

def is_point_on_curve(x, y):
    lhs = (y * y) % SM2_P
    rhs = (x * x * x + SM2_A * x + SM2_B) % SM2_P
    return lhs == rhs

def analyze_sm2_invalid(cert):
    reasons = []

    point_format = cert.get("point_format")
    x_hex = cert.get("x_hex")
    y_hex = cert.get("y_hex")

    # 1) point_format
    if point_format != "uncompressed":
        reasons.append("invalid_point_format")

    # 2) x/y missing
    if not x_hex or not y_hex:
        reasons.append("missing_coordinates")

    else:
        try:
            x = int(x_hex, 16)
            y = int(y_hex, 16)

            # 3) 长度检查
            if len(x_hex) != 64 or len(y_hex) != 64:
                reasons.append("invalid_length")

            # 4) 超出域范围
            if x >= SM2_P or y >= SM2_P:
                reasons.append("out_of_field")

            # 5) 零点检查
            if x == 0 and y == 0:
                reasons.append("zero_point")

            # 6) 曲线方程检查
            if not is_point_on_curve(x, y):
                reasons.append("curve_violation")

        except Exception:
            reasons.append("invalid_hex")

    return reasons

def main():
    input_file = "/home/skl/SMINE/processing_output/weak_keys/error/SM2_Invalid.jsonl"
    output_dir = "/home/skl/SMINE/processing_output/weak_keys/error"
    os.makedirs(output_dir, exist_ok=True)

    combination_counter = Counter()
    combination_files = defaultdict(list)  # 原因组合 -> list of certs

    # 读取证书并分析原因
    with open(input_file, "r") as f:
        for line in f:
            cert = json.loads(line.strip())
            fp = cert.get("fingerprint_sha256")
            reasons = analyze_sm2_invalid(cert)
            if not reasons:
                reasons = ["unknown"]
            reasons.sort()
            combo_key = "&".join(reasons)
            combination_counter[combo_key] += 1
            combination_files[combo_key].append(cert)

    # 写每个组合原因对应的 JSONL 文件
    for combo, certs in combination_files.items():
        safe_name = combo.replace(" ", "_").replace("/", "_")
        out_file = os.path.join(output_dir, f"SM2_Invalid_{safe_name}.jsonl")
        with open(out_file, "w") as f:
            for cert in certs:
                f.write(json.dumps(cert) + "\n")

    # 写统计报告
    report_file = os.path.join(output_dir, "SM2_Invalid_reason_combination_report.txt")
    with open(report_file, "w") as f:
        total_certs = sum(combination_counter.values())
        f.write(f"Total SM2 Invalid certificates: {total_certs}\n\n")
        for combo, count in combination_counter.most_common():
            f.write(f"{combo}: {count}\n")

    print("分析完成，组合原因报告和 JSONL 文件生成在:", output_dir)

if __name__ == "__main__":
    main()