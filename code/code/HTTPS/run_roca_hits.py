#!/usr/bin/env python3
import argparse
import json
import os
from collections import Counter
from tqdm import tqdm


def roca_detect(n: int) -> bool:
    """
    Core ROCA fingerprint logic adapted from badkeys/crocs ROCA detector.
    """
    if n <= 2:
        return False

    generator = 65537
    generator_order = 2454106387091158800
    pp = [16, 81, 25, 7, 11, 13, 17, 23, 29, 37, 41, 53, 83]
    modulus = 0x924CBA6AE99DFA084537FACC54948DF0C23DA044D8CABE0EDD75BC6

    if pow(n, generator_order, modulus) != 1:
        return False

    for prime_to_power in pp:
        order_div_prime_power = generator_order // prime_to_power
        g_dash = pow(generator, order_div_prime_power, modulus)
        h_dash = pow(n, order_div_prime_power, modulus)

        found = False
        cur = 1
        for _ in range(prime_to_power):
            if cur == h_dash:
                found = True
                break
            cur = (cur * g_dash) % modulus

        if not found:
            return False

    return True


def iter_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rsa", required=True, help="rsa_keys.jsonl")
    ap.add_argument("--out", required=True, help="roca_hits.jsonl")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    cache = {}
    seen = set()
    hits = 0
    total = 0

    with open(args.out, "w", encoding="utf-8") as out:
        for row in tqdm(iter_jsonl(args.rsa), desc="ROCA", unit="keys"):
            total += 1
            fp = row["fingerprint_sha256"]
            n_hex = row["modulus_hex"]

            if n_hex not in cache:
                n = int(n_hex, 16)
                cache[n_hex] = roca_detect(n)

            if cache[n_hex]:
                key = (fp, "ROCA")
                if key not in seen:
                    seen.add(key)
                    out.write(json.dumps({
                        "fingerprint_sha256": fp,
                        "test_case": "ROCA",
                        "source": "roca",
                    }, ensure_ascii=False) + "\n")
                    hits += 1

    summary = {
        "total_rsa_rows": total,
        "unique_moduli_checked": len(cache),
        "hits": hits,
        "output": args.out,
    }

    with open(args.out + ".summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()