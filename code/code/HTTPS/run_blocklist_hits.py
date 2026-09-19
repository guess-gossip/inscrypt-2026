#!/usr/bin/env python3
import argparse
import json
import os
from collections import Counter
from tqdm import tqdm

from badkeys.allkeys import blocklist


def iter_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rsa", required=True, help="rsa_keys.jsonl")
    ap.add_argument("--out", required=True, help="blocklist_hits.jsonl")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    cache = {}
    seen = set()
    hits = 0
    total = 0
    subtests = Counter()

    with open(args.out, "w", encoding="utf-8") as out:
        for row in tqdm(iter_jsonl(args.rsa), desc="Blocklists", unit="keys"):
            total += 1
            fp = row["fingerprint_sha256"]
            n_hex = row["modulus_hex"]

            if n_hex not in cache:
                n = int(n_hex, 16)
                try:
                    cache[n_hex] = blocklist(n)
                except SystemExit:
                    raise
                except Exception as e:
                    cache[n_hex] = {"error": str(e)}

            res = cache[n_hex]
            if isinstance(res, dict) and res.get("detected"):
                key = (fp, "Blocklists")
                if key not in seen:
                    seen.add(key)
                    subtest = res.get("subtest")
                    if subtest:
                        subtests[subtest] += 1

                    out.write(json.dumps({
                        "fingerprint_sha256": fp,
                        "test_case": "Blocklists",
                        "source": "badkeys_blocklist",
                        "subtest": res.get("subtest"),
                        "blid": res.get("blid"),
                        "lookup": res.get("lookup"),
                        "debug": res.get("debug"),
                    }, ensure_ascii=False) + "\n")
                    hits += 1

    summary = {
        "total_rsa_rows": total,
        "unique_moduli_checked": len(cache),
        "hits": hits,
        "subtests": dict(subtests),
        "output": args.out,
    }

    with open(args.out + ".summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()