#!/usr/bin/env python3
import argparse
import json
import os
from collections import defaultdict
from math import gcd
from typing import Dict, List, Set, Tuple

from tqdm import tqdm
from batch_gcd import batch_gcd

try:
    import gmpy2
    HAVE_GMPY2 = True
except Exception:
    HAVE_GMPY2 = False


def to_bigint_from_hex(h: str):
    if HAVE_GMPY2:
        return gmpy2.mpz(h, 16)
    return int(h, 16)


def bigint_gcd(a, b):
    if HAVE_GMPY2:
        return gmpy2.gcd(a, b)
    return gcd(int(a), int(b))


def is_nontrivial_gcd(g, n) -> bool:
    return g not in (0, 1, n)


def iter_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_checkpoint(path: str) -> Dict:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "phase": "intra",          # intra -> cross -> done
        "intra_chunk_index": 0,
        "cross_chunk_index": 0,
        "written_hits": 0,
    }


def save_checkpoint(path: str, checkpoint: Dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def load_existing_hits(out_path: str) -> Set[Tuple[str, str]]:
    seen = set()
    if not os.path.exists(out_path):
        return seen

    with open(out_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                seen.add((row["fingerprint_sha256"], row["test_case"]))
            except Exception:
                continue
    return seen


def write_hit(out_f, seen_hits: Set[Tuple[str, str]], fingerprint: str, gcd_value) -> bool:
    key = (fingerprint, "Fastgcd")
    if key in seen_hits:
        return False

    row = {
        "fingerprint_sha256": fingerprint,
        "test_case": "Fastgcd",
        "source": "batch-gcd",
        "gcd_hex": format(int(gcd_value), "x"),
    }
    out_f.write(json.dumps(row, ensure_ascii=False) + "\n")
    seen_hits.add(key)
    return True


def chunk_ranges(n: int, chunk_size: int) -> List[Tuple[int, int]]:
    return [(i, min(i + chunk_size, n)) for i in range(0, n, chunk_size)]


def prod_of_list(values: List):
    if HAVE_GMPY2:
        p = gmpy2.mpz(1)
    else:
        p = 1
    for v in values:
        p *= v
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rsa", required=True, help="rsa_keys.jsonl")
    ap.add_argument("--out", required=True, help="fastgcd_hits.jsonl")
    ap.add_argument("--chunk-size", type=int, default=20000, help="Unique moduli per chunk")
    ap.add_argument("--flush-every-chunk", type=int, default=1)
    args = ap.parse_args()

    outdir = os.path.dirname(args.out)
    if outdir:
        os.makedirs(outdir, exist_ok=True)

    checkpoint_path = args.out + ".checkpoint.json"
    summary_path = args.out + ".summary.json"

    checkpoint = load_checkpoint(checkpoint_path)
    seen_hits = load_existing_hits(args.out)

    # --------------------------------------------------
    # Step 1: load and deduplicate moduli
    # --------------------------------------------------
    mod_to_fps = defaultdict(list)

    for row in tqdm(iter_jsonl(args.rsa), desc="Load RSA moduli", unit="keys"):
        mod_to_fps[row["modulus_hex"]].append(row["fingerprint_sha256"])

    unique_moduli_hex = list(mod_to_fps.keys())
    unique_moduli = [to_bigint_from_hex(h) for h in unique_moduli_hex]

    n_unique = len(unique_moduli)
    ranges = chunk_ranges(n_unique, args.chunk_size)

    print(f"Unique RSA moduli: {n_unique}")
    print(f"Chunks: {len(ranges)} (chunk_size={args.chunk_size})")
    print(f"gmpy2_enabled: {HAVE_GMPY2}")

    # --------------------------------------------------
    # Step 2: precompute chunk products and total product
    # --------------------------------------------------
    chunk_products = []
    for start, end in tqdm(ranges, desc="Build chunk products", unit="chunk"):
        cp = prod_of_list(unique_moduli[start:end])
        chunk_products.append(cp)

    total_product = prod_of_list(chunk_products)

    # --------------------------------------------------
    # Step 3A: intra-chunk batch_gcd
    # --------------------------------------------------
    try:
        with open(args.out, "a", encoding="utf-8") as out_f:
            if checkpoint["phase"] == "intra":
                for chunk_idx in tqdm(
                    range(checkpoint["intra_chunk_index"], len(ranges)),
                    desc="Intra-chunk batch_gcd",
                    unit="chunk",
                ):
                    start, end = ranges[chunk_idx]
                    chunk_moduli = unique_moduli[start:end]
                    chunk_hex = unique_moduli_hex[start:end]

                    # Run exact batch_gcd within this chunk
                    if len(chunk_moduli) == 1:
                        gcds = [1]
                    else:
                        gcds = batch_gcd(*chunk_moduli)

                    for n_hex, n_val, g_val in zip(chunk_hex, chunk_moduli, gcds):
                        if is_nontrivial_gcd(g_val, n_val):
                            for fp in mod_to_fps[n_hex]:
                                if write_hit(out_f, seen_hits, fp, g_val):
                                    checkpoint["written_hits"] += 1

                    checkpoint["intra_chunk_index"] = chunk_idx + 1
                    if chunk_idx % args.flush_every_chunk == 0:
                        out_f.flush()
                        save_checkpoint(checkpoint_path, checkpoint)

                checkpoint["phase"] = "cross"
                checkpoint["cross_chunk_index"] = 0
                out_f.flush()
                save_checkpoint(checkpoint_path, checkpoint)

            # --------------------------------------------------
            # Step 3B: cross-chunk gcd against product of other chunks
            # Exact detection of shared factors across different chunks
            # --------------------------------------------------
            if checkpoint["phase"] == "cross":
                for chunk_idx in tqdm(
                    range(checkpoint["cross_chunk_index"], len(ranges)),
                    desc="Cross-chunk GCD",
                    unit="chunk",
                ):
                    start, end = ranges[chunk_idx]
                    chunk_moduli = unique_moduli[start:end]
                    chunk_hex = unique_moduli_hex[start:end]

                    # Product of all moduli not in this chunk
                    other_product = total_product // chunk_products[chunk_idx]

                    for n_hex, n_val in tqdm(
                        zip(chunk_hex, chunk_moduli),
                        total=(end - start),
                        desc=f"Cross chunk {chunk_idx + 1}/{len(ranges)}",
                        leave=False,
                        unit="mod",
                    ):
                        g_val = bigint_gcd(n_val, other_product)
                        if is_nontrivial_gcd(g_val, n_val):
                            for fp in mod_to_fps[n_hex]:
                                if write_hit(out_f, seen_hits, fp, g_val):
                                    checkpoint["written_hits"] += 1

                    checkpoint["cross_chunk_index"] = chunk_idx + 1
                    if chunk_idx % args.flush_every_chunk == 0:
                        out_f.flush()
                        save_checkpoint(checkpoint_path, checkpoint)

                checkpoint["phase"] = "done"
                out_f.flush()
                save_checkpoint(checkpoint_path, checkpoint)

    except KeyboardInterrupt:
        save_checkpoint(checkpoint_path, checkpoint)
        summary = {
            "interrupted": True,
            "phase": checkpoint["phase"],
            "intra_chunk_index": checkpoint["intra_chunk_index"],
            "cross_chunk_index": checkpoint["cross_chunk_index"],
            "total_rsa_rows": sum(len(v) for v in mod_to_fps.values()),
            "unique_moduli_checked": n_unique,
            "hits": checkpoint["written_hits"],
            "output": args.out,
            "checkpoint_file": checkpoint_path,
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return

    summary = {
        "interrupted": False,
        "phase": checkpoint["phase"],
        "total_rsa_rows": sum(len(v) for v in mod_to_fps.values()),
        "unique_moduli_checked": n_unique,
        "hits": checkpoint["written_hits"],
        "output": args.out,
        "checkpoint_file": checkpoint_path,
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()