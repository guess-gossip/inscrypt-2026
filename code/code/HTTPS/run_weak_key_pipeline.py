#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
from collections import Counter, defaultdict
from math import gcd
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    from tqdm import tqdm
except Exception:
    def tqdm(iterable=None, **kwargs):
        return iterable if iterable is not None else _NullProgress()


    class _NullProgress:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def update(self, *_args, **_kwargs):
            return None


try:
    import gmpy2

    HAVE_GMPY2 = True
except Exception:
    gmpy2 = None
    HAVE_GMPY2 = False

try:
    from batch_gcd import batch_gcd as external_batch_gcd

    HAVE_BATCH_GCD = True
except Exception:
    external_batch_gcd = None
    HAVE_BATCH_GCD = False


SMALL_PRIMES = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
    37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113,
]

P256 = {
    "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
}

P384 = {
    "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    "a": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
    "b": 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
}

P521 = {
    "p": 2**521 - 1,
    "a": 2**521 - 4,
    "b": int(
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109"
        "e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        16,
    ),
}

SM2 = {
    "p": 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    "a": 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    "b": 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
}


def iter_jsonl(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_json(path: Path, default: dict) -> dict:
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    return default


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def append_jsonl(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("a", encoding="utf-8")


def write_jsonl(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8")


def bigint_from_hex(h: str):
    return gmpy2.mpz(h, 16) if HAVE_GMPY2 else int(h, 16)


def bigint_gcd(a, b):
    return gmpy2.gcd(a, b) if HAVE_GMPY2 else gcd(int(a), int(b))


def product(values: Iterable):
    p = gmpy2.mpz(1) if HAVE_GMPY2 else 1
    for value in values:
        p *= value
    return p


def is_nontrivial_gcd(g, n) -> bool:
    return g not in (0, 1, n)


def detect_repeating_byte_pattern(n_hex: str, min_repeat_len: int = 16) -> bool:
    if len(n_hex) % 2 == 1:
        n_hex = "0" + n_hex
    data = bytes.fromhex(n_hex)
    run = 1
    for i in range(1, len(data)):
        if data[i] == data[i - 1]:
            run += 1
            if run >= min_repeat_len:
                return True
        else:
            run = 1
    return False


def has_small_prime_factor(n: int) -> bool:
    return any(n % p == 0 and n != p for p in SMALL_PRIMES)


def fermat_factorable_heuristic(n: int, max_steps: int = 50000) -> bool:
    if n <= 0 or n % 2 == 0:
        return False
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            return p > 1 and q > 1 and p * q == n
        a += 1
    return False


def is_point_on_curve(x: int, y: int, curve: Dict[str, int]) -> bool:
    p = curve["p"]
    return (y * y - (x * x * x + curve["a"] * x + curve["b"])) % p == 0


def ecc_invalid_basic(curve: Optional[str], x_hex: Optional[str], y_hex: Optional[str]) -> bool:
    if not curve or not x_hex or not y_hex:
        return True
    try:
        x = int(x_hex, 16)
        y = int(y_hex, 16)
    except Exception:
        return True
    if x == 0 and y == 0:
        return True

    name = curve.lower()
    if name == "secp256r1":
        return not is_point_on_curve(x, y, P256)
    if name == "secp384r1":
        return not is_point_on_curve(x, y, P384)
    if name == "secp521r1":
        return not is_point_on_curve(x, y, P521)
    return False


def analyze_sm2_invalid(row: dict) -> List[str]:
    reasons = []
    point_format = row.get("point_format")
    x_hex = row.get("x_hex")
    y_hex = row.get("y_hex")

    if point_format != "uncompressed":
        reasons.append("invalid_point_format")
    if not x_hex or not y_hex:
        reasons.append("missing_coordinates")
        return reasons

    try:
        x = int(x_hex, 16)
        y = int(y_hex, 16)
    except Exception:
        return [*reasons, "invalid_hex"]

    if len(x_hex) != 64 or len(y_hex) != 64:
        reasons.append("invalid_length")
    if x >= SM2["p"] or y >= SM2["p"]:
        reasons.append("out_of_field")
    if x == 0 and y == 0:
        reasons.append("zero_point")
    if not is_point_on_curve(x, y, SM2):
        reasons.append("curve_violation")
    return reasons


def sm2_invalid_basic(point_format: Optional[str], x_hex: Optional[str], y_hex: Optional[str]) -> bool:
    return bool(analyze_sm2_invalid({"point_format": point_format, "x_hex": x_hex, "y_hex": y_hex}))


def load_existing_hits(path: Path) -> Tuple[Set[Tuple[str, str]], Counter]:
    seen: Set[Tuple[str, str]] = set()
    counter = Counter()
    if not path.exists():
        return seen, counter
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
                key = (row["fingerprint_sha256"], row["test_case"])
                seen.add(key)
                counter[row["test_case"]] += 1
            except Exception:
                continue
    return seen, counter


def write_hit(out_f, seen: Set[Tuple[str, str]], counter: Counter, fp: str, test_case: str, source: str, **extra) -> bool:
    key = (fp, test_case)
    if key in seen:
        return False
    row = {"fingerprint_sha256": fp, "test_case": test_case, "source": source}
    row.update(extra)
    out_f.write(json.dumps(row, ensure_ascii=False) + "\n")
    seen.add(key)
    counter[test_case] += 1
    return True


def run_local_checks(args, out_dir: Path) -> Path:
    out_path = out_dir / "weak_key_hits_local.jsonl"
    checkpoint_path = out_path.with_suffix(out_path.suffix + ".checkpoint.json")
    summary_path = out_path.with_suffix(out_path.suffix + ".summary.json")
    checkpoint = load_json(
        checkpoint_path,
        {"offsets": {"rsa": 0, "ecc": 0, "sm2": 0}, "processed_counts": {"rsa": 0, "ecc": 0, "sm2": 0}},
    )
    seen, counter = load_existing_hits(out_path)

    with append_jsonl(out_path) as out_f:
        if args.rsa:
            process_local_rsa(args.rsa, out_f, seen, counter, checkpoint, checkpoint_path, args)
        if args.ecc:
            process_local_ecc(args.ecc, out_f, seen, counter, checkpoint, checkpoint_path, args)
        if args.sm2:
            process_local_sm2(args.sm2, out_f, seen, counter, checkpoint, checkpoint_path, args)

    summary = {
        "processed_counts": checkpoint.get("processed_counts", {}),
        "certs_with_hits": len({fp for fp, _ in seen}),
        "total_hits": len(seen),
        "case_counts": dict(counter),
        "output": str(out_path),
        "checkpoint_file": str(checkpoint_path),
    }
    save_json(summary_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return out_path


def process_local_rsa(path: str, out_f, seen, counter, checkpoint, checkpoint_path: Path, args) -> None:
    section = "rsa"
    total_bytes = os.path.getsize(path)
    start_offset = checkpoint["offsets"].get(section, 0)
    processed = 0
    with open(path, "r", encoding="utf-8") as f, tqdm(total=total_bytes, initial=start_offset, unit="B", unit_scale=True, desc="Local RSA") as bar:
        f.seek(start_offset)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            bar.update(f.tell() - pos)
            checkpoint["offsets"][section] = f.tell()
            checkpoint["processed_counts"][section] = checkpoint["processed_counts"].get(section, 0) + 1
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                fp = row["fingerprint_sha256"]
                n = int(row["modulus_hex"], 16)
                e = int(row["exponent"])
                if e <= 1 or e % 2 == 0:
                    write_hit(out_f, seen, counter, fp, "RSA Invalid", "local")
                if has_small_prime_factor(n):
                    write_hit(out_f, seen, counter, fp, "Small Factors", "local")
                if detect_repeating_byte_pattern(row["modulus_hex"]):
                    write_hit(out_f, seen, counter, fp, "Pattern", "local")
                if args.enable_fermat and n > 1 and n % 2 == 1 and fermat_factorable_heuristic(n, args.fermat_max_steps):
                    write_hit(out_f, seen, counter, fp, "Fermat", "local")
            except Exception:
                continue
            processed += 1
            if processed % args.flush_every == 0:
                out_f.flush()
                save_json(checkpoint_path, checkpoint)
    out_f.flush()
    save_json(checkpoint_path, checkpoint)


def process_local_ecc(path: str, out_f, seen, counter, checkpoint, checkpoint_path: Path, args) -> None:
    section = "ecc"
    total_bytes = os.path.getsize(path)
    start_offset = checkpoint["offsets"].get(section, 0)
    processed = 0
    with open(path, "r", encoding="utf-8") as f, tqdm(total=total_bytes, initial=start_offset, unit="B", unit_scale=True, desc="Local ECC") as bar:
        f.seek(start_offset)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            bar.update(f.tell() - pos)
            checkpoint["offsets"][section] = f.tell()
            checkpoint["processed_counts"][section] = checkpoint["processed_counts"].get(section, 0) + 1
            try:
                row = json.loads(line)
                if ecc_invalid_basic(row.get("curve"), row.get("x_hex"), row.get("y_hex")):
                    write_hit(out_f, seen, counter, row["fingerprint_sha256"], "ECC Invalid", "local")
            except Exception:
                continue
            processed += 1
            if processed % args.flush_every == 0:
                out_f.flush()
                save_json(checkpoint_path, checkpoint)
    out_f.flush()
    save_json(checkpoint_path, checkpoint)


def process_local_sm2(path: str, out_f, seen, counter, checkpoint, checkpoint_path: Path, args) -> None:
    section = "sm2"
    total_bytes = os.path.getsize(path)
    start_offset = checkpoint["offsets"].get(section, 0)
    processed = 0
    with open(path, "r", encoding="utf-8") as f, tqdm(total=total_bytes, initial=start_offset, unit="B", unit_scale=True, desc="Local SM2") as bar:
        f.seek(start_offset)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            bar.update(f.tell() - pos)
            checkpoint["offsets"][section] = f.tell()
            checkpoint["processed_counts"][section] = checkpoint["processed_counts"].get(section, 0) + 1
            try:
                row = json.loads(line)
                if analyze_sm2_invalid(row):
                    write_hit(out_f, seen, counter, row["fingerprint_sha256"], "SM2 Invalid", "local")
            except Exception:
                continue
            processed += 1
            if processed % args.flush_every == 0:
                out_f.flush()
                save_json(checkpoint_path, checkpoint)
    out_f.flush()
    save_json(checkpoint_path, checkpoint)


def roca_detect(n: int) -> bool:
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
        cur = 1
        found = False
        for _ in range(prime_to_power):
            if cur == h_dash:
                found = True
                break
            cur = (cur * g_dash) % modulus
        if not found:
            return False
    return True


def run_roca(args, out_dir: Path) -> Optional[Path]:
    if not args.rsa:
        print("[skip] ROCA requires --rsa")
        return None
    out_path = out_dir / "roca_hits.jsonl"
    cache = {}
    seen = set()
    hits = 0
    total = 0
    with write_jsonl(out_path) as out:
        for row in tqdm(iter_jsonl(args.rsa), desc="ROCA", unit="keys"):
            total += 1
            fp = row["fingerprint_sha256"]
            n_hex = row["modulus_hex"]
            if n_hex not in cache:
                cache[n_hex] = roca_detect(int(n_hex, 16))
            if cache[n_hex] and (fp, "ROCA") not in seen:
                seen.add((fp, "ROCA"))
                out.write(json.dumps({"fingerprint_sha256": fp, "test_case": "ROCA", "source": "roca"}, ensure_ascii=False) + "\n")
                hits += 1
    summary = {"total_rsa_rows": total, "unique_moduli_checked": len(cache), "hits": hits, "output": str(out_path)}
    save_json(out_path.with_suffix(out_path.suffix + ".summary.json"), summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return out_path


def run_blocklist(args, out_dir: Path) -> Optional[Path]:
    if not args.rsa:
        print("[skip] Blocklists requires --rsa")
        return None
    try:
        from badkeys.allkeys import blocklist
    except Exception as exc:
        msg = f"badkeys is required for blocklist checks: {exc}"
        if args.strict_deps:
            raise RuntimeError(msg) from exc
        print(f"[skip] {msg}")
        return None

    out_path = out_dir / "blocklist_hits.jsonl"
    cache = {}
    seen = set()
    subtests = Counter()
    hits = 0
    total = 0
    with write_jsonl(out_path) as out:
        for row in tqdm(iter_jsonl(args.rsa), desc="Blocklists", unit="keys"):
            total += 1
            fp = row["fingerprint_sha256"]
            n_hex = row["modulus_hex"]
            if n_hex not in cache:
                try:
                    cache[n_hex] = blocklist(int(n_hex, 16))
                except Exception as exc:
                    cache[n_hex] = {"error": str(exc)}
            res = cache[n_hex]
            if isinstance(res, dict) and res.get("detected") and (fp, "Blocklists") not in seen:
                seen.add((fp, "Blocklists"))
                if res.get("subtest"):
                    subtests[res["subtest"]] += 1
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
    summary = {"total_rsa_rows": total, "unique_moduli_checked": len(cache), "hits": hits, "subtests": dict(subtests), "output": str(out_path)}
    save_json(out_path.with_suffix(out_path.suffix + ".summary.json"), summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return out_path


def chunk_ranges(n: int, chunk_size: int) -> List[Tuple[int, int]]:
    return [(i, min(i + chunk_size, n)) for i in range(0, n, chunk_size)]


def fallback_batch_gcd(values: List):
    if len(values) <= 1:
        return [1 for _ in values]
    total = product(values)
    return [bigint_gcd(n, total // n) for n in values]


def exact_batch_gcd(values: List):
    if HAVE_BATCH_GCD:
        return external_batch_gcd(*values)
    return fallback_batch_gcd(values)


def run_fastgcd(args, out_dir: Path) -> Optional[Path]:
    if not args.rsa:
        print("[skip] FastGCD requires --rsa")
        return None
    if not HAVE_BATCH_GCD:
        print("[warn] batch_gcd module not found; using slower built-in fallback for intra-chunk GCD")

    out_path = out_dir / "fastgcd_hits.jsonl"
    checkpoint_path = out_path.with_suffix(out_path.suffix + ".checkpoint.json")
    summary_path = out_path.with_suffix(out_path.suffix + ".summary.json")
    checkpoint = load_json(checkpoint_path, {"phase": "intra", "intra_chunk_index": 0, "cross_chunk_index": 0, "written_hits": 0})
    seen, _ = load_existing_hits(out_path)

    mod_to_fps = defaultdict(list)
    for row in tqdm(iter_jsonl(args.rsa), desc="Load RSA moduli", unit="keys"):
        mod_to_fps[row["modulus_hex"]].append(row["fingerprint_sha256"])
    moduli_hex = list(mod_to_fps.keys())
    moduli = [bigint_from_hex(h) for h in moduli_hex]
    ranges = chunk_ranges(len(moduli), args.chunk_size)
    chunk_products = [product(moduli[start:end]) for start, end in tqdm(ranges, desc="Build chunk products", unit="chunk")]
    total_product = product(chunk_products)
    counter = Counter()

    with append_jsonl(out_path) as out_f:
        if checkpoint["phase"] == "intra":
            for chunk_idx in tqdm(range(checkpoint["intra_chunk_index"], len(ranges)), desc="Intra-chunk FastGCD", unit="chunk"):
                start, end = ranges[chunk_idx]
                gcds = exact_batch_gcd(moduli[start:end])
                for n_hex, n_val, g_val in zip(moduli_hex[start:end], moduli[start:end], gcds):
                    if is_nontrivial_gcd(g_val, n_val):
                        for fp in mod_to_fps[n_hex]:
                            if write_hit(out_f, seen, counter, fp, "Fastgcd", "batch-gcd", gcd_hex=format(int(g_val), "x")):
                                checkpoint["written_hits"] += 1
                checkpoint["intra_chunk_index"] = chunk_idx + 1
                if chunk_idx % args.flush_every_chunk == 0:
                    out_f.flush()
                    save_json(checkpoint_path, checkpoint)
            checkpoint["phase"] = "cross"
            checkpoint["cross_chunk_index"] = 0
            save_json(checkpoint_path, checkpoint)

        if checkpoint["phase"] == "cross":
            for chunk_idx in tqdm(range(checkpoint["cross_chunk_index"], len(ranges)), desc="Cross-chunk FastGCD", unit="chunk"):
                start, end = ranges[chunk_idx]
                other_product = total_product // chunk_products[chunk_idx]
                for n_hex, n_val in tqdm(zip(moduli_hex[start:end], moduli[start:end]), total=end - start, desc=f"Cross {chunk_idx + 1}/{len(ranges)}", leave=False):
                    g_val = bigint_gcd(n_val, other_product)
                    if is_nontrivial_gcd(g_val, n_val):
                        for fp in mod_to_fps[n_hex]:
                            if write_hit(out_f, seen, counter, fp, "Fastgcd", "batch-gcd", gcd_hex=format(int(g_val), "x")):
                                checkpoint["written_hits"] += 1
                checkpoint["cross_chunk_index"] = chunk_idx + 1
                if chunk_idx % args.flush_every_chunk == 0:
                    out_f.flush()
                    save_json(checkpoint_path, checkpoint)
            checkpoint["phase"] = "done"
            save_json(checkpoint_path, checkpoint)

    summary = {
        "phase": checkpoint["phase"],
        "total_rsa_rows": sum(len(v) for v in mod_to_fps.values()),
        "unique_moduli_checked": len(moduli),
        "hits": checkpoint["written_hits"],
        "gmpy2_enabled": HAVE_GMPY2,
        "batch_gcd_enabled": HAVE_BATCH_GCD,
        "output": str(out_path),
        "checkpoint_file": str(checkpoint_path),
    }
    save_json(summary_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return out_path


def run_sm2_reasons(args, out_dir: Path) -> Optional[Path]:
    input_path = args.sm2_invalid_jsonl
    generated = False
    if not input_path:
        if not args.sm2:
            print("[skip] SM2 invalid reason analysis requires --sm2 or --sm2-invalid-jsonl")
            return None
        input_path = str(out_dir / "error" / "SM2_Invalid.jsonl")
        generated = True
        with write_jsonl(Path(input_path)) as out:
            for row in tqdm(iter_jsonl(args.sm2), desc="Extract SM2 Invalid details", unit="keys"):
                if analyze_sm2_invalid(row):
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")

    output_dir = out_dir / "error"
    output_dir.mkdir(parents=True, exist_ok=True)
    combo_counter = Counter()
    combo_rows = defaultdict(list)
    for row in iter_jsonl(input_path):
        reasons = analyze_sm2_invalid(row) or ["unknown"]
        reasons.sort()
        combo = "&".join(reasons)
        combo_counter[combo] += 1
        combo_rows[combo].append(row)

    for combo, rows in combo_rows.items():
        safe_name = combo.replace(" ", "_").replace("/", "_")
        with write_jsonl(output_dir / f"SM2_Invalid_{safe_name}.jsonl") as out:
            for row in rows:
                out.write(json.dumps(row, ensure_ascii=False) + "\n")

    report_path = output_dir / "SM2_Invalid_reason_combination_report.txt"
    with report_path.open("w", encoding="utf-8") as f:
        f.write(f"Total SM2 Invalid certificates: {sum(combo_counter.values())}\n")
        f.write(f"Input: {input_path}\n")
        f.write(f"Generated from --sm2: {generated}\n\n")
        for combo, count in combo_counter.most_common():
            f.write(f"{combo}: {count}\n")
    print(f"[ok] SM2 invalid reason report: {report_path}")
    return report_path


def aggregate_outputs(out_dir: Path) -> Path:
    hit_files = [
        out_dir / "weak_key_hits_local.jsonl",
        out_dir / "roca_hits.jsonl",
        out_dir / "blocklist_hits.jsonl",
        out_dir / "fastgcd_hits.jsonl",
    ]
    combined_path = out_dir / "weak_key_combined_hits.jsonl"
    summary_path = out_dir / "weak_key_classification_summary.json"
    report_path = out_dir / "weak_key_classification_report.md"
    seen = set()
    by_case = Counter()
    by_source = Counter()
    by_fp = defaultdict(list)

    with write_jsonl(combined_path) as out:
        for path in hit_files:
            if not path.exists():
                continue
            for row in iter_jsonl(str(path)):
                fp = row.get("fingerprint_sha256")
                test_case = row.get("test_case")
                if not fp or not test_case:
                    continue
                key = (fp, test_case)
                if key in seen:
                    continue
                seen.add(key)
                by_case[test_case] += 1
                by_source[row.get("source", "unknown")] += 1
                by_fp[fp].append(test_case)
                out.write(json.dumps(row, ensure_ascii=False) + "\n")

    multi_case = {fp: cases for fp, cases in by_fp.items() if len(cases) > 1}
    summary = {
        "combined_hits": len(seen),
        "certs_with_hits": len(by_fp),
        "certs_with_multiple_weak_categories": len(multi_case),
        "case_counts": dict(by_case),
        "source_counts": dict(by_source),
        "combined_output": str(combined_path),
    }
    save_json(summary_path, summary)

    lines = [
        "# Weak Key Detection Summary",
        "",
        f"- Certificates with at least one hit: {len(by_fp)}",
        f"- Total unique `(fingerprint, test_case)` hits: {len(seen)}",
        f"- Certificates with multiple weak categories: {len(multi_case)}",
        "",
        "## Case Counts",
        "",
        "| test_case | count |",
        "| --- | ---: |",
    ]
    for case, count in by_case.most_common():
        lines.append(f"| {case} | {count} |")
    lines.extend(["", "## Source Counts", "", "| source | count |", "| --- | ---: |"])
    for source, count in by_source.most_common():
        lines.append(f"| {source} | {count} |")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return combined_path


def parse_stages(value: str) -> List[str]:
    if value == "all":
        return ["local", "roca", "blocklist", "fastgcd", "sm2-reasons", "aggregate"]
    return [item.strip() for item in value.split(",") if item.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run weak-key checks and classify weak certificates in one pipeline.")
    parser.add_argument("--rsa", help="RSA public-key JSONL, each row needs fingerprint_sha256/modulus_hex/exponent")
    parser.add_argument("--ecc", help="ECC public-key JSONL, each row needs fingerprint_sha256/curve/x_hex/y_hex")
    parser.add_argument("--sm2", help="SM2 public-key JSONL, each row needs fingerprint_sha256/point_format/x_hex/y_hex")
    parser.add_argument("--sm2-invalid-jsonl", help="Existing full SM2_Invalid.jsonl for reason classification")
    parser.add_argument("--out-dir", default="weak_key_outputs", help="Output directory")
    parser.add_argument("--stages", default="all", help="all or comma list: local,roca,blocklist,fastgcd,sm2-reasons,aggregate")
    parser.add_argument("--strict-deps", action="store_true", help="Fail instead of skipping optional missing dependencies")
    parser.add_argument("--enable-fermat", action="store_true", help="Enable slow Fermat heuristic in local RSA checks")
    parser.add_argument("--fermat-max-steps", type=int, default=50000)
    parser.add_argument("--flush-every", type=int, default=1000)
    parser.add_argument("--chunk-size", type=int, default=20000, help="Unique RSA moduli per FastGCD chunk")
    parser.add_argument("--flush-every-chunk", type=int, default=1)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stages = parse_stages(args.stages)

    print(json.dumps({
        "out_dir": str(out_dir),
        "stages": stages,
        "gmpy2_enabled": HAVE_GMPY2,
        "batch_gcd_enabled": HAVE_BATCH_GCD,
    }, ensure_ascii=False, indent=2))

    if "local" in stages:
        run_local_checks(args, out_dir)
    if "roca" in stages:
        run_roca(args, out_dir)
    if "blocklist" in stages:
        run_blocklist(args, out_dir)
    if "fastgcd" in stages:
        run_fastgcd(args, out_dir)
    if "sm2-reasons" in stages:
        run_sm2_reasons(args, out_dir)
    if "aggregate" in stages:
        aggregate_outputs(out_dir)


if __name__ == "__main__":
    main()
