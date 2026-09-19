#!/usr/bin/env python3
import argparse
import json
import math
import os
from collections import Counter
from typing import Dict, Optional, Set, Tuple

from tqdm import tqdm


SMALL_PRIMES = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
    37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113,
]


# -----------------------------
# Curve parameters
# -----------------------------
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
    "a": (2**521 - 1) - 3,
    "b": int(
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109"
        "e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        16,
    ),
}

# Correct SM2 parameters
SM2 = {
    "p": 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    "a": 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    "b": 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
}


def detect_repeating_byte_pattern(n_hex: str, min_repeat_len: int = 16) -> bool:
    if len(n_hex) % 2 == 1:
        n_hex = "0" + n_hex
    b = bytes.fromhex(n_hex)

    if not b:
        return False

    run = 1
    for i in range(1, len(b)):
        if b[i] == b[i - 1]:
            run += 1
            if run >= min_repeat_len:
                return True
        else:
            run = 1
    return False


def has_small_prime_factor(n: int) -> bool:
    for p in SMALL_PRIMES:
        if n % p == 0 and n != p:
            return True
    return False


def fermat_factorable_heuristic(n: int, max_steps: int = 50000) -> bool:
    """
    Heuristic only.
    Very slow on large datasets.
    """
    if n <= 0 or n % 2 == 0:
        return False

    a = math.isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_steps):
        b2 = a * a - n
        if b2 >= 0:
            b = math.isqrt(b2)
            if b * b == b2:
                p = a - b
                q = a + b
                if p > 1 and q > 1 and p * q == n:
                    return True
        a += 1

    return False


def is_point_on_curve(x: int, y: int, curve: Dict[str, int]) -> bool:
    p = curve["p"]
    a = curve["a"]
    b = curve["b"]
    lhs = pow(y, 2, p)
    rhs = (pow(x, 3, p) + (a * x) + b) % p
    return lhs == rhs


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


def sm2_invalid_basic(point_format: Optional[str], x_hex: Optional[str], y_hex: Optional[str]) -> bool:
    """
    Strict SM2 public-key validation:
    1) must be uncompressed
    2) x/y must exist
    3) x/y must be 256-bit coordinates (32 bytes => 64 hex chars)
    4) x and y must be in field range
    5) point must not be infinity/zero-like placeholder
    6) point must satisfy the SM2 curve equation
    """
    if point_format != "uncompressed":
        return True

    if not x_hex or not y_hex:
        return True

    try:
        x = int(x_hex, 16)
        y = int(y_hex, 16)
    except Exception:
        return True

    if len(x_hex) != 64 or len(y_hex) != 64:
        return True

    if x == 0 and y == 0:
        return True

    p = SM2["p"]
    if x >= p or y >= p:
        return True

    return not is_point_on_curve(x, y, SM2)


def load_checkpoint(path: str) -> Dict:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "offsets": {"rsa": 0, "ecc": 0, "sm2": 0},
        "processed_counts": {"rsa": 0, "ecc": 0, "sm2": 0},
        "case_counts": {},
    }


def save_checkpoint(path: str, checkpoint: Dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def load_existing_hits(out_path: str) -> Tuple[Set[Tuple[str, str]], Counter]:
    seen = set()
    case_counter = Counter()
    if not os.path.exists(out_path):
        return seen, case_counter

    with open(out_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                fp = row["fingerprint_sha256"]
                tc = row["test_case"]
                seen.add((fp, tc))
                case_counter[tc] += 1
            except Exception:
                continue
    return seen, case_counter


def write_hit(out_f, seen_hits: Set[Tuple[str, str]], case_counter: Counter, fp: str, test_case: str) -> bool:
    key = (fp, test_case)
    if key in seen_hits:
        return False

    row = {
        "fingerprint_sha256": fp,
        "test_case": test_case,
        "source": "local",
    }
    out_f.write(json.dumps(row, ensure_ascii=False) + "\n")
    seen_hits.add(key)
    case_counter[test_case] += 1
    return True


def process_rsa_file(
    path: str,
    out_f,
    seen_hits: Set[Tuple[str, str]],
    checkpoint: Dict,
    checkpoint_path: str,
    case_counter: Counter,
    enable_fermat: bool,
    fermat_max_steps: int,
    flush_every: int,
) -> int:
    section = "rsa"
    total_bytes = os.path.getsize(path)
    start_offset = checkpoint["offsets"].get(section, 0)
    processed = 0

    with open(path, "r", encoding="utf-8") as f, tqdm(
        total=total_bytes,
        initial=start_offset,
        unit="B",
        unit_scale=True,
        desc="RSA",
    ) as pbar:
        f.seek(start_offset)

        while True:
            line_start = f.tell()
            line = f.readline()
            if not line:
                break

            pbar.update(f.tell() - line_start)
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
                    write_hit(out_f, seen_hits, case_counter, fp, "RSA Invalid")

                if has_small_prime_factor(n):
                    write_hit(out_f, seen_hits, case_counter, fp, "Small Factors")

                if detect_repeating_byte_pattern(row["modulus_hex"], min_repeat_len=16):
                    write_hit(out_f, seen_hits, case_counter, fp, "Pattern")

                if enable_fermat and n > 1 and n % 2 == 1:
                    try:
                        if fermat_factorable_heuristic(n, max_steps=fermat_max_steps):
                            write_hit(out_f, seen_hits, case_counter, fp, "Fermat")
                    except Exception:
                        pass

                processed += 1

                if processed % flush_every == 0:
                    out_f.flush()
                    save_checkpoint(checkpoint_path, checkpoint)

            except Exception:
                pass

    out_f.flush()
    save_checkpoint(checkpoint_path, checkpoint)
    return processed


def process_ecc_file(
    path: str,
    out_f,
    seen_hits: Set[Tuple[str, str]],
    checkpoint: Dict,
    checkpoint_path: str,
    case_counter: Counter,
    flush_every: int,
) -> int:
    section = "ecc"
    total_bytes = os.path.getsize(path)
    start_offset = checkpoint["offsets"].get(section, 0)
    processed = 0

    with open(path, "r", encoding="utf-8") as f, tqdm(
        total=total_bytes,
        initial=start_offset,
        unit="B",
        unit_scale=True,
        desc="ECC",
    ) as pbar:
        f.seek(start_offset)

        while True:
            line_start = f.tell()
            line = f.readline()
            if not line:
                break

            pbar.update(f.tell() - line_start)
            checkpoint["offsets"][section] = f.tell()
            checkpoint["processed_counts"][section] = checkpoint["processed_counts"].get(section, 0) + 1

            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
                fp = row["fingerprint_sha256"]
                if ecc_invalid_basic(row.get("curve"), row.get("x_hex"), row.get("y_hex")):
                    write_hit(out_f, seen_hits, case_counter, fp, "ECC Invalid")

                processed += 1

                if processed % flush_every == 0:
                    out_f.flush()
                    save_checkpoint(checkpoint_path, checkpoint)

            except Exception:
                pass

    out_f.flush()
    save_checkpoint(checkpoint_path, checkpoint)
    return processed


def process_sm2_file(
    path: str,
    out_f,
    seen_hits: Set[Tuple[str, str]],
    checkpoint: Dict,
    checkpoint_path: str,
    case_counter: Counter,
    flush_every: int,
) -> int:
    section = "sm2"
    total_bytes = os.path.getsize(path)
    start_offset = checkpoint["offsets"].get(section, 0)
    processed = 0

    with open(path, "r", encoding="utf-8") as f, tqdm(
        total=total_bytes,
        initial=start_offset,
        unit="B",
        unit_scale=True,
        desc="SM2",
    ) as pbar:
        f.seek(start_offset)

        while True:
            line_start = f.tell()
            line = f.readline()
            if not line:
                break

            pbar.update(f.tell() - line_start)
            checkpoint["offsets"][section] = f.tell()
            checkpoint["processed_counts"][section] = checkpoint["processed_counts"].get(section, 0) + 1

            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
                fp = row["fingerprint_sha256"]
                if sm2_invalid_basic(row.get("point_format"), row.get("x_hex"), row.get("y_hex")):
                    write_hit(out_f, seen_hits, case_counter, fp, "SM2 Invalid")

                processed += 1

                if processed % flush_every == 0:
                    out_f.flush()
                    save_checkpoint(checkpoint_path, checkpoint)

            except Exception:
                pass

    out_f.flush()
    save_checkpoint(checkpoint_path, checkpoint)
    return processed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rsa", help="rsa_keys.jsonl")
    ap.add_argument("--ecc", help="ecc_keys.jsonl")
    ap.add_argument("--sm2", help="sm2_keys.jsonl")
    ap.add_argument("--out", required=True, help="weak_key_hits_local.jsonl")
    ap.add_argument("--enable-fermat", action="store_true", help="Enable slow Fermat heuristic")
    ap.add_argument("--fermat-max-steps", type=int, default=50000)
    ap.add_argument("--flush-every", type=int, default=1000, help="Flush/checkpoint every N processed rows per section")
    ap.add_argument("--only-sm2", action="store_true", help="Only process the SM2 input file")
    args = ap.parse_args()

    outdir = os.path.dirname(args.out)
    if outdir:
        os.makedirs(outdir, exist_ok=True)

    checkpoint_path = args.out + ".checkpoint.json"
    summary_path = args.out + ".summary.json"

    checkpoint = load_checkpoint(checkpoint_path)
    seen_hits, case_counter = load_existing_hits(args.out)

    try:
        with open(args.out, "a", encoding="utf-8") as out_f:
            if args.only_sm2:
                if not args.sm2:
                    raise ValueError("--only-sm2 requires --sm2")
                process_sm2_file(
                    path=args.sm2,
                    out_f=out_f,
                    seen_hits=seen_hits,
                    checkpoint=checkpoint,
                    checkpoint_path=checkpoint_path,
                    case_counter=case_counter,
                    flush_every=args.flush_every,
                )
            else:
                if args.rsa:
                    process_rsa_file(
                        path=args.rsa,
                        out_f=out_f,
                        seen_hits=seen_hits,
                        checkpoint=checkpoint,
                        checkpoint_path=checkpoint_path,
                        case_counter=case_counter,
                        enable_fermat=args.enable_fermat,
                        fermat_max_steps=args.fermat_max_steps,
                        flush_every=args.flush_every,
                    )

                if args.ecc:
                    process_ecc_file(
                        path=args.ecc,
                        out_f=out_f,
                        seen_hits=seen_hits,
                        checkpoint=checkpoint,
                        checkpoint_path=checkpoint_path,
                        case_counter=case_counter,
                        flush_every=args.flush_every,
                    )

                if args.sm2:
                    process_sm2_file(
                        path=args.sm2,
                        out_f=out_f,
                        seen_hits=seen_hits,
                        checkpoint=checkpoint,
                        checkpoint_path=checkpoint_path,
                        case_counter=case_counter,
                        flush_every=args.flush_every,
                    )

    except KeyboardInterrupt:
        save_checkpoint(checkpoint_path, checkpoint)
        summary = {
            "interrupted": True,
            "checkpoint_file": checkpoint_path,
            "processed_counts": checkpoint.get("processed_counts", {}),
            "offsets": checkpoint.get("offsets", {}),
            "certs_with_hits": len({fp for fp, _ in seen_hits}),
            "total_hits": len(seen_hits),
            "case_counts": dict(case_counter),
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return

    checkpoint["case_counts"] = dict(case_counter)
    save_checkpoint(checkpoint_path, checkpoint)

    summary = {
        "interrupted": False,
        "checkpoint_file": checkpoint_path,
        "processed_counts": checkpoint.get("processed_counts", {}),
        "offsets": checkpoint.get("offsets", {}),
        "certs_with_hits": len({fp for fp, _ in seen_hits}),
        "total_hits": len(seen_hits),
        "case_counts": dict(case_counter),
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()