#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from math import gcd
from pathlib import Path
from typing import Iterable, Optional

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

try:
    from tqdm import tqdm
except Exception:
    def tqdm(iterable=None, **_kwargs):
        return iterable if iterable is not None else []

try:
    import gmpy2

    HAVE_GMPY2 = True
except Exception:
    gmpy2 = None
    HAVE_GMPY2 = False


CATEGORIES = ("bank", "edu", "gov")
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")

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


@dataclass
class CertKey:
    category: str
    kind: str
    fingerprint_sha256: str
    path: str
    subject: str
    issuer: str
    key_type: str
    key_size: Optional[int] = None
    modulus_hex: Optional[str] = None
    exponent: Optional[int] = None
    curve: Optional[str] = None
    point_format: Optional[str] = None
    x_hex: Optional[str] = None
    y_hex: Optional[str] = None
    parse_error: Optional[str] = None


def iter_cert_paths(root: Path) -> Iterable[tuple[str, str, Path]]:
    for category in CATEGORIES:
        for path in sorted((root / category).glob("*.pem")):
            yield category, "sm2", path
    for category in CATEGORIES:
        normal_dir = root / "normal_cert_collection" / "normal_certs" / category
        for path in sorted(normal_dir.glob("*.pem")):
            yield category, "ordinary", path


def default_out_dir(root: Path) -> Path:
    name = root.name
    if name.startswith("data") and len(name) > len("data"):
        return root.parent / f"analysis_outputs{name[len('data'):]}" / "weak_key_cert_analysis"
    return root / "weak_key_cert_analysis"


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def point_format_and_xy_from_bytes(data: bytes) -> tuple[str, Optional[str], Optional[str]]:
    if not data:
        return "missing", None, None
    first = data[0]
    if first == 4:
        body = data[1:]
        if len(body) % 2:
            return "uncompressed_invalid_length", None, None
        half = len(body) // 2
        return "uncompressed", body[:half].hex(), body[half:].hex()
    if first in (2, 3):
        return "compressed", data[1:].hex(), None
    return f"unknown_0x{first:02x}", None, None


def extract_sm2_public_point_with_openssl(path: Path) -> tuple[str, Optional[str], Optional[str]]:
    text = subprocess.check_output(
        [OPENSSL_BIN, "x509", "-in", str(path), "-noout", "-text"],
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    pub_hex_parts = []
    in_pub = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "pub:":
            in_pub = True
            continue
        if in_pub:
            if stripped.startswith("ASN1 OID:") or stripped.startswith("NIST CURVE:"):
                break
            if re.fullmatch(r"[0-9a-fA-F:]+", stripped):
                pub_hex_parts.append(stripped.replace(":", ""))
    if not pub_hex_parts:
        return "missing", None, None
    return point_format_and_xy_from_bytes(bytes.fromhex("".join(pub_hex_parts)))


def extract_cert_key(category: str, kind: str, path: Path) -> CertKey:
    try:
        cert = load_cert(path)
        fp = cert_fingerprint(cert)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        try:
            public_key = cert.public_key()
        except UnsupportedAlgorithm:
            point_format, x_hex, y_hex = extract_sm2_public_point_with_openssl(path)
            return CertKey(
                category=category,
                kind=kind,
                fingerprint_sha256=fp,
                path=str(path),
                subject=subject,
                issuer=issuer,
                key_type="SM2",
                key_size=256,
                point_format=point_format,
                x_hex=x_hex,
                y_hex=y_hex,
            )

        if isinstance(public_key, rsa.RSAPublicKey):
            numbers = public_key.public_numbers()
            return CertKey(
                category=category,
                kind=kind,
                fingerprint_sha256=fp,
                path=str(path),
                subject=subject,
                issuer=issuer,
                key_type="RSA",
                key_size=public_key.key_size,
                modulus_hex=format(numbers.n, "x"),
                exponent=numbers.e,
            )
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            numbers = public_key.public_numbers()
            size_hex = (public_key.key_size + 3) // 4
            return CertKey(
                category=category,
                kind=kind,
                fingerprint_sha256=fp,
                path=str(path),
                subject=subject,
                issuer=issuer,
                key_type="ECC",
                key_size=public_key.key_size,
                curve=public_key.curve.name,
                point_format="uncompressed",
                x_hex=f"{numbers.x:0{size_hex}x}",
                y_hex=f"{numbers.y:0{size_hex}x}",
            )
        return CertKey(
            category=category,
            kind=kind,
            fingerprint_sha256=fp,
            path=str(path),
            subject=subject,
            issuer=issuer,
            key_type=type(public_key).__name__,
            key_size=getattr(public_key, "key_size", None),
        )
    except Exception as exc:
        return CertKey(
            category=category,
            kind=kind,
            fingerprint_sha256=path.stem if re.fullmatch(r"[0-9a-fA-F]{64}", path.stem) else "",
            path=str(path),
            subject="",
            issuer="",
            key_type="parse_error",
            parse_error=repr(exc),
        )


def is_point_on_curve(x: int, y: int, curve: dict[str, int]) -> bool:
    p = curve["p"]
    return (y * y - (x * x * x + curve["a"] * x + curve["b"])) % p == 0


def analyze_sm2_invalid(cert: CertKey) -> list[str]:
    reasons = []
    if cert.point_format != "uncompressed":
        reasons.append("invalid_point_format")
    if not cert.x_hex or not cert.y_hex:
        reasons.append("missing_coordinates")
        return reasons
    try:
        x = int(cert.x_hex, 16)
        y = int(cert.y_hex, 16)
    except Exception:
        return [*reasons, "invalid_hex"]
    if len(cert.x_hex) != 64 or len(cert.y_hex) != 64:
        reasons.append("invalid_length")
    if x >= SM2["p"] or y >= SM2["p"]:
        reasons.append("out_of_field")
    if x == 0 and y == 0:
        reasons.append("zero_point")
    if not is_point_on_curve(x, y, SM2):
        reasons.append("curve_violation")
    return reasons


def analyze_ecc_invalid(cert: CertKey) -> list[str]:
    if not cert.curve or not cert.x_hex or not cert.y_hex:
        return ["missing_curve_or_coordinates"]
    try:
        x = int(cert.x_hex, 16)
        y = int(cert.y_hex, 16)
    except Exception:
        return ["invalid_hex"]
    if x == 0 and y == 0:
        return ["zero_point"]
    curve = cert.curve.lower()
    params = {"secp256r1": P256, "secp384r1": P384, "secp521r1": P521}.get(curve)
    if params is None:
        return []
    if not is_point_on_curve(x, y, params):
        return ["curve_violation"]
    return []


def has_small_prime_factor(n: int) -> bool:
    return any(n % p == 0 and n != p for p in SMALL_PRIMES)


def detect_repeating_byte_pattern(n_hex: str, min_repeat_len: int = 16) -> bool:
    if len(n_hex) % 2:
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


def fermat_factorable_heuristic(n: int, max_steps: int) -> bool:
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


def bigint(n: int):
    return gmpy2.mpz(n) if HAVE_GMPY2 else n


def bigint_gcd(a, b):
    return gmpy2.gcd(a, b) if HAVE_GMPY2 else gcd(int(a), int(b))


def product(values: Iterable):
    p = gmpy2.mpz(1) if HAVE_GMPY2 else 1
    for value in values:
        p *= value
    return p


def write_hit(hits: list[dict], cert: CertKey, test_case: str, source: str, **details) -> None:
    row = {
        "fingerprint_sha256": cert.fingerprint_sha256,
        "category": cert.category,
        "kind": cert.kind,
        "path": cert.path,
        "key_type": cert.key_type,
        "key_size": cert.key_size,
        "test_case": test_case,
        "source": source,
    }
    row.update(details)
    hits.append(row)


def run_blocklist_if_available(rsa_certs: list[CertKey], hits: list[dict], strict: bool) -> None:
    try:
        from badkeys.allkeys import blocklist
    except Exception as exc:
        message = f"badkeys not available, skip blocklist: {exc}"
        if strict:
            raise RuntimeError(message) from exc
        print(f"[warn] {message}")
        return
    cache = {}
    for cert in tqdm(rsa_certs, desc="Blocklist", unit="cert"):
        if not cert.modulus_hex:
            continue
        if cert.modulus_hex not in cache:
            try:
                cache[cert.modulus_hex] = blocklist(int(cert.modulus_hex, 16))
            except Exception as exc:
                cache[cert.modulus_hex] = {"error": str(exc)}
        res = cache[cert.modulus_hex]
        if isinstance(res, dict) and res.get("detected"):
            write_hit(
                hits,
                cert,
                "Blocklists",
                "badkeys_blocklist",
                subtest=res.get("subtest"),
                blid=res.get("blid"),
                lookup=res.get("lookup"),
            )


def run_fastgcd(rsa_certs: list[CertKey], hits: list[dict], chunk_size: int) -> None:
    mod_to_certs = defaultdict(list)
    for cert in rsa_certs:
        if cert.modulus_hex:
            mod_to_certs[cert.modulus_hex].append(cert)
    moduli_hex = list(mod_to_certs)
    moduli = [bigint(int(h, 16)) for h in moduli_hex]
    ranges = [(i, min(i + chunk_size, len(moduli))) for i in range(0, len(moduli), chunk_size)]
    if not ranges:
        return
    chunk_products = [product(moduli[start:end]) for start, end in tqdm(ranges, desc="FastGCD products", unit="chunk")]
    total_product = product(chunk_products)

    for chunk_index, (start, end) in enumerate(tqdm(ranges, desc="FastGCD cross", unit="chunk")):
        other_product = total_product // chunk_products[chunk_index]
        for n_hex, n_val in zip(moduli_hex[start:end], moduli[start:end]):
            g = bigint_gcd(n_val, other_product)
            if g not in (0, 1, n_val):
                for cert in mod_to_certs[n_hex]:
                    write_hit(hits, cert, "Fastgcd", "batch-gcd", gcd_hex=format(int(g), "x"))


def dedupe_hits(hits: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for hit in hits:
        key = (hit["fingerprint_sha256"], hit["test_case"], hit.get("source"), hit.get("subtest"), hit.get("gcd_hex"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hit)
    return deduped


def md_table(headers: list[str], rows: Iterable[Iterable[object]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(x) for x in row) + " |")
    return "\n".join(lines)


def write_outputs(out_dir: Path, certs: list[CertKey], hits: list[dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    public_keys_path = out_dir / "cert_public_keys.jsonl"
    hits_path = out_dir / "weak_key_hits.jsonl"
    summary_path = out_dir / "weak_key_summary.json"
    report_path = out_dir / "weak_key_report.md"
    sm2_reason_path = out_dir / "sm2_invalid_reason_report.md"

    with public_keys_path.open("w", encoding="utf-8") as f:
        for cert in certs:
            f.write(json.dumps(asdict(cert), ensure_ascii=False) + "\n")
    with hits_path.open("w", encoding="utf-8") as f:
        for hit in hits:
            f.write(json.dumps(hit, ensure_ascii=False) + "\n")

    key_counts = Counter((cert.kind, cert.category, cert.key_type) for cert in certs)
    hit_counts = Counter((hit["kind"], hit["category"], hit["test_case"]) for hit in hits)
    hit_by_case = Counter(hit["test_case"] for hit in hits)
    hit_by_kind = Counter(hit["kind"] for hit in hits)
    hit_by_category = Counter(hit["category"] for hit in hits)
    certs_with_hits = {hit["fingerprint_sha256"] for hit in hits}

    summary = {
        "total_certs": len(certs),
        "certs_by_kind_category_key_type": {"|".join(k): v for k, v in key_counts.items()},
        "total_hits": len(hits),
        "certs_with_hits": len(certs_with_hits),
        "hits_by_case": dict(hit_by_case),
        "hits_by_kind": dict(hit_by_kind),
        "hits_by_category": dict(hit_by_category),
        "outputs": {
            "public_keys": str(public_keys_path),
            "hits": str(hits_path),
            "report": str(report_path),
            "sm2_reason_report": str(sm2_reason_path),
        },
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    sample_rows = []
    for hit in hits[:30]:
        sample_rows.append([
            hit["kind"],
            hit["category"],
            hit["test_case"],
            hit["key_type"],
            hit.get("key_size", ""),
            Path(hit["path"]).name[:18],
            hit.get("reasons", hit.get("subtest", hit.get("gcd_hex", ""))),
        ])

    report = [
        "# Certificate Weak-Key Analysis",
        "",
        f"- Total certificates parsed: {len(certs)}",
        f"- Certificates with weak-key/security hits: {len(certs_with_hits)}",
        f"- Total unique hits: {len(hits)}",
        "",
        "## Key Type Distribution",
        "",
        md_table(["kind", "category", "key_type", "count"], [(k[0], k[1], k[2], v) for k, v in sorted(key_counts.items())]),
        "",
        "## Hit Counts",
        "",
        md_table(["kind", "category", "test_case", "count"], [(k[0], k[1], k[2], v) for k, v in sorted(hit_counts.items())]),
        "",
        "## Sample Hits",
        "",
        md_table(["kind", "category", "test_case", "key_type", "key_size", "cert", "details"], sample_rows),
        "",
    ]
    report_path.write_text("\n".join(report), encoding="utf-8")

    sm2_reasons = Counter()
    for hit in hits:
        if hit["test_case"] == "SM2 Invalid":
            sm2_reasons["&".join(hit.get("reasons", [])) or "unknown"] += 1
    sm2_lines = [
        "# SM2 Invalid Reason Report",
        "",
        md_table(["reason combination", "count"], sm2_reasons.most_common()),
        "",
    ]
    sm2_reason_path.write_text("\n".join(sm2_lines), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))


def analyze_dataset(args: argparse.Namespace) -> None:
    root = Path(args.cert_root)
    out_dir = Path(args.out_dir) if args.out_dir else default_out_dir(root)

    certs = [extract_cert_key(category, kind, path) for category, kind, path in tqdm(list(iter_cert_paths(root)), desc="Extract public keys", unit="cert")]
    rsa_certs = [cert for cert in certs if cert.key_type == "RSA" and cert.modulus_hex]
    ecc_certs = [cert for cert in certs if cert.key_type == "ECC"]
    sm2_certs = [cert for cert in certs if cert.key_type == "SM2"]

    hits: list[dict] = []
    for cert in tqdm(rsa_certs, desc="Local RSA checks", unit="cert"):
        n = int(cert.modulus_hex or "0", 16)
        e = int(cert.exponent or 0)
        if e <= 1 or e % 2 == 0:
            write_hit(hits, cert, "RSA Invalid", "local", reason="invalid_exponent")
        if cert.key_size and cert.key_size < args.min_rsa_bits:
            write_hit(hits, cert, "RSA Weak Size", "local", threshold=args.min_rsa_bits)
        if has_small_prime_factor(n):
            write_hit(hits, cert, "Small Factors", "local")
        if detect_repeating_byte_pattern(cert.modulus_hex):
            write_hit(hits, cert, "Pattern", "local")
        if roca_detect(n):
            write_hit(hits, cert, "ROCA", "roca")
        if args.enable_fermat and n > 1 and n % 2 == 1 and fermat_factorable_heuristic(n, args.fermat_max_steps):
            write_hit(hits, cert, "Fermat", "local", max_steps=args.fermat_max_steps)

    for cert in tqdm(ecc_certs, desc="ECC checks", unit="cert"):
        reasons = analyze_ecc_invalid(cert)
        if reasons:
            write_hit(hits, cert, "ECC Invalid", "local", reasons=reasons)

    for cert in tqdm(sm2_certs, desc="SM2 checks", unit="cert"):
        reasons = analyze_sm2_invalid(cert)
        if reasons:
            write_hit(hits, cert, "SM2 Invalid", "local", reasons=reasons)

    if args.enable_blocklist:
        run_blocklist_if_available(rsa_certs, hits, args.strict_deps)
    if args.enable_fastgcd:
        run_fastgcd(rsa_certs, hits, args.chunk_size)

    write_outputs(out_dir, certs, dedupe_hits(hits))


def main() -> None:
    global OPENSSL_BIN
    parser = argparse.ArgumentParser(description="Weak-key analysis for the SM2-vs-ordinary-TLS certificate dataset.")
    parser.add_argument("--cert-root", default=".", help="Directory containing bank/edu/gov and normal_cert_collection")
    parser.add_argument(
        "--out-dir",
        default="",
        help="Output directory. Default: analysis_outputs<dataset suffix>/weak_key_cert_analysis for data-like cert roots, otherwise <cert-root>/weak_key_cert_analysis.",
    )
    parser.add_argument("--min-rsa-bits", type=int, default=2048)
    parser.add_argument("--enable-fermat", action="store_true", help="Enable slow Fermat heuristic")
    parser.add_argument("--fermat-max-steps", type=int, default=50000)
    parser.add_argument("--enable-blocklist", action="store_true", help="Use badkeys blocklist if installed")
    parser.add_argument("--enable-fastgcd", action="store_true", help="Run GCD shared-prime detection over ordinary RSA certificates")
    parser.add_argument("--chunk-size", type=int, default=20000)
    parser.add_argument("--strict-deps", action="store_true", help="Fail when optional dependencies are missing")
    parser.add_argument("--openssl-bin", default=OPENSSL_BIN, help="OpenSSL/Tongsuo command used to print SM2 public keys")
    args = parser.parse_args()
    OPENSSL_BIN = args.openssl_bin
    analyze_dataset(args)


if __name__ == "__main__":
    main()
