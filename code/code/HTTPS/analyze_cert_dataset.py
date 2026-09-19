#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import ipaddress
import re
import statistics
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, ExtendedKeyUsageOID, NameOID


CATEGORIES = ("bank", "edu", "gov")
NOW = datetime.now(UTC)

SIG_NAMES = {
    "1.2.156.10197.1.501": "SM2-with-SM3",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
}


@dataclass(frozen=True)
class CertMeta:
    category: str
    kind: str
    sha256: str
    path: str
    subject: str
    subject_cn: str
    issuer: str
    issuer_cn: str
    issuer_org: str
    not_before: datetime
    not_after: datetime
    valid_days: int
    status: str
    sig_alg: str
    pubkey: str
    has_san: bool
    san_dns_count: int
    has_server_auth: bool
    has_ct_sct: bool
    has_aia: bool
    has_crl_dp: bool
    is_ca: str
    key_usage: str


def oid_name(oid: x509.ObjectIdentifier) -> str:
    return SIG_NAMES.get(oid.dotted_string, getattr(oid, "_name", oid.dotted_string))


def read_domain_map(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                rows.append((parts[0], parts[1].lower()))
    return rows


def read_domain_or_domain_ip_map(root: Path, category: str) -> list[tuple[str, str]]:
    domain_map = root / f"{category}_domain_map.txt"
    if domain_map.exists():
        return read_domain_map(domain_map)
    domain_ip_map = root / f"{category}_domain_ip_map.txt"
    return read_domain_map(domain_ip_map)


def read_normal_map(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                rows.append(
                    {
                        "domain": parts[0],
                        "sm2_hash": parts[1].lower(),
                        "ip": parts[2],
                        "normal_hash": parts[3].lower(),
                        "status": parts[5],
                    }
                )
    return rows


def read_normal_map_for_category(root: Path, category: str) -> list[dict[str, str]]:
    enriched_path = root / "normal_cert_collection" / f"{category}_domain_ip_map_with_normal_cert.txt"
    if enriched_path.exists():
        return read_normal_map(enriched_path)
    return read_normal_map(root / "normal_cert_collection" / "normal_domain_ip_maps" / f"{category}_domain_ip_map.txt")


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def count_pem_certificates(path: Path) -> int:
    return path.read_bytes().count(b"-----BEGIN CERTIFICATE-----")


def hash_pem(path: Path) -> str:
    cert = load_cert(path)
    return cert.fingerprint(hashes.SHA256()).hex()


def first_name(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else ""


def cert_status(not_before: datetime, not_after: datetime) -> str:
    if NOW < not_before:
        return "not_yet_valid"
    if NOW > not_after:
        return "expired"
    return "valid"


def has_aia_ca_issuers(cert: x509.Certificate) -> bool:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except Exception:
        return False
    return any(access.access_method == AuthorityInformationAccessOID.CA_ISSUERS for access in aia)


def public_key_label(cert: x509.Certificate) -> str:
    oid = cert.public_key_algorithm_oid
    oid_text = oid_name(oid)
    try:
        key = cert.public_key()
    except Exception:
        if oid.dotted_string == "1.2.840.10045.2.1":
            return "EC-SM2-256"
        return oid_text
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA-{key.curve.name}-{key.key_size}"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA-{key.key_size}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(key).__name__


def extension_flags_from_openssl(path: Path) -> tuple[bool, int, bool, bool, bool, bool, str, str]:
    try:
        text = subprocess.check_output(
            ["openssl", "x509", "-in", str(path), "-noout", "-text"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return False, 0, False, False, False, False, "parse_error", "parse_error"

    has_san = "X509v3 Subject Alternative Name" in text
    san_dns_count = len(re.findall(r"\bDNS:", text))
    has_server_auth = "TLS Web Server Authentication" in text
    has_ct_sct = "CT Precertificate SCTs" in text
    has_aia = "Authority Information Access" in text
    has_crl_dp = "X509v3 CRL Distribution Points" in text
    if "CA:FALSE" in text:
        is_ca = "false"
    elif "CA:TRUE" in text:
        is_ca = "true"
    else:
        is_ca = "missing"

    key_usage = "missing"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "X509v3 Key Usage" in line:
            for next_line in lines[i + 1 : i + 4]:
                stripped = next_line.strip()
                if stripped and not stripped.startswith("X509v3"):
                    names = []
                    mapping = {
                        "Digital Signature": "digital_signature",
                        "Non Repudiation": "non_repudiation",
                        "Key Encipherment": "key_encipherment",
                        "Data Encipherment": "data_encipherment",
                        "Key Agreement": "key_agreement",
                        "Certificate Sign": "key_cert_sign",
                        "CRL Sign": "crl_sign",
                    }
                    for label, normalized in mapping.items():
                        if label in stripped:
                            names.append(normalized)
                    key_usage = "+".join(names) if names else stripped
                    break
            break

    return has_san, san_dns_count, has_server_auth, has_ct_sct, has_aia, has_crl_dp, is_ca, key_usage


def extension_flags(cert: x509.Certificate, path: Path) -> tuple[bool, int, bool, bool, bool, bool, str, str]:
    has_san = False
    san_dns_count = 0
    has_server_auth = False
    has_ct_sct = False
    has_aia = False
    has_crl_dp = False
    is_ca = "missing"
    key_usage = "missing"

    try:
        extensions = cert.extensions
    except Exception:
        return extension_flags_from_openssl(path)

    try:
        san = extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        has_san = True
        san_dns_count = len(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    try:
        eku = extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        has_server_auth = ExtendedKeyUsageOID.SERVER_AUTH in eku
    except x509.ExtensionNotFound:
        pass

    try:
        extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        has_ct_sct = True
    except x509.ExtensionNotFound:
        pass

    try:
        extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        has_aia = True
    except x509.ExtensionNotFound:
        pass

    try:
        extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        has_crl_dp = True
    except x509.ExtensionNotFound:
        pass

    try:
        bc = extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        is_ca = "true" if bc.ca else "false"
    except x509.ExtensionNotFound:
        pass

    try:
        ku = extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        values = []
        if ku.digital_signature:
            values.append("digital_signature")
        if ku.content_commitment:
            values.append("non_repudiation")
        if ku.key_encipherment:
            values.append("key_encipherment")
        if ku.data_encipherment:
            values.append("data_encipherment")
        if ku.key_agreement:
            values.append("key_agreement")
        if ku.key_cert_sign:
            values.append("key_cert_sign")
        if ku.crl_sign:
            values.append("crl_sign")
        key_usage = "+".join(values) if values else "present_empty"
    except x509.ExtensionNotFound:
        pass

    return has_san, san_dns_count, has_server_auth, has_ct_sct, has_aia, has_crl_dp, is_ca, key_usage


def cert_meta(path: Path, category: str, kind: str, sha_hint: str | None = None) -> CertMeta:
    cert = load_cert(path)
    sha = sha_hint or cert.fingerprint(hashes.SHA256()).hex()
    has_san, san_dns_count, has_server_auth, has_ct_sct, has_aia, has_crl_dp, is_ca, key_usage = extension_flags(cert, path)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    return CertMeta(
        category=category,
        kind=kind,
        sha256=sha,
        path=str(path),
        subject=cert.subject.rfc4514_string(),
        subject_cn=first_name(cert.subject, NameOID.COMMON_NAME),
        issuer=cert.issuer.rfc4514_string(),
        issuer_cn=first_name(cert.issuer, NameOID.COMMON_NAME),
        issuer_org=first_name(cert.issuer, NameOID.ORGANIZATION_NAME),
        not_before=not_before,
        not_after=not_after,
        valid_days=(not_after - not_before).days,
        status=cert_status(not_before, not_after),
        sig_alg=oid_name(cert.signature_algorithm_oid),
        pubkey=public_key_label(cert),
        has_san=has_san,
        san_dns_count=san_dns_count,
        has_server_auth=has_server_auth,
        has_ct_sct=has_ct_sct,
        has_aia=has_aia,
        has_crl_dp=has_crl_dp,
        is_ca=is_ca,
        key_usage=key_usage,
    )


def pct(n: int, d: int) -> str:
    return "0.0%" if d == 0 else f"{n / d * 100:.1f}%"


def md_table(headers: list[str], rows: Iterable[Iterable[object]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(x) for x in row) + " |")
    return "\n".join(lines)


def read_csv_dicts(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def as_int(value: object) -> int:
    try:
        return int(str(value))
    except Exception:
        return 0


def as_float(value: object) -> float:
    try:
        return float(str(value))
    except Exception:
        return 0.0


def ratio_text(n: int, d: int) -> str:
    return f"{n}/{d} ({pct(n, d)})"


def describe_days(values: list[int]) -> tuple[str, str, str, str]:
    if not values:
        return "-", "-", "-", "-"
    return (
        f"{statistics.median(values):.0f}",
        f"{statistics.mean(values):.1f}",
        str(min(values)),
        str(max(values)),
    )


def top_counter(counter: Counter[str], n: int = 10) -> str:
    if not counter:
        return "-"
    return "; ".join(f"{k} ({v})" for k, v in counter.most_common(n))


def writable_path(path: Path) -> Path:
    if not path.exists():
        return path
    try:
        with path.open("a"):
            pass
        return path
    except PermissionError:
        return path.with_name(f"{path.stem}_new{path.suffix}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate SM2/ordinary TLS certificate dataset report.")
    parser.add_argument("--cert-root", type=Path, default=Path("."), help="Dataset root containing bank/edu/gov and normal_cert_collection.")
    parser.add_argument("--out-dir", type=Path, default=None, help="Directory for report and metadata outputs.")
    parser.add_argument("--report-name", default="sm2_tls_certificate_report.md", help="Markdown report filename.")
    parser.add_argument("--as-of-date", default="", help="UTC date used for certificate validity status, YYYY-MM-DD.")
    parser.add_argument("--skip-chain-section", action="store_true", help="Do not write the certificate-chain observability section.")
    parser.add_argument("--skip-failure-section", action="store_true", help="Do not write the remaining ordinary-certificate failures section.")
    parser.add_argument("--skip-weak-key-section", action="store_true", help="Do not write the weak-key section.")
    parser.add_argument("--skip-handshake-section", action="store_true", help="Do not write the TLS handshake-speed section.")
    return parser.parse_args()


def drop_markdown_sections(lines: list[str], heading_prefixes: set[str]) -> list[str]:
    kept: list[str] = []
    dropping = False
    for line in lines:
        if line.startswith("## "):
            dropping = any(line.startswith(prefix) for prefix in heading_prefixes)
        if not dropping:
            kept.append(line)
    return kept


def drop_conclusion_items(lines: list[str], item_prefixes: set[str]) -> list[str]:
    kept: list[str] = []
    in_conclusions = False
    for line in lines:
        if line.startswith("## 10."):
            in_conclusions = True
        elif line.startswith("## 11."):
            in_conclusions = False
        if in_conclusions and any(line.startswith(prefix) for prefix in item_prefixes):
            continue
        kept.append(line)
    return kept


def main() -> None:
    global NOW
    args = parse_args()
    root = args.cert_root.resolve()
    out_dir = args.out_dir.resolve() if args.out_dir else root / "analysis_outputs"
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.as_of_date:
        NOW = datetime.fromisoformat(args.as_of_date).replace(tzinfo=UTC)

    sm2_maps = {cat: read_domain_or_domain_ip_map(root, cat) for cat in CATEGORIES}
    normal_maps = {cat: read_normal_map_for_category(root, cat) for cat in CATEGORIES}

    sm2_meta: list[CertMeta] = []
    for cat in CATEGORIES:
        for pem in sorted((root / cat).glob("*.pem")):
            sm2_meta.append(cert_meta(pem, cat, "sm2", pem.stem.lower()))

    normal_meta: list[CertMeta] = []
    for cat in CATEGORIES:
        for pem in sorted((root / "normal_cert_collection" / "normal_certs" / cat).glob("*.pem")):
            normal_meta.append(cert_meta(pem, cat, "ordinary", pem.stem.lower()))

    all_normal_hashes = {m.sha256 for m in normal_meta}
    map_normal_hashes = {
        row["normal_hash"]
        for rows in normal_maps.values()
        for row in rows
        if row["status"] == "ok" and re.fullmatch(r"[0-9a-f]{64}", row["normal_hash"])
    }

    summary_rows = []
    for cat in CATEGORIES:
        sm2_rows = sm2_maps[cat]
        normal_rows = normal_maps[cat]
        domains = {d for d, _ in sm2_rows}
        sm2_hashes = {h for _, h in sm2_rows}
        ips = {r["ip"] for r in normal_rows}
        ok_rows = [r for r in normal_rows if r["status"] == "ok"]
        ok_ips = {r["ip"] for r in ok_rows}
        failed_ips = {r["ip"] for r in normal_rows if r["status"] != "ok"}
        domains_with_ok = {r["domain"] for r in ok_rows}
        normal_hashes = {r["normal_hash"] for r in ok_rows if re.fullmatch(r"[0-9a-f]{64}", r["normal_hash"])}
        summary_rows.append(
            [
                cat,
                len(sm2_rows),
                len(domains),
                len(sm2_hashes),
                len(ips),
                len(ok_ips),
                len(failed_ips),
                f"{len(domains_with_ok)}/{len(domains)} ({pct(len(domains_with_ok), len(domains))})",
                len(normal_hashes),
            ]
        )

    global_domains = {d for rows in sm2_maps.values() for d, _ in rows}
    global_sm2 = {h for rows in sm2_maps.values() for _, h in rows}
    global_ips = {r["ip"] for rows in normal_maps.values() for r in rows}
    global_ok_ips = {r["ip"] for rows in normal_maps.values() for r in rows if r["status"] == "ok"}
    global_failed_ips = {r["ip"] for rows in normal_maps.values() for r in rows if r["status"] != "ok"}
    global_ok_domains = {r["domain"] for rows in normal_maps.values() for r in rows if r["status"] == "ok"}
    summary_rows.append(
        [
            "total",
            sum(len(v) for v in sm2_maps.values()),
            len(global_domains),
            len(global_sm2),
            len(global_ips),
            len(global_ok_ips),
            len(global_failed_ips),
            f"{len(global_ok_domains)}/{len(global_domains)} ({pct(len(global_ok_domains), len(global_domains))})",
            len(map_normal_hashes),
        ]
    )

    cert_stat_rows = []
    for kind, metas in [("SM2", sm2_meta), ("ordinary TLS", normal_meta)]:
        for cat in (*CATEGORIES, "total"):
            subset = metas if cat == "total" else [m for m in metas if m.category == cat]
            valid_days = [m.valid_days for m in subset]
            med, avg, mn, mx = describe_days(valid_days)
            cert_stat_rows.append(
                [
                    kind,
                    cat,
                    len(subset),
                    top_counter(Counter(m.sig_alg for m in subset), 4),
                    top_counter(Counter(m.pubkey for m in subset), 4),
                    top_counter(Counter(m.status for m in subset), 4),
                    med,
                    avg,
                    mn,
                    mx,
                ]
            )

    ext_rows = []
    for kind, metas in [("SM2", sm2_meta), ("ordinary TLS", normal_meta)]:
        for cat in (*CATEGORIES, "total"):
            subset = metas if cat == "total" else [m for m in metas if m.category == cat]
            total = len(subset)
            ext_rows.append(
                [
                    kind,
                    cat,
                    f"{sum(m.has_san for m in subset)}/{total} ({pct(sum(m.has_san for m in subset), total)})",
                    f"{sum(m.has_server_auth for m in subset)}/{total} ({pct(sum(m.has_server_auth for m in subset), total)})",
                    f"{sum(m.has_ct_sct for m in subset)}/{total} ({pct(sum(m.has_ct_sct for m in subset), total)})",
                    f"{sum(m.has_aia for m in subset)}/{total} ({pct(sum(m.has_aia for m in subset), total)})",
                    f"{sum(m.has_crl_dp for m in subset)}/{total} ({pct(sum(m.has_crl_dp for m in subset), total)})",
                    top_counter(Counter(m.key_usage for m in subset), 3),
                ]
            )

    chain_base_dir = root / "analysis_outputs" / "certificate_chains"
    sm2_tongsuo_chain_dir = root / "analysis_outputs" / "certificate_chains_sm2_tongsuo_verify"
    chain_summary_path = chain_base_dir / "chain_summary.csv"
    chain_details_path = chain_base_dir / "chain_details.csv"
    ca_info_path = chain_base_dir / "ca_bundle_info.json"
    sm2_tongsuo_summary_path = sm2_tongsuo_chain_dir / "chain_summary.csv"
    sm2_tongsuo_details_path = sm2_tongsuo_chain_dir / "chain_details.csv"
    sm2_tongsuo_ca_info_path = sm2_tongsuo_chain_dir / "ca_bundle_info.json"
    base_chain_summary_rows = read_csv_dicts(chain_summary_path)
    base_chain_detail_rows = read_csv_dicts(chain_details_path)
    sm2_tongsuo_summary_rows = read_csv_dicts(sm2_tongsuo_summary_path)
    sm2_tongsuo_detail_rows = read_csv_dicts(sm2_tongsuo_details_path)
    ca_info = json.loads(ca_info_path.read_text(encoding="utf-8")) if ca_info_path.exists() else {}
    sm2_tongsuo_ca_info = json.loads(sm2_tongsuo_ca_info_path.read_text(encoding="utf-8")) if sm2_tongsuo_ca_info_path.exists() else {}
    if sm2_tongsuo_summary_rows:
        chain_summary_rows = sm2_tongsuo_summary_rows + [row for row in base_chain_summary_rows if row.get("kind") == "ordinary"]
        chain_detail_rows = sm2_tongsuo_detail_rows + [row for row in base_chain_detail_rows if row.get("kind") == "ordinary"]
    else:
        chain_summary_rows = base_chain_summary_rows
        chain_detail_rows = base_chain_detail_rows

    chain_rows = []
    if chain_summary_rows:
        for row in chain_summary_rows:
            targets = as_int(row.get("targets"))
            chain_rows.append(
                [
                    "SM2" if row.get("kind") == "sm2" else "ordinary TLS",
                    row.get("category", ""),
                    targets,
                    ratio_text(as_int(row.get("connect_ok")), targets),
                    ratio_text(as_int(row.get("has_intermediate")), targets),
                    ratio_text(as_int(row.get("leaf_only_non_self_signed")), targets),
                    ratio_text(as_int(row.get("issuer_subject_link_mismatch")), targets),
                    ratio_text(as_int(row.get("potential_broken_chain")), targets),
                    ratio_text(as_int(row.get("self_signed_leaf")), targets),
                    ratio_text(as_int(row.get("aia_ca_issuers")), targets),
                    ratio_text(as_int(row.get("verify_ok")), targets),
                    ratio_text(as_int(row.get("missing_trust_anchor_or_intermediate")), targets),
                ]
            )
    else:
        chain_items = []
        for meta in [*sm2_meta, *normal_meta]:
            path = root / meta.path
            try:
                cert = load_cert(path)
                pem_cert_count = count_pem_certificates(path)
                self_signed_leaf = cert.subject == cert.issuer
                aia_ca_issuers = has_aia_ca_issuers(cert)
            except Exception:
                pem_cert_count = 0
                self_signed_leaf = False
                aia_ca_issuers = False
            chain_items.append(
                {
                    "kind": "SM2" if meta.kind == "sm2" else "ordinary TLS",
                    "category": meta.category,
                    "pem_cert_count": pem_cert_count,
                    "leaf_only": pem_cert_count == 1,
                    "embedded_chain": pem_cert_count > 1,
                    "self_signed_leaf": self_signed_leaf,
                    "aia_ca_issuers": aia_ca_issuers,
                }
            )

        for kind in ("SM2", "ordinary TLS"):
            for cat in (*CATEGORIES, "total"):
                subset = [item for item in chain_items if item["kind"] == kind and (cat == "total" or item["category"] == cat)]
                total = len(subset)
                chain_rows.append(
                    [
                        kind,
                        cat,
                        total,
                        ratio_text(total, total),
                        "not measured",
                        "not measured",
                        "not measured",
                        "not measured",
                        ratio_text(sum(item["self_signed_leaf"] for item in subset), total),
                        ratio_text(sum(item["aia_ca_issuers"] for item in subset), total),
                        "not measured",
                        "not measured",
                    ]
                )

    sm2_verify_classes = Counter(row.get("verify_error_class", "") for row in chain_detail_rows if row.get("kind") == "sm2" and row.get("verify_error_class"))
    ordinary_verify_classes = Counter(row.get("verify_error_class", "") for row in chain_detail_rows if row.get("kind") == "ordinary" and row.get("verify_error_class"))
    active_sm2_ca_info = sm2_tongsuo_ca_info or ca_info
    ca_bundle_errors = active_sm2_ca_info.get("built_sm2_ca_bundle", {}).get("errors", []) if active_sm2_ca_info else []

    issuer_rows = []
    for kind, metas in [("SM2", sm2_meta), ("ordinary TLS", normal_meta)]:
        issuer_rows.append([kind, top_counter(Counter(m.issuer_org or m.issuer_cn or "(empty)" for m in metas), 12)])

    reuse_rows = []
    for cat in CATEGORIES:
        sm2_to_domains: dict[str, set[str]] = defaultdict(set)
        normal_to_domains: dict[str, set[str]] = defaultdict(set)
        normal_to_ips: dict[str, set[str]] = defaultdict(set)
        sm2_to_normal: dict[str, set[str]] = defaultdict(set)
        normal_to_sm2: dict[str, set[str]] = defaultdict(set)
        for domain, sm2_hash in sm2_maps[cat]:
            sm2_to_domains[sm2_hash].add(domain)
        for row in normal_maps[cat]:
            if row["status"] != "ok":
                continue
            normal_hash = row["normal_hash"]
            normal_to_domains[normal_hash].add(row["domain"])
            normal_to_ips[normal_hash].add(row["ip"])
            sm2_to_normal[row["sm2_hash"]].add(normal_hash)
            normal_to_sm2[normal_hash].add(row["sm2_hash"])
        reuse_rows.append(
            [
                cat,
                sum(1 for v in sm2_to_domains.values() if len(v) > 1),
                max((len(v) for v in sm2_to_domains.values()), default=0),
                sum(1 for v in normal_to_domains.values() if len(v) > 1),
                max((len(v) for v in normal_to_domains.values()), default=0),
                sum(1 for v in normal_to_ips.values() if len(v) > 1),
                sum(1 for v in sm2_to_normal.values() if len(v) > 1),
                sum(1 for v in normal_to_sm2.values() if len(v) > 1),
            ]
        )

    pair_examples: list[list[object]] = []
    for cat in CATEGORIES:
        sm2_to_normal: dict[str, set[str]] = defaultdict(set)
        normal_to_sm2: dict[str, set[str]] = defaultdict(set)
        normal_to_domains: dict[str, set[str]] = defaultdict(set)
        for row in normal_maps[cat]:
            if row["status"] == "ok":
                sm2_to_normal[row["sm2_hash"]].add(row["normal_hash"])
                normal_to_sm2[row["normal_hash"]].add(row["sm2_hash"])
                normal_to_domains[row["normal_hash"]].add(row["domain"])
        for sm2_hash, normals in sorted(sm2_to_normal.items(), key=lambda x: (-len(x[1]), x[0])):
            if len(normals) > 1:
                pair_examples.append([cat, "one SM2 -> many ordinary", sm2_hash[:12], len(normals), ", ".join(sorted(n[:12] for n in normals)[:6])])
        for normal_hash, sm2s in sorted(normal_to_sm2.items(), key=lambda x: (-len(x[1]), x[0])):
            if len(sm2s) > 1:
                domains = ", ".join(sorted(normal_to_domains[normal_hash])[:10])
                pair_examples.append([cat, "one ordinary -> many SM2", normal_hash[:12], len(sm2s), domains])

    failure_rows = []
    failure_path = root / "normal_cert_collection" / "normal_cert_failures.csv"
    if failure_path.exists():
        with failure_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                failure_rows.append(
                    [
                        row.get("category", ""),
                        row.get("ip", ""),
                        row.get("source_domain_count", ""),
                        row.get("tried_domains", ""),
                        row.get("error", ""),
                    ]
                )

    speed_summary_path = root / "analysis_outputs" / "tls_handshake_speed" / "tls_handshake_speed_summary.csv"
    speed_rows_raw = read_csv_dicts(speed_summary_path)
    speed_rows = []
    speed_by_category = defaultdict(dict)
    for row in speed_rows_raw:
        attempts = as_int(row.get("attempts"))
        successes = as_int(row.get("successes"))
        median_ms = as_float(row.get("median_ms"))
        avg_ms = as_float(row.get("avg_ms"))
        speed_rows.append(
            [
                row.get("category", ""),
                row.get("mode", ""),
                attempts,
                ratio_text(successes, attempts),
                f"{median_ms:.2f}" if row.get("median_ms") else "",
                f"{avg_ms:.2f}" if row.get("avg_ms") else "",
                row.get("min_ms", ""),
                row.get("max_ms", ""),
            ]
        )
        speed_by_category[row.get("category", "")][row.get("mode", "")] = row

    speed_compare_rows = []
    for category in CATEGORIES:
        ordinary = speed_by_category.get(category, {}).get("ordinary")
        sm2_speed = speed_by_category.get(category, {}).get("sm2_ntls")
        if ordinary and sm2_speed:
            ordinary_median = as_float(ordinary.get("median_ms"))
            sm2_median = as_float(sm2_speed.get("median_ms"))
            diff = sm2_median - ordinary_median
            speed_compare_rows.append(
                [
                    category,
                    f"{ordinary_median:.2f}",
                    f"{sm2_median:.2f}",
                    f"{diff:.2f}",
                    "SM2/NTLS faster" if diff < 0 else "ordinary TLS faster",
                    ratio_text(as_int(ordinary.get("successes")), as_int(ordinary.get("attempts"))),
                    ratio_text(as_int(sm2_speed.get("successes")), as_int(sm2_speed.get("attempts"))),
                ]
            )

    weak_summary_path = root / "analysis_outputs" / "weak_key_cert_analysis" / "weak_key_summary.json"
    weak_hits_path = root / "analysis_outputs" / "weak_key_cert_analysis" / "weak_key_hits.jsonl"
    weak_summary = {}
    weak_hit_rows = []
    if weak_summary_path.exists():
        weak_summary = json.loads(weak_summary_path.read_text(encoding="utf-8"))
    if weak_hits_path.exists():
        for line in weak_hits_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            hit = json.loads(line)
            weak_hit_rows.append(
                [
                    hit.get("kind", ""),
                    hit.get("category", ""),
                    hit.get("test_case", ""),
                    hit.get("key_type", ""),
                    hit.get("key_size", ""),
                    Path(hit.get("path", "")).name[:18],
                    f"threshold={hit['threshold']}" if "threshold" in hit else hit.get("reason", hit.get("reasons", "")),
                ]
            )

    weak_case_rows = []
    if weak_summary:
        for case, count in sorted(weak_summary.get("hits_by_case", {}).items()):
            weak_case_rows.append([case, count])
    weak_kind_rows = []
    if weak_summary:
        for kind, count in sorted(weak_summary.get("hits_by_kind", {}).items()):
            weak_kind_rows.append([kind, count])
    weak_category_rows = []
    if weak_summary:
        for category, count in sorted(weak_summary.get("hits_by_category", {}).items()):
            weak_category_rows.append([category, count])

    notes = [
        "# SM2 与普通 TLS 证书数据统计报告",
        "",
        f"统计时间口径：以 {NOW.date().isoformat()} UTC 判断证书是否有效；所有结果来自本地目录 `{root.resolve()}`，未重新联网采集。",
        "",
        "## 1. 样本覆盖与采集结果",
        "",
        md_table(
            ["category", "SM2 map rows", "unique domains", "unique SM2 certs", "resolved IPs", "ok IPs", "failed IPs", "domains with ordinary cert", "unique ordinary certs"],
            summary_rows,
        ),
        "",
        "解读：域名层面，普通证书覆盖率接近完整；剩余失败集中在两个 edu IP，不能因为同域名另一个 IP 可访问而改记成功。",
        "",
        "## 2. 证书算法与有效期",
        "",
        md_table(
            ["kind", "category", "certs", "signature algorithms", "public keys", "validity status", "median days", "avg days", "min", "max"],
            cert_stat_rows,
        ),
        "",
        "## 3. 扩展项与 WebPKI 生态特征",
        "",
        md_table(
            ["kind", "category", "SAN", "serverAuth EKU", "CT SCT", "AIA", "CRL DP", "top keyUsage"],
            ext_rows,
        ),
        "",
        "## 4. 签发机构分布",
        "",
        md_table(["kind", "top issuer organization/CN"], issuer_rows),
        "",
        "## 5. 证书链可观察性",
        "",
        md_table(
            [
                "kind",
                "category",
                "targets",
                "connect ok",
                "has intermediate",
                "leaf-only non-self-signed",
                "issuer link mismatch",
                "potential broken",
                "self-signed leaf",
                "AIA caIssuers",
                "verify ok",
                "missing trust/intermediate",
            ],
            chain_rows,
        ),
        "",
        f"说明：本节使用重新握手采集的服务端发送链；普通 TLS 来自 `analysis_outputs/certificate_chains`，使用 `{ca_info.get('ordinary_ca_file', '')}` 验证；SM2 来自 `analysis_outputs/certificate_chains_sm2_tongsuo_verify`，使用 Tongsuo 和 `{active_sm2_ca_info.get('sm2_ca_file', '')}` 验证。`potential broken` 表示未返回证书、只返回非自签 leaf，或服务端发送链的相邻 issuer/subject 无法接续。`verify ok` 是 OpenSSL/Tongsuo 基于相应 CA 包的验证结果；SM2 侧若国密信任锚不完整，`missing trust/intermediate` 会偏高。另需注意，SM2/NTLS 可能同时发送签名证书、加密证书及链证书，其发送顺序和语义不一定等同普通 TLS 的单 leaf 证书链，因此 SM2 的 issuer/subject mismatch 应作为“链结构异常/需人工复核”指标，而不宜机械等同于普通 WebPKI 断链。",
        "",
        md_table(["kind", "verify_error_class", "count"], [["SM2", k, v] for k, v in sm2_verify_classes.most_common()] + [["ordinary TLS", k, v] for k, v in ordinary_verify_classes.most_common()]),
        "",
        f"SM2_CA 合并结果：成功合并 {ca_info.get('built_sm2_ca_bundle', {}).get('cert_count', 0)} 张证书；解析失败 {len(ca_bundle_errors)} 个文件。解析失败文件包括：{'; '.join(ca_bundle_errors) if ca_bundle_errors else '无'}",
        "",
        "## 6. 复用关系",
        "",
        md_table(
            [
                "category",
                "SM2 certs reused by domains",
                "max domains per SM2",
                "ordinary certs reused by domains",
                "max domains per ordinary",
                "ordinary certs reused by IPs",
                "SM2 certs mapping to many ordinary",
                "ordinary certs mapping to many SM2",
            ],
            reuse_rows,
        ),
        "",
        md_table(["category", "relation", "hash prefix", "count", "example"], pair_examples),
        "",
        "## 7. 剩余普通证书采集失败样本",
        "",
        md_table(["category", "ip", "domain count", "tried domains", "error"], failure_rows),
        "",
        "## 8. 弱钥检测结果",
        "",
        f"弱钥检测基于证书中的公钥参数完成，共解析 {weak_summary.get('total_certs', 0)} 张证书；发现 {weak_summary.get('certs_with_hits', 0)} 张证书存在弱钥或弱参数命中，唯一命中记录 {weak_summary.get('total_hits', 0)} 条。",
        "",
        md_table(["test_case", "count"], weak_case_rows),
        "",
        md_table(["kind", "count"], weak_kind_rows),
        "",
        md_table(["category", "count"], weak_category_rows),
        "",
        md_table(["kind", "category", "test_case", "key_type", "key_size", "cert", "details"], weak_hit_rows),
        "",
        "解读：当前弱钥命中全部来自普通 TLS 证书，均为 RSA-1024 公钥长度低于现代 TLS/WebPKI 的 2048-bit 基线；SM2 证书未发现点格式错误、坐标缺失、坐标越界、零点或曲线方程不满足等无效公钥问题。",
        "",
        "## 9. TLS 握手速度测量",
        "",
        md_table(["category", "mode", "attempts", "successes", "median ms", "avg ms", "min ms", "max ms"], speed_rows),
        "",
        md_table(["category", "ordinary median ms", "SM2/NTLS median ms", "SM2-ordinary diff ms", "faster mode", "ordinary success", "SM2 success"], speed_compare_rows),
        "",
        "解读：在本次服务器实测中，SM2/NTLS 的中位握手时间在 bank、edu、gov 三类中均低于普通 TLS；但 edu 类 SM2/NTLS 成功率明显低于普通 TLS。因此速度结论应限定为“成功连接样本中的握手耗时”，不能忽略失败率、网络波动和不同服务器实现造成的偏差。",
        "",
        "## 10. 可写入论文的初步结论",
        "",
        "1. 在同一批站点中，SM2/国密证书与普通 TLS 证书呈现并行部署：SM2 侧使用 SM2-with-SM3 与 SM2 曲线，普通 TLS 侧主要使用 RSA-2048/sha256WithRSAEncryption，说明两套证书体系在密码算法、CA 生态和客户端兼容目标上分离。",
        "2. 普通 TLS 证书具备更典型的 WebPKI 生态特征，例如 SAN、serverAuth EKU、AIA/CRL、CT SCT 覆盖率更高；SM2 样本中这些扩展项更不稳定，部分证书更像专用系统或网关证书。",
        "3. SM2 证书有效期跨度显著更长，长有效期降低运维轮换成本，但扩大密钥泄露、算法迁移和撤销失效时的风险窗口。普通 TLS 证书有效期更短，更符合 WebPKI 近年收紧有效期的趋势。",
        "4. 证书与域名/IP 不是一一对应：同一 SM2 证书可覆盖多个域名，同一普通证书也可能被多个域名/IP 复用；论文应按“域名覆盖、IP 采集、唯一证书属性”三个层次分别报告。",
        "5. 两个 edu IP 的失败应作为测量限制保留：失败表示指定 IP 的 TLS 直连采集失败，不否定该域名经其他解析地址可获得普通证书。",
        "6. 弱钥检测显示普通 TLS 侧存在少量 RSA-1024 证书，而 SM2 侧没有发现无效曲线点类问题；这说明普通证书并不天然比 SM2 证书更安全，二者需要分别从算法、证书配置和密钥参数三个层次评价。",
        "7. 证书链实测显示普通 TLS 的验证通过率显著高于 SM2。改用 Tongsuo 验证后，SM2 侧已有 245/1722 通过，但仍有大量样本因证书过期、信任锚/中间证书缺失或链结构需复核而未通过，说明 SM2 证书链生态与普通 WebPKI 相比更不稳定。",
        "8. TLS 握手测速显示，在成功连接样本中 SM2/NTLS 中位耗时更低，但部分类别成功率较低；论文中应同时报告时延和成功率，避免只用速度均值判断优劣。",
        "",
        "## 11. 与 nss21.pdf 的衔接建议",
        "",
        "`nss21.pdf` 是 *Re-check Your Certificates! Experiences and Lessons Learnt from Real-world HTTPS Certificate Deployments*。它把 HTTPS 证书部署问题拆成 SAN mismatch、long validity、broken chain、certificate opacity、obsolete crypto algorithms，并进一步讨论 issuer、sharing、revocation 等可用性/运维因素。",
        "",
        "本文可以沿用类似结构，但把问题域从普通 WebPKI 扩展到“SM2/国密证书与普通 TLS 证书并行部署”：",
        "",
        "1. 测量对象：以 bank/edu/gov 三类域名为样本，分别报告域名、解析 IP、唯一证书三个层次，避免把证书去重口径与 IP 采集口径混合。",
        "2. 配置正确性：对普通 TLS 侧沿用 nss21.pdf 的 SAN、有效期、CT/SCT、过时算法等维度；对 SM2 侧不直接套用浏览器 WebPKI 合规标准，而是作为生态差异和潜在风险指标比较。",
        "3. 运维风险：把证书复用作为核心分析变量。nss21.pdf 认为共享证书会关联部署不一致；本数据也显示 bank/edu/gov 都存在一个证书覆盖大量域名或一个 SM2 对应多个普通证书的现象。",
        "4. 安全解释：SM2 的算法本身不是唯一评价对象，更重要的是证书生命周期、扩展项完整性、撤销/透明度机制、客户端支持边界和网关/专用系统部署习惯。",
        "",
    ]

    drop_headings: set[str] = set()
    drop_items: set[str] = set()
    if args.skip_chain_section:
        drop_headings.add("## 5.")
        drop_items.add("7.")
    if args.skip_failure_section:
        drop_headings.add("## 7.")
        drop_items.add("5.")
    if args.skip_weak_key_section:
        drop_headings.add("## 8.")
        drop_items.add("6.")
    if args.skip_handshake_section:
        drop_headings.add("## 9.")
        drop_items.add("8.")
    if drop_headings:
        notes = drop_markdown_sections(notes, drop_headings)
    if drop_items:
        notes = drop_conclusion_items(notes, drop_items)

    report_path = out_dir / args.report_name
    report_path.write_text("\n".join(notes), encoding="utf-8")

    csv_path = writable_path(out_dir / "certificate_metadata.csv")
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(CertMeta.__dataclass_fields__.keys()))
        writer.writeheader()
        for meta in [*sm2_meta, *normal_meta]:
            row = meta.__dict__.copy()
            row["not_before"] = meta.not_before.isoformat()
            row["not_after"] = meta.not_after.isoformat()
            writer.writerow(row)

    excel_csv_path = writable_path(out_dir / "certificate_metadata_excel.csv")
    with excel_csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(CertMeta.__dataclass_fields__.keys()))
        writer.writeheader()
        for meta in [*sm2_meta, *normal_meta]:
            row = meta.__dict__.copy()
            row["not_before"] = meta.not_before.isoformat()
            row["not_after"] = meta.not_after.isoformat()
            writer.writerow(row)

    xlsx_path = writable_path(out_dir / "certificate_metadata.xlsx")
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        from openpyxl.utils import get_column_letter

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "certificate_metadata"
        fields = list(CertMeta.__dataclass_fields__.keys())
        sheet.append(fields)
        for meta in [*sm2_meta, *normal_meta]:
            row = meta.__dict__.copy()
            row["not_before"] = meta.not_before.isoformat()
            row["not_after"] = meta.not_after.isoformat()
            sheet.append([row[field] for field in fields])

        header_fill = PatternFill(fill_type="solid", fgColor="D9EAF7")
        for cell in sheet[1]:
            cell.font = Font(bold=True)
            cell.fill = header_fill
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
        widths = {
            "A": 12,
            "B": 12,
            "C": 22,
            "D": 34,
            "E": 54,
            "F": 28,
            "G": 54,
            "H": 32,
            "I": 36,
            "J": 24,
            "K": 24,
            "M": 14,
            "N": 26,
            "O": 18,
            "W": 44,
        }
        for idx in range(1, len(fields) + 1):
            letter = get_column_letter(idx)
            sheet.column_dimensions[letter].width = widths.get(letter, 16)
        workbook.save(xlsx_path)
    except Exception as exc:
        xlsx_path = Path(f"{xlsx_path} (not written: {exc})")

    print(report_path)
    print(csv_path)
    print(excel_csv_path)
    print(xlsx_path)


if __name__ == "__main__":
    main()
