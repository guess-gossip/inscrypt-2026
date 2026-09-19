#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID


CATEGORIES = ("bank", "edu", "gov")
PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def read_sm2_targets(root: Path, categories: list[str]) -> list[dict]:
    targets = []
    seen = set()
    for category in categories:
        domain_ip_path = root / f"{category}_domain_ip_map.txt"
        path = domain_ip_path if domain_ip_path.exists() else root / f"{category}_domain_map.txt"
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                domain, sm2_hash = parts[0], parts[1].lower()
                if sm2_hash.upper() == "NA":
                    continue
                ip = parts[2] if len(parts) >= 3 else ""
                connect_host = ip or domain
                key = (category, domain, connect_host, sm2_hash)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    {
                        "kind": "sm2",
                        "category": category,
                        "domain": domain,
                        "connect_host": connect_host,
                        "sni": domain,
                        "ip": ip,
                        "expected_leaf_sha256": sm2_hash,
                    }
                )
    return targets


def read_ordinary_targets(root: Path, categories: list[str]) -> list[dict]:
    targets = []
    seen = set()
    for category in categories:
        enriched_path = root / "normal_cert_collection" / f"{category}_domain_ip_map_with_normal_cert.txt"
        path = enriched_path if enriched_path.exists() else root / "normal_cert_collection" / "normal_domain_ip_maps" / f"{category}_domain_ip_map.txt"
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 6 or parts[5] != "ok":
                    continue
                domain, _sm2_hash, ip, normal_hash = parts[:4]
                key = (category, ip, domain, normal_hash.lower())
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    {
                        "kind": "ordinary",
                        "category": category,
                        "domain": domain,
                        "connect_host": ip,
                        "sni": domain,
                        "ip": ip,
                        "expected_leaf_sha256": normal_hash.lower(),
                    }
                )
    return targets


def cert_sha256_pem(pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(pem)
    return cert.fingerprint(hashes.SHA256()).hex()


def load_cert_any(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def pem_bytes_from_cert_path(path: Path) -> bytes:
    cert = load_cert_any(path)
    return cert.public_bytes(serialization.Encoding.PEM)


def default_out_dir(root: Path) -> Path:
    name = root.name
    if name.startswith("data") and len(name) > len("data"):
        return root.parent / f"analysis_outputs{name[len('data'):]}" / "certificate_chains"
    return root / "certificate_chains"


def build_ca_bundle_from_dir(ca_dir: Path, out_path: Path) -> tuple[str, int, list[str]]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    certs = []
    errors = []
    if not ca_dir.exists():
        return "", 0, [f"CA directory does not exist: {ca_dir}"]
    for path in sorted(ca_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".pem", ".crt", ".cer", ".der"}:
            continue
        try:
            certs.append(pem_bytes_from_cert_path(path))
        except Exception as exc:
            errors.append(f"{path}: {exc!r}")
    if certs:
        out_path.write_bytes(b"\n".join(certs) + b"\n")
        return str(out_path), len(certs), errors
    return "", 0, errors


def first_name(cert_name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    values = cert_name.get_attributes_for_oid(oid)
    return values[0].value if values else ""


def name_text(cert_name: x509.Name) -> str:
    try:
        return cert_name.rfc4514_string()
    except Exception:
        return str(cert_name)


def cert_name_key(cert_name: x509.Name) -> str:
    return name_text(cert_name)


def load_ca_subjects(ca_dir: Path) -> dict[str, list[str]]:
    subjects: dict[str, list[str]] = {}
    if not ca_dir.exists():
        return subjects
    for path in sorted(ca_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".pem", ".crt", ".cer", ".der"}:
            continue
        try:
            cert = load_cert_any(path)
        except Exception:
            continue
        subjects.setdefault(cert_name_key(cert.subject), []).append(str(path))
    return subjects


def load_ca_subjects_from_file(ca_file: str) -> dict[str, list[str]]:
    subjects: dict[str, list[str]] = {}
    if not ca_file:
        return subjects
    path = Path(ca_file)
    if not path.exists() or not path.is_file():
        return subjects
    data = path.read_bytes()
    pems = split_pems(data)
    if pems:
        for idx, pem in enumerate(pems, start=1):
            try:
                cert = x509.load_pem_x509_certificate(pem)
            except Exception:
                continue
            subjects.setdefault(cert_name_key(cert.subject), []).append(f"{path}#{idx}")
        return subjects
    try:
        cert = x509.load_der_x509_certificate(data)
    except Exception:
        return subjects
    subjects.setdefault(cert_name_key(cert.subject), []).append(str(path))
    return subjects


def merge_subject_maps(*maps: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for item in maps:
        for subject, paths in item.items():
            merged.setdefault(subject, []).extend(paths)
    return merged


def collect_sm2_map_usage(root: Path, categories: list[str]) -> dict[str, dict]:
    usage: dict[str, dict] = {}
    for target in read_sm2_targets(root, categories):
        sm2_hash = target["expected_leaf_sha256"]
        item = usage.setdefault(sm2_hash, {"categories": set(), "domains": set(), "ips": set()})
        item["categories"].add(target["category"])
        item["domains"].add(target["domain"])
        if target.get("ip"):
            item["ips"].add(target["ip"])
    return usage


def write_sm2_ca_issuer_inventory(root: Path, out_dir: Path, categories: list[str], sm2_ca_dir: Path) -> None:
    usage = collect_sm2_map_usage(root, categories)
    ca_subjects = load_ca_subjects(sm2_ca_dir)
    rows = []
    issuer_counter: Counter[str] = Counter()
    missing_issuer_counter: Counter[str] = Counter()

    for category in categories:
        for path in sorted((root / category).glob("*.pem")):
            try:
                cert = load_cert_any(path)
            except Exception as exc:
                rows.append(
                    {
                        "category": category,
                        "sm2_hash": path.stem.lower(),
                        "parse_error": repr(exc),
                        "subject": "",
                        "subject_cn": "",
                        "issuer": "",
                        "issuer_cn": "",
                        "issuer_org": "",
                        "self_signed": "",
                        "aia_ca_issuers": "",
                        "domain_count": 0,
                        "ip_count": 0,
                        "example_domains": "",
                        "example_ips": "",
                        "issuer_subject_found_in_sm2_ca_dir": "",
                        "matching_sm2_ca_files": "",
                    }
                )
                continue

            sm2_hash = cert.fingerprint(hashes.SHA256()).hex()
            subject = name_text(cert.subject)
            issuer = name_text(cert.issuer)
            issuer_counter[issuer] += 1
            found_files = ca_subjects.get(cert_name_key(cert.issuer), [])
            if not found_files and cert.subject != cert.issuer:
                missing_issuer_counter[issuer] += 1
            aia = get_aia_ca_issuers(cert)
            item = usage.get(sm2_hash, {"domains": set(), "ips": set()})
            domains = sorted(item["domains"])
            ips = sorted(item["ips"])
            rows.append(
                {
                    "category": category,
                    "sm2_hash": sm2_hash,
                    "parse_error": "",
                    "subject": subject,
                    "subject_cn": first_name(cert.subject, NameOID.COMMON_NAME),
                    "issuer": issuer,
                    "issuer_cn": first_name(cert.issuer, NameOID.COMMON_NAME),
                    "issuer_org": first_name(cert.issuer, NameOID.ORGANIZATION_NAME),
                    "self_signed": cert.subject == cert.issuer,
                    "aia_ca_issuers": ";".join(aia),
                    "domain_count": len(domains),
                    "ip_count": len(ips),
                    "example_domains": ";".join(domains[:10]),
                    "example_ips": ";".join(ips[:10]),
                    "issuer_subject_found_in_sm2_ca_dir": bool(found_files),
                    "matching_sm2_ca_files": ";".join(found_files),
                }
            )

    write_csv(out_dir / "sm2_ca_issuer_inventory.csv", rows)
    issuer_rows = [
        {
            "issuer": issuer,
            "cert_count": count,
            "issuer_subject_found_in_sm2_ca_dir": bool(ca_subjects.get(issuer)),
            "matching_sm2_ca_files": ";".join(ca_subjects.get(issuer, [])),
        }
        for issuer, count in issuer_counter.most_common()
    ]
    write_csv(out_dir / "sm2_ca_issuer_summary.csv", issuer_rows)
    missing_rows = [
        {"issuer": issuer, "cert_count": count}
        for issuer, count in missing_issuer_counter.most_common()
    ]
    write_csv(out_dir / "sm2_ca_missing_issuer_candidates.csv", missing_rows)

    report = [
        "# SM2 CA / Issuer Inventory",
        "",
        f"SM2 certificates parsed from `{root}`. Existing CA files checked under `{sm2_ca_dir}` by subject name.",
        "",
        "## Top Issuers",
        "",
        md_table(
            ["issuer", "cert_count", "found in SM2_CA"],
            [[row["issuer"], row["cert_count"], row["issuer_subject_found_in_sm2_ca_dir"]] for row in issuer_rows[:30]],
        ),
        "",
        "## Missing Issuer-Subject Candidates",
        "",
        "These are leaf certificate issuers whose subject name was not found in the current SM2_CA directory. They may be intermediate CAs rather than roots, but adding the corresponding CA certificates can reduce false `missing_trust_anchor_or_intermediate` results.",
        "",
        md_table(["issuer", "cert_count"], [[row["issuer"], row["cert_count"]] for row in missing_rows[:50]]),
        "",
    ]
    (out_dir / "sm2_ca_issuer_report.md").write_text("\n".join(report), encoding="utf-8")


def split_pems(output: bytes) -> list[bytes]:
    return [match.group(0) + b"\n" for match in PEM_RE.finditer(output)]


def run_s_client(target: dict, args: argparse.Namespace) -> tuple[bool, bytes, str, float, list[str]]:
    if target["kind"] == "sm2":
        command = [
            args.tongsuo_bin,
            "s_client",
            "-connect",
            f"{target['connect_host']}:{args.port}",
            "-servername",
            target["sni"],
            "-showcerts",
            "-ntls",
            "-enable_ntls",
        ]
    else:
        command = [
            args.openssl_bin,
            "s_client",
            "-connect",
            f"{target['connect_host']}:{args.port}",
            "-servername",
            target["sni"],
            "-showcerts",
        ]

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        data = proc.stdout + b"\n" + proc.stderr
        ok = proc.returncode == 0 or b"-----BEGIN CERTIFICATE-----" in data
        return ok, data, proc.stderr.decode("utf-8", errors="replace"), elapsed_ms, command
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return False, b"", repr(exc), elapsed_ms, command


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def save_chain_files(out_dir: Path, target: dict, pems: list[bytes]) -> dict:
    leaf_sha = cert_sha256_pem(pems[0]) if pems else ""
    base_name = f"{safe_name(target['domain'])}__{safe_name(target.get('ip') or 'domain')}__{leaf_sha[:16]}"
    base_dir = out_dir / "chains" / target["kind"] / target["category"] / base_name
    leaf_dir = base_dir / "leaf"
    intermediates_dir = base_dir / "intermediates"
    fullchain_dir = base_dir / "fullchain"
    ntls_leafs_dir = base_dir / "ntls_leafs"
    leaf_dir.mkdir(parents=True, exist_ok=True)
    intermediates_dir.mkdir(parents=True, exist_ok=True)
    fullchain_dir.mkdir(parents=True, exist_ok=True)
    ntls_leafs_dir.mkdir(parents=True, exist_ok=True)

    leaf_path = leaf_dir / "leaf.pem"
    intermediates_path = intermediates_dir / "intermediates.pem"
    fullchain_path = fullchain_dir / "server_sent_chain.pem"
    manifest_path = base_dir / "manifest.json"
    ntls_leaf_paths = []
    ntls_signing_cert_path = ""
    ntls_encryption_cert_path = ""

    if pems:
        leaf_path.write_bytes(pems[0])
        intermediates_path.write_bytes(b"".join(pems[1:]))
        fullchain_path.write_bytes(b"".join(pems))
        try:
            certs = [x509.load_pem_x509_certificate(pem) for pem in pems]
            for pos, cert in enumerate(certs[:peer_leaf_count(certs)]):
                role = classify_ntls_leaf_role(cert)
                path = ntls_leafs_dir / f"peer_leaf_{pos}_{role}.pem"
                path.write_bytes(pems[pos])
                ntls_leaf_paths.append(str(path))
                if role in {"signing", "signing_and_encryption"} and not ntls_signing_cert_path:
                    ntls_signing_cert_path = str(path)
                if role in {"encryption", "signing_and_encryption"} and not ntls_encryption_cert_path:
                    ntls_encryption_cert_path = str(path)
        except Exception:
            pass
    else:
        leaf_path.write_bytes(b"")
        intermediates_path.write_bytes(b"")
        fullchain_path.write_bytes(b"")

    manifest = {
        **target,
        "leaf_sha256": leaf_sha,
        "server_sent_cert_count": len(pems),
        "leaf_path": str(leaf_path),
        "intermediates_path": str(intermediates_path),
        "fullchain_path": str(fullchain_path),
        "ntls_leaf_paths": ntls_leaf_paths,
        "ntls_signing_cert_path": ntls_signing_cert_path,
        "ntls_encryption_cert_path": ntls_encryption_cert_path,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def get_aia_ca_issuers(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except Exception:
        return []
    return [
        str(access.access_location.value)
        for access in aia
        if access.access_method == AuthorityInformationAccessOID.CA_ISSUERS
    ]


def cert_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
    except Exception:
        return cert.subject == cert.issuer


def key_usage_flags(cert: x509.Certificate) -> list[str]:
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except Exception:
        return []
    flags = []
    if ku.digital_signature:
        flags.append("digital_signature")
    if ku.content_commitment:
        flags.append("non_repudiation")
    if ku.key_encipherment:
        flags.append("key_encipherment")
    if ku.data_encipherment:
        flags.append("data_encipherment")
    try:
        if ku.key_agreement:
            flags.append("key_agreement")
    except Exception:
        pass
    if ku.key_cert_sign:
        flags.append("key_cert_sign")
    if ku.crl_sign:
        flags.append("crl_sign")
    return flags


def classify_ntls_leaf_role(cert: x509.Certificate) -> str:
    if cert_is_ca(cert):
        return "ca"
    flags = set(key_usage_flags(cert))
    signing = bool(flags & {"digital_signature", "non_repudiation"})
    encryption = bool(flags & {"key_encipherment", "data_encipherment", "key_agreement"})
    if signing and encryption:
        return "signing_and_encryption"
    if signing:
        return "signing"
    if encryption:
        return "encryption"
    return "unknown_leaf"


def issuer_subject_link_ok(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    return child.issuer == issuer.subject


def same_leaf_identity(left: x509.Certificate, right: x509.Certificate) -> bool:
    return left.subject == right.subject and left.issuer == right.issuer and not cert_is_ca(left) and not cert_is_ca(right)


def peer_leaf_count(certs: list[x509.Certificate]) -> int:
    if not certs or cert_is_ca(certs[0]) or certs[0].subject == certs[0].issuer:
        return 0
    first = certs[0]
    count = 0
    for cert in certs:
        if same_leaf_identity(first, cert):
            count += 1
            continue
        break
    return count


def issuer_subject_present(certs: list[x509.Certificate], issuer: x509.Name) -> bool:
    return any(cert.subject == issuer for cert in certs)


def chain_links_ok_from(certs: list[x509.Certificate], start: int) -> bool:
    if start >= len(certs) - 1:
        return True
    return all(issuer_subject_link_ok(certs[i], certs[i + 1]) for i in range(start, len(certs) - 1))


def chain_observation(pems: list[bytes], trust_subjects: dict[str, list[str]] | None = None) -> dict:
    trust_subjects = trust_subjects or {}
    if not pems:
        return {
            "server_sent_cert_count": 0,
            "has_leaf": False,
            "has_intermediate": False,
            "leaf_self_signed": False,
            "leaf_issuer_found_in_ca_set": False,
            "terminal_subject_found_in_ca_set": False,
            "terminal_subject": "",
            "terminal_issuer": "",
            "terminal_issuer_found_in_ca_set": False,
            "ntls_peer_leaf_count": 0,
            "ntls_dual_leaf_pair": False,
            "ntls_leaf_roles": "",
            "ntls_signing_cert_sha256": "",
            "ntls_signing_cert_position": "",
            "ntls_encryption_cert_sha256": "",
            "ntls_encryption_cert_position": "",
            "server_missing_intermediate_candidate": False,
            "local_ca_not_covered_candidate": False,
            "ambiguous_server_or_local_ca_gap": False,
            "chain_gap_basis": "",
            "issuer_subject_chain_ok": False,
            "potential_broken_chain": True,
            "candidate_incomplete_chain": False,
            "local_trust_gap_or_missing_intermediate": False,
            "server_chain_status": "no_certificate_returned",
            "reason": "no_certificate_returned",
            "aia_ca_issuers": "",
        }

    certs = [x509.load_pem_x509_certificate(pem) for pem in pems]
    leaf = certs[0]
    leaf_self_signed = leaf.subject == leaf.issuer
    leaf_issuer_key = cert_name_key(leaf.issuer)
    leaf_issuer_found = leaf_issuer_key in trust_subjects
    leaf_aia_issuers = get_aia_ca_issuers(leaf)
    terminal = certs[-1]
    terminal_subject = name_text(terminal.subject)
    terminal_issuer = name_text(terminal.issuer)
    terminal_self_signed = terminal.subject == terminal.issuer
    terminal_subject_found = cert_name_key(terminal.subject) in trust_subjects
    terminal_issuer_found = cert_name_key(terminal.issuer) in trust_subjects
    terminal_aia_issuers = get_aia_ca_issuers(terminal)
    aia_issuers = leaf_aia_issuers
    pcount = peer_leaf_count(certs)
    peer_certs = certs[:pcount]
    role_items = []
    signing_cert_sha = ""
    signing_cert_position = ""
    encryption_cert_sha = ""
    encryption_cert_position = ""
    for pos, cert in enumerate(peer_certs):
        role = classify_ntls_leaf_role(cert)
        sha = cert_sha256(cert)
        role_items.append(f"{pos}:{role}:{sha[:16]}")
        if role in {"signing", "signing_and_encryption"} and not signing_cert_sha:
            signing_cert_sha = sha
            signing_cert_position = str(pos)
        if role in {"encryption", "signing_and_encryption"} and not encryption_cert_sha:
            encryption_cert_sha = sha
            encryption_cert_position = str(pos)

    server_missing_intermediate = False
    local_ca_not_covered = False
    ambiguous_gap = False
    chain_gap_basis = ""

    if leaf_self_signed:
        reason = "leaf_self_signed"
        server_chain_status = "leaf_self_signed"
        potential_broken = False
        link_ok = True
        candidate_incomplete = False
        local_trust_gap = False
        if not terminal_subject_found:
            local_ca_not_covered = True
            chain_gap_basis = "self_signed_leaf_not_in_ca_set"
    elif len(certs) == 1:
        if leaf_issuer_found:
            reason = "leaf_only_issuer_in_ca_set"
            server_chain_status = "leaf_only_issuer_in_ca_set"
            potential_broken = False
            candidate_incomplete = False
            local_trust_gap = False
        else:
            reason = "leaf_only_unknown_issuer"
            server_chain_status = "leaf_only_unknown_issuer"
            potential_broken = False
            candidate_incomplete = True
            local_trust_gap = True
            if leaf_aia_issuers:
                server_missing_intermediate = True
                chain_gap_basis = "leaf_only_with_aia_ca_issuers"
            else:
                ambiguous_gap = True
                local_ca_not_covered = True
                chain_gap_basis = "leaf_only_without_aia_ca_issuers"
        link_ok = False
    else:
        issuer_after_peers = pcount < len(certs) and pcount > 0 and certs[pcount].subject == leaf.issuer
        peer_to_issuer_ok = issuer_after_peers and all(cert.issuer == certs[pcount].subject for cert in peer_certs)
        tail_ok = chain_links_ok_from(certs, pcount)
        link_ok = bool(peer_to_issuer_ok and tail_ok)
        if link_ok:
            if pcount >= 2:
                reason = "ntls_dual_leaf_then_issuer"
                server_chain_status = "ntls_dual_leaf_then_issuer"
            elif terminal_self_signed:
                reason = "issuer_subject_links_ok_terminal_self_signed"
                server_chain_status = "issuer_subject_links_ok_terminal_self_signed"
            elif terminal_issuer_found:
                reason = "issuer_subject_links_ok_terminal_issuer_in_ca_set"
                server_chain_status = "issuer_subject_links_ok_terminal_issuer_in_ca_set"
            else:
                reason = "issuer_subject_links_ok_terminal_issuer_unknown"
                server_chain_status = "issuer_subject_links_ok_terminal_issuer_unknown"
            potential_broken = False
            if terminal_self_signed:
                candidate_incomplete = False
                local_trust_gap = False
                if not terminal_subject_found:
                    local_ca_not_covered = True
                    chain_gap_basis = "terminal_self_signed_not_in_ca_set"
            elif terminal_issuer_found:
                candidate_incomplete = False
                local_trust_gap = False
            else:
                candidate_incomplete = True
                local_trust_gap = True
                local_ca_not_covered = True
                chain_gap_basis = "linked_chain_terminal_issuer_not_in_ca_set"
        elif pcount >= 1 and not issuer_after_peers and not issuer_subject_present(certs[pcount:], leaf.issuer):
            if leaf_issuer_found:
                reason = "leaf_or_ntls_peer_issuer_in_ca_set"
                server_chain_status = "leaf_or_ntls_peer_issuer_in_ca_set"
                potential_broken = False
                candidate_incomplete = False
                local_trust_gap = False
                link_ok = True
            else:
                reason = "ntls_peer_issuer_not_sent" if pcount >= 2 else "leaf_only_unknown_issuer"
                server_chain_status = reason
                potential_broken = False
                candidate_incomplete = True
                local_trust_gap = True
                if leaf_aia_issuers:
                    server_missing_intermediate = True
                    chain_gap_basis = "peer_leaf_issuer_not_sent_with_aia_ca_issuers"
                else:
                    ambiguous_gap = True
                    local_ca_not_covered = True
                    chain_gap_basis = "peer_leaf_issuer_not_sent_without_aia_ca_issuers"
        else:
            reason = "issuer_subject_link_mismatch"
            server_chain_status = "issuer_subject_link_mismatch"
            potential_broken = True
            candidate_incomplete = False
            local_trust_gap = False
            chain_gap_basis = "server_sent_adjacent_issuer_subject_mismatch"

    return {
        "server_sent_cert_count": len(certs),
        "has_leaf": True,
        "has_intermediate": len(certs) > 1,
        "leaf_self_signed": leaf_self_signed,
        "leaf_issuer_found_in_ca_set": leaf_issuer_found,
        "terminal_subject_found_in_ca_set": terminal_subject_found,
        "terminal_subject": terminal_subject,
        "terminal_issuer": terminal_issuer,
        "terminal_issuer_found_in_ca_set": terminal_issuer_found,
        "ntls_peer_leaf_count": pcount,
        "ntls_dual_leaf_pair": pcount >= 2,
        "ntls_leaf_roles": ";".join(role_items),
        "ntls_signing_cert_sha256": signing_cert_sha,
        "ntls_signing_cert_position": signing_cert_position,
        "ntls_encryption_cert_sha256": encryption_cert_sha,
        "ntls_encryption_cert_position": encryption_cert_position,
        "server_missing_intermediate_candidate": server_missing_intermediate,
        "local_ca_not_covered_candidate": local_ca_not_covered,
        "ambiguous_server_or_local_ca_gap": ambiguous_gap,
        "chain_gap_basis": chain_gap_basis,
        "issuer_subject_chain_ok": link_ok,
        "potential_broken_chain": potential_broken,
        "candidate_incomplete_chain": candidate_incomplete,
        "local_trust_gap_or_missing_intermediate": local_trust_gap,
        "server_chain_status": server_chain_status,
        "reason": reason,
        "aia_ca_issuers": ";".join(aia_issuers),
        "terminal_aia_ca_issuers": ";".join(terminal_aia_issuers),
    }


def classify_verify_error(verify_ok, verify_error: str) -> str:
    if verify_ok == "":
        return ""
    if verify_ok is True:
        return "ok"
    lower = verify_error.lower()
    if "unable to get local issuer certificate" in lower or "unable to get issuer certificate" in lower or "self-signed certificate" in lower:
        return "missing_trust_anchor_or_intermediate"
    if "certificate has expired" in lower:
        return "expired"
    if "certificate is not yet valid" in lower:
        return "not_yet_valid"
    if "certificate signature failure" in lower or "unable to verify the first certificate" in lower:
        return "chain_verification_failed"
    return "other_verify_error"


def interpret_verify_result(kind: str, verify_result: dict, observation: dict) -> str:
    if not verify_result.get("verify_ran"):
        return ""
    if verify_result.get("verify_ok") is True:
        return "ok"
    error_class = verify_result.get("verify_error_class", "")
    if error_class == "missing_trust_anchor_or_intermediate":
        if kind == "sm2":
            if observation.get("server_missing_intermediate_candidate"):
                return "server_missing_intermediate_candidate"
            if observation.get("local_ca_not_covered_candidate"):
                return "local_sm2_ca_not_covered_candidate"
            if observation.get("ambiguous_server_or_local_ca_gap"):
                return "ambiguous_server_missing_or_local_sm2_ca_gap"
            return "sm2_ca_gap_or_server_missing_intermediate"
        if observation.get("local_trust_gap_or_missing_intermediate"):
            if observation.get("server_missing_intermediate_candidate"):
                return "server_missing_intermediate_candidate"
            if observation.get("local_ca_not_covered_candidate"):
                return "local_ca_not_covered_candidate"
            return "local_ca_gap_or_server_missing_intermediate"
    return error_class


def openssl_verify_leaf(manifest: dict, args: argparse.Namespace, ca_file: str, ca_label: str) -> dict:
    if not args.verify:
        return {"verify_ran": False, "verify_ok": "", "verify_error": "", "verify_error_class": "", "verify_ca_file": "", "verify_ca_label": ""}

    leaf = manifest["leaf_path"]
    intermediates = manifest["intermediates_path"]
    verify_bin = args.tongsuo_bin if ca_label == "sm2" else args.openssl_bin
    command = [verify_bin, "verify"]
    if ca_file:
        command += ["-CAfile", ca_file]
    if args.ca_path:
        command += ["-CApath", args.ca_path]
    if Path(intermediates).exists() and Path(intermediates).stat().st_size > 0:
        command += ["-untrusted", intermediates]
    command.append(leaf)

    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=args.timeout)
        output = (proc.stdout + "\n" + proc.stderr).strip()
        verify_ok = proc.returncode == 0
        return {
            "verify_ran": True,
            "verify_ok": verify_ok,
            "verify_error": output,
            "verify_error_class": classify_verify_error(verify_ok, output),
            "verify_ca_file": ca_file,
            "verify_ca_label": ca_label,
        }
    except Exception as exc:
        output = repr(exc)
        return {
            "verify_ran": True,
            "verify_ok": False,
            "verify_error": output,
            "verify_error_class": classify_verify_error(False, output),
            "verify_ca_file": ca_file,
            "verify_ca_label": ca_label,
        }


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def md_table(headers: list[str], rows: Iterable[Iterable[object]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(x) for x in row) + " |")
    return "\n".join(lines)


def collect_one_target(
    idx: int,
    total: int,
    target: dict,
    args: argparse.Namespace,
    out_dir: Path,
    ordinary_ca_file: str,
    sm2_ca_file: str,
    ordinary_trust_subjects: dict[str, list[str]],
    sm2_trust_subjects: dict[str, list[str]],
) -> dict:
    print(f"[{idx}/{total}] {target['kind']} {target['category']} {target['domain']} {target.get('ip') or ''}", flush=True)
    ok, output, error, elapsed_ms, command = run_s_client(target, args)
    pems = split_pems(output)
    manifest = save_chain_files(out_dir, target, pems)
    trust_subjects = sm2_trust_subjects if target["kind"] == "sm2" else ordinary_trust_subjects
    observation = chain_observation(pems, trust_subjects)
    if target["kind"] == "sm2":
        ca_file = sm2_ca_file
        ca_label = "sm2"
    else:
        ca_file = ordinary_ca_file
        ca_label = "ordinary"
    verify_result = (
        openssl_verify_leaf(manifest, args, ca_file=ca_file, ca_label=ca_label)
        if pems
        else {
            "verify_ran": bool(args.verify),
            "verify_ok": False if args.verify else "",
            "verify_error": "no certificate returned" if args.verify else "",
            "verify_error_class": "no_certificate_returned" if args.verify else "",
            "verify_ca_file": ca_file if args.verify else "",
            "verify_ca_label": ca_label if args.verify else "",
        }
    )
    leaf_matches_expected = (
        bool(manifest.get("leaf_sha256"))
        and bool(target.get("expected_leaf_sha256"))
        and manifest["leaf_sha256"].lower() == target["expected_leaf_sha256"].lower()
    )
    expected = target.get("expected_leaf_sha256", "").lower()
    chain_fingerprints = []
    if expected:
        for pem in pems:
            try:
                chain_fingerprints.append(cert_sha256(x509.load_pem_x509_certificate(pem)))
            except Exception:
                chain_fingerprints.append("")
    expected_positions = [str(pos) for pos, fp in enumerate(chain_fingerprints) if fp.lower() == expected]
    expected_leaf_found_in_chain = bool(expected_positions)
    return {
        **target,
        "connect_ok": ok,
        "elapsed_ms": f"{elapsed_ms:.2f}",
        "command": " ".join(command),
        "leaf_sha256": manifest.get("leaf_sha256", ""),
        "leaf_matches_expected": leaf_matches_expected,
        "expected_leaf_found_in_chain": expected_leaf_found_in_chain,
        "expected_leaf_chain_positions": ";".join(expected_positions),
        **observation,
        **verify_result,
        "verify_interpretation": interpret_verify_result(target["kind"], verify_result, observation),
        "expected_matches_ntls_signing_cert": bool(expected and observation.get("ntls_signing_cert_sha256", "").lower() == expected),
        "expected_matches_ntls_encryption_cert": bool(expected and observation.get("ntls_encryption_cert_sha256", "").lower() == expected),
        "leaf_path": manifest.get("leaf_path", ""),
        "intermediates_path": manifest.get("intermediates_path", ""),
        "fullchain_path": manifest.get("fullchain_path", ""),
        "ntls_leaf_paths": ";".join(manifest.get("ntls_leaf_paths", [])),
        "ntls_signing_cert_path": manifest.get("ntls_signing_cert_path", ""),
        "ntls_encryption_cert_path": manifest.get("ntls_encryption_cert_path", ""),
        "error": error.strip().splitlines()[-1] if error.strip() else "",
    }


def summarize(rows: list[dict], out_dir: Path) -> None:
    summary_rows = []
    for kind in ("sm2", "ordinary"):
        for category in (*CATEGORIES, "total"):
            subset = [r for r in rows if r["kind"] == kind and (category == "total" or r["category"] == category)]
            if not subset:
                continue
            summary_rows.append(
                {
                    "kind": kind,
                    "category": category,
                    "targets": len(subset),
                    "connect_ok": sum(str(r["connect_ok"]).lower() == "true" for r in subset),
                    "leaf_matches_expected": sum(str(r["leaf_matches_expected"]).lower() == "true" for r in subset),
                    "expected_leaf_found_in_chain": sum(str(r.get("expected_leaf_found_in_chain", "")).lower() == "true" for r in subset),
                    "leaf_mismatch_or_missing": sum(str(r["leaf_matches_expected"]).lower() != "true" for r in subset),
                    "ntls_dual_leaf_pair": sum(str(r.get("ntls_dual_leaf_pair", "")).lower() == "true" for r in subset),
                    "leaf_only_unknown_issuer": sum(r["reason"] == "leaf_only_unknown_issuer" for r in subset),
                    "leaf_only_issuer_in_ca_set": sum(r["reason"] == "leaf_only_issuer_in_ca_set" for r in subset),
                    "has_intermediate": sum(str(r["has_intermediate"]).lower() == "true" for r in subset),
                    "issuer_subject_link_mismatch": sum(r["reason"] == "issuer_subject_link_mismatch" for r in subset),
                    "potential_broken_chain": sum(str(r["potential_broken_chain"]).lower() == "true" for r in subset),
                    "candidate_incomplete_chain": sum(str(r["candidate_incomplete_chain"]).lower() == "true" for r in subset),
                    "local_trust_gap_or_missing_intermediate": sum(str(r["local_trust_gap_or_missing_intermediate"]).lower() == "true" for r in subset),
                    "server_missing_intermediate_candidate": sum(str(r.get("server_missing_intermediate_candidate", "")).lower() == "true" for r in subset),
                    "local_ca_not_covered_candidate": sum(str(r.get("local_ca_not_covered_candidate", "")).lower() == "true" for r in subset),
                    "ambiguous_server_or_local_ca_gap": sum(str(r.get("ambiguous_server_or_local_ca_gap", "")).lower() == "true" for r in subset),
                    "self_signed_leaf": sum(str(r["leaf_self_signed"]).lower() == "true" for r in subset),
                    "aia_ca_issuers": sum(bool(r["aia_ca_issuers"]) for r in subset),
                    "verify_ok": sum(str(r.get("verify_ok", "")).lower() == "true" for r in subset),
                    "missing_trust_anchor_or_intermediate": sum(r.get("verify_error_class") == "missing_trust_anchor_or_intermediate" for r in subset),
                    "sm2_ca_gap_or_server_missing_intermediate": sum(r.get("verify_interpretation") == "sm2_ca_gap_or_server_missing_intermediate" for r in subset),
                    "verify_server_missing_intermediate_candidate": sum(r.get("verify_interpretation") == "server_missing_intermediate_candidate" for r in subset),
                    "verify_local_sm2_ca_not_covered_candidate": sum(r.get("verify_interpretation") == "local_sm2_ca_not_covered_candidate" for r in subset),
                    "verify_ambiguous_server_or_local_ca_gap": sum(r.get("verify_interpretation") == "ambiguous_server_missing_or_local_sm2_ca_gap" for r in subset),
                }
            )

    write_csv(out_dir / "chain_summary.csv", summary_rows)
    report_rows = [
        [
            r["kind"],
            r["category"],
            r["targets"],
            r["connect_ok"],
            r["leaf_matches_expected"],
            r["expected_leaf_found_in_chain"],
            r["leaf_mismatch_or_missing"],
            r["ntls_dual_leaf_pair"],
            r["has_intermediate"],
            r["leaf_only_unknown_issuer"],
            r["leaf_only_issuer_in_ca_set"],
            r["issuer_subject_link_mismatch"],
            r["potential_broken_chain"],
            r["candidate_incomplete_chain"],
            r["local_trust_gap_or_missing_intermediate"],
            r["server_missing_intermediate_candidate"],
            r["local_ca_not_covered_candidate"],
            r["ambiguous_server_or_local_ca_gap"],
            r["self_signed_leaf"],
            r["aia_ca_issuers"],
            r["verify_ok"],
            r["missing_trust_anchor_or_intermediate"],
            r["sm2_ca_gap_or_server_missing_intermediate"],
            r["verify_server_missing_intermediate_candidate"],
            r["verify_local_sm2_ca_not_covered_candidate"],
            r["verify_ambiguous_server_or_local_ca_gap"],
        ]
        for r in summary_rows
    ]
    report = [
        "# Certificate Chain Collection and Broken-Chain Analysis",
        "",
        "This report is based on certificates sent by servers during fresh handshakes. Leaf certificates and intermediates are saved in separate directories.",
        "",
        md_table(
            [
                "kind",
                "category",
                "targets",
                "connect ok",
                "leaf matches expected",
                "expected leaf found in chain",
                "leaf mismatch/missing",
                "NTLS dual leaf pair",
                "has intermediate",
                "leaf-only unknown issuer",
                "leaf-only issuer in CA set",
                "issuer link mismatch",
                "potential broken",
                "candidate incomplete",
                "local CA gap or missing intermediate",
                "server missing intermediate candidate",
                "local CA not covered candidate",
                "ambiguous server/local CA gap",
                "self-signed leaf",
                "AIA caIssuers",
                "verify ok",
                "missing trust/intermediate",
                "SM2 CA gap or server missing intermediate",
                "verify server missing intermediate candidate",
                "verify local SM2 CA not covered candidate",
                "verify ambiguous server/local CA gap",
            ],
            report_rows,
        ),
        "",
        "Definition used here: `potential broken` is limited to no certificate returned or adjacent issuer/subject link mismatch after NTLS peer leaf certificates have been grouped. `server missing intermediate candidate` means the server did not send the issuer certificate for the leaf/NTLS peer leaf group and the leaf exposes AIA caIssuers. `local CA not covered candidate` means the server-sent chain is structurally usable but ends at a CA not covered by the configured CA set, or there is no AIA evidence to separate a private/local CA gap from a missing intermediate. Ambiguous rows should be checked against SM2_CA completeness and manual CA availability.",
        "",
    ]
    (out_dir / "chain_report.md").write_text("\n".join(report), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect server-sent certificate chains for SM2/NTLS and ordinary TLS, with separate leaf/intermediate storage.")
    parser.add_argument("--cert-root", default=".", help="Directory containing bank/edu/gov maps and normal_cert_collection")
    parser.add_argument("--out-dir", default="", help="Output directory. Default: analysis_outputs<dataset suffix>/certificate_chains for data-like cert roots.")
    parser.add_argument("--categories", default="bank,edu,gov")
    parser.add_argument("--mode", choices=["all", "sm2", "ordinary"], default="all")
    parser.add_argument("--limit-per-kind-category", type=int, default=0, help="0 means no limit")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=12)
    parser.add_argument("--openssl-bin", default="openssl")
    parser.add_argument("--tongsuo-bin", default="tongsuo-openssl")
    parser.add_argument("--verify", action="store_true", help="Run openssl verify for each collected chain")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent handshake/verify workers. Use 1 for deterministic single-threaded collection.")
    parser.add_argument("--ca-file", default="", help="Fallback CA bundle for openssl verify")
    parser.add_argument("--ordinary-ca-file", default="", help="CA bundle for ordinary TLS verification")
    parser.add_argument("--sm2-ca-file", default="", help="CA bundle for SM2 verification")
    parser.add_argument("--sm2-ca-dir", default="SM2_CA", help="Directory containing downloaded SM2 root/intermediate certificates")
    parser.add_argument("--built-sm2-ca-file", default="", help="Where to write merged SM2 CA bundle when --sm2-ca-dir is used")
    parser.add_argument("--ca-path", default="", help="CA directory for openssl verify")
    parser.add_argument("--ca-inventory-only", action="store_true", help="Only write SM2 issuer/CA inventory files; do not collect chains.")
    args = parser.parse_args()

    root = Path(args.cert_root)
    out_dir = Path(args.out_dir) if args.out_dir else default_out_dir(root)
    out_dir.mkdir(parents=True, exist_ok=True)
    categories = [c.strip() for c in args.categories.split(",") if c.strip()]

    write_sm2_ca_issuer_inventory(root, out_dir, categories, Path(args.sm2_ca_dir))
    if args.ca_inventory_only:
        print(out_dir / "sm2_ca_issuer_inventory.csv")
        print(out_dir / "sm2_ca_issuer_summary.csv")
        print(out_dir / "sm2_ca_missing_issuer_candidates.csv")
        print(out_dir / "sm2_ca_issuer_report.md")
        return

    ordinary_ca_file = args.ordinary_ca_file or args.ca_file
    sm2_ca_file = args.sm2_ca_file or args.ca_file
    sm2_bundle_info = {"path": sm2_ca_file, "cert_count": 0, "errors": []}
    if args.verify and not args.sm2_ca_file and args.sm2_ca_dir:
        built_sm2_ca_file = Path(args.built_sm2_ca_file) if args.built_sm2_ca_file else out_dir / "sm2_ca_bundle.pem"
        built_path, cert_count, errors = build_ca_bundle_from_dir(Path(args.sm2_ca_dir), built_sm2_ca_file)
        if built_path:
            sm2_ca_file = built_path
        sm2_bundle_info = {"path": sm2_ca_file, "cert_count": cert_count, "errors": errors}

    sm2_trust_subjects = merge_subject_maps(load_ca_subjects(Path(args.sm2_ca_dir)), load_ca_subjects_from_file(sm2_ca_file))
    ordinary_trust_subjects = load_ca_subjects_from_file(ordinary_ca_file)

    targets = []
    if args.mode in ("all", "sm2"):
        targets.extend(read_sm2_targets(root, categories))
    if args.mode in ("all", "ordinary"):
        targets.extend(read_ordinary_targets(root, categories))

    if args.limit_per_kind_category:
        kept = []
        counts = Counter()
        for target in targets:
            key = (target["kind"], target["category"])
            if counts[key] < args.limit_per_kind_category:
                kept.append(target)
                counts[key] += 1
        targets = kept

    indexed_targets = list(enumerate(targets, start=1))
    rows = []
    if args.workers <= 1:
        for idx, target in indexed_targets:
            rows.append(
                collect_one_target(
                    idx,
                    len(targets),
                    target,
                    args,
                    out_dir,
                    ordinary_ca_file,
                    sm2_ca_file,
                    ordinary_trust_subjects,
                    sm2_trust_subjects,
                )
            )
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    collect_one_target,
                    idx,
                    len(targets),
                    target,
                    args,
                    out_dir,
                    ordinary_ca_file,
                    sm2_ca_file,
                    ordinary_trust_subjects,
                    sm2_trust_subjects,
                ): idx
                for idx, target in indexed_targets
            }
            completed_rows = []
            for future in as_completed(futures):
                completed_rows.append((futures[future], future.result()))
            rows = [row for _, row in sorted(completed_rows, key=lambda item: item[0])]

    write_csv(out_dir / "chain_details.csv", rows)
    (out_dir / "ca_bundle_info.json").write_text(
        json.dumps(
            {
                "ordinary_ca_file": ordinary_ca_file,
                "sm2_ca_file": sm2_ca_file,
                "sm2_ca_dir": args.sm2_ca_dir,
                "ordinary_trust_subject_count": len(ordinary_trust_subjects),
                "sm2_trust_subject_count": len(sm2_trust_subjects),
                "built_sm2_ca_bundle": sm2_bundle_info,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    summarize(rows, out_dir)
    print(out_dir / "chain_details.csv")
    print(out_dir / "chain_summary.csv")
    print(out_dir / "chain_report.md")


if __name__ == "__main__":
    main()
