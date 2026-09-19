#!/usr/bin/env python3
"""
Collect ordinary TLS certificates for domains that already have SM2 cert hashes.

Input files are expected to look like:

    example.gov.cn 0123abcd...

For each ``*_domain_map.txt`` file this script:
  1. Resolves each domain to IP addresses.
  2. Writes ``*_domain_ip_map.txt`` with a third column containing IPs.
  3. Groups records by IP.
  4. Connects to each IP:443 with one of the grouped domains as SNI and saves
     the ordinary TLS leaf certificate, deduplicated by certificate SHA-256.
  5. Writes ordinary-certificate domain/IP maps under
     ``normal_domain_ip_maps/*_domain_ip_map.txt``.

The original map files are never modified unless you explicitly copy the output
files over them after checking the results.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import ipaddress
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
except Exception:  # cryptography is optional; collection still works.
    x509 = None
    rsa = ec = dsa = ed25519 = ed448 = None


DEFAULT_CATEGORIES = ("bank", "edu", "gov")


@dataclass(frozen=True)
class MapEntry:
    category: str
    line_no: int
    domain: str
    sm2_hash: str


@dataclass(frozen=True)
class ResolvedEntry:
    entry: MapEntry
    ips: tuple[str, ...]
    error: str = ""


@dataclass(frozen=True)
class CertResult:
    category: str
    ip: str
    port: int
    ok: bool
    sni_domain: str = ""
    cert_sha256: str = ""
    pem_path: str = ""
    source_domains: tuple[str, ...] = ()
    source_sm2_hashes: tuple[str, ...] = ()
    tried_domains: tuple[str, ...] = ()
    error: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    signature_algorithm: str = ""
    public_key_type: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve domains, append IPs to map files, and collect ordinary TLS certificates by IP."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("."),
        help="Directory containing bank_domain_map.txt, edu_domain_map.txt, gov_domain_map.txt.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("normal_cert_collection"),
        help="Directory for maps, PEM files, indexes, and failure logs.",
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=list(DEFAULT_CATEGORIES),
        help="Category prefixes to process. Default: bank edu gov.",
    )
    parser.add_argument("--port", type=int, default=443, help="TLS port. Default: 443.")
    parser.add_argument("--workers", type=int, default=64, help="Concurrent workers. Default: 64.")
    parser.add_argument("--timeout", type=float, default=8.0, help="DNS/TLS timeout in seconds. Default: 8.")
    parser.add_argument("--retries", type=int, default=1, help="TLS retry count per SNI candidate. Default: 1.")
    parser.add_argument(
        "--max-sni-candidates",
        type=int,
        default=6,
        help="How many domains to try for one IP before marking the IP failed. Default: 6.",
    )
    parser.add_argument(
        "--ipv4-only",
        action="store_true",
        help="Only keep IPv4 addresses from DNS results.",
    )
    parser.add_argument(
        "--skip-private-ip",
        action="store_true",
        help="Also drop private IPs from DNS results. Loopback, link-local, multicast, reserved, and unspecified IPs are always skipped.",
    )
    parser.add_argument(
        "--resolve-only",
        action="store_true",
        help="Only write *_domain_ip_map.txt; do not collect certificates.",
    )
    parser.add_argument(
        "--use-input-domain-ip-maps",
        action="store_true",
        help="Read existing *_domain_ip_map.txt files from --input-dir and collect by those explicit domain/IP pairs; skip DNS resolution.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite PEM files when the same ordinary certificate hash is seen again.",
    )
    parser.add_argument(
        "--build-normal-domain-maps-only",
        action="store_true",
        help="Build normal_domain_ip_maps from existing output files; do not resolve domains or collect certificates.",
    )
    parser.add_argument(
        "--retry-failures-only",
        action="store_true",
        help="Retry failed domains from existing normal_cert_failures.csv and merge results into existing output files.",
    )
    parser.add_argument(
        "--no-retry-refresh-dns",
        action="store_true",
        help="Do not refresh DNS for failed domains before retrying failures.",
    )
    return parser.parse_args()


def load_map(path: Path, category: str) -> list[MapEntry]:
    entries: list[MapEntry] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                print(f"[WARN] skip malformed line {path}:{line_no}: {line}", file=sys.stderr)
                continue
            entries.append(MapEntry(category=category, line_no=line_no, domain=parts[0].strip(), sm2_hash=parts[1].strip()))
    return entries


def usable_ip(ip_text: str, ipv4_only: bool, skip_private_ip: bool) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if ipv4_only and ip.version != 4:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    if skip_private_ip and ip.is_private:
        return False
    return True


def sort_ips(ips: Iterable[str]) -> tuple[str, ...]:
    def key(ip_text: str) -> tuple[int, int | bytes]:
        ip = ipaddress.ip_address(ip_text)
        if ip.version == 4:
            return (0, int(ip))
        return (1, ip.packed)

    return tuple(sorted(set(ips), key=key))


def resolve_domain(entry: MapEntry, port: int, timeout: float, ipv4_only: bool, skip_private_ip: bool) -> ResolvedEntry:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(entry.domain, port, type=socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip_text = info[4][0]
            if usable_ip(ip_text, ipv4_only=ipv4_only, skip_private_ip=skip_private_ip):
                ips.append(ip_text)
        return ResolvedEntry(entry=entry, ips=sort_ips(ips))
    except Exception as exc:
        return ResolvedEntry(entry=entry, ips=(), error=repr(exc))
    finally:
        socket.setdefaulttimeout(old_timeout)


def pem_from_der(der: bytes) -> str:
    return ssl.DER_cert_to_PEM_cert(der)


def make_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass
    return context


def fetch_leaf_cert(ip: str, port: int, sni_domain: str, timeout: float) -> bytes:
    context = make_ssl_context()
    with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)
        with context.wrap_socket(raw_sock, server_hostname=sni_domain) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("server returned no peer certificate")
            return der


def _name_to_text(name: object) -> str:
    try:
        return str(name.rfc4514_string())
    except Exception:
        return ""


def parse_cert_metadata(der: bytes) -> dict[str, str]:
    if x509 is None:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der)
        public_key = cert.public_key()
        public_key_type = type(public_key).__name__
        if rsa is not None and isinstance(public_key, rsa.RSAPublicKey):
            public_key_type = f"RSA-{public_key.key_size}"
        elif ec is not None and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key_type = f"EC-{public_key.curve.name}"
        elif dsa is not None and isinstance(public_key, dsa.DSAPublicKey):
            public_key_type = f"DSA-{public_key.key_size}"
        elif ed25519 is not None and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key_type = "Ed25519"
        elif ed448 is not None and isinstance(public_key, ed448.Ed448PublicKey):
            public_key_type = "Ed448"

        not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
        not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
        signature_algorithm = getattr(cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string)
        return {
            "subject": _name_to_text(cert.subject),
            "issuer": _name_to_text(cert.issuer),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "signature_algorithm": signature_algorithm,
            "public_key_type": public_key_type,
        }
    except Exception as exc:
        return {"subject": "", "issuer": "", "signature_algorithm": f"parse_error:{exc!r}", "public_key_type": ""}


def collect_for_ip(
    category: str,
    ip: str,
    entries: list[MapEntry],
    port: int,
    timeout: float,
    retries: int,
    max_sni_candidates: int,
    output_dir: Path,
    force: bool,
) -> CertResult:
    domains = tuple(dict.fromkeys(entry.domain for entry in entries))
    sm2_hashes = tuple(sorted(set(entry.sm2_hash for entry in entries)))
    tried = domains[:max_sni_candidates]
    last_error = ""

    for domain in tried:
        for attempt in range(retries + 1):
            try:
                der = fetch_leaf_cert(ip=ip, port=port, sni_domain=domain, timeout=timeout)
                cert_sha256 = hashlib.sha256(der).hexdigest()
                category_dir = output_dir / "normal_certs" / category
                category_dir.mkdir(parents=True, exist_ok=True)
                pem_path = category_dir / f"{cert_sha256}.pem"
                if force or not pem_path.exists():
                    pem_path.write_text(pem_from_der(der), encoding="ascii")
                metadata = parse_cert_metadata(der)
                return CertResult(
                    category=category,
                    ip=ip,
                    port=port,
                    ok=True,
                    sni_domain=domain,
                    cert_sha256=cert_sha256,
                    pem_path=str(pem_path),
                    source_domains=domains,
                    source_sm2_hashes=sm2_hashes,
                    tried_domains=tried,
                    subject=metadata.get("subject", ""),
                    issuer=metadata.get("issuer", ""),
                    not_before=metadata.get("not_before", ""),
                    not_after=metadata.get("not_after", ""),
                    signature_algorithm=metadata.get("signature_algorithm", ""),
                    public_key_type=metadata.get("public_key_type", ""),
                )
            except Exception as exc:
                last_error = f"{domain} attempt {attempt + 1}/{retries + 1}: {exc!r}"
                if attempt < retries:
                    time.sleep(0.2 * (attempt + 1))

    return CertResult(
        category=category,
        ip=ip,
        port=port,
        ok=False,
        source_domains=domains,
        source_sm2_hashes=sm2_hashes,
        tried_domains=tried,
        error=last_error or "no SNI candidate tried",
    )


def write_domain_ip_maps(output_dir: Path, grouped_results: dict[str, list[ResolvedEntry]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for category, results in grouped_results.items():
        out_path = output_dir / f"{category}_domain_ip_map.txt"
        with out_path.open("w", encoding="utf-8", newline="") as f:
            for result in sorted(results, key=lambda item: item.entry.line_no):
                ips = ",".join(result.ips) if result.ips else "-"
                f.write(f"{result.entry.domain} {result.entry.sm2_hash} {ips}\n")


def write_resolution_failures(output_dir: Path, grouped_results: dict[str, list[ResolvedEntry]]) -> None:
    path = output_dir / "resolution_failures.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "line_no", "domain", "sm2_hash", "error"])
        writer.writeheader()
        for category, results in grouped_results.items():
            for result in results:
                if result.error or not result.ips:
                    writer.writerow(
                        {
                            "category": category,
                            "line_no": result.entry.line_no,
                            "domain": result.entry.domain,
                            "sm2_hash": result.entry.sm2_hash,
                            "error": result.error or "no usable IP after filtering",
                        }
                    )


def group_by_ip(grouped_results: dict[str, list[ResolvedEntry]]) -> dict[tuple[str, str], list[MapEntry]]:
    ip_groups: dict[tuple[str, str], list[MapEntry]] = {}
    for category, results in grouped_results.items():
        for result in results:
            for ip in result.ips:
                ip_groups.setdefault((category, ip), []).append(result.entry)
    return ip_groups


def write_cert_indexes(output_dir: Path, results: list[CertResult]) -> None:
    index_path = output_dir / "normal_cert_index.csv"
    failure_path = output_dir / "normal_cert_failures.csv"

    index_fields = [
        "category",
        "ip",
        "port",
        "sni_domain",
        "normal_cert_sha256",
        "pem_path",
        "source_domain_count",
        "source_domains",
        "source_sm2_hashes",
        "subject",
        "issuer",
        "not_before",
        "not_after",
        "signature_algorithm",
        "public_key_type",
    ]
    with index_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=index_fields)
        writer.writeheader()
        for result in results:
            if not result.ok:
                continue
            writer.writerow(
                {
                    "category": result.category,
                    "ip": result.ip,
                    "port": result.port,
                    "sni_domain": result.sni_domain,
                    "normal_cert_sha256": result.cert_sha256,
                    "pem_path": result.pem_path,
                    "source_domain_count": len(result.source_domains),
                    "source_domains": ";".join(result.source_domains),
                    "source_sm2_hashes": ";".join(result.source_sm2_hashes),
                    "subject": result.subject,
                    "issuer": result.issuer,
                    "not_before": result.not_before,
                    "not_after": result.not_after,
                    "signature_algorithm": result.signature_algorithm,
                    "public_key_type": result.public_key_type,
                }
            )

    with failure_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["category", "ip", "port", "source_domain_count", "tried_domains", "source_sm2_hashes", "error"],
        )
        writer.writeheader()
        for result in results:
            if result.ok:
                continue
            writer.writerow(
                {
                    "category": result.category,
                    "ip": result.ip,
                    "port": result.port,
                    "source_domain_count": len(result.source_domains),
                    "tried_domains": ";".join(result.tried_domains),
                    "source_sm2_hashes": ";".join(result.source_sm2_hashes),
                    "error": result.error,
                }
            )


def _status_token(status: str) -> str:
    return "_".join((status or "-").split())


def write_normal_domain_ip_maps(
    output_dir: Path,
    grouped_results: dict[str, list[ResolvedEntry]],
    cert_results: list[CertResult],
) -> None:
    """Write per-domain ordinary certificate mappings using the IP collection result."""
    lookup = {(result.category, result.ip): result for result in cert_results}
    map_dir = output_dir / "normal_domain_ip_maps"
    map_dir.mkdir(parents=True, exist_ok=True)

    for category, results in grouped_results.items():
        out_path = map_dir / f"{category}_domain_ip_map.txt"
        with out_path.open("w", encoding="utf-8", newline="") as f:
            for resolved in sorted(results, key=lambda item: item.entry.line_no):
                if not resolved.ips:
                    f.write(f"{resolved.entry.domain} {resolved.entry.sm2_hash} - - - unresolved\n")
                    continue

                for ip in resolved.ips:
                    cert_result = lookup.get((category, ip))
                    if cert_result is None:
                        normal_hash = "-"
                        pem_path = "-"
                        status = "not_collected"
                    elif cert_result.ok:
                        normal_hash = cert_result.cert_sha256
                        pem_path = cert_result.pem_path
                        status = "ok"
                    else:
                        normal_hash = "-"
                        pem_path = "-"
                        status = f"collect_failed:{_status_token(cert_result.error)}"

                    f.write(
                        f"{resolved.entry.domain} {resolved.entry.sm2_hash} "
                        f"{ip} {normal_hash} {pem_path} {status}\n"
                    )


def write_enriched_domain_ip_maps(
    output_dir: Path,
    grouped_results: dict[str, list[ResolvedEntry]],
    cert_results: list[CertResult],
) -> None:
    """Write root-level domain/IP maps with ordinary certificate columns."""
    lookup = {(result.category, result.ip): result for result in cert_results}
    output_dir.mkdir(parents=True, exist_ok=True)

    for category, results in grouped_results.items():
        out_path = output_dir / f"{category}_domain_ip_map_with_normal_cert.txt"
        with out_path.open("w", encoding="utf-8", newline="") as f:
            for resolved in sorted(results, key=lambda item: item.entry.line_no):
                if not resolved.ips:
                    f.write(f"{resolved.entry.domain} {resolved.entry.sm2_hash} - - - unresolved\n")
                    continue

                for ip in resolved.ips:
                    cert_result = lookup.get((category, ip))
                    if cert_result is None:
                        normal_hash = "-"
                        pem_path = "-"
                        status = "not_collected"
                    elif cert_result.ok:
                        normal_hash = cert_result.cert_sha256
                        pem_path = cert_result.pem_path
                        status = "ok"
                    else:
                        normal_hash = "-"
                        pem_path = "-"
                        status = f"collect_failed:{_status_token(cert_result.error)}"

                    f.write(
                        f"{resolved.entry.domain} {resolved.entry.sm2_hash} "
                        f"{ip} {normal_hash} {pem_path} {status}\n"
                    )


def load_existing_domain_ip_maps(output_dir: Path, categories: Iterable[str]) -> dict[str, list[ResolvedEntry]]:
    grouped_results: dict[str, list[ResolvedEntry]] = {}
    for category in categories:
        path = output_dir / f"{category}_domain_ip_map.txt"
        if not path.exists():
            continue
        grouped_results[category] = []
        with path.open("r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, 1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=2)
                if len(parts) < 3:
                    print(f"[WARN] skip malformed line {path}:{line_no}: {line}", file=sys.stderr)
                    continue
                ip_text = parts[2].strip()
                ips = tuple(ip for ip in ip_text.split(",") if ip and ip != "-")
                entry = MapEntry(category=category, line_no=line_no, domain=parts[0], sm2_hash=parts[1])
                grouped_results[category].append(ResolvedEntry(entry=entry, ips=ips))
    return grouped_results


def load_existing_cert_results(output_dir: Path) -> list[CertResult]:
    results: list[CertResult] = []
    index_path = output_dir / "normal_cert_index.csv"
    failure_path = output_dir / "normal_cert_failures.csv"

    if index_path.exists():
        with index_path.open("r", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                results.append(
                    CertResult(
                        category=row.get("category", ""),
                        ip=row.get("ip", ""),
                        port=int(row.get("port") or 443),
                        ok=True,
                        sni_domain=row.get("sni_domain", ""),
                        cert_sha256=row.get("normal_cert_sha256", ""),
                        pem_path=row.get("pem_path", ""),
                        source_domains=tuple(filter(None, row.get("source_domains", "").split(";"))),
                        source_sm2_hashes=tuple(filter(None, row.get("source_sm2_hashes", "").split(";"))),
                        subject=row.get("subject", ""),
                        issuer=row.get("issuer", ""),
                        not_before=row.get("not_before", ""),
                        not_after=row.get("not_after", ""),
                        signature_algorithm=row.get("signature_algorithm", ""),
                        public_key_type=row.get("public_key_type", ""),
                    )
                )

    if failure_path.exists():
        with failure_path.open("r", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                results.append(
                    CertResult(
                        category=row.get("category", ""),
                        ip=row.get("ip", ""),
                        port=int(row.get("port") or 443),
                        ok=False,
                        source_sm2_hashes=tuple(filter(None, row.get("source_sm2_hashes", "").split(";"))),
                        tried_domains=tuple(filter(None, row.get("tried_domains", "").split(";"))),
                        error=row.get("error", ""),
                    )
                )
    return results

def filter_grouped_result_ips(
    grouped_results: dict[str, list[ResolvedEntry]],
    ipv4_only: bool,
    skip_private_ip: bool,
) -> dict[str, list[ResolvedEntry]]:
    filtered: dict[str, list[ResolvedEntry]] = {}
    for category, results in grouped_results.items():
        filtered[category] = []
        for result in results:
            ips = tuple(ip for ip in result.ips if usable_ip(ip, ipv4_only=ipv4_only, skip_private_ip=skip_private_ip))
            filtered[category].append(ResolvedEntry(entry=result.entry, ips=ips, error=result.error))
    return filtered


def failed_domain_keys(failed_results: Iterable[CertResult]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for result in failed_results:
        for domain in result.tried_domains:
            keys.add((result.category, domain))
    return keys


def refresh_failed_domain_ips(
    grouped_results: dict[str, list[ResolvedEntry]],
    failed_results: list[CertResult],
    port: int,
    timeout: float,
    workers: int,
    ipv4_only: bool,
    skip_private_ip: bool,
) -> dict[str, list[ResolvedEntry]]:
    target_keys = failed_domain_keys(failed_results)
    if not target_keys:
        return grouped_results

    entries: list[MapEntry] = []
    for category, results in grouped_results.items():
        for result in results:
            key = (category, result.entry.domain)
            if key in target_keys:
                entries.append(result.entry)

    if not entries:
        return grouped_results

    print(f"[INFO] refreshing DNS for {len(entries)} failed-domain entries before retry ...")
    refreshed: dict[tuple[str, str, str], ResolvedEntry] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(resolve_domain, entry, port, timeout, ipv4_only, skip_private_ip)
            for entry in entries
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            key = (result.entry.category, result.entry.domain, result.entry.sm2_hash)
            refreshed[key] = result
            ips = ",".join(result.ips) if result.ips else "-"
            print(f"[INFO] refreshed {result.entry.category} {result.entry.domain}: {ips}")

    updated: dict[str, list[ResolvedEntry]] = {}
    for category, results in grouped_results.items():
        updated[category] = []
        for result in results:
            key = (result.entry.category, result.entry.domain, result.entry.sm2_hash)
            refreshed_result = refreshed.get(key)
            if refreshed_result and refreshed_result.ips:
                updated[category].append(refreshed_result)
            else:
                updated[category].append(result)
    return updated

def retry_failed_cert_results(
    output_dir: Path,
    grouped_results: dict[str, list[ResolvedEntry]],
    existing_results: list[CertResult],
    port: int,
    timeout: float,
    retries: int,
    max_sni_candidates: int,
    workers: int,
    force: bool,
) -> list[CertResult]:
    failed_results = [result for result in existing_results if not result.ok]
    failed_keys = {(result.category, result.ip) for result in failed_results}
    retry_domain_keys = failed_domain_keys(failed_results)
    if not failed_results:
        print("[INFO] no failed IPs found in existing normal_cert_failures.csv")
        return existing_results

    all_ip_groups = group_by_ip(grouped_results)
    retry_groups = {
        key: entries
        for key, entries in all_ip_groups.items()
        if any((key[0], entry.domain) in retry_domain_keys for entry in entries)
    }
    missing_keys = sorted(failed_keys - set(all_ip_groups))
    for category, ip in missing_keys:
        print(f"[WARN] previous failed IP is not collectable after filtering/refreshing, keeping old failure unless another IP for the same domain succeeds: {category} {ip}")

    print(f"[INFO] retrying {len(retry_groups)} failed-domain category/IP groups with {workers} workers ...")
    retried_results: list[CertResult] = []
    if retry_groups:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(
                    collect_for_ip,
                    category,
                    ip,
                    entries,
                    port,
                    timeout,
                    retries,
                    max_sni_candidates,
                    output_dir,
                    force,
                )
                for (category, ip), entries in sorted(retry_groups.items())
            ]
            for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
                result = future.result()
                retried_results.append(result)
                status = "ok" if result.ok else "failed"
                print(f"[INFO] retried {index}/{len(futures)}: {result.category} {result.ip} {status}")

    retried_by_key = {(result.category, result.ip): result for result in retried_results}
    success_domain_keys = {
        (result.category, domain)
        for result in retried_results
        if result.ok
        for domain in result.source_domains
    }
    merged_by_key: dict[tuple[str, str], CertResult] = {}
    for result in existing_results:
        key = (result.category, result.ip)
        if key in retried_by_key:
            merged_by_key[key] = retried_by_key[key]
        elif not result.ok and any((result.category, domain) in success_domain_keys for domain in result.tried_domains):
            continue
        else:
            merged_by_key[key] = result

    for key, result in retried_by_key.items():
        merged_by_key[key] = result

    success_count = sum(1 for result in retried_results if result.ok)
    failed_count = len(retried_results) - success_count
    print(f"[INFO] retry result: success={success_count}, failed={failed_count}")
    return sorted(merged_by_key.values(), key=lambda result: (result.category, result.ip))

def print_summary(grouped_results: dict[str, list[ResolvedEntry]], cert_results: list[CertResult] | None) -> None:
    print("\nResolution summary")
    for category, results in grouped_results.items():
        domain_count = len(results)
        resolved_count = sum(1 for result in results if result.ips)
        unique_ips = len({ip for result in results for ip in result.ips})
        print(f"  {category}: domains={domain_count}, resolved={resolved_count}, unique_ips={unique_ips}")

    if cert_results is None:
        return

    ok_results = [result for result in cert_results if result.ok]
    failed_results = [result for result in cert_results if not result.ok]
    unique_cert_hashes = {result.cert_sha256 for result in ok_results}
    print("\nCertificate collection summary")
    print(f"  ip_groups={len(cert_results)}, success={len(ok_results)}, failed={len(failed_results)}")
    print(f"  unique ordinary certs={len(unique_cert_hashes)}")


def main() -> int:
    args = parse_args()
    input_dir = args.input_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if x509 is None:
        print("[INFO] cryptography is not installed; PEM collection works, metadata columns will be mostly empty.")

    if args.build_normal_domain_maps_only or args.retry_failures_only:
        grouped_results = load_existing_domain_ip_maps(output_dir, args.categories)
        cert_results = load_existing_cert_results(output_dir)
        if not grouped_results:
            print(f"[ERROR] no existing *_domain_ip_map.txt files found under: {output_dir}", file=sys.stderr)
            return 2
        if not cert_results:
            print(f"[ERROR] no existing normal_cert_index.csv/normal_cert_failures.csv found under: {output_dir}", file=sys.stderr)
            return 2

        if args.retry_failures_only:
            cert_results_before_retry = cert_results
            grouped_results = filter_grouped_result_ips(grouped_results, args.ipv4_only, args.skip_private_ip)
            if not args.no_retry_refresh_dns:
                grouped_results = refresh_failed_domain_ips(
                    grouped_results=grouped_results,
                    failed_results=[result for result in cert_results_before_retry if not result.ok],
                    port=args.port,
                    timeout=args.timeout,
                    workers=args.workers,
                    ipv4_only=args.ipv4_only,
                    skip_private_ip=args.skip_private_ip,
                )
            cert_results = retry_failed_cert_results(
                output_dir=output_dir,
                grouped_results=grouped_results,
                existing_results=cert_results_before_retry,
                port=args.port,
                timeout=args.timeout,
                retries=args.retries,
                max_sni_candidates=args.max_sni_candidates,
                workers=args.workers,
                force=args.force,
            )
            write_cert_indexes(output_dir, cert_results)
            write_normal_domain_ip_maps(output_dir, grouped_results, cert_results)
            write_enriched_domain_ip_maps(output_dir, grouped_results, cert_results)
            print_summary(grouped_results, cert_results)
            print(f"\n[DONE] merged retry results under: {output_dir}")
            return 0

        write_normal_domain_ip_maps(output_dir, grouped_results, cert_results)
        write_enriched_domain_ip_maps(output_dir, grouped_results, cert_results)
        print(f"[DONE] wrote ordinary certificate domain/IP maps under: {output_dir / 'normal_domain_ip_maps'}")
        return 0

    if args.use_input_domain_ip_maps:
        grouped_results = load_existing_domain_ip_maps(input_dir, args.categories)
        grouped_results = filter_grouped_result_ips(grouped_results, args.ipv4_only, args.skip_private_ip)
        if not grouped_results:
            print(f"[ERROR] no input *_domain_ip_map.txt files found under: {input_dir}", file=sys.stderr)
            return 2
        total_targets = sum(len(result.ips) for results in grouped_results.values() for result in results)
        if total_targets == 0:
            print("[ERROR] no usable domain/IP targets found in input maps", file=sys.stderr)
            return 2
        print(f"[INFO] using {total_targets} explicit domain/IP targets from: {input_dir}")
        write_domain_ip_maps(output_dir, grouped_results)
        write_resolution_failures(output_dir, grouped_results)
    else:
        entries_by_category: dict[str, list[MapEntry]] = {}
        for category in args.categories:
            path = input_dir / f"{category}_domain_map.txt"
            if not path.exists():
                print(f"[WARN] missing map file: {path}", file=sys.stderr)
                continue
            entries_by_category[category] = load_map(path, category)

        all_entries = [entry for entries in entries_by_category.values() for entry in entries]
        if not all_entries:
            print("[ERROR] no input entries found", file=sys.stderr)
            return 2

        print(f"[INFO] resolving {len(all_entries)} domains with {args.workers} workers ...")
        grouped_results: dict[str, list[ResolvedEntry]] = {category: [] for category in entries_by_category}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [
                executor.submit(
                    resolve_domain,
                    entry,
                    args.port,
                    args.timeout,
                    args.ipv4_only,
                    args.skip_private_ip,
                )
                for entry in all_entries
            ]
            for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
                result = future.result()
                grouped_results[result.entry.category].append(result)
                if index % 100 == 0 or index == len(futures):
                    print(f"[INFO] resolved {index}/{len(futures)}")

        write_domain_ip_maps(output_dir, grouped_results)
        write_resolution_failures(output_dir, grouped_results)

    if args.resolve_only:
        print_summary(grouped_results, cert_results=None)
        print(f"\n[DONE] wrote outputs under: {output_dir}")
        return 0

    ip_groups = group_by_ip(grouped_results)
    print(f"[INFO] collecting ordinary TLS certs for {len(ip_groups)} category/IP groups ...")
    cert_results: list[CertResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(
                collect_for_ip,
                category,
                ip,
                entries,
                args.port,
                args.timeout,
                args.retries,
                args.max_sni_candidates,
                output_dir,
                args.force,
            )
            for (category, ip), entries in sorted(ip_groups.items())
        ]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            cert_results.append(future.result())
            if index % 50 == 0 or index == len(futures):
                ok_count = sum(1 for result in cert_results if result.ok)
                print(f"[INFO] collected {index}/{len(futures)} ip groups, success={ok_count}")

    write_cert_indexes(output_dir, cert_results)
    write_normal_domain_ip_maps(output_dir, grouped_results, cert_results)
    write_enriched_domain_ip_maps(output_dir, grouped_results, cert_results)
    print_summary(grouped_results, cert_results)
    print(f"\n[DONE] wrote outputs under: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())







