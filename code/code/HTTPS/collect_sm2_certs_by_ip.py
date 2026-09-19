#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import os
import re
import socket
import subprocess
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from tqdm import tqdm
except Exception:
    tqdm = None


CATEGORIES = ("bank", "edu", "gov")
CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
SCLIENT_MODES = [
    ("ntls", ["-ntls", "-enable_ntls"]),
    ("tls13_sm4_gcm_sm3", ["-tls1_3", "-ciphersuites", "TLS_SM4_GCM_SM3"]),
]


@dataclass(frozen=True)
class DomainEntry:
    category: str
    domain: str
    original_sm2_hash: str


@dataclass(frozen=True)
class Target:
    category: str
    domain: str
    ip: str
    original_sm2_hash: str
    normal_cert_hash: str = ""
    normal_pem_path: str = ""
    normal_status: str = ""
    source: str = ""


@dataclass
class Result:
    category: str
    domain: str
    ip: str
    original_sm2_hash: str
    ok: bool
    normal_cert_hash: str = ""
    normal_pem_path: str = ""
    normal_status: str = ""
    source: str = ""
    collected_sm2_hash: str = ""
    pem_path: str = ""
    mode: str = ""
    error: str = ""
    elapsed_ms: float = 0.0

    @property
    def matches_original_hash(self) -> str:
        if not self.ok or not self.collected_sm2_hash or not self.original_sm2_hash:
            return ""
        return "yes" if self.collected_sm2_hash == self.original_sm2_hash else "no"


def read_domain_map(path: Path, category: str) -> list[DomainEntry]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            rows.append(DomainEntry(category=category, domain=parts[0], original_sm2_hash=parts[1].lower()))
    return rows


def usable_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    return True


def resolve_domain(domain: str, port: int, timeout: float) -> tuple[str, ...]:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
    finally:
        socket.setdefaulttimeout(old_timeout)
    ips = []
    seen = set()
    for info in infos:
        ip = info[4][0]
        if "%" in ip:
            ip = ip.split("%", 1)[0]
        if usable_ip(ip) and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return tuple(ips)


def build_targets_by_dns(entries: list[DomainEntry], port: int, dns_timeout: float) -> tuple[list[Target], list[dict]]:
    targets = []
    failures = []
    for entry in entries:
        try:
            ips = resolve_domain(entry.domain, port=port, timeout=dns_timeout)
            if not ips:
                failures.append({"category": entry.category, "domain": entry.domain, "error": "no_usable_ip"})
                continue
            for ip in ips:
                targets.append(Target(entry.category, entry.domain, ip, entry.original_sm2_hash))
        except Exception as exc:
            failures.append({"category": entry.category, "domain": entry.domain, "error": repr(exc)})
    return targets, failures


def build_targets_from_expanded_normal_maps(root: Path, categories: Iterable[str]) -> list[Target]:
    targets = []
    seen = set()
    for category in categories:
        path = root / "normal_cert_collection" / "normal_domain_ip_maps" / f"{category}_domain_ip_map.txt"
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                domain, sm2_hash, ip = parts[:3]
                if not usable_ip(ip):
                    continue
                key = (category, domain, ip)
                if key in seen:
                    continue
                seen.add(key)
                normal_cert_hash = parts[3] if len(parts) > 3 else ""
                normal_pem_path = parts[4] if len(parts) > 4 else ""
                normal_status = parts[5] if len(parts) > 5 else ""
                targets.append(
                    Target(
                        category=category,
                        domain=domain,
                        ip=ip,
                        original_sm2_hash=sm2_hash.lower(),
                        normal_cert_hash=normal_cert_hash,
                        normal_pem_path=normal_pem_path,
                        normal_status=normal_status,
                        source="expanded_normal_domain_ip_maps",
                    )
                )
    return targets


def build_targets_from_compact_normal_maps(root: Path, categories: Iterable[str]) -> list[Target]:
    targets = []
    seen = set()
    for category in categories:
        path = root / "normal_cert_collection" / f"{category}_domain_ip_map.txt"
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                domain, sm2_hash, ip_list = parts[:3]
                for ip in ip_list.split(","):
                    ip = ip.strip()
                    if not usable_ip(ip):
                        continue
                    key = (category, domain, ip)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(
                        Target(
                            category=category,
                            domain=domain,
                            ip=ip,
                            original_sm2_hash=sm2_hash.lower(),
                            source="compact_normal_cert_collection_maps",
                        )
                    )
    return targets


def build_targets_from_normal_maps(root: Path, categories: Iterable[str], source: str) -> list[Target]:
    if source == "expanded":
        return build_targets_from_expanded_normal_maps(root, categories)
    if source == "compact":
        return build_targets_from_compact_normal_maps(root, categories)

    targets = []
    seen = set()
    for target in [
        *build_targets_from_expanded_normal_maps(root, categories),
        *build_targets_from_compact_normal_maps(root, categories),
    ]:
        key = (target.category, target.domain, target.ip)
        if key in seen:
            continue
        seen.add(key)
        targets.append(target)
    return targets


def extract_first_cert(data: bytes) -> bytes | None:
    match = CERT_RE.search(data)
    if not match:
        return None
    return match.group(0).replace(b"\r\n", b"\n").strip() + b"\n"


def collect_one(target: Target, args: argparse.Namespace) -> Result:
    env = os.environ.copy()
    env["OPENSSL_sm_tls13_strict"] = "1"
    failures = []
    start = time.perf_counter()

    for mode_name, mode_args in SCLIENT_MODES:
        command = [
            args.openssl,
            "s_client",
            "-connect",
            f"{target.ip}:{args.port}",
            "-servername",
            target.domain,
            "-showcerts",
            *mode_args,
        ]
        try:
            proc = subprocess.run(
                command,
                input=b"",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{mode_name}:timeout_after_{args.timeout}s")
            continue
        except Exception as exc:
            failures.append(f"{mode_name}:execute_failed:{exc!r}")
            continue

        cert_pem = extract_first_cert(proc.stdout + b"\n" + proc.stderr)
        if cert_pem:
            cert_hash = hashlib.sha256(cert_pem).hexdigest()
            category_dir = Path(args.output_dir) / "sm2_certs_by_ip" / target.category
            category_dir.mkdir(parents=True, exist_ok=True)
            pem_path = category_dir / f"{cert_hash}.pem"
            if args.force or not pem_path.exists():
                pem_path.write_bytes(cert_pem)
            return Result(
                category=target.category,
                domain=target.domain,
                ip=target.ip,
                original_sm2_hash=target.original_sm2_hash,
                ok=True,
                normal_cert_hash=target.normal_cert_hash,
                normal_pem_path=target.normal_pem_path,
                normal_status=target.normal_status,
                source=target.source,
                collected_sm2_hash=cert_hash,
                pem_path=str(pem_path),
                mode=mode_name,
                elapsed_ms=(time.perf_counter() - start) * 1000,
            )

        stderr = proc.stderr.decode("utf-8", errors="replace").strip().replace("\n", " ")
        failures.append(f"{mode_name}:no_cert:returncode={proc.returncode}:stderr={stderr[:300]}")

    return Result(
        category=target.category,
        domain=target.domain,
        ip=target.ip,
        original_sm2_hash=target.original_sm2_hash,
        ok=False,
        normal_cert_hash=target.normal_cert_hash,
        normal_pem_path=target.normal_pem_path,
        normal_status=target.normal_status,
        source=target.source,
        error=" | ".join(failures),
        elapsed_ms=(time.perf_counter() - start) * 1000,
    )


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_target_inventory(output_dir: Path, targets: list[Target], resolution_failures: list[dict]) -> None:
    target_rows = [
        {
            "category": t.category,
            "domain": t.domain,
            "ip": t.ip,
            "original_sm2_hash": t.original_sm2_hash,
            "normal_cert_hash": t.normal_cert_hash,
            "normal_pem_path": t.normal_pem_path,
            "normal_status": t.normal_status,
            "source": t.source,
        }
        for t in sorted(targets, key=lambda x: (x.category, x.domain, x.ip))
    ]
    write_csv(
        output_dir / "sm2_by_ip_targets.csv",
        target_rows,
        [
            "category",
            "domain",
            "ip",
            "original_sm2_hash",
            "normal_cert_hash",
            "normal_pem_path",
            "normal_status",
            "source",
        ],
    )

    rows = []
    for category in (*CATEGORIES, "total"):
        if category == "total":
            subset = targets
        else:
            subset = [t for t in targets if t.category == category]
        domain_to_ips = defaultdict(set)
        for target in subset:
            domain_to_ips[target.domain].add(target.ip)
        rows.append(
            {
                "category": category,
                "domains": len(domain_to_ips),
                "targets_domain_ip": len(subset),
                "unique_ips": len({t.ip for t in subset}),
                "domains_with_multiple_ips": sum(1 for ips in domain_to_ips.values() if len(ips) > 1),
            }
        )
    write_csv(
        output_dir / "sm2_by_ip_target_summary.csv",
        rows,
        ["category", "domains", "targets_domain_ip", "unique_ips", "domains_with_multiple_ips"],
    )
    write_csv(output_dir / "resolution_failures.csv", resolution_failures, ["category", "domain", "error"])

    report_lines = [
        "# SM2 Domain/IP Target Inventory",
        "",
        "This file lists the domain/IP targets that will be used for explicit SM2 certificate collection.",
        "",
        "| category | domains | domain/IP targets | unique IPs | multi-IP domains |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        report_lines.append(
            f"| {row['category']} | {row['domains']} | {row['targets_domain_ip']} | {row['unique_ips']} | {row['domains_with_multiple_ips']} |"
        )
    report_lines.extend(
        [
            "",
            "Run without `--build-targets-only` to collect SM2 certificates for these explicit domain/IP targets.",
            "",
        ]
    )
    (output_dir / "sm2_by_ip_target_report.md").write_text("\n".join(report_lines), encoding="utf-8")


def summarize(output_dir: Path, entries: list[DomainEntry], targets: list[Target], results: list[Result], resolution_failures: list[dict]) -> None:
    ok_results = [r for r in results if r.ok]
    domain_to_ips = defaultdict(set)
    domain_to_hashes = defaultdict(set)
    domain_to_original = {}
    domain_to_ok_ips = defaultdict(set)
    category_domains = defaultdict(set)

    for entry in entries:
        category_domains[entry.category].add(entry.domain)
        domain_to_original[(entry.category, entry.domain)] = entry.original_sm2_hash
    for target in targets:
        domain_to_ips[(target.category, target.domain)].add(target.ip)
    for result in ok_results:
        domain_to_hashes[(result.category, result.domain)].add(result.collected_sm2_hash)
        domain_to_ok_ips[(result.category, result.domain)].add(result.ip)

    summary_rows = []
    for category in (*CATEGORIES, "total"):
        if category == "total":
            domains = {(e.category, e.domain) for e in entries}
            subset_targets = targets
            subset_results = results
            subset_ok = ok_results
        else:
            domains = {(category, d) for d in category_domains[category]}
            subset_targets = [t for t in targets if t.category == category]
            subset_results = [r for r in results if r.category == category]
            subset_ok = [r for r in ok_results if r.category == category]
        multi_ip_domains = sum(1 for key in domains if len(domain_to_ips.get(key, set())) > 1)
        multi_cert_domains = sum(1 for key in domains if len(domain_to_hashes.get(key, set())) > 1)
        changed_domains = sum(
            1
            for key in domains
            if domain_to_hashes.get(key)
            and domain_to_original.get(key)
            and any(h != domain_to_original[key] for h in domain_to_hashes[key])
        )
        summary_rows.append(
            {
                "category": category,
                "domains": len(domains),
                "targets_domain_ip": len(subset_targets),
                "ok_targets": sum(1 for r in subset_results if r.ok),
                "failed_targets": sum(1 for r in subset_results if not r.ok),
                "ok_targets_matching_original_hash": sum(1 for r in subset_results if r.ok and r.collected_sm2_hash == r.original_sm2_hash),
                "ok_targets_different_from_original_hash": sum(1 for r in subset_results if r.ok and r.collected_sm2_hash != r.original_sm2_hash),
                "unique_collected_sm2_certs": len({r.collected_sm2_hash for r in subset_ok}),
                "domains_with_multiple_ips": multi_ip_domains,
                "domains_with_multiple_sm2_certs_across_ips": multi_cert_domains,
                "domains_with_collected_hash_different_from_original": changed_domains,
            }
        )

    diff_rows = []
    for key in sorted(domain_to_ips):
        hashes = sorted(domain_to_hashes.get(key, set()))
        original = domain_to_original.get(key, "")
        if len(hashes) > 1 or (hashes and original and any(h != original for h in hashes)):
            category, domain = key
            diff_rows.append(
                {
                    "category": category,
                    "domain": domain,
                    "original_sm2_hash": original,
                    "ips": ";".join(sorted(domain_to_ips[key])),
                    "ok_ips": ";".join(sorted(domain_to_ok_ips.get(key, set()))),
                    "collected_sm2_hashes": ";".join(hashes),
                    "hash_count": len(hashes),
                    "has_different_hash_across_ips": len(hashes) > 1,
                    "differs_from_original": bool(hashes and original and any(h != original for h in hashes)),
                }
            )

    write_csv(
        output_dir / "sm2_by_ip_summary.csv",
        summary_rows,
        [
            "category",
            "domains",
            "targets_domain_ip",
            "ok_targets",
            "failed_targets",
            "ok_targets_matching_original_hash",
            "ok_targets_different_from_original_hash",
            "unique_collected_sm2_certs",
            "domains_with_multiple_ips",
            "domains_with_multiple_sm2_certs_across_ips",
            "domains_with_collected_hash_different_from_original",
        ],
    )
    write_csv(
        output_dir / "sm2_by_ip_differences.csv",
        diff_rows,
        [
            "category",
            "domain",
            "original_sm2_hash",
            "ips",
            "ok_ips",
            "collected_sm2_hashes",
            "hash_count",
            "has_different_hash_across_ips",
            "differs_from_original",
        ],
    )
    mismatch_rows = [
        {
            "category": r.category,
            "domain": r.domain,
            "ip": r.ip,
            "original_sm2_hash": r.original_sm2_hash,
            "collected_sm2_hash": r.collected_sm2_hash,
            "mode": r.mode,
            "pem_path": r.pem_path,
            "normal_cert_hash": r.normal_cert_hash,
            "normal_status": r.normal_status,
            "source": r.source,
        }
        for r in sorted(results, key=lambda x: (x.category, x.domain, x.ip))
        if r.ok and r.collected_sm2_hash != r.original_sm2_hash
    ]
    write_csv(
        output_dir / "sm2_by_ip_mismatches.csv",
        mismatch_rows,
        [
            "category",
            "domain",
            "ip",
            "original_sm2_hash",
            "collected_sm2_hash",
            "mode",
            "pem_path",
            "normal_cert_hash",
            "normal_status",
            "source",
        ],
    )
    failure_rows = [
        {
            "category": r.category,
            "domain": r.domain,
            "ip": r.ip,
            "original_sm2_hash": r.original_sm2_hash,
            "normal_cert_hash": r.normal_cert_hash,
            "normal_status": r.normal_status,
            "source": r.source,
            "elapsed_ms": f"{r.elapsed_ms:.2f}",
            "error": r.error,
        }
        for r in sorted(results, key=lambda x: (x.category, x.domain, x.ip))
        if not r.ok
    ]
    write_csv(
        output_dir / "sm2_by_ip_failures.csv",
        failure_rows,
        [
            "category",
            "domain",
            "ip",
            "original_sm2_hash",
            "normal_cert_hash",
            "normal_status",
            "source",
            "elapsed_ms",
            "error",
        ],
    )
    write_csv(output_dir / "resolution_failures.csv", resolution_failures, ["category", "domain", "error"])

    report_lines = [
        "# SM2 Certificate Collection by Domain/IP",
        "",
        "This report checks whether the same domain returns different SM2 certificates on different resolved IPs.",
        "",
        "| category | domains | domain/IP targets | ok | failed | ok matching original | ok different from original | unique SM2 certs | multi-IP domains | domains with multiple SM2 certs across IPs | domains differing from original hash |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary_rows:
        report_lines.append(
            f"| {row['category']} | {row['domains']} | {row['targets_domain_ip']} | {row['ok_targets']} | {row['failed_targets']} | "
            f"{row['ok_targets_matching_original_hash']} | {row['ok_targets_different_from_original_hash']} | "
            f"{row['unique_collected_sm2_certs']} | {row['domains_with_multiple_ips']} | "
            f"{row['domains_with_multiple_sm2_certs_across_ips']} | {row['domains_with_collected_hash_different_from_original']} |"
        )
    report_lines.extend(
        [
            "",
            f"Difference rows written to `sm2_by_ip_differences.csv`: {len(diff_rows)}",
            f"Per-target mismatches written to `sm2_by_ip_mismatches.csv`: {len(mismatch_rows)}",
            f"Failed domain/IP targets written to `sm2_by_ip_failures.csv`: {len(failure_rows)}",
            "",
        ]
    )
    (output_dir / "sm2_by_ip_report.md").write_text("\n".join(report_lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect SM2 certificates by explicit domain/IP target.")
    parser.add_argument("--input-dir", default=".", help="Directory containing bank/edu/gov_domain_map.txt")
    parser.add_argument("--output-dir", default="sm2_cert_collection_by_ip")
    parser.add_argument("--categories", default="bank,edu,gov")
    parser.add_argument("--openssl", default="/opt/tongsuo/bin/openssl", help="Tongsuo openssl binary")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=12)
    parser.add_argument("--dns-timeout", type=float, default=5)
    parser.add_argument("--use-normal-ip-maps", action="store_true", help="Use normal_cert_collection/normal_domain_ip_maps IPs instead of fresh DNS")
    parser.add_argument(
        "--normal-ip-map-source",
        choices=("expanded", "compact", "both"),
        default="expanded",
        help="When --use-normal-ip-maps is set, choose expanded normal_domain_ip_maps, compact normal_cert_collection maps, or their union.",
    )
    parser.add_argument("--build-targets-only", action="store_true", help="Only write the domain/IP target inventory; do not connect to servers.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing PEM files")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    categories = [c.strip() for c in args.categories.split(",") if c.strip()]

    entries = []
    for category in categories:
        entries.extend(read_domain_map(root / f"{category}_domain_map.txt", category))

    if args.use_normal_ip_maps:
        targets = build_targets_from_normal_maps(root, categories, args.normal_ip_map_source)
        resolution_failures = []
    else:
        targets, resolution_failures = build_targets_by_dns(entries, port=args.port, dns_timeout=args.dns_timeout)

    print(f"domains: {len(entries)}")
    print(f"domain/ip targets: {len(targets)}")
    print(f"resolution failures: {len(resolution_failures)}")
    print(f"output dir: {output_dir}")
    write_target_inventory(output_dir, targets, resolution_failures)

    if args.build_targets_only:
        print(output_dir / "sm2_by_ip_targets.csv")
        print(output_dir / "sm2_by_ip_target_summary.csv")
        print(output_dir / "sm2_by_ip_target_report.md")
        return

    results = []
    progress = tqdm(total=len(targets), desc="collect SM2 by IP", unit="target") if tqdm else None
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_map = {executor.submit(collect_one, target, args): target for target in targets}
        for future in as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as exc:
                target = future_map[future]
                results.append(
                    Result(
                        target.category,
                        target.domain,
                        target.ip,
                        target.original_sm2_hash,
                        ok=False,
                        normal_cert_hash=target.normal_cert_hash,
                        normal_pem_path=target.normal_pem_path,
                        normal_status=target.normal_status,
                        source=target.source,
                        error=f"worker_exception:{exc!r}",
                    )
                )
            if progress:
                progress.update(1)
    if progress:
        progress.close()

    result_rows = [
        {
            "category": r.category,
            "domain": r.domain,
            "ip": r.ip,
            "original_sm2_hash": r.original_sm2_hash,
            "normal_cert_hash": r.normal_cert_hash,
            "normal_pem_path": r.normal_pem_path,
            "normal_status": r.normal_status,
            "source": r.source,
            "status": "ok" if r.ok else "failed",
            "collected_sm2_hash": r.collected_sm2_hash,
            "matches_original_hash": r.matches_original_hash,
            "pem_path": r.pem_path,
            "mode": r.mode,
            "elapsed_ms": f"{r.elapsed_ms:.2f}",
            "error": r.error,
        }
        for r in sorted(results, key=lambda x: (x.category, x.domain, x.ip))
    ]
    write_csv(
        output_dir / "sm2_by_ip_index.csv",
        result_rows,
        [
            "category",
            "domain",
            "ip",
            "original_sm2_hash",
            "normal_cert_hash",
            "normal_pem_path",
            "normal_status",
            "source",
            "status",
            "collected_sm2_hash",
            "matches_original_hash",
            "pem_path",
            "mode",
            "elapsed_ms",
            "error",
        ],
    )
    summarize(output_dir, entries, targets, results, resolution_failures)
    print(output_dir / "sm2_by_ip_summary.csv")
    print(output_dir / "sm2_by_ip_differences.csv")
    print(output_dir / "sm2_by_ip_report.md")


if __name__ == "__main__":
    main()
