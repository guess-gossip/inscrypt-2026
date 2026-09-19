#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Batch download SM2 certificates with Tongsuo.

Commands tried per domain:
  /opt/tongsuo/bin/openssl s_client -connect <domain>:443 -servername <domain> -showcerts -tls1_3 -ciphersuites TLS_SM4_GCM_SM3
  /opt/tongsuo/bin/openssl s_client -connect <domain>:443 -servername <domain> -showcerts -ntls -enable_ntls

Usage:
  python3 download_certs.py gov.txt
  python3 download_certs.py gov.txt --workers 10 --timeout 15
"""

import argparse
import base64
import hashlib
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, FIRST_COMPLETED, wait
from pathlib import Path
from urllib.parse import urlparse

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


DEFAULT_OPENSSL_BIN = "/opt/tongsuo/bin/openssl"
DEFAULT_BASE_DIR = "/root/SM2"
DEFAULT_WORKERS = 25
DEFAULT_TIMEOUT = 12
DEFAULT_DNS_TIMEOUT = 5
DEFAULT_PORT = 443
MODE_NAME = "sm2_auto"
OUTPUT_SUFFIX = ""
STATE_SUFFIX = ""
SCLIENT_MODES = [
    ("ntls", ["-ntls", "-enable_ntls"]),
    ("tls13_sm4_gcm_sm3", ["-tls1_3", "-ciphersuites", "TLS_SM4_GCM_SM3"]),
]

CERT_PATTERN = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)


def normalize_domain(value):
    value = value.strip()
    if not value:
        return ""

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path

    value = value.split("/")[0].split("?")[0].split("#")[0]
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if ":" in value and not value.startswith("["):
        value = value.split(":", 1)[0]

    return value.strip().strip(".").lower()


def read_domains(input_file):
    domains = []
    seen = set()
    with open(input_file, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domain = normalize_domain(line)
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
    return domains


def ensure_dir(path):
    path.mkdir(parents=True, exist_ok=True)


def load_set(file_path):
    if not file_path.exists():
        return set()
    with open(file_path, "r", encoding="utf-8") as file:
        return {line.strip().split()[0] for line in file if line.strip()}


def append_line(file_path, line):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "a", encoding="utf-8") as file:
        file.write(f"{line}\n")


def compute_sha256(data):
    return hashlib.sha256(data).hexdigest()


def resolve_domain(domain, port, timeout):
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, port)
        return True
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(old_timeout)


def extract_first_cert(stdout):
    match = CERT_PATTERN.search(stdout)
    if not match:
        return None
    cert = match.group(0).replace(b"\r\n", b"\n").strip() + b"\n"
    return cert


def build_s_client_cmd(openssl_bin, domain, port, mode_args):
    return [
        openssl_bin,
        "s_client",
        "-connect",
        f"{domain}:{port}",
        "-servername",
        domain,
        "-showcerts",
        *mode_args,
    ]


def process_domain(domain, openssl_bin, port, timeout, dns_timeout):
    if not resolve_domain(domain, port, dns_timeout):
        return domain, None, None, "dns_resolve_failed"

    env = os.environ.copy()
    env["OPENSSL_sm_tls13_strict"] = "1"
    failures = []

    for mode_name, mode_args in SCLIENT_MODES:
        cmd = build_s_client_cmd(openssl_bin, domain, port, mode_args)
        try:
            proc = subprocess.run(
                cmd,
                input=b"",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{mode_name}:timeout_after_{timeout}s")
            continue
        except Exception as exc:
            failures.append(f"{mode_name}:execute_failed:{exc}")
            continue

        cert_pem = extract_first_cert(proc.stdout)
        if cert_pem:
            cert_hash = compute_sha256(cert_pem)
            cert_b64 = base64.b64encode(cert_pem).decode("ascii")
            return domain, cert_hash, cert_b64, mode_name

        stderr = proc.stderr.decode("utf-8", errors="ignore").strip().replace("\n", " ")
        if len(stderr) > 300:
            stderr = stderr[:300] + "..."
        reason = f"{mode_name}:no_cert_found:returncode={proc.returncode}"
        if stderr:
            reason = f"{reason}:stderr={stderr}"
        failures.append(reason)

    return domain, None, None, " | ".join(failures)


def save_success(cert_hash, cert_b64, output_dir, hash_file, domain_map_file, domain, unique_hashes):
    cert_pem = base64.b64decode(cert_b64)
    if cert_hash not in unique_hashes:
        cert_file = output_dir / f"{cert_hash}.pem"
        with open(cert_file, "wb") as file:
            file.write(cert_pem)
        unique_hashes.add(cert_hash)
        append_line(hash_file, cert_hash)

    append_line(domain_map_file, f"{domain} {cert_hash}")


def iter_domain_results(pending, args):
    domain_iter = iter(pending)
    future_to_domain = {}
    executor = ProcessPoolExecutor(max_workers=args.workers)
    interrupted = False

    def submit_next():
        try:
            domain = next(domain_iter)
        except StopIteration:
            return
        future = executor.submit(
            process_domain,
            domain,
            args.openssl,
            args.port,
            args.timeout,
            args.dns_timeout,
        )
        future_to_domain[future] = domain

    try:
        for _ in range(args.workers):
            submit_next()

        while future_to_domain:
            done, _ = wait(future_to_domain, return_when=FIRST_COMPLETED)
            for future in done:
                domain = future_to_domain.pop(future)
                try:
                    yield future.result()
                except Exception as exc:
                    yield domain, None, None, f"worker_exception:{exc}"
                submit_next()
    except KeyboardInterrupt:
        interrupted = True
        for future in future_to_domain:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=True)


def make_paths(input_file, base_dir):
    base_name = input_file.stem
    state_name = f"{base_name}{STATE_SUFFIX}"
    output_name = f"{base_name}{OUTPUT_SUFFIX}"

    return {
        "output_dir": base_dir / output_name,
        "success_file": base_dir / f"{state_name}_success.txt",
        "hash_file": base_dir / f"{state_name}_cert_hashes.txt",
        "domain_map_file": base_dir / f"{state_name}_domain_map.txt",
        "report_file": input_file.parent / f"{state_name}_report.txt",
    }


def generate_report(input_file, paths, total, success_count, unique_hashes):
    report_lines = [
        "=" * 60,
        f"report_time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"mode: {MODE_NAME}",
        f"input_file: {input_file}",
        f"cert_output_dir: {paths['output_dir']}",
        f"total_domains: {total}",
        f"successful_domains: {success_count}",
        f"unique_certs: {len(unique_hashes)}",
        f"failed_or_pending_domains: {max(total - success_count, 0)}",
        f"success_rate: {success_count / total * 100:.2f}%" if total else "success_rate: N/A",
        "=" * 60,
    ]
    for line in report_lines:
        print(line)

    with open(paths["report_file"], "w", encoding="utf-8") as file:
        file.write("\n".join(report_lines))
    print(f"report saved to: {paths['report_file']}")


def parse_args():
    parser = argparse.ArgumentParser(description="Batch download SM2 certificates with Tongsuo.")
    parser.add_argument("input_file", help="domain list file")
    parser.add_argument("--openssl", default=DEFAULT_OPENSSL_BIN, help=f"Tongsuo openssl path, default: {DEFAULT_OPENSSL_BIN}")
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR, help=f"output base directory, default: {DEFAULT_BASE_DIR}")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"parallel workers, default: {DEFAULT_WORKERS}")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"s_client timeout seconds, default: {DEFAULT_TIMEOUT}")
    parser.add_argument("--dns-timeout", type=int, default=DEFAULT_DNS_TIMEOUT, help=f"DNS timeout seconds, default: {DEFAULT_DNS_TIMEOUT}")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"HTTPS port, default: {DEFAULT_PORT}")
    parser.add_argument("--no-resume", action="store_true", help="ignore previous successful domains")
    return parser.parse_args()


def main():
    args = parse_args()
    args.workers = max(1, args.workers)

    input_file = Path(args.input_file)
    if not input_file.exists():
        print(f"input file does not exist: {input_file}")
        sys.exit(1)

    if not Path(args.openssl).exists():
        print(f"openssl not found: {args.openssl}")
        sys.exit(1)

    base_dir = Path(args.base_dir)
    paths = make_paths(input_file, base_dir)
    ensure_dir(paths["output_dir"])

    completed_set = set() if args.no_resume else load_set(paths["success_file"])
    unique_hashes = load_set(paths["hash_file"])
    all_domains = read_domains(input_file)
    pending = [domain for domain in all_domains if domain not in completed_set]

    print(f"mode: {MODE_NAME}")
    print("command modes:")
    for mode_name, mode_args in SCLIENT_MODES:
        print(f"  {mode_name}: {' '.join(mode_args)}")
    print("OPENSSL_sm_tls13_strict=1 is set automatically for each child process.")
    print(f"input domains: {len(all_domains)}")
    print(f"already successful domains: {len(completed_set)}")
    print(f"pending domains: {len(pending)}")
    print(f"cert output dir: {paths['output_dir']}")
    print(f"resume file: {paths['success_file']}")
    print(f"workers: {args.workers}, timeout: {args.timeout}s, dns timeout: {args.dns_timeout}s")
    print("SNI enabled with -servername; duplicate certificates are saved only once.")

    progress = tqdm(total=len(pending), desc="download certs", unit="domain") if tqdm else None
    success_this_run = 0
    processed_this_run = 0

    try:
        for domain, cert_hash, data, _reason in iter_domain_results(pending, args):
            processed_this_run += 1
            if cert_hash:
                save_success(
                    cert_hash,
                    data,
                    paths["output_dir"],
                    paths["hash_file"],
                    paths["domain_map_file"],
                    domain,
                    unique_hashes,
                )
                completed_set.add(domain)
                append_line(paths["success_file"], domain)
                success_this_run += 1

            if progress:
                progress.update(1)
            elif processed_this_run % 100 == 0:
                print(f"processed: {processed_this_run}/{len(pending)}")
    except KeyboardInterrupt:
        print("\ninterrupted. Successful domains have been saved and will be skipped next time.")
    finally:
        if progress:
            progress.close()

    generate_report(
        input_file=input_file,
        paths=paths,
        total=len(all_domains),
        success_count=len(completed_set),
        unique_hashes=unique_hashes,
    )


if __name__ == "__main__":
    main()
