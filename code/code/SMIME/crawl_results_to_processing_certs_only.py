#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

CERT_ATTRS = {
    "userCertificate",
    "userCertificate;binary",
    "userSMIMECertificate",
    "userSMIMECertificate;binary",
    "cACertificate",
    "cACertificate;binary",
}

OPTIONAL_ATTRS = {
    "crossCertificatePair",
    "crossCertificatePair;binary",
}

RESULT_FILE_RE = re.compile(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)_(?P<port>\d+)\.json$")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Convert SMINE ldap_crawler results/*.json into certs.jsonl only, "
            "for piping into processing/run.py certs."
        )
    )
    p.add_argument(
        "--results-dir",
        default="/home/skl/SMINE/cn_hk_crawl_output/results",
        help="Directory containing crawler result JSON files",
    )
    p.add_argument(
        "--out-dir",
        default="./processing_input",
        help="Output directory for processing-ready files",
    )
    p.add_argument(
        "--include-cross-certificate-pair",
        action="store_true",
        help="Also emit crossCertificatePair / crossCertificatePair;binary values as certs",
    )
    p.add_argument(
        "--only-completely-crawled",
        action="store_true",
        help="Only process result files where completely_crawled is true",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output files in out-dir",
    )
    return p.parse_args()


def ensure_clean(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"Refusing to overwrite existing file: {path} (use --force)")


def normalize_b64(s: str) -> str:
    return "".join(s.split())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def iter_cert_values(entry: dict[str, Any], include_cross: bool) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    attrs = entry.get("attributes") or {}
    allowed = set(CERT_ATTRS)
    if include_cross:
        allowed |= OPTIONAL_ATTRS

    for attr_name, values in attrs.items():
        if attr_name not in allowed:
            continue
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str):
                continue
            norm = normalize_b64(value)
            if norm:
                out.append((attr_name, norm))
    return out


def extract_ip_port(path: Path) -> tuple[str, int]:
    m = RESULT_FILE_RE.match(path.name)
    if not m:
        raise ValueError(f"Unexpected result filename format: {path.name}")
    ip = m.group("ip")
    port = int(m.group("port"))
    ipaddress.ip_address(ip)
    return ip, port


def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen_certs (
            cert_id TEXT PRIMARY KEY,
            first_seen_result_file TEXT NOT NULL,
            source_attr TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def try_insert_cert(
    conn: sqlite3.Connection,
    cert_id: str,
    first_seen_result_file: str,
    source_attr: str,
) -> bool:
    try:
        conn.execute(
            "INSERT INTO seen_certs (cert_id, first_seen_result_file, source_attr) VALUES (?, ?, ?)",
            (cert_id, first_seen_result_file, source_attr),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def should_skip_file(crawl: dict[str, Any], only_completely_crawled: bool) -> bool:
    if not only_completely_crawled:
        return False
    return crawl.get("completely_crawled") is not True


def main() -> int:
    args = parse_args()
    results_dir = Path(args.results_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    certs_jsonl = out_dir / "certs.jsonl"
    summary_json = out_dir / "summary.json"
    state_db = out_dir / "state.sqlite3"

    for p in (certs_jsonl, summary_json, state_db):
        ensure_clean(p, args.force)

    if not results_dir.exists():
        raise FileNotFoundError(f"results dir not found: {results_dir}")

    result_files = sorted(results_dir.glob("*.json"))
    if not result_files:
        raise FileNotFoundError(f"No result JSON files found under: {results_dir}")

    conn = init_db(state_db)

    summary: dict[str, Any] = {
        "results_dir": str(results_dir),
        "out_dir": str(out_dir),
        "include_cross_certificate_pair": args.include_cross_certificate_pair,
        "only_completely_crawled": args.only_completely_crawled,
        "result_files_found": len(result_files),
        "result_files_processed": 0,
        "result_files_skipped": 0,
        "unique_certs_written": 0,
        "duplicate_certs_skipped": 0,
        "invalid_base64_values_skipped": 0,
        "processed_items": [],
        "skipped_items": [],
    }

    with certs_jsonl.open("w", encoding="utf-8") as certs_f:
        for result_path in result_files:
            ip, port = extract_ip_port(result_path)
            crawl = load_json(result_path)

            if should_skip_file(crawl, args.only_completely_crawled):
                summary["result_files_skipped"] += 1
                summary["skipped_items"].append(
                    {
                        "result_file": result_path.name,
                        "ip": ip,
                        "port": port,
                        "reason": "completely_crawled is not true",
                    }
                )
                continue

            entries = crawl.get("result") or []
            if not isinstance(entries, list):
                entries = []

            host_entry_count = 0
            host_cert_value_count = 0
            host_unique_cert_ids: set[str] = set()

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                host_entry_count += 1
                for attr_name, b64_value in iter_cert_values(
                    entry,
                    include_cross=args.include_cross_certificate_pair,
                ):
                    host_cert_value_count += 1
                    try:
                        der = base64.b64decode(b64_value, validate=True)
                    except Exception:
                        summary["invalid_base64_values_skipped"] += 1
                        continue

                    cert_id = sha256_hex(der)
                    host_unique_cert_ids.add(cert_id)

                    inserted = try_insert_cert(conn, cert_id, result_path.name, attr_name)
                    if inserted:
                        cert_record = {
                            "_id": cert_id,
                            "cert_data": b64_value,
                            "source_result_file": result_path.name,
                            "source_ip": ip,
                            "source_port": port,
                            "source_attribute": attr_name,
                        }
                        certs_f.write(json.dumps(cert_record, ensure_ascii=False) + "\n")
                        summary["unique_certs_written"] += 1
                    else:
                        summary["duplicate_certs_skipped"] += 1

            summary["result_files_processed"] += 1
            summary["processed_items"].append(
                {
                    "result_file": result_path.name,
                    "ip": ip,
                    "port": port,
                    "entry_count": host_entry_count,
                    "certificate_value_count": host_cert_value_count,
                    "unique_cert_ids_for_file": len(host_unique_cert_ids),
                    "completely_crawled": crawl.get("completely_crawled"),
                }
            )

    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    conn.close()

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print()
    print("Next steps:")
    print("  cd processing")
    print(f"  python run.py certs < {certs_jsonl}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
