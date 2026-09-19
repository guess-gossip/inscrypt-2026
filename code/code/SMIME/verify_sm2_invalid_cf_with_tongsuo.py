#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
    load_pem_pkcs7_certificates,
)


PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def cert_fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def parse_cert_data(cert_data: Union[str, bytes]) -> x509.Certificate:
    candidates: list[bytes] = []
    if isinstance(cert_data, str):
        raw = cert_data.encode("utf-8")
        candidates.append(raw)
        candidates.append(
            b"-----BEGIN CERTIFICATE-----\n"
            + b"\n".join(raw[i:i + 64] for i in range(0, len(raw), 64))
            + b"\n-----END CERTIFICATE-----\n"
        )
        try:
            import base64
            candidates.append(base64.b64decode(cert_data, validate=False))
        except Exception:
            pass
    else:
        candidates.append(cert_data)

    errors: list[str] = []
    for candidate in candidates:
        for parser in (
            x509.load_pem_x509_certificate,
            x509.load_der_x509_certificate,
            load_pem_pkcs7_certificates,
            load_der_pkcs7_certificates,
        ):
            try:
                parsed = parser(candidate)
                if isinstance(parsed, list):
                    if parsed:
                        return parsed[0]
                else:
                    return parsed
            except Exception as e:
                errors.append(str(e))
    raise ValueError("; ".join(errors[:4]))


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except Exception:
                continue


def load_sm2_fingerprints(path: Path) -> set[str]:
    fps: set[str] = set()
    for line_no, obj in read_jsonl(path):
        fp = obj.get("fingerprint_sha256")
        if isinstance(fp, str):
            fps.add(fp.lower())
        if line_no % 100000 == 0:
            print(f"[progress] loaded {len(fps)} SM2 fingerprints from {line_no} lines", file=sys.stderr, flush=True)
    return fps


def select_sm2_invalid_cf_records(
    chain_results_path: Path,
    sm2_fps: set[str],
    limit: int | None = None,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for line_no, obj in read_jsonl(chain_results_path):
        leaf_fp = str(obj.get("leaf_fingerprint", "")).lower()
        if (
            leaf_fp in sm2_fps
            and obj.get("validation_result") == "INVALID_CF"
        ):
            selected.append(obj)
            if limit is not None and len(selected) >= limit:
                break
        if line_no % 100000 == 0:
            print(f"[progress] scanned {line_no} chain results; selected {len(selected)} SM2 INVALID_CF", file=sys.stderr, flush=True)
    return selected


def needed_fingerprints(records: list[dict[str, Any]]) -> set[str]:
    needed: set[str] = set()
    for rec in records:
        for chain in rec.get("chains") or []:
            if isinstance(chain, list):
                needed.update(str(fp).lower() for fp in chain)
    return needed


def load_needed_from_smime(
    smime_path: Path,
    needed: set[str],
    certs: dict[str, bytes],
) -> None:
    unresolved = needed - set(certs)
    for line_no, obj in read_jsonl(smime_path):
        if not unresolved:
            break

        candidate_ids = [
            obj.get("_id"),
            obj.get("id"),
            obj.get("fingerprint_sha256"),
        ]
        hit = next(
            (str(x).lower() for x in candidate_ids if isinstance(x, str) and str(x).lower() in unresolved),
            None,
        )
        if hit is None:
            continue

        cert_data = obj.get("cert_data")
        if not isinstance(cert_data, (str, bytes)):
            continue

        try:
            cert = parse_cert_data(cert_data)
            fp = cert_fp(cert)
            if fp in needed:
                certs[fp] = cert_pem(cert)
                unresolved.discard(fp)
        except Exception:
            continue
        finally:
            if line_no % 100000 == 0:
                print(
                    f"[progress] scanned {line_no} S/MIME records; resolved {len(certs)} certs; remaining {len(unresolved)}",
                    file=sys.stderr,
                    flush=True,
                )


def load_needed_from_bundles(
    bundle_dir: Path,
    needed: set[str],
    certs: dict[str, bytes],
) -> None:
    unresolved = needed - set(certs)
    if not unresolved:
        return

    for bundle in sorted(bundle_dir.glob("*.crt")):
        if not unresolved:
            break
        before = len(unresolved)
        data = bundle.read_bytes()
        for match in PEM_RE.finditer(data):
            pem = match.group(0) + b"\n"
            try:
                cert = x509.load_pem_x509_certificate(pem)
                fp = cert_fp(cert)
            except Exception:
                continue
            if fp in unresolved:
                certs[fp] = pem
                unresolved.discard(fp)
                if not unresolved:
                    break
        print(
            f"[progress] scanned bundle {bundle.name}; resolved {before - len(unresolved)} certs; remaining {len(unresolved)}",
            file=sys.stderr,
            flush=True,
        )


def find_default_tongsuo() -> str | None:
    local = Path("tools") / "tongsuo-install" / "bin" / "openssl.exe"
    if local.exists():
        return str(local)

    for name in ("tongsuo", "tongsuo.exe", "openssl", "openssl.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


def run_tongsuo_version(tongsuo: str) -> str:
    try:
        proc = subprocess.run(
            [tongsuo, "version", "-a"],
            text=True,
            capture_output=True,
            timeout=20,
        )
        return (proc.stdout + proc.stderr).strip()
    except Exception as e:
        return f"version_error:{e}"


def classify_verify_output(returncode: int, output: str) -> str:
    text = output.lower()
    if returncode == 0 and ": ok" in text:
        return "OK"
    if returncode == 0:
        return "OK"
    if "unsupported" in text or "unknown" in text:
        return "UNSUPPORTED_ALGORITHM"
    if "certificate signature failure" in text:
        return "CERTIFICATE_SIGNATURE_FAILURE"
    if "invalid ca certificate" in text:
        return "INVALID_CA_CERTIFICATE"
    if "key usage" in text:
        return "KEY_USAGE_FAILURE"
    if "unable to get issuer certificate" in text:
        return "UNABLE_TO_GET_ISSUER"
    if "self-signed certificate" in text:
        return "SELF_SIGNED_OR_UNTRUSTED"
    if "expired" in text:
        return "TIME_VALIDITY_ERROR"
    if "error" in text:
        return "VERIFY_ERROR"
    return "VERIFY_FAILED"


def verify_chain_with_tongsuo(
    tongsuo: str,
    chain: list[str],
    certs: dict[str, bytes],
    timeout: int,
    work_dir: Path,
) -> dict[str, Any]:
    chain = [fp.lower() for fp in chain]
    missing = [fp for fp in chain if fp not in certs]
    if len(chain) < 2:
        return {
            "returncode": None,
            "status": "MISSING_CHAIN",
            "missing_fingerprints": missing,
            "message": "chain has fewer than two certificates",
        }
    if missing:
        return {
            "returncode": None,
            "status": "MISSING_CERTIFICATE_MATERIAL",
            "missing_fingerprints": missing,
            "message": "one or more chain certificates could not be reconstructed",
        }

    leaf_path = work_dir / "leaf.pem"
    ca_path = work_dir / "chain_issuers.pem"
    leaf_path.write_bytes(certs[chain[0]])
    ca_path.write_bytes(b"".join(certs[fp] for fp in chain[1:]))

    cmd = [
        tongsuo,
        "verify",
        "-no_check_time",
        "-CAfile",
        str(ca_path),
        str(leaf_path),
    ]
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        output = (proc.stdout + proc.stderr).strip()
        return {
            "returncode": proc.returncode,
            "status": classify_verify_output(proc.returncode, output),
            "message": output[:1000],
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": None,
            "status": "TIMEOUT",
            "message": str(e)[:1000],
        }
    except Exception as e:
        return {
            "returncode": None,
            "status": "COMMAND_ERROR",
            "message": str(e)[:1000],
        }


def write_markdown_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Tongsuo Verification for SM2 INVALID_CF Chains",
        "",
        f"- Generated at: `{summary['generated_at']}`",
        f"- Tongsuo executable: `{summary['tongsuo_executable']}`",
        f"- Selected SM2 INVALID_CF records: {summary['selected_records']:,}",
        f"- Records with all needed certificate material: {summary['records_with_complete_material']:,}",
        f"- Records with missing certificate material: {summary['records_with_missing_material']:,}",
        f"- Records accepted by Tongsuo: {summary['tongsuo_valid_records']:,}",
        f"- Records still failing in Tongsuo: {summary['tongsuo_invalid_records']:,}",
        "",
        "## Per-Record Status",
        "",
        "| Status | Count |",
        "|---|---:|",
    ]
    for status, count in summary["record_status_counts"].items():
        lines.append(f"| `{status}` | {count:,} |")

    lines.extend([
        "",
        "## Chain-Attempt Status",
        "",
        "| Status | Count |",
        "|---|---:|",
    ])
    for status, count in summary["chain_attempt_status_counts"].items():
        lines.append(f"| `{status}` | {count:,} |")

    lines.extend([
        "",
        "## Tongsuo Version",
        "",
        "```text",
        summary.get("tongsuo_version", ""),
        "```",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Re-verify SM2 INVALID_CF candidate chains with Tongsuo."
    )
    ap.add_argument("--sm2-keys", default="processing_output/weak_keys/sm2_keys.jsonl")
    ap.add_argument("--chain-results", default="processing_output/chain_results.jsonl")
    ap.add_argument("--smime-certs", default="processing_output/smime_certs.jsonl")
    ap.add_argument("--bundles", default="chain_verification/crt-bundles")
    ap.add_argument("--output-dir", default="processing_output/tongsuo_sm2_invalid_cf")
    ap.add_argument("--tongsuo", default=None, help="Path to Tongsuo openssl-compatible executable")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=None, help="Debug limit")
    args = ap.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    tongsuo = args.tongsuo or find_default_tongsuo()
    if tongsuo is None:
        raise SystemExit("Could not find Tongsuo. Pass --tongsuo PATH.")

    sm2_fps = load_sm2_fingerprints(Path(args.sm2_keys))
    records = select_sm2_invalid_cf_records(
        Path(args.chain_results),
        sm2_fps,
        limit=args.limit,
    )
    needed = needed_fingerprints(records)

    certs: dict[str, bytes] = {}
    load_needed_from_smime(Path(args.smime_certs), needed, certs)
    load_needed_from_bundles(Path(args.bundles), needed, certs)

    detail_path = output_dir / "tongsuo_sm2_invalid_cf_results.jsonl"
    summary_path = output_dir / "tongsuo_sm2_invalid_cf_summary.json"
    report_path = output_dir / "tongsuo_sm2_invalid_cf_report.md"

    record_status_counts: Counter[str] = Counter()
    chain_status_counts: Counter[str] = Counter()
    missing_material_records = 0
    complete_material_records = 0
    valid_records = 0
    invalid_records = 0

    def verify_record(task: tuple[int, dict[str, Any]], tmp_path: Path) -> dict[str, Any]:
        idx, rec = task
        chains = rec.get("chains") or []
        leaf_fp = str(rec.get("leaf_fingerprint", "")).lower()
        attempts = []
        record_valid = False
        record_missing = False

        for chain_index, chain in enumerate(chains):
            if not isinstance(chain, list):
                continue
            work_dir = tmp_path / f"r{idx}_c{chain_index}"
            work_dir.mkdir()
            result = verify_chain_with_tongsuo(
                tongsuo=tongsuo,
                chain=[str(fp) for fp in chain],
                certs=certs,
                timeout=args.timeout,
                work_dir=work_dir,
            )
            result["chain_index"] = chain_index
            attempts.append(result)
            if result["status"] == "OK":
                record_valid = True
            if result["status"] == "MISSING_CERTIFICATE_MATERIAL":
                record_missing = True

        if record_valid:
            record_status = "TONGSUO_VALID"
        elif record_missing:
            record_status = "MISSING_CERTIFICATE_MATERIAL"
        else:
            record_status = "TONGSUO_INVALID"

        return {
            "leaf_fingerprint": leaf_fp,
            "original_historical": rec.get("historical"),
            "original_status": rec.get("status"),
            "original_validation_result": rec.get("validation_result"),
            "chain_count": rec.get("chain_count"),
            "tongsuo_record_status": record_status,
            "attempts": attempts,
        }

    with tempfile.TemporaryDirectory(prefix="tongsuo_sm2_invalid_cf_") as tmp:
        tmp_path = Path(tmp)
        tasks = list(enumerate(records, 1))
        with detail_path.open("w", encoding="utf-8") as fout:
            with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
                futures = {executor.submit(verify_record, task, tmp_path): task[0] for task in tasks}
                completed = 0
                for fut in as_completed(futures):
                    detail = fut.result()
                    completed += 1

                    record_status = detail["tongsuo_record_status"]
                    record_status_counts[record_status] += 1
                    if record_status == "TONGSUO_VALID":
                        valid_records += 1
                        complete_material_records += 1
                    elif record_status == "MISSING_CERTIFICATE_MATERIAL":
                        missing_material_records += 1
                    else:
                        invalid_records += 1
                        complete_material_records += 1

                    for attempt in detail["attempts"]:
                        chain_status_counts[attempt["status"]] += 1

                    fout.write(json.dumps(detail, ensure_ascii=False) + "\n")
                    if completed % 1000 == 0:
                        print(
                            f"[progress] verified {completed}/{len(records)} records",
                            file=sys.stderr,
                            flush=True,
                        )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tongsuo_executable": str(tongsuo),
        "tongsuo_version": run_tongsuo_version(tongsuo),
        "inputs": {
            "sm2_keys": args.sm2_keys,
            "chain_results": args.chain_results,
            "smime_certs": args.smime_certs,
            "bundles": args.bundles,
        },
        "selected_records": len(records),
        "needed_certificate_fingerprints": len(needed),
        "resolved_certificate_fingerprints": len(certs),
        "missing_certificate_fingerprints": len(needed - set(certs)),
        "records_with_complete_material": complete_material_records,
        "records_with_missing_material": missing_material_records,
        "tongsuo_valid_records": valid_records,
        "tongsuo_invalid_records": invalid_records,
        "record_status_counts": dict(record_status_counts),
        "chain_attempt_status_counts": dict(chain_status_counts),
        "outputs": {
            "details": str(detail_path),
            "summary": str(summary_path),
            "report": str(report_path),
        },
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown_report(report_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
