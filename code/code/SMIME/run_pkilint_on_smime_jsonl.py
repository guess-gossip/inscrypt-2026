#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Run pkilint on SMIME JSONL produced by SMINE filtering."
    )
    p.add_argument(
        "--input",
        default="processing_output/smime_certs.jsonl",
        help="Input JSONL path (default: processing_output/smime_certs.jsonl)",
    )
    p.add_argument(
        "--output-dir",
        default="processing_output/pkilint",
        help="Output directory (default: processing_output/pkilint)",
    )
    p.add_argument(
        "--pkilint-bin",
        default="lint_cabf_smime_cert",
        help="pkilint executable name or full path",
    )
    p.add_argument(
        "--cutoff-date",
        default="2023-01-01",
        help="Only lint certs with notBefore >= this date, format YYYY-MM-DD "
             "(default: 2023-01-01 for paper reproduction)",
    )
    p.add_argument(
        "--no-cutoff",
        action="store_true",
        help="Disable issuance-date filtering and lint all certs",
    )
    p.add_argument(
        "--severity",
        default="ERROR",
        choices=["INFO", "NOTICE", "WARNING", "ERROR", "FATAL"],
        help="pkilint severity threshold (default: ERROR)",
    )
    p.add_argument(
        "--progress-every",
        type=int,
        default=10000,
        help="Print progress every N linted certs (default: 10000)",
    )
    p.add_argument(
        "--max-certs",
        type=int,
        default=0,
        help="Stop after linting this many eligible certs; 0 means no limit",
    )
    return p


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)


def parse_cutoff_date(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def load_cert_from_cert_data(cert_data: str) -> x509.Certificate:
    cert_data = cert_data.strip()

    if "-----BEGIN CERTIFICATE-----" in cert_data:
        return x509.load_pem_x509_certificate(cert_data.encode("utf-8"))

    der = base64.b64decode(cert_data, validate=False)
    return x509.load_der_x509_certificate(der)


def get_not_before_utc(cert: x509.Certificate) -> datetime:
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc
    dt = cert.not_valid_before
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def safe_json_loads(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return text


def classify_result(stdout_obj: Any, exit_code: int) -> int:
    """
    Best-effort finding count.
    pkilint documents that the process exit code is the number of reported findings.
    """
    if exit_code >= 0:
        return exit_code
    return 0


def main() -> int:
    args = build_argparser().parse_args()

    root = Path(__file__).resolve().parent
    input_path = (root / args.input).resolve()
    output_dir = (root / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        print(f"[!] Input not found: {input_path}", file=sys.stderr)
        return 1

    results_path = output_dir / "pkilint_results.jsonl"
    errors_path = output_dir / "pkilint_errors.jsonl"
    summary_path = output_dir / "pkilint_summary.json"

    cutoff = None if args.no_cutoff else parse_cutoff_date(args.cutoff_date)

    total_lines = 0
    decoded_ok = 0
    eligible_by_date = 0
    linted = 0
    skipped_pre_cutoff = 0
    decode_errors = 0
    lint_invocation_errors = 0
    zero_finding = 0
    nonzero_finding = 0

    with (
        input_path.open("r", encoding="utf-8", errors="replace") as fin,
        results_path.open("w", encoding="utf-8") as f_out,
        errors_path.open("w", encoding="utf-8") as f_err,
        tempfile.NamedTemporaryFile(suffix=".der", delete=True) as tmp_der,
    ):
        tmp_der_path = Path(tmp_der.name)

        for line_no, raw_line in enumerate(fin, start=1):
            line = raw_line.strip()
            if not line:
                continue

            total_lines += 1

            try:
                doc = json.loads(line)
                if not isinstance(doc, dict):
                    raise ValueError("JSON line is not an object")

                cert_data = doc.get("cert_data")
                if not isinstance(cert_data, str) or not cert_data.strip():
                    raise ValueError("missing cert_data")

                cert = load_cert_from_cert_data(cert_data)
                decoded_ok += 1

                not_before = get_not_before_utc(cert)

                if cutoff is not None and not_before < cutoff:
                    skipped_pre_cutoff += 1
                    continue

                eligible_by_date += 1

                der_bytes = cert.public_bytes(serialization.Encoding.DER)
                tmp_der_path.write_bytes(der_bytes)

                cmd = [
                    args.pkilint_bin,
                    "lint",
                    "-g",
                    "-o",
                    "-f",
                    "JSON",
                    "-s",
                    args.severity,
                    str(tmp_der_path),
                ]

                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )

                linted += 1

                stdout_text = proc.stdout.strip()
                stderr_text = proc.stderr.strip()

                stdout_obj = safe_json_loads(stdout_text) if stdout_text else None
                stderr_is_real_error = (
                    "usage:" in stderr_text.lower()
                    or "error:" in stderr_text.lower()
                    or "traceback" in stderr_text.lower()
                )

                if stderr_is_real_error:
                    finding_count = None
                    lint_invocation_errors += 1
                else:
                    finding_count = proc.returncode
                    if finding_count == 0:
                        zero_finding += 1
                    else:
                        nonzero_finding += 1

                out_doc = {
                    "line_no": line_no,
                    "id": doc.get("id") or doc.get("_id"),
                    "not_before": not_before.isoformat(),
                    "pkilint_cmd": " ".join(cmd[:-1]) + " <temp.der>",
                    "pkilint_exit_code": proc.returncode,
                    "finding_count": finding_count,
                    "detected_profile_stderr": stderr_text or None,
                    "pkilint_output": stdout_obj,
                }
                f_out.write(json_dumps(out_doc) + "\n")

                if args.max_certs > 0 and linted >= args.max_certs:
                    break

                if args.progress_every > 0 and linted > 0 and linted % args.progress_every == 0:
                    print(
                        f"[+] linted={linted} eligible={eligible_by_date} "
                        f"skipped_pre_cutoff={skipped_pre_cutoff} "
                        f"decode_errors={decode_errors} lint_invocation_errors={lint_invocation_errors}",
                        file=sys.stderr,
                    )

            except subprocess.SubprocessError as e:
                lint_invocation_errors += 1
                f_err.write(
                    json_dumps(
                        {
                            "line_no": line_no,
                            "stage": "pkilint_subprocess",
                            "error": str(e),
                            "raw": raw_line.rstrip("\n"),
                        }
                    )
                    + "\n"
                )
            except Exception as e:
                decode_errors += 1
                f_err.write(
                    json_dumps(
                        {
                            "line_no": line_no,
                            "stage": "decode_or_parse",
                            "error": str(e),
                            "raw": raw_line.rstrip("\n"),
                        }
                    )
                    + "\n"
                )

    summary = {
        "input": str(input_path),
        "output_dir": str(output_dir),
        "pkilint_bin": args.pkilint_bin,
        "severity": args.severity,
        "cutoff_date": None if args.no_cutoff else args.cutoff_date,
        "counts": {
            "total_lines": total_lines,
            "decoded_ok": decoded_ok,
            "eligible_by_date": eligible_by_date,
            "skipped_pre_cutoff": skipped_pre_cutoff,
            "linted": linted,
            "decode_errors": decode_errors,
            "lint_invocation_errors": lint_invocation_errors,
            "zero_finding": zero_finding,
            "nonzero_finding": nonzero_finding,
        },
        "outputs": {
            "results": str(results_path),
            "errors": str(errors_path),
            "summary": str(summary_path),
        },
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())