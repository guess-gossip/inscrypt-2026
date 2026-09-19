#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Aggregate pkilint_results.jsonl into paper-style BR statistics."
    )
    p.add_argument(
        "--input",
        default="processing_output/pkilint/pkilint_results.jsonl",
        help="Input JSONL path (default: processing_output/pkilint/pkilint_results.jsonl)",
    )
    p.add_argument(
        "--output-dir",
        default="processing_output/pkilint/aggregate_v2",
        help="Output directory (default: processing_output/pkilint/aggregate_v2)",
    )
    p.add_argument(
        "--top-n",
        type=int,
        default=100,
        help="Top N rows for code/validator outputs (default: 100)",
    )
    return p


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def map_code_to_group(code: str, validator: str = "", message: str = "") -> str:
    """
    Best-effort grouping aligned more closely to the paper's BR error categories.
    This is still an approximation, but much tighter than the first version.
    """

    code = normalize_text(code)
    validator = normalize_text(validator)
    message = normalize_text(message).lower()

    # ---------- Missing Mandatory Information ----------
    missing_exact = {
        "cabf.smime.missing_required_attribute",
        "cabf.smime.certificate_policies_extension_missing",
        "cabf.smime.san_extension_missing",
        "cabf.smime.extended_key_usage_extension_missing",
        "cabf.smime.key_usage_extension_missing",
        "cabf.smime.no_required_reserved_policy_oid",
        "pkix.authority_key_identifier_extension_absent",
        "pkix.authority_key_identifier_keyid_missing",
        "cabf.smime.required_attribute_missing_for_dependent_attribute",
    }
    if code in missing_exact:
        return "Missing Mandatory Information"

    missing_substrings = [
        "missing_required",
        "extension_missing",
        "required_attribute_missing",
        "authority_key_identifier",
        "no_required_reserved_policy_oid",
        "san_does_not_contain_email_address",
        "subject_email_address_not_in_san",
        "aia_ocsp_has_no_http_uri",
        "aia_ca_issuers_has_no_http_uri",
        "no_http_crldp_uri",
        "crldp_fullname_prohibited_uri_scheme",
    ]
    if any(x in code for x in missing_substrings):
        return "Missing Mandatory Information"

    if "PresenceValidator" in validator:
        return "Missing Mandatory Information"

    # ---------- Key Usage Issue ----------
    key_usage_exact = {
        "cabf.smime.prohibited_ku_present",
        "cabf.smime.prohibited_eku_present",
        "cabf.smime.unknown_certificate_key_usage_type",
        "pkix.ca_certificate_keycertsign_keyusage_not_set",
    }
    if code in key_usage_exact:
        return "Key Usage Issue"

    key_usage_substrings = [
        "_ku_",
        "_eku_",
        "key_usage",
        "extended_key_usage",
    ]
    if any(x in code for x in key_usage_substrings):
        return "Key Usage Issue"

    if "KeyUsage" in validator or "ExtendedKeyUsage" in validator:
        return "Key Usage Issue"

    # ---------- Insecure Parameters ----------
    insecure_exact = {
        "cabf.smime.certificate_validity_period_exceeds_1185_days",
        "cabf.rsa_modulus_invalid_length",
        "cabf.smime.prohibited_signature_algorithm_encoding",
        "cabf.smime.prohibited_spki_algorithm_encoding",
        "cabf.smime.anypolicy_present",
    }
    if code in insecure_exact:
        return "Insecure Parameters"

    insecure_substrings = [
        "validity_period_exceeds",
        "rsa_modulus",
        "algorithm_encoding",
        "spki_algorithm",
        "signature_algorithm",
        "modulus_invalid_length",
        "anypolicy",
        "weak_",
        "deprecated",
        "prohibited_signature_algorithm",
        "prohibited_spki_algorithm",
    ]
    if any(x in code for x in insecure_substrings):
        return "Insecure Parameters"

    if "ValidityPeriod" in validator:
        return "Insecure Parameters"

    # ---------- Prohibited Value ----------
    prohibited_exact = {
        "cabf.smime.prohibited_attribute",
        "cabf.smime.prohibited_generalname_type_present",
        "cabf.smime.crldp_fullname_prohibited_generalname_type",
        "cabf.internal_domain_name",
        "cabf.internal_ip_address",
        "cabf.smime.is_ca_certificate",
    }
    if code in prohibited_exact:
        return "Prohibited Value"

    prohibited_substrings = [
        "prohibited_attribute",
        "prohibited_generalname_type",
        "internal_domain_name",
        "internal_ip_address",
        "is_ca_certificate",
        "ca_certificate",
    ]
    if any(x in code for x in prohibited_substrings):
        return "Prohibited Value"

    # ---------- Faulty Value ----------
    faulty_exact = {
        "pkix.invalid_uri_syntax",
        "pkix.invalid_domain_name_syntax",
        "pkix.invalid_email_address_syntax",
        "itu.invalid_asn1_syntax",
        "itu.invalid_printablestring_character",
        "itu.bitstring_not_der_encoded",
        "cabf.cps_uri_is_not_http",
        "cabf.invalid_country_code",
        "msft.invalid_user_principal_name_syntax",
    }
    if code in faulty_exact:
        return "Faulty Value"

    faulty_substrings = [
        "invalid_uri_syntax",
        "invalid_domain_name_syntax",
        "invalid_email_address_syntax",
        "invalid_asn1_syntax",
        "invalid_printablestring",
        "bitstring_not_der_encoded",
        "invalid_country_code",
        "not_http",
        "invalid_",
        "malformed",
        "bad_value",
    ]
    if any(x in code for x in faulty_substrings):
        return "Faulty Value"

    # ---------- Wrong Criticality ----------
    wrong_criticality_exact = {
        "cabf.critical_crldp_extension",
        "pkix.basic_constraints_extension_not_critical",
        "pkix.authority_key_identifier_critical",
        "pkix.certificate_skid_extension_critical",
    }
    if code in wrong_criticality_exact:
        return "Wrong Criticality"

    if "critical" in code or "Criticality" in validator:
        return "Wrong Criticality"

    # ---------- Unknown Value ----------
    unknown_exact = {
        "cabf.smime.common_name_value_unknown_source",
    }
    if code in unknown_exact:
        return "Unknown Value"

    unknown_substrings = [
        "unknown_source",
        "unknown_",
        "unrecognized",
        "unsupported",
    ]
    if any(x in code for x in unknown_substrings):
        return "Unknown Value"

    # ---------- Oversharing Information ----------
    oversharing_substrings = [
        "oversharing",
        "contains_extra_attribute",
        "contains_extra_information",
        "too_many_attributes",
        "insignificant_attribute_value_present",
    ]
    if any(x in code for x in oversharing_substrings):
        return "Oversharing Information"

    # ---------- base/internal parser exceptions ----------
    if code == "base.unhandled_exception":
        return "Other"

    return "Other"


def write_counter_json(path: Path, counter: Counter, top_n: int | None = None, key_name: str = "key"):
    items = counter.most_common(top_n)
    payload = [{key_name: k, "count": v} for k, v in items]
    path.write_text(json_dumps(payload), encoding="utf-8")


def write_counter_csv(path: Path, counter: Counter, header_key: str, top_n: int | None = None):
    items = counter.most_common(top_n)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([header_key, "count"])
        for k, v in items:
            w.writerow([k, v])


def write_group_with_codes_json(path: Path, group_counter: Counter, group_to_codes: dict[str, Counter], top_n: int):
    payload = []
    for group, count in group_counter.most_common():
        payload.append(
            {
                "group": group,
                "count": count,
                "top_codes": [
                    {"code": code, "count": c}
                    for code, c in group_to_codes.get(group, Counter()).most_common(top_n)
                ],
            }
        )
    path.write_text(json_dumps(payload), encoding="utf-8")


def main() -> int:
    args = build_argparser().parse_args()

    root = Path(__file__).resolve().parent
    input_path = (root / args.input).resolve()
    output_dir = (root / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    total_docs = 0
    docs_with_results = 0
    docs_with_findings = 0
    total_findings = 0

    code_counter = Counter()
    validator_counter = Counter()
    group_counter = Counter()
    finding_count_distribution = Counter()
    profile_counter = Counter()

    docs_per_code = Counter()
    docs_per_group = Counter()
    docs_per_validator = Counter()

    group_to_codes: dict[str, Counter] = {}
    line_errors = []

    with input_path.open("r", encoding="utf-8", errors="replace") as fin:
        for line_no, raw_line in enumerate(fin, start=1):
            line = raw_line.strip()
            if not line:
                continue

            total_docs += 1

            try:
                doc = json.loads(line)
                if not isinstance(doc, dict):
                    raise ValueError("JSON line is not an object")

                results_obj = doc.get("pkilint_output")
                findings = results_obj.get("results", []) if isinstance(results_obj, dict) else []
                profile = normalize_text(doc.get("detected_profile_stderr"))

                if profile:
                    profile_counter[profile] += 1

                docs_with_results += 1

                finding_count_distribution[int(doc.get("finding_count", 0) or 0)] += 1

                per_doc_codes = set()
                per_doc_groups = set()
                per_doc_validators = set()

                if findings:
                    docs_with_findings += 1

                for result in findings:
                    validator = normalize_text(result.get("validator")) or "UNKNOWN_VALIDATOR"
                    validator_counter[validator] += 1
                    per_doc_validators.add(validator)

                    descs = result.get("finding_descriptions", [])
                    for desc in descs:
                        code = normalize_text(desc.get("code")) or "UNKNOWN_CODE"
                        message = normalize_text(desc.get("message"))
                        group = map_code_to_group(code, validator=validator, message=message)

                        total_findings += 1
                        code_counter[code] += 1
                        group_counter[group] += 1
                        per_doc_codes.add(code)
                        per_doc_groups.add(group)

                        if group not in group_to_codes:
                            group_to_codes[group] = Counter()
                        group_to_codes[group][code] += 1

                for code in per_doc_codes:
                    docs_per_code[code] += 1
                for group in per_doc_groups:
                    docs_per_group[group] += 1
                for validator in per_doc_validators:
                    docs_per_validator[validator] += 1

            except Exception as e:
                line_errors.append(
                    {
                        "line_no": line_no,
                        "error": str(e),
                        "raw": raw_line.rstrip("\n")[:2000],
                    }
                )

    summary = {
        "input": str(input_path),
        "counts": {
            "total_docs": total_docs,
            "docs_with_results": docs_with_results,
            "docs_with_findings": docs_with_findings,
            "total_findings": total_findings,
            "distinct_codes": len(code_counter),
            "distinct_validators": len(validator_counter),
            "distinct_groups": len(group_counter),
            "distinct_profiles": len(profile_counter),
            "line_parse_errors": len(line_errors),
        },
        "outputs": {
            "summary": str(output_dir / "aggregate_summary.json"),
            "top_codes_json": str(output_dir / "top_codes.json"),
            "top_codes_csv": str(output_dir / "top_codes.csv"),
            "top_validators_json": str(output_dir / "top_validators.json"),
            "top_validators_csv": str(output_dir / "top_validators.csv"),
            "top_groups_json": str(output_dir / "top_groups.json"),
            "top_groups_csv": str(output_dir / "top_groups.csv"),
            "docs_per_code_json": str(output_dir / "docs_per_code.json"),
            "docs_per_group_json": str(output_dir / "docs_per_group.json"),
            "docs_per_validator_json": str(output_dir / "docs_per_validator.json"),
            "profiles_json": str(output_dir / "profiles.json"),
            "finding_count_distribution_json": str(output_dir / "finding_count_distribution.json"),
            "group_with_codes_json": str(output_dir / "group_with_codes.json"),
            "aggregate_line_errors_json": str(output_dir / "aggregate_line_errors.json"),
        },
    }

    (output_dir / "aggregate_summary.json").write_text(json_dumps(summary), encoding="utf-8")

    write_counter_json(output_dir / "top_codes.json", code_counter, top_n=args.top_n, key_name="code")
    write_counter_csv(output_dir / "top_codes.csv", code_counter, "code", top_n=args.top_n)

    write_counter_json(output_dir / "top_validators.json", validator_counter, top_n=args.top_n, key_name="validator")
    write_counter_csv(output_dir / "top_validators.csv", validator_counter, "validator", top_n=args.top_n)

    write_counter_json(output_dir / "top_groups.json", group_counter, top_n=None, key_name="group")
    write_counter_csv(output_dir / "top_groups.csv", group_counter, "group", top_n=None)

    write_counter_json(output_dir / "docs_per_code.json", docs_per_code, top_n=args.top_n, key_name="code")
    write_counter_json(output_dir / "docs_per_group.json", docs_per_group, top_n=None, key_name="group")
    write_counter_json(output_dir / "docs_per_validator.json", docs_per_validator, top_n=args.top_n, key_name="validator")
    write_counter_json(output_dir / "profiles.json", profile_counter, top_n=None, key_name="profile")
    write_counter_json(output_dir / "finding_count_distribution.json", finding_count_distribution, top_n=None, key_name="finding_count")

    write_group_with_codes_json(
        output_dir / "group_with_codes.json",
        group_counter=group_counter,
        group_to_codes=group_to_codes,
        top_n=args.top_n,
    )

    (output_dir / "aggregate_line_errors.json").write_text(
        json_dumps(line_errors[:1000]),
        encoding="utf-8",
    )

    print(json_dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())