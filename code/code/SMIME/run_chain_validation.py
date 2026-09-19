#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

from chain_verification.smime_chain_verifier.bundles.load_crt_bundles import load_crt_bundles
from chain_verification.smime_chain_verifier.utils.cert import (
    convert_to_pem,
    get_access_locations,
    get_cert_fingerprint,
    get_issuer_hash,
    get_subject_hash,
    is_root,
)
from chain_verification.smime_chain_verifier.utils.cert_parser import x509CertificateParser
from chain_verification.smime_chain_verifier.utils.request_cert import request_certificate

TRUSTED_BUNDLE_KEYS = {"mozilla", "microsoft", "macOS", "chrome"}


def name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    vals = name.get_attributes_for_oid(oid)
    return vals[0].value if vals else None


class CAStore:
    def __init__(self) -> None:
        self.by_fp: dict[str, x509.Certificate] = {}
        self.by_subject_hash: dict[str, list[x509.Certificate]] = defaultdict(list)
        self.origins: dict[str, set[str]] = defaultdict(set)
        self.seen_access_locations: set[str] = set()

    def add_cert(self, cert: x509.Certificate, origin: str) -> bool:
        fp = get_cert_fingerprint(cert)
        is_new = fp not in self.by_fp
        if is_new:
            self.by_fp[fp] = cert
            self.by_subject_hash[get_subject_hash(cert)].append(cert)
        self.origins[fp].add(origin)
        return is_new

    def get_issuers(self, cert: x509.Certificate) -> list[x509.Certificate]:
        return self.by_subject_hash.get(get_issuer_hash(cert), [])

    def get_origins(self, cert: x509.Certificate) -> set[str]:
        return self.origins.get(get_cert_fingerprint(cert), set())


def unique_by_issuer(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    seen = set()
    out: list[x509.Certificate] = []
    for cert in certs:
        issuer_key = cert.issuer.rfc4514_string()
        if issuer_key not in seen:
            seen.add(issuer_key)
            out.append(cert)
    return out


def build_candidate_chains(
    store: CAStore,
    leaf: x509.Certificate,
    max_depth: int = 10,
) -> list[list[x509.Certificate]]:
    chains: list[list[x509.Certificate]] = []

    def dfs(chain: list[x509.Certificate], depth: int) -> None:
        last = chain[-1]
        if depth >= max_depth or is_root(last):
            chains.append(chain)
            return

        issuers = unique_by_issuer(store.get_issuers(last))
        extended = False
        for issuer in issuers:
            # 避免 A->B, B->A 之类的环
            if any(c.subject == issuer.subject for c in chain):
                continue
            extended = True
            dfs(chain + [issuer], depth + 1)

        if not extended:
            chains.append(chain)

    dfs([leaf], 0)
    return chains


def validate_chain(chain: list[x509.Certificate]) -> tuple[str, str]:
    if len(chain) < 2:
        return ("INVALID_CNF", "Chain must include at least a leaf and a root certificate.")

    try:
        leaf = crypto.load_certificate(crypto.FILETYPE_PEM, convert_to_pem(chain[0]))
        store = crypto.X509Store()

        # chain[1:] 里包含中间证书和根证书
        for cert in chain[1:]:
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, convert_to_pem(cert)))

        # 与仓库逻辑保持一致：关闭时间检查，是否过期单独输出
        store.set_flags(0x200000)

        ctx = crypto.X509StoreContext(store, leaf)
        ctx.verify_certificate()
        return ("VALID", "")

    except crypto.X509StoreContextError as e:
        return ("INVALID_CF", str(e))
    except Exception as e:
        return ("INVALID_CF", str(e))


def classify_chain_status(
    store: CAStore,
    chains: list[list[x509.Certificate]],
) -> tuple[str, str, dict[str, int] | None, dict[str, str] | None]:
    """
    返回:
      status: trusted / untrusted / non_validatable
      validation_result: VALID / INVALID_CF / INVALID_CNF
      origin_info
      root_info
    """
    best_invalid = ("INVALID_CNF", "")
    saw_valid_untrusted = None

    for chain in chains:
        vr, err = validate_chain(chain)

        if vr != "VALID":
            best_invalid = (vr, err)
            continue

        root = chain[-1]
        origins = store.get_origins(root)
        origin_info = {
            "mozilla": int(any("mozilla" in x for x in origins)),
            "microsoft": int(any("microsoft" in x for x in origins)),
            "macOS": int(any("macOS" in x for x in origins)),
            "chrome": int(any("chrome" in x for x in origins)),
            "cencys": int(any("cencys" in x for x in origins)),
            "ccadb": int(any("ccadb" in x for x in origins)),
            "smine": int(any("smine" in x for x in origins)),
            "aia": int(any("aia" in x for x in origins)),
        }
        root_info = {
            "common_name": name_attr(root.issuer, NameOID.COMMON_NAME),
            "organizational_unit_name": name_attr(root.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "organization_name": name_attr(root.issuer, NameOID.ORGANIZATION_NAME),
        }

        if any(origin_info[k] == 1 for k in TRUSTED_BUNDLE_KEYS):
            return ("trusted", vr, origin_info, root_info)

        saw_valid_untrusted = ("untrusted", vr, origin_info, root_info)

    if saw_valid_untrusted is not None:
        return saw_valid_untrusted

    return ("non_validatable", best_invalid[0], None, None)


def enrich_store_from_aia(
    store: CAStore,
    leaf: x509.Certificate,
    workers: int = 8,
    aia_max_depth: int = 10,
) -> None:
    pending = {
        loc for loc in get_access_locations(leaf)
        if loc not in store.seen_access_locations
    }

    for _ in range(aia_max_depth):
        if not pending:
            break

        newly_added: list[x509.Certificate] = []

        with ThreadPoolExecutor(max_workers=workers) as ex:
            fut_map = {ex.submit(request_certificate, loc): loc for loc in pending}
            for fut in as_completed(fut_map):
                loc = fut_map[fut]
                store.seen_access_locations.add(loc)
                try:
                    cert = fut.result()
                    if store.add_cert(cert, "aia"):
                        newly_added.append(cert)
                except Exception:
                    # 网络失败 / LDAP失败 / 非证书内容，直接跳过
                    pass

        next_pending = set()
        for cert in newly_added:
            for loc in get_access_locations(cert):
                if loc not in store.seen_access_locations:
                    next_pending.add(loc)

        pending = next_pending


def load_ca_bundles(bundle_dir: Path) -> CAStore:
    store = CAStore()
    crt_bundles = load_crt_bundles(str(bundle_dir))
    for filename, certs in crt_bundles:
        for cert in certs:
            store.add_cert(cert, filename)
    return store


def cert_to_fp_chain(chain: list[x509.Certificate]) -> list[str]:
    return [get_cert_fingerprint(c) for c in chain]


def is_historical(cert: x509.Certificate) -> bool:
    now = datetime.now(timezone.utc)
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return now > not_after


def process_leaf(
    parser: x509CertificateParser,
    store: CAStore,
    record: dict[str, Any],
    workers: int,
    aia_max_depth: int,
    fetch_aia: bool,
) -> dict[str, Any]:
    cert = parser.parse(record["cert_data"])
    leaf_fp = get_cert_fingerprint(cert)

    if fetch_aia:
        enrich_store_from_aia(store, cert, workers=workers, aia_max_depth=aia_max_depth)

    chains = build_candidate_chains(store, cert, max_depth=10)
    status, validation_result, origin_info, root_info = classify_chain_status(store, chains)

    result = {
        "id": record.get("_id") or record.get("id") or leaf_fp,
        "leaf_fingerprint": leaf_fp,
        "historical": is_historical(cert),
        "status": status,
        "validation_result": validation_result,
        "chain_count": len(chains),
        "origin_info": origin_info,
        "root_info": root_info,
        "chains": [cert_to_fp_chain(chain) for chain in chains],
    }
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Run S/MIME chain validation after pkilint.")
    ap.add_argument("--input", required=True, help="Path to smime_certs.jsonl")
    ap.add_argument("--bundles", required=True, help="Directory containing *.crt bundles")
    ap.add_argument("--output", required=True, help="Path to output chain_results.jsonl")
    ap.add_argument("--summary", required=True, help="Path to output chain_summary.json")
    ap.add_argument("--workers", type=int, default=8, help="Workers for AIA fetching")
    ap.add_argument("--aia-max-depth", type=int, default=10, help="Recursive AIA fetch depth")
    ap.add_argument("--no-aia", action="store_true", help="Disable fetching issuer certs from AIA")
    args = ap.parse_args()

    parser = x509CertificateParser()
    store = load_ca_bundles(Path(args.bundles))

    counters = Counter()
    validation_counters = Counter()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(args.input, "r", encoding="utf-8") as fin, open(out_path, "w", encoding="utf-8") as fout:
        for line_no, line in enumerate(fin, 1):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
                if "cert_data" not in record:
                    raise ValueError("Missing cert_data")
            except Exception as e:
                result = {
                    "id": f"line-{line_no}",
                    "status": "non_validatable",
                    "validation_result": "INVALID_CERT",
                    "error": f"Bad input line: {e}",
                }
                fout.write(json.dumps(result, ensure_ascii=False) + "\n")
                counters["non_validatable"] += 1
                validation_counters["INVALID_CERT"] += 1
                continue

            try:
                result = process_leaf(
                    parser=parser,
                    store=store,
                    record=record,
                    workers=args.workers,
                    aia_max_depth=args.aia_max_depth,
                    fetch_aia=not args.no_aia,
                )
            except Exception as e:
                result = {
                    "id": record.get("_id") or record.get("id") or f"line-{line_no}",
                    "status": "non_validatable",
                    "validation_result": "INVALID_CERT",
                    "error": str(e),
                }

            fout.write(json.dumps(result, ensure_ascii=False) + "\n")

            counters[result["status"]] += 1
            validation_counters[result["validation_result"]] += 1
            if result.get("historical") is True:
                counters["historical"] += 1
            elif result.get("historical") is False:
                counters["non_historical"] += 1

    summary = {
        "input": args.input,
        "bundles": args.bundles,
        "output": args.output,
        "total": sum(counters[k] for k in ("trusted", "untrusted", "non_validatable")),
        "status_counts": {
            "trusted": counters["trusted"],
            "untrusted": counters["untrusted"],
            "non_validatable": counters["non_validatable"],
        },
        "historical_counts": {
            "historical": counters["historical"],
            "non_historical": counters["non_historical"],
        },
        "validation_result_counts": dict(validation_counters),
    }

    summary_path = Path(args.summary)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()