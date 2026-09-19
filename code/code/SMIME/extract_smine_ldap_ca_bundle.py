#!/usr/bin/env python3
import argparse
import base64
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes


def load_cert_from_text(text: str):
    text = text.strip()
    if not text:
        return None

    # PEM
    if "BEGIN CERTIFICATE" in text:
        return x509.load_pem_x509_certificate(text.encode("utf-8"))

    # base64 DER
    try:
        der = base64.b64decode(text, validate=False)
        return x509.load_der_x509_certificate(der)
    except Exception:
        return None


def is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bool(bc.ca)
    except Exception:
        return cert.issuer == cert.subject


def cert_fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def iter_input_files(path: Path):
    if path.is_file():
        yield path
        return
    for p in path.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".jsonl", ".json", ".pem", ".crt", ".cer", ".txt"}:
            yield p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="file or directory containing crawled cert data")
    ap.add_argument("--output", default="crt-bundles/smine_ldap_ca_bundle.crt")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    seen = set()
    ca_pems = []

    for file in iter_input_files(in_path):
        try:
            if file.suffix.lower() == ".jsonl":
                with open(file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        cert_data = obj.get("cert_data")
                        if not isinstance(cert_data, str):
                            continue
                        cert = load_cert_from_text(cert_data)
                        if cert and is_ca(cert):
                            fp = cert_fp(cert)
                            if fp not in seen:
                                seen.add(fp)
                                ca_pems.append(cert_to_pem(cert))

            elif file.suffix.lower() == ".json":
                with open(file, "r", encoding="utf-8") as f:
                    try:
                        obj = json.load(f)
                    except Exception:
                        continue

                candidates = []
                if isinstance(obj, dict):
                    if isinstance(obj.get("cert_data"), str):
                        candidates.append(obj["cert_data"])
                elif isinstance(obj, list):
                    for item in obj:
                        if isinstance(item, dict) and isinstance(item.get("cert_data"), str):
                            candidates.append(item["cert_data"])

                for cert_data in candidates:
                    cert = load_cert_from_text(cert_data)
                    if cert and is_ca(cert):
                        fp = cert_fp(cert)
                        if fp not in seen:
                            seen.add(fp)
                            ca_pems.append(cert_to_pem(cert))

            else:
                text = file.read_text(encoding="utf-8", errors="ignore")
                cert = load_cert_from_text(text)
                if cert and is_ca(cert):
                    fp = cert_fp(cert)
                    if fp not in seen:
                        seen.add(fp)
                        ca_pems.append(cert_to_pem(cert))

        except Exception:
            pass

    with open(out_path, "w", encoding="utf-8") as f:
        for pem in ca_pems:
            f.write(pem)
            if not pem.endswith("\n"):
                f.write("\n")

    print(f"[+] Wrote {len(ca_pems)} CA certs to {out_path}")


if __name__ == "__main__":
    main()
