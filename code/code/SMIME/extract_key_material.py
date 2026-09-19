#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"

# Accept both the standard SM2 curve OID and the alternate OID observed in your data/errors.
SM2_CURVE_OIDS = {
    "1.2.156.10197.1.301",  # standard SM2 curve OID seen in most certs
    "1.2.156.197.1.301",    # alternate OID observed in your parse_errors.jsonl
}


def load_cert_from_row(row: Dict[str, Any]) -> Tuple[Optional[x509.Certificate], Optional[bytes], str]:
    """
    Support common field names:
      - cert_data
      - cert
      - pem
      - certificate
      - der_b64
    """
    candidates = [
        row.get("cert_data"),
        row.get("cert"),
        row.get("pem"),
        row.get("certificate"),
        row.get("der_b64"),
    ]
    candidates = [c for c in candidates if c]

    if not candidates:
        return None, None, "missing_certificate_field"

    raw = candidates[0]

    if isinstance(raw, str):
        s = raw.strip()

        # PEM
        if "BEGIN CERTIFICATE" in s:
            try:
                cert = x509.load_pem_x509_certificate(s.encode("utf-8"))
                der = cert.public_bytes(serialization.Encoding.DER)
                return cert, der, ""
            except Exception as e:
                return None, None, f"pem_parse_error:{e}"

        # base64 DER
        try:
            der = base64.b64decode(s, validate=False)
            cert = x509.load_der_x509_certificate(der)
            return cert, der, ""
        except Exception:
            pass

        # maybe hex DER
        try:
            der = bytes.fromhex(s)
            cert = x509.load_der_x509_certificate(der)
            return cert, der, ""
        except Exception as e:
            return None, None, f"unknown_cert_encoding:{e}"

    return None, None, "unsupported_certificate_type"


def safe_subject(cert: x509.Certificate) -> str:
    try:
        return cert.subject.rfc4514_string()
    except Exception:
        return ""


def safe_issuer(cert: x509.Certificate) -> str:
    try:
        return cert.issuer.rfc4514_string()
    except Exception:
        return ""


def safe_subject_cn(cert: x509.Certificate) -> str:
    try:
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def safe_issuer_cn(cert: x509.Certificate) -> str:
    try:
        attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def safe_not_before(cert: x509.Certificate) -> str:
    try:
        return cert.not_valid_before_utc.isoformat()
    except Exception:
        try:
            return cert.not_valid_before.isoformat()
        except Exception:
            return ""


def safe_not_after(cert: x509.Certificate) -> str:
    try:
        return cert.not_valid_after_utc.isoformat()
    except Exception:
        try:
            return cert.not_valid_after.isoformat()
        except Exception:
            return ""


def cert_fingerprint_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def spki_sha256_from_spki_der(spki_der: bytes) -> str:
    return hashlib.sha256(spki_der).hexdigest()


def int_to_fixed_hex(n: int, byte_len: int) -> str:
    return format(n, f"0{byte_len * 2}x")


# -----------------------------
# Minimal DER helpers
# -----------------------------
def read_length(data: bytes, offset: int) -> Tuple[int, int]:
    first = data[offset]
    if first < 0x80:
        return first, 1
    nbytes = first & 0x7F
    if nbytes == 0:
        raise ValueError("Indefinite length DER is not supported")
    length = int.from_bytes(data[offset + 1: offset + 1 + nbytes], "big")
    return length, 1 + nbytes


def read_tlv(data: bytes, offset: int) -> Dict[str, Any]:
    if offset >= len(data):
        raise ValueError("Offset out of bounds")

    tag = data[offset]
    length, len_len = read_length(data, offset + 1)
    header_len = 1 + len_len
    value_start = offset + header_len
    end = value_start + length

    if end > len(data):
        raise ValueError("TLV length exceeds buffer")

    return {
        "tag": tag,
        "start": offset,
        "header_len": header_len,
        "value_start": value_start,
        "length": length,
        "end": end,
        "value": data[value_start:end],
        "full": data[offset:end],
    }


def parse_sequence_children(seq_tlv: Dict[str, Any]) -> List[Dict[str, Any]]:
    if seq_tlv["tag"] != 0x30:
        raise ValueError("Expected SEQUENCE")
    children = []
    i = 0
    value = seq_tlv["value"]
    while i < len(value):
        child = read_tlv(value, i)
        children.append(child)
        i = child["end"]
    return children


def decode_oid(oid_bytes: bytes) -> str:
    if not oid_bytes:
        raise ValueError("Empty OID bytes")

    first = oid_bytes[0]
    oid = [first // 40, first % 40]

    value = 0
    for b in oid_bytes[1:]:
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            oid.append(value)
            value = 0

    if value != 0:
        raise ValueError("Malformed OID encoding")

    return ".".join(str(x) for x in oid)


def extract_spki_metadata_from_der(cert_der: bytes) -> Dict[str, Any]:
    """
    Extract algorithm OID / curve OID / raw BIT STRING public key bytes
    without relying on cryptography's public_key() support.
    """
    top = read_tlv(cert_der, 0)
    top_children = parse_sequence_children(top)
    if len(top_children) < 1:
        raise ValueError("Malformed certificate SEQUENCE")

    tbs = top_children[0]
    tbs_children = parse_sequence_children(tbs)

    idx = 0
    if tbs_children and tbs_children[0]["tag"] == 0xA0:  # [0] EXPLICIT version
        idx = 1

    spki_index = idx + 5
    if len(tbs_children) <= spki_index:
        raise ValueError("TBSCertificate missing SPKI")

    spki = tbs_children[spki_index]
    spki_children = parse_sequence_children(spki)
    if len(spki_children) < 2:
        raise ValueError("Malformed SubjectPublicKeyInfo")

    alg = spki_children[0]
    bitstr = spki_children[1]

    alg_children = parse_sequence_children(alg)
    if not alg_children or alg_children[0]["tag"] != 0x06:
        raise ValueError("SPKI algorithm missing OID")

    algorithm_oid = decode_oid(alg_children[0]["value"])
    curve_oid = None

    if len(alg_children) >= 2 and alg_children[1]["tag"] == 0x06:
        curve_oid = decode_oid(alg_children[1]["value"])

    if bitstr["tag"] != 0x03:
        raise ValueError("SPKI public key is not BIT STRING")

    bitstr_value = bitstr["value"]
    if not bitstr_value:
        raise ValueError("Empty BIT STRING in SPKI")

    unused_bits = bitstr_value[0]
    public_key_bytes = bitstr_value[1:]

    return {
        "algorithm_oid": algorithm_oid,
        "curve_oid": curve_oid,
        "unused_bits": unused_bits,
        "public_key_bytes": public_key_bytes,
        "spki_der": spki["full"],
    }


def extract_ec_point_from_spki_public_key_bytes(public_key_bytes: bytes) -> Dict[str, Any]:
    """
    EC/SM2 public key point usually encoded as:
      04 || X || Y   (uncompressed)
      02/03 || X     (compressed)
    """
    if not public_key_bytes:
        return {
            "point_format": "missing",
            "point_hex": None,
            "x_hex": None,
            "y_hex": None,
        }

    first = public_key_bytes[0]
    if first == 0x04:
        if (len(public_key_bytes) - 1) % 2 != 0:
            return {
                "point_format": "uncompressed_invalid_length",
                "point_hex": public_key_bytes.hex(),
                "x_hex": None,
                "y_hex": None,
            }
        coord_len = (len(public_key_bytes) - 1) // 2
        x = public_key_bytes[1:1 + coord_len]
        y = public_key_bytes[1 + coord_len:]
        return {
            "point_format": "uncompressed",
            "point_hex": public_key_bytes.hex(),
            "x_hex": x.hex(),
            "y_hex": y.hex(),
        }

    if first in (0x02, 0x03):
        return {
            "point_format": "compressed",
            "point_hex": public_key_bytes.hex(),
            "x_hex": public_key_bytes[1:].hex(),
            "y_hex": None,
        }

    return {
        "point_format": f"unknown_0x{first:02x}",
        "point_hex": public_key_bytes.hex(),
        "x_hex": None,
        "y_hex": None,
    }


def exception_mentions_sm2(exc_text: str) -> bool:
    if not exc_text:
        return False
    return any(oid in exc_text for oid in SM2_CURVE_OIDS)


def is_sm2_spki(spki_meta: Optional[Dict[str, Any]], exc_text: str = "") -> bool:
    if exception_mentions_sm2(exc_text):
        return True
    if spki_meta is None:
        return False

    alg_oid = spki_meta.get("algorithm_oid")
    curve_oid = spki_meta.get("curve_oid")
    return (curve_oid in SM2_CURVE_OIDS) or (alg_oid in SM2_CURVE_OIDS)


def normalize_sm2_curve_oid(spki_meta: Optional[Dict[str, Any]]) -> str:
    if spki_meta is None:
        return "1.2.156.10197.1.301"
    curve_oid = spki_meta.get("curve_oid")
    if curve_oid in SM2_CURVE_OIDS:
        return curve_oid
    return "1.2.156.10197.1.301"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="smime_certs.jsonl")
    ap.add_argument("--outdir", required=True, help="output dir")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    rsa_path = os.path.join(args.outdir, "rsa_keys.jsonl")
    ecc_path = os.path.join(args.outdir, "ecc_keys.jsonl")
    sm2_path = os.path.join(args.outdir, "sm2_keys.jsonl")
    other_path = os.path.join(args.outdir, "other_keys.jsonl")
    err_path = os.path.join(args.outdir, "parse_errors.jsonl")

    rsa_out = open(rsa_path, "w", encoding="utf-8")
    ecc_out = open(ecc_path, "w", encoding="utf-8")
    sm2_out = open(sm2_path, "w", encoding="utf-8")
    other_out = open(other_path, "w", encoding="utf-8")
    err_out = open(err_path, "w", encoding="utf-8")

    total = 0
    rsa_count = 0
    ecc_count = 0
    sm2_count = 0
    other_count = 0
    err_count = 0

    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            total += 1
            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
            except Exception as e:
                err_out.write(json.dumps({
                    "row_number": total,
                    "error": f"json_error:{e}",
                }, ensure_ascii=False) + "\n")
                err_count += 1
                continue

            cert, der, err = load_cert_from_row(row)
            if cert is None or der is None:
                err_out.write(json.dumps({
                    "row_number": total,
                    "error": err,
                }, ensure_ascii=False) + "\n")
                err_count += 1
                continue

            try:
                fp = cert_fingerprint_sha256(der)

                base = {
                    "fingerprint_sha256": fp,
                    "subject": safe_subject(cert),
                    "issuer": safe_issuer(cert),
                    "subject_cn": safe_subject_cn(cert),
                    "issuer_cn": safe_issuer_cn(cert),
                    "not_before": safe_not_before(cert),
                    "not_after": safe_not_after(cert),
                    "row_number": total,
                }

                try:
                    spki_meta = extract_spki_metadata_from_der(der)
                    base["spki_algorithm_oid"] = spki_meta.get("algorithm_oid")
                    base["spki_curve_oid"] = spki_meta.get("curve_oid")
                    base["spki_sha256"] = spki_sha256_from_spki_der(spki_meta["spki_der"])
                except Exception:
                    spki_meta = None
                    base["spki_algorithm_oid"] = None
                    base["spki_curve_oid"] = None
                    base["spki_sha256"] = None

                try:
                    pubkey = cert.public_key()
                except Exception as e:
                    exc_text = str(e)

                    if is_sm2_spki(spki_meta, exc_text):
                        point_info = extract_ec_point_from_spki_public_key_bytes(
                            spki_meta["public_key_bytes"] if spki_meta is not None else b""
                        )
                        rec = {
                            **base,
                            "key_type": "SM2",
                            "curve": "sm2p256v1",
                            "curve_oid": normalize_sm2_curve_oid(spki_meta),
                            "algorithm_oid": spki_meta.get("algorithm_oid") if spki_meta else None,
                            "key_size": 256,
                            **point_info,
                            "public_key_error": exc_text,
                        }
                        sm2_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        sm2_count += 1
                        continue

                    err_out.write(json.dumps({
                        **base,
                        "error": f"public_key_error:{exc_text}",
                    }, ensure_ascii=False) + "\n")
                    err_count += 1
                    continue

                if isinstance(pubkey, rsa.RSAPublicKey):
                    nums = pubkey.public_numbers()
                    rec = {
                        **base,
                        "key_type": "RSA",
                        "modulus_hex": format(nums.n, "x"),
                        "exponent": nums.e,
                        "key_size": pubkey.key_size,
                    }
                    rsa_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    rsa_count += 1
                    continue

                if isinstance(pubkey, ec.EllipticCurvePublicKey):
                    nums = pubkey.public_numbers()
                    byte_len = (pubkey.key_size + 7) // 8
                    curve_name = getattr(pubkey.curve, "name", type(pubkey.curve).__name__)
                    curve_oid = base.get("spki_curve_oid")

                    if curve_name.lower() in {"sm2", "sm2p256v1"} or curve_oid in SM2_CURVE_OIDS:
                        rec = {
                            **base,
                            "key_type": "SM2",
                            "curve": "sm2p256v1",
                            "curve_oid": curve_oid if curve_oid in SM2_CURVE_OIDS else "1.2.156.10197.1.301",
                            "key_size": pubkey.key_size,
                            "point_format": "uncompressed",
                            "x_hex": int_to_fixed_hex(nums.x, byte_len),
                            "y_hex": int_to_fixed_hex(nums.y, byte_len),
                            "point_hex": "04" + int_to_fixed_hex(nums.x, byte_len) + int_to_fixed_hex(nums.y, byte_len),
                        }
                        sm2_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        sm2_count += 1
                        continue

                    rec = {
                        **base,
                        "key_type": "ECC",
                        "curve": curve_name,
                        "key_size": pubkey.key_size,
                        "x_hex": int_to_fixed_hex(nums.x, byte_len),
                        "y_hex": int_to_fixed_hex(nums.y, byte_len),
                    }
                    ecc_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    ecc_count += 1
                    continue

                rec = {
                    **base,
                    "key_type": type(pubkey).__name__,
                }
                other_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                other_count += 1

            except Exception as e:
                err_out.write(json.dumps({
                    "row_number": total,
                    "error": f"record_processing_error:{e}",
                }, ensure_ascii=False) + "\n")
                err_count += 1
                continue

    rsa_out.close()
    ecc_out.close()
    sm2_out.close()
    other_out.close()
    err_out.close()

    summary = {
        "total_rows": total,
        "rsa_keys": rsa_count,
        "ecc_keys": ecc_count,
        "sm2_keys": sm2_count,
        "other_keys": other_count,
        "parse_errors": err_count,
        "outputs": {
            "rsa": rsa_path,
            "ecc": ecc_path,
            "sm2": sm2_path,
            "other": other_path,
            "errors": err_path,
        },
    }

    with open(os.path.join(args.outdir, "extract_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()