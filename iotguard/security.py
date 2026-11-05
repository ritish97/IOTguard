"""
IoTGuard Security & Model Verification Module
Implements Production Readiness Pillar 3: Security:
- Tier 2 Cryptographic Signature Verification for XGBoost models.
- Verifies model authenticity before loading to prevent model poisoning / tampering.
- Privilege separation utilities for least-privilege detection and privileged response.
"""

import os
import hmac
import hashlib
import json
from pathlib import Path
from typing import Union, Optional, Tuple, Dict, Any


DEFAULT_SECRET_KEY = b"iotguard-edge-tier2-master-key-2026"


def compute_file_hmac_sha256(file_path: Union[str, Path], key: bytes = DEFAULT_SECRET_KEY) -> str:
    """
    Computes HMAC-SHA256 digest of a model file.
    """
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Model file not found: {p}")

    mac = hmac.new(key, digestmod=hashlib.sha256)
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            mac.update(chunk)
    return mac.hexdigest()


def sign_model_file(
    model_path: Union[str, Path],
    key: bytes = DEFAULT_SECRET_KEY,
    output_sig_path: Optional[Union[str, Path]] = None,
    signer_identity: str = "Tier2-Cloud-Management"
) -> Path:
    """
    Signs a model file and writes a metadata signature sidecar file (.sig).
    """
    model_p = Path(model_path)
    sig_p = Path(output_sig_path) if output_sig_path else model_p.with_suffix(model_p.suffix + ".sig")

    digest = compute_file_hmac_sha256(model_p, key=key)
    signature_data = {
        "model_file": model_p.name,
        "algorithm": "HMAC-SHA256",
        "signer": signer_identity,
        "file_size": model_p.stat().st_size,
        "signature": digest
    }

    with open(sig_p, "w", encoding="utf-8") as f:
        json.dump(signature_data, f, indent=2)

    return sig_p


def verify_model_signature(
    model_path: Union[str, Path],
    sig_path: Optional[Union[str, Path]] = None,
    key: bytes = DEFAULT_SECRET_KEY
) -> Tuple[bool, str]:
    """
    Verifies that the model file matches the cryptographic signature in the sidecar.
    Returns (is_valid, message).
    """
    model_p = Path(model_path)
    if not model_p.exists():
        return False, f"Model file missing: {model_p}"

    sig_p = Path(sig_path) if sig_path else model_p.with_suffix(model_p.suffix + ".sig")
    if not sig_p.exists():
        return False, f"Signature sidecar file missing: {sig_p}"

    try:
        with open(sig_p, "r", encoding="utf-8") as f:
            sig_data = json.load(f)

        expected_sig = sig_data.get("signature", "")
        if not expected_sig:
            return False, "Invalid signature file: signature field missing."

        current_digest = compute_file_hmac_sha256(model_p, key=key)

        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(current_digest, expected_sig):
            return True, f"Model successfully verified. Signed by: {sig_data.get('signer', 'Unknown')}"
        else:
            return False, "Model verification failed: Signature mismatch! Model file may be corrupted or tampered."

    except Exception as e:
        return False, f"Verification error: {str(e)}"
