#!/usr/bin/env python3
"""Verify the public Feishu encrypted URL challenge without printing secrets."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DOMAIN = "tx.nstarzx.cn"
SITE_ROOT = Path(f"/www/wwwroot/{DOMAIN}")


def _encrypt(plaintext: bytes, encrypt_key: str) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    key = hashlib.sha256(encrypt_key.encode()).digest()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()


def main() -> int:
    secret_root = SITE_ROOT / "secrets"
    try:
        binding_id = (SITE_ROOT / "config" / "feishu_binding_id").read_text().strip()
        verification_token = (secret_root / "feishu_verification_token").read_text().strip()
        encrypt_key = (secret_root / "feishu_encrypt_key").read_text().strip()
    except OSError:
        print("verification failed: Feishu configuration files are unavailable", file=sys.stderr)
        return 1

    marker = f"trpc-verification-{secrets.token_hex(8)}"
    inner = json.dumps(
        {
            "challenge": marker,
            "token": verification_token,
            "type": "url_verification",
        },
        separators=(",", ":"),
    ).encode()
    outer = json.dumps({"encrypt": _encrypt(inner, encrypt_key)}, separators=(",", ":")).encode()
    request = urllib.request.Request(
        f"https://{DOMAIN}/v1/channels/feishu/{binding_id}/callback",
        data=outer,
        # The developer console's initial encrypted URL challenge has no
        # X-Lark-Signature headers. Normal events remain signature-gated.
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            payload = json.loads(response.read())
            status = response.status
    except urllib.error.HTTPError as exc:
        print(f"verification failed: callback returned HTTP {exc.code}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        print("verification failed: public callback response is invalid", file=sys.stderr)
        return 1

    matched = isinstance(payload, dict) and secrets.compare_digest(
        str(payload.get("challenge", "")), marker
    )
    print(
        json.dumps(
            {
                "callback_url": f"https://{DOMAIN}/v1/channels/feishu/{binding_id}/callback",
                "http_status": status,
                "challenge_match": matched,
                "challenge_mode": "unsigned_encrypted_console_compatible",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if status == 200 and matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
