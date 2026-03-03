"""
crypto.py — File integrity utilities for GhostDrop.
"""

import hashlib
import json
import os

CHUNK_SIZE = 65_536


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(filepath: str) -> bytes:
    basename = os.path.basename(filepath)
    size     = os.path.getsize(filepath)
    digest   = sha256_file(filepath)
    return json.dumps({"filename": basename, "size": size, "sha256": digest}).encode()


def parse_manifest(data: bytes) -> dict:
    try:
        m = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid manifest: {exc}") from exc

    for key in ("filename", "size", "sha256"):
        if key not in m:
            raise ValueError(f"Manifest missing field: {key!r}")

    fn = m["filename"]
    bad_seps = [os.sep]
    if os.altsep:
        bad_seps.append(os.altsep)
    if any(sep in fn for sep in bad_seps) or ".." in fn or fn.startswith("."):
        raise ValueError(f"Unsafe filename rejected: {fn!r}")

    if not isinstance(m["size"], int) or m["size"] < 0:
        raise ValueError(f"Invalid size: {m['size']!r}")

    if not isinstance(m["sha256"], str) or len(m["sha256"]) != 64:
        raise ValueError(f"Invalid sha256: {m['sha256']!r}")

    return m


def verify_file(path: str, expected: str) -> bool:
    return sha256_file(path) == expected.lower()
