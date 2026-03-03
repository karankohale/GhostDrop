"""
transport.py — Pure-Python TCP transport for GhostDrop.

Why not Magic Wormhole?
  Magic Wormhole depends on Twisted + libsodium C extensions that are
  unreliable to install on Windows without Visual Studio Build Tools.
  This module replaces it with stdlib sockets + the `cryptography`
  package (which ships pre-built wheels for Win/Mac/Linux on PyPI).

Protocol (all integers are big-endian):
  ┌──────────────────────────────────────────────┐
  │  Handshake: 32-byte session key exchange     │
  │  Each message: 4-byte length + N bytes       │
  │  All payloads: AES-256-GCM encrypted         │
  └──────────────────────────────────────────────┘
"""

import os
import socket
import struct
import secrets
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_PORT   = 54321
MAGIC_HEADER   = b"GHOSTDROP\x02"   # bumped to v2 — incompatible with old builds
CHUNK_SIZE     = 65_536             # 64 KB per message
NONCE_SIZE     = 12                 # AES-GCM nonce
MSG_LEN_FMT    = "!I"               # 4-byte big-endian unsigned int
MSG_LEN_SIZE   = struct.calcsize(MSG_LEN_FMT)


# ── Key exchange (X25519 ECDH) ────────────────────────────────────────────────

def _generate_keypair():
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub          # pub is 32 raw bytes


def _derive_session_key(priv_key, peer_pub_bytes: bytes) -> bytes:
    """Derive a 32-byte AES-256 key via X25519 DH + HKDF-SHA256."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared   = priv_key.exchange(peer_pub)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ghostdrop-session-key-v2",
    )
    return hkdf.derive(shared)


# ── Framed, encrypted I/O ─────────────────────────────────────────────────────

def _send_raw(sock: socket.socket, data: bytes):
    """Send length-prefixed raw bytes."""
    sock.sendall(struct.pack(MSG_LEN_FMT, len(data)) + data)


def _recv_raw(sock: socket.socket) -> bytes:
    """Receive one length-prefixed raw message."""
    header = _recv_exactly(sock, MSG_LEN_SIZE)
    (length,) = struct.unpack(MSG_LEN_FMT, header)
    return _recv_exactly(sock, length)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)


def send_message(sock: socket.socket, aesgcm: AESGCM, data: bytes):
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct    = aesgcm.encrypt(nonce, data, None)
    _send_raw(sock, nonce + ct)


def recv_message(sock: socket.socket, aesgcm: AESGCM) -> bytes:
    payload = _recv_raw(sock)
    nonce, ct = payload[:NONCE_SIZE], payload[NONCE_SIZE:]
    return aesgcm.decrypt(nonce, ct, None)


# ── Sender-side connection ────────────────────────────────────────────────────

class SenderTransport:
    """Listens for one inbound connection, performs ECDH, returns ready socket."""

    def __init__(self, port: int = DEFAULT_PORT):
        self.port = port
        self._priv, self.pub_bytes = _generate_keypair()
        self._server_sock = None
        self.sock    = None
        self.aesgcm  = None

    def listen(self):
        """Bind and start listening. Call before displaying the code."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", self.port))
        self._server_sock.listen(1)

    def accept(self, timeout: int = 300):
        """Block until receiver connects and complete ECDH handshake."""
        self._server_sock.settimeout(timeout)
        conn, _ = self._server_sock.accept()
        self._server_sock.close()
        self.sock = conn

        # Handshake: magic header + pub key
        magic = _recv_exactly(conn, len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise ConnectionError("Invalid magic header — version mismatch?")

        peer_pub = _recv_exactly(conn, 32)
        conn.sendall(MAGIC_HEADER + self.pub_bytes)

        session_key = _derive_session_key(self._priv, peer_pub)
        self.aesgcm = AESGCM(session_key)

    def send(self, data: bytes):
        send_message(self.sock, self.aesgcm, data)

    def recv(self) -> bytes:
        return recv_message(self.sock, self.aesgcm)

    def close(self):
        if self.sock:
            try: self.sock.close()
            except Exception: pass


# ── Receiver-side connection ──────────────────────────────────────────────────

class ReceiverTransport:
    """Connects to sender, performs ECDH, returns ready socket."""

    def __init__(self):
        self._priv, self.pub_bytes = _generate_keypair()
        self.sock   = None
        self.aesgcm = None

    def connect(self, host: str, port: int = DEFAULT_PORT, timeout: int = 30):
        self.sock = socket.create_connection((host, port), timeout=timeout)

        # Handshake: send magic + pub key, receive sender's pub key
        self.sock.sendall(MAGIC_HEADER + self.pub_bytes)

        magic = _recv_exactly(self.sock, len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise ConnectionError("Invalid magic header — version mismatch?")

        peer_pub    = _recv_exactly(self.sock, 32)
        session_key = _derive_session_key(self._priv, peer_pub)
        self.aesgcm = AESGCM(session_key)

    def send(self, data: bytes):
        send_message(self.sock, self.aesgcm, data)

    def recv(self) -> bytes:
        return recv_message(self.sock, self.aesgcm)

    def close(self):
        if self.sock:
            try: self.sock.close()
            except Exception: pass
