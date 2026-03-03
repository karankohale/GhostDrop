"""
ghostdrop.py — Cross-platform secure file transfer (Win / Mac / Linux).

Transport: Raw TCP sockets  (no Magic Wormhole — works everywhere)
Encryption: X25519 ECDH  +  AES-256-GCM
Integrity:  SHA-256 verified on receiver

Usage:
    python ghostdrop.py send <file> [--port PORT]
    python ghostdrop.py receive <code> --host <sender-ip> [--out DIR]
"""

import argparse
import os
import sys
import time

from tqdm import tqdm

import ui
import crypto
import codegen
from transport import SenderTransport, ReceiverTransport, CHUNK_SIZE


def _human_size(num: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


# ── Send ──────────────────────────────────────────────────────────────────────

def send_file(filepath: str, port: int):
    if not os.path.isfile(filepath):
        ui.error(f"File not found: {filepath!r}")
        sys.exit(1)

    size     = os.path.getsize(filepath)
    filename = os.path.basename(filepath)

    ui.info(f"Preparing  : {filename}  ({_human_size(size)})")
    ui.info("Computing SHA-256 checksum...")

    manifest_bytes = crypto.build_manifest(filepath)
    sha256         = crypto.sha256_file(filepath)
    ui.success(f"SHA-256    : {sha256[:20]}...")

    transport = SenderTransport(port=port)
    transport.listen()

    local_ip = codegen.get_local_ip()
    code     = codegen.generate_code(port)

    ui.code_display(code, local_ip, port)
    ui.info("Waiting for receiver...  (Ctrl+C to cancel)")

    try:
        transport.accept(timeout=300)
    except OSError as exc:
        ui.error(f"Connection failed: {exc}")
        sys.exit(1)

    ui.success("Receiver connected — starting transfer...")
    transport.send(manifest_bytes)

    ack = transport.recv()
    if ack != b"GO":
        ui.error(f"Receiver rejected: {ack.decode(errors='replace')}")
        transport.close()
        sys.exit(1)

    start = time.perf_counter()

    with open(filepath, "rb") as f:
        with tqdm(total=size, unit="B", unit_scale=True, desc="  Sending ",
                  colour="cyan",
                  bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{rate_fmt}]"
                  ) as bar:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                transport.send(chunk)
                bar.update(len(chunk))

    receipt = transport.recv()
    elapsed = time.perf_counter() - start

    if receipt == b"OK":
        ui.transfer_summary(filename, size, sha256, elapsed)
    else:
        ui.error(f"Receiver reported: {receipt.decode(errors='replace')}")

    transport.close()


# ── Receive ───────────────────────────────────────────────────────────────────

def receive_file(code: str, host: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    _, port = codegen.parse_code(code)

    ui.info(f"Connecting to {host}:{port} ...")

    transport = ReceiverTransport()
    try:
        transport.connect(host, port, timeout=30)
    except OSError as exc:
        ui.error(f"Could not connect: {exc}")
        ui.info("Check the sender's IP and that port is not blocked by firewall.")
        sys.exit(1)

    ui.success("Connected!")

    raw_manifest = transport.recv()

    try:
        manifest = crypto.parse_manifest(raw_manifest)
    except ValueError as exc:
        ui.error(f"Manifest invalid: {exc}")
        transport.send(b"FAIL: bad manifest")
        transport.close()
        sys.exit(1)

    filename     = manifest["filename"]
    size         = manifest["size"]
    expected_sha = manifest["sha256"]

    out_path = os.path.join(output_dir, filename)
    if os.path.exists(out_path):
        ui.warning(f"File exists: {out_path!r} — saving as .ghostdrop copy")
        out_path += ".ghostdrop"

    ui.info(f"Receiving  : {filename}  ({_human_size(size)})")
    ui.info(f"Saving to  : {os.path.abspath(out_path)}")

    transport.send(b"GO")

    start    = time.perf_counter()
    received = 0

    with open(out_path, "wb") as f:
        with tqdm(total=size, unit="B", unit_scale=True, desc="  Receiving",
                  colour="green",
                  bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{rate_fmt}]"
                  ) as bar:
            while received < size:
                chunk = transport.recv()
                f.write(chunk)
                received += len(chunk)
                bar.update(len(chunk))

    elapsed = time.perf_counter() - start

    ui.info("Verifying SHA-256...")
    if crypto.verify_file(out_path, expected_sha):
        ui.success("Integrity check passed!")
        transport.send(b"OK")
        ui.transfer_summary(filename, size, expected_sha, elapsed)
    else:
        actual = crypto.sha256_file(out_path)
        ui.error("Integrity check FAILED!")
        ui.error(f"  Expected : {expected_sha}")
        ui.error(f"  Actual   : {actual}")
        transport.send(b"FAIL: sha256 mismatch")
        os.remove(out_path)
        ui.warning("Corrupt file deleted.")

    transport.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="ghostdrop",
        description="Cross-platform secure file transfer — no login required",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    sp = sub.add_parser("send", help="Send a file")
    sp.add_argument("file", help="File to send")
    sp.add_argument("--port", type=int, default=54321,
                    help="TCP port to listen on (default: 54321)")

    rp = sub.add_parser("receive", help="Receive a file")
    rp.add_argument("code", help="Transfer code from sender")
    rp.add_argument("--host", required=True,
                    help="Sender's IP address (e.g. 192.168.1.10)")
    rp.add_argument("--out", metavar="DIR", default=".",
                    help="Output directory (default: current dir)")

    return parser


def main():
    ui.banner()
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        ui.print_usage()
        sys.exit(0)

    try:
        if args.command == "send":
            send_file(args.file, port=args.port)
        elif args.command == "receive":
            receive_file(args.code, host=args.host, output_dir=args.out)
    except KeyboardInterrupt:
        ui.warning("\nCancelled.")
        sys.exit(0)


if __name__ == "__main__":
    main()
