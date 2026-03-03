"""
codegen.py — Generate and parse short human-readable transfer codes.

Format:  <port>-<adjective>-<noun>
Example: 54321-ghost-delta

The receiver uses the code to know the sender's IP + port + a shared
pin that's mixed into the session display for verification.
"""

import random
import socket

ADJECTIVES = [
    "ghost", "silent", "swift", "dark", "neon", "cold", "sharp",
    "hollow", "amber", "crisp", "solar", "lunar", "iron", "steel",
    "frost", "ember", "stone", "cloud", "storm", "rapid", "quiet",
    "bright", "lost", "raw", "clean", "true", "bold", "deep",
]

NOUNS = [
    "delta", "echo", "foxtrot", "kilo", "nova", "orbit", "pixel",
    "relay", "signal", "tango", "vector", "wave", "zeta", "alpha",
    "bravo", "cipher", "drone", "flash", "gamma", "hydra", "index",
    "jumper", "karma", "laser", "mango", "nexus", "omega", "pulse",
]


def generate_code(port: int) -> str:
    adj  = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    return f"{port}-{adj}-{noun}"


def parse_code(code: str):
    """
    Parse a transfer code into (host, port).

    Accepts two formats:
      1. Full:  <ip>:<port>-<adj>-<noun>     (LAN, explicit IP)
      2. Short: <port>-<adj>-<noun>          (same machine / user supplies IP)

    Returns (host_or_None, port).
    """
    parts = code.strip().split("-")
    if len(parts) < 3:
        raise ValueError(
            f"Invalid code format: {code!r}\n"
            "Expected: <port>-<word>-<word>  or  <ip>:<port>-<word>-<word>"
        )

    # First segment may be "ip:port" or just "port"
    first = parts[0]
    if ":" in first:
        host_str, port_str = first.rsplit(":", 1)
    else:
        host_str = None
        port_str = first

    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Could not parse port from code segment: {first!r}")

    return host_str, port


def get_local_ip() -> str:
    """Best-effort: return the machine's LAN IP (not 127.0.0.1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()
