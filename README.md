# 👻 GhostDrop

**Secure peer-to-peer file transfer — Windows ↔ Mac ↔ Linux, no login required.**

```
   _____ _               _   _____
  / ____| |             | | |  __ \
 | |  __| |__   ___  ___| |_| |  | |_ __ ___  _ __
 | | |_ | '_ \ / _ \/ __| __| |  | | '__/ _ \| '_ \
 | |__| | | | | (_) \__ \ |_| |__| | | | (_) | |_) |
  \_____|_| |_|\___/|___/\__|_____/|_|  \___/| .__/
                                              |_|
```

---

## Why No Magic Wormhole?

The original GhostDrop used Magic Wormhole which requires **Twisted + libsodium
C extensions** — these frequently fail to install on Windows without Visual Studio
Build Tools. GhostDrop v2 replaces this with:

- **Raw TCP sockets** (stdlib — zero install friction)
- **`cryptography` package** (has pre-built wheels for Win/Mac/Linux on PyPI)

The result: `pip install -r requirements.txt` works on all platforms, first try.

---

## Security Model

```
┌─────────────────────────────────────────────────────────────┐
│  1. X25519 ECDH key exchange  (Diffie-Hellman over Curve25519)
│  2. HKDF-SHA256 derives a 32-byte session key
│  3. Every message: AES-256-GCM encrypted with fresh random nonce
│  4. SHA-256 of the file verified after transfer completes
│  5. Malicious filenames (path traversal) rejected at manifest stage
└─────────────────────────────────────────────────────────────┘
```

No relay server sees file contents. The session key never leaves either machine.

---

## Installation

```bash
git clone https://github.com/yourname/ghostdrop
cd ghostdrop
pip install -r requirements.txt
```

Works on Python 3.8+.

---

## Usage

### Step 1 — Sender

```bash
python ghostdrop.py send photo.zip
```

Output:

```
  ┌──────────────────────────────────────────────────┐
  │    Transfer Code : 54321-ghost-delta             │
  │    Your LAN IP  : 192.168.1.42                  │
  │    Port         : 54321                          │
  └──────────────────────────────────────────────────┘

  Receiver command:
    python ghostdrop.py receive 54321-ghost-delta --host 192.168.1.42
```

### Step 2 — Receiver (any OS)

```bash
python ghostdrop.py receive 54321-ghost-delta --host 192.168.1.42
```

### Options

```
send:
  --port PORT     TCP port to listen on (default: 54321)

receive:
  --host IP       Sender's IP address (required)
  --out DIR       Directory to save the file (default: current dir)
```

---

## Cross-Platform Scenarios

| Sender | Receiver | Works? |
|--------|----------|--------|
| Windows | Mac | ✅ |
| Mac | Linux | ✅ |
| Linux | Windows | ✅ |
| Windows | Windows | ✅ |
| Mac | Mac | ✅ |

**Same network (LAN/WiFi):** Works out of the box — use the LAN IP shown.

**Different networks (internet):** The sender needs to either:
- Forward the port on their router, or
- Use a tool like `ngrok tcp 54321` and share the ngrok address

---

## Firewall / Port Notes

- Default port: **54321** (TCP)
- On **Windows**: Windows Defender may show a firewall popup — click "Allow"
- On **macOS**: May ask for network permission — click "Allow"
- On **Linux**: If `ufw` is active: `sudo ufw allow 54321/tcp`

---

## Build Single Binary

```bash
pip install pyinstaller
pyinstaller --onefile ghostdrop.py
# Windows: dist/ghostdrop.exe
# Mac/Linux: dist/ghostdrop
```

---

## Project Structure

```
ghostdrop/
├── ghostdrop.py      # CLI entrypoint — send/receive orchestration
├── transport.py      # TCP socket layer — X25519 ECDH + AES-256-GCM
├── crypto.py         # SHA-256 manifest creation and verification
├── codegen.py        # Human-readable transfer code generation
├── ui.py             # Terminal output helpers
├── requirements.txt
└── README.md
```

---

## License

MIT
