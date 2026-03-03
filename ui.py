from colorama import Fore, Style, init
import pyfiglet

init(autoreset=True)


def banner():
    ascii_banner = pyfiglet.figlet_format("GhostDrop", font="slant")
    print(Fore.CYAN + ascii_banner)
    print(Fore.WHITE + Style.BRIGHT + "  Secure P2P File Transfer  |  E2E Encrypted  |  No Login\n")
    print(Fore.WHITE + "─" * 60 + "\n")


def info(msg):    print(Fore.BLUE  + Style.BRIGHT + "  [>] " + Style.NORMAL + msg)
def success(msg): print(Fore.GREEN + Style.BRIGHT + "  [+] " + Style.NORMAL + msg)
def error(msg):   print(Fore.RED   + Style.BRIGHT + "  [!] " + Style.NORMAL + msg)
def warning(msg): print(Fore.YELLOW+ Style.BRIGHT + "  [~] " + Style.NORMAL + msg)


def code_display(code: str, local_ip: str, port: int):
    print()
    print(Fore.WHITE + "  ┌──────────────────────────────────────────────────┐")
    print(Fore.WHITE + "  │  " + Fore.YELLOW + Style.BRIGHT +
          f"  Transfer Code : {code:<33}" + Fore.WHITE + "│")
    print(Fore.WHITE + "  │  " + Fore.CYAN +
          f"  Your LAN IP  : {local_ip:<33}" + Fore.WHITE + "│")
    print(Fore.WHITE + "  │  " + Fore.CYAN +
          f"  Port         : {port:<33}" + Fore.WHITE + "│")
    print(Fore.WHITE + "  └──────────────────────────────────────────────────┘")
    print()
    print(Fore.WHITE + "  Receiver command:")
    print(Fore.GREEN + Style.BRIGHT +
          f"    python ghostdrop.py receive {code} --host {local_ip}")
    print()


def transfer_summary(filename: str, size: int, sha256: str, elapsed: float):
    speed     = size / elapsed if elapsed > 0 else 0
    size_str  = _human_size(size)
    speed_str = _human_size(speed) + "/s"
    sha_short = sha256[:28] + "..." if len(sha256) > 28 else sha256
    print()
    print(Fore.WHITE + "  ┌──────────────────────────────────────────────────┐")
    print(Fore.WHITE + "  │  " + Fore.GREEN + Style.BRIGHT + "  Transfer Complete                             " + Fore.WHITE + "│")
    print(Fore.WHITE + "  ├──────────────────────────────────────────────────┤")
    print(Fore.WHITE + f"  │  File    : {Fore.CYAN}{filename:<39}{Fore.WHITE}│")
    print(Fore.WHITE + f"  │  Size    : {Fore.CYAN}{size_str:<39}{Fore.WHITE}│")
    print(Fore.WHITE + f"  │  Speed   : {Fore.CYAN}{speed_str:<39}{Fore.WHITE}│")
    print(Fore.WHITE + f"  │  SHA-256 : {Fore.CYAN}{sha_short:<39}{Fore.WHITE}│")
    print(Fore.WHITE + "  └──────────────────────────────────────────────────┘")
    print()


def print_usage():
    print(Fore.WHITE + Style.BRIGHT + "\n  Usage:\n")
    print(Fore.CYAN  + "    python ghostdrop.py send <file> [--port PORT]")
    print(Fore.CYAN  + "    python ghostdrop.py receive <code> --host <sender-ip> [--out DIR]")
    print()


def _human_size(num: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"
