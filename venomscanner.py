#!/usr/bin/env python3
"""
VenomScanner - Python engine (asyncio)

Host discovery, fast concurrent TCP port scanning and nmap-style service/version
detection (-sV) with a hacker-style terminal UI. Standard library only.
Exports results to .txt, .json or .csv depending on the -o file extension.

Only scan networks and hosts you own or have written permission to test.
"""
import argparse
import asyncio
import csv
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
import time
from datetime import datetime

VERSION = "3.0"
DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"
RISKY_PORTS = {21, 23, 135, 139, 445, 3389, 5900}
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
TLS_PORTS = {443, 8443, 993, 995, 465, 636}
TLS_BASE = {993: "imap", 995: "pop3", 465: "smtp", 636: "ldap"}

GUESS = {
    21: ("ftp", "FTP server"),
    22: ("ssh", "SSH server"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP mail server"),
    53: ("domain", "DNS"),
    111: ("rpcbind", "RPC portmapper"),
    135: ("msrpc", "Microsoft Windows RPC"),
    139: ("netbios-ssn", "NetBIOS session service"),
    445: ("microsoft-ds", "SMB file sharing, Windows/Samba"),
    2049: ("nfs", "NFS"),
    3306: ("mysql", "MySQL/MariaDB"),
    3389: ("ms-wbt-server", "Remote Desktop / RDP"),
    5432: ("postgresql", "PostgreSQL"),
    5900: ("vnc", "VNC remote desktop"),
}

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


# ----------------------------------------------------------------- colors
class Colors:
    def __init__(self, enabled):
        e = (lambda code: f"\x1b[{code}m") if enabled else (lambda code: "")
        self.G = e("38;5;46")
        self.DG = e("38;5;34")
        self.R = e("38;5;196")
        self.Y = e("38;5;226")
        self.C = e("38;5;51")
        self.GR = e("38;5;240")
        self.B = e("1")
        self.X = e("0")


# ----------------------------------------------------------------- ui
ART = [
    r" __     __                            ",
    r" \ \   / /__ _ __   ___  _ __ ___     ",
    r"  \ \ / / _ \  _ \ / _ \|  _   _ \    ",
    r"   \ V /  __/ | | | (_) | | | | | |   ",
    r"    \_/ \___|_| |_|\___/|_| |_| |_|   ",
]


def banner(c, animate):
    print()
    for line in ART:
        print(f"{c.G}{line}{c.X}")
        if animate:
            time.sleep(0.04)
    print(f"{c.B}{c.C}    S  C  A  N  N  E  R   {c.GR}v{VERSION} (python engine){c.X}")
    print(f"{c.DG}    ─────────────────────────────────────{c.X}")
    print(f"{c.Y}    [!] authorized targets only. you are responsible.{c.X}\n")


def typewrite(text, animate):
    if animate:
        for ch in text:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(0.012)
        print()
    else:
        print(text)


def die(c, msg):
    print(f"{c.R}[x] Error:{c.X} {msg}", file=sys.stderr)
    sys.exit(1)


async def progress(state, c):
    spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    width = 32
    while True:
        total = max(1, state["total"])
        done = min(state["done"], total)
        pct = done * 100 // total
        filled = done * width // total
        bar = "█" * filled + "░" * (width - filled)
        sys.stdout.write(
            f"\r{c.C}{spin[i % len(spin)]}{c.X} {c.B}{c.G}{state['label']:<10}{c.X} "
            f"{c.DG}[{c.G}{bar}{c.DG}]{c.X} {pct:3d}%  {c.GR}{done}/{total}{c.X}\x1b[K"
        )
        sys.stdout.flush()
        i += 1
        await asyncio.sleep(0.1)


# ----------------------------------------------------------------- parsing
def parse_ports(spec, c):
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if re.fullmatch(r"\d+", part):
            p = int(part)
            if not 1 <= p <= 65535:
                die(c, f"Bad port: {part}")
            ports.append(p)
        elif re.fullmatch(r"\d+-\d+", part):
            lo, hi = map(int, part.split("-"))
            if not (1 <= lo <= hi <= 65535):
                die(c, f"Bad range: {part}")
            ports.extend(range(lo, hi + 1))
        else:
            die(c, f"Bad port spec: {part}")
    seen = set()
    return [p for p in ports if not (p in seen or seen.add(p))]


def expand_target(target, c):
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            die(c, f"Invalid CIDR: {target}")
        if net.version != 4 or net.prefixlen < 16:
            die(c, "CIDR must be IPv4 with prefix between 16 and 32")
        hosts = [str(h) for h in net.hosts()]
        return hosts or [str(net.network_address)]
    try:
        return [str(ipaddress.IPv4Address(target))]
    except ValueError:
        pass
    try:
        return [socket.gethostbyname(target)]
    except OSError:
        die(c, f"Cannot resolve hostname: {target}")


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ----------------------------------------------------------------- probes
async def ping(host, timeout):
    if shutil.which("ping"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", str(max(1, int(timeout))), host,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                return (await asyncio.wait_for(proc.wait(), timeout + 2)) == 0
            except asyncio.TimeoutError:
                proc.kill()
                return False
        except OSError:
            pass
    # fallback: TCP ping on a few common ports (a refused connection also means "up")
    for port in (80, 443, 22, 445):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            w.close()
            return True
        except ConnectionRefusedError:
            return True
        except Exception:
            continue
    return False


async def is_open(host, port, timeout):
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except Exception:
        return False
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    return True


async def grab(host, port, payload, wait, timeout, ctx=None):
    """Connect, optionally send payload, return (banner_text, tls_version)."""
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout + wait
        )
    except Exception:
        return "", None
    data = b""
    tls_ver = None
    try:
        ssl_obj = w.get_extra_info("ssl_object")
        tls_ver = ssl_obj.version() if ssl_obj else None
        if payload:
            w.write(payload)
            await w.drain()
        try:
            data = await asyncio.wait_for(r.read(2048), wait)
            if payload and data:
                while len(data) < 4096:
                    more = await asyncio.wait_for(r.read(2048), 0.5)
                    if not more:
                        break
                    data += more
        except asyncio.TimeoutError:
            pass
    except Exception:
        pass
    finally:
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
    return data.decode("latin-1"), tls_ver


def identify(port, banner):
    """Return (service, version) parsed from a banner; '' when unknown."""
    if not banner:
        return "", ""
    first = banner.split("\n", 1)[0].strip("\r")
    if banner.startswith("SSH-"):
        proto, _, rest = first[4:].partition("-")
        return "ssh", f"{rest.replace('_', ' ')} (protocol {proto})"
    if banner.startswith("HTTP/"):
        m = re.search(r"^Server:\s*(.+?)\s*$", banner, re.I | re.M)
        return "http", m.group(1).strip("\r") if m else ""
    if banner.startswith("220"):
        ver = re.sub(r"^220[ -]", "", first)
        ver = re.sub(r"^\((.*)\)$", r"\1", ver)
        smtp = re.search("smtp", first, re.I) or port in (25, 465, 587)
        return ("smtp" if smtp else "ftp"), ver
    if banner.startswith("+OK"):
        return "pop3", first[4:]
    if banner.startswith("* OK"):
        return "imap", first[5:]
    if banner.startswith("+PONG"):
        return "redis", ""
    m = re.search(r"\d+\.\d+\.\d+[-\w.]*", banner)
    if port == 3306 and m:
        ver = m.group(0)
        if "mariadb" in banner.lower():
            ver = "MariaDB " + ver
        return "mysql", ver
    if port == 5432:
        return "postgresql", ""
    if first and re.fullmatch(r"[ -~]+", first):
        return "", first[:60]
    return "", ""


async def detect(host, port, timeout, wait):
    probe = (
        f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: venomscanner\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    name = ver = ""

    if port in TLS_PORTS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        banner, tls_ver = await grab(
            host, port, probe if port in (443, 8443) else b"", wait, timeout, ctx
        )
        if banner or tls_ver:
            name, ver = identify(port, banner)
            base = name or TLS_BASE.get(port, "http")
            extra = f"({tls_ver})" if tls_ver else ""
            return "ssl/" + base, " ".join(x for x in (ver, extra) if x)
    elif port in HTTP_PORTS:
        banner, _ = await grab(host, port, probe, wait, timeout)
        name, ver = identify(port, banner)
    elif port == 6379:
        banner, _ = await grab(host, port, b"PING\r\n", wait, timeout)
        name, ver = identify(port, banner)
    else:
        banner, _ = await grab(host, port, b"", wait, timeout)
        if not banner:
            banner, _ = await grab(host, port, probe, wait, timeout)
        name, ver = identify(port, banner)

    if not ver and port in GUESS:
        gname, gver = GUESS[port]
        name = name or gname
        ver = f"{gver} (guessed from port)"
    return name, ver


# ----------------------------------------------------------------- engine
async def pool(items, fn, jobs, state):
    q = asyncio.Queue()
    for it in items:
        q.put_nowait(it)

    async def worker():
        while True:
            try:
                it = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                await fn(*it)
            except Exception:
                pass
            finally:
                state["done"] += 1

    if items:
        await asyncio.gather(*(worker() for _ in range(min(jobs, len(items)))))


async def run_scan(args, hosts, ports, c, tty):
    state = {"label": "", "done": 0, "total": 1}
    prog = asyncio.create_task(progress(state, c)) if tty else None
    timeout = args.timeout

    alive = list(hosts)
    if not args.no_ping:
        alive = []
        state.update(label="DISCOVERY", done=0, total=len(hosts))

        async def disc(h):
            if await ping(h, timeout):
                alive.append(h)

        await pool([(h,) for h in hosts], disc, args.jobs, state)

    results = {h: [] for h in alive}
    state.update(label="PORT SCAN", done=0, total=max(1, len(alive) * len(ports)))

    async def scan(h, p):
        if await is_open(h, p, timeout):
            results[h].append(p)

    await pool([(h, p) for h in alive for p in ports], scan, args.jobs, state)

    info = {}
    if args.sv:
        open_items = [(h, p) for h in alive for p in sorted(results[h])]
        state.update(label="VERSIONS", done=0, total=max(1, len(open_items)))

        async def ver(h, p):
            info[(h, p)] = await detect(h, p, timeout, args.banner_wait)

        await pool(open_items, ver, min(args.jobs, 64), state)

    if prog:
        prog.cancel()
        try:
            await prog
        except asyncio.CancelledError:
            pass
        sys.stdout.write("\r\x1b[K")

    data = {}
    for h in alive:
        rows = []
        for p in sorted(results[h]):
            svc, v = info.get((h, p), ("", ""))
            rows.append({
                "port": p,
                "state": "open",
                "service": svc or service_name(p),
                "version": v if args.sv else "",
                "risky": p in RISKY_PORTS,
            })
        data[h] = rows
    return data


# ----------------------------------------------------------------- report
def ip_key(ip):
    return tuple(int(x) for x in ip.split("."))


def build_report(args, data, total_hosts, nports, elapsed, c):
    L = []
    L.append(f"{c.G}╔══════════════════════════════════════════════════╗{c.X}")
    L.append(f"{c.G}║{c.B}  VENOMSCANNER REPORT                             {c.G}║{c.X}")
    L.append(f"{c.G}╚══════════════════════════════════════════════════╝{c.X}")
    L.append(f"{c.GR} target :{c.X} {args.target}")
    L.append(f"{c.GR} date   :{c.X} {datetime.now():%F %T}\n")

    open_total = risky = 0
    for ip in sorted(data, key=ip_key):
        L.append(f"{c.DG}┌─[ {c.B}{c.C}{ip}{c.X}{c.DG} ]──────── {c.G}● ALIVE{c.X}")
        if args.sv and data[ip]:
            L.append(f"{c.DG}│{c.X}  {c.B}{c.GR}{'PORT':<9} {'STATE':<7} {'SERVICE':<14} VERSION{c.X}")
        for r in data[ip]:
            open_total += 1
            col = c.R if r["risky"] else c.G
            risky += r["risky"]
            if args.sv:
                L.append(
                    f"{c.DG}│{c.X}  {col}{str(r['port']) + '/tcp':<9}{c.X} {col}{'open':<7}{c.X} "
                    f"{c.GR}{r['service']:<14}{c.X} {c.C}{r['version'] or 'no banner / unidentified'}{c.X}"
                )
            else:
                tag = "OPEN ⚠" if r["risky"] else "OPEN  "
                L.append(
                    f"{c.DG}│{c.X}  {col}{str(r['port']) + '/tcp':<7}{c.X} {col}{tag}{c.X}  "
                    f"{c.GR}{r['service']}{c.X}"
                )
        if not data[ip]:
            L.append(f"{c.DG}│{c.X}  {c.GR}no open ports found (of {nports} scanned){c.X}")
        L.append(f"{c.DG}└──────────────────────────────────────{c.X}\n")

    L.append(f"{c.G}━━━━━━━━━━━━━━━━━━ SUMMARY ━━━━━━━━━━━━━━━━━━━━━{c.X}")
    L.append(f"  {c.GR}Hosts up    :{c.X} {c.B}{c.G}{len(data)}{c.X} / {total_hosts}")
    L.append(f"  {c.GR}Open ports  :{c.X} {c.B}{c.G}{open_total}{c.X}")
    L.append(f"  {c.GR}Risky ports :{c.X} {c.B}{c.R}{risky}{c.X}  {c.GR}(telnet/ftp/smb/rdp/vnc){c.X}")
    L.append(f"  {c.GR}Elapsed     :{c.X} {elapsed:.1f}s")
    if args.sv:
        L.append(f"  {c.GR}Mode        :{c.X} service/version detection ON (-sV)")
    else:
        L.append(f"  {c.GR}Tip         :{c.X} add -sV to detect service versions")
    L.append(f"{c.G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{c.X}")
    return "\n".join(L)


def save_output(path, args, data, report_text, elapsed):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        doc = {
            "tool": "venomscanner", "version": VERSION, "target": args.target,
            "date": datetime.now().isoformat(timespec="seconds"),
            "elapsed_seconds": round(elapsed, 2), "version_scan": args.sv,
            "hosts": [{"ip": ip, "ports": data[ip]} for ip in sorted(data, key=ip_key)],
        }
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)
    elif ext == ".csv":
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["host", "port", "state", "service", "version", "risky"])
            for ip in sorted(data, key=ip_key):
                for r in data[ip]:
                    w.writerow([ip, r["port"], r["state"], r["service"], r["version"], r["risky"]])
    else:
        with open(path, "w") as f:
            f.write(ANSI_RE.sub("", report_text) + "\n")


# ----------------------------------------------------------------- main
def build_parser():
    p = argparse.ArgumentParser(add_help=False, prog="venomscanner")
    p.add_argument("target", nargs="?")
    p.add_argument("-p", dest="ports", default=DEFAULT_PORTS)
    p.add_argument("-t", dest="timeout", type=float, default=1.0)
    p.add_argument("-j", dest="jobs", type=int, default=200)
    p.add_argument("-n", dest="no_ping", action="store_true")
    p.add_argument("-o", dest="outfile")
    p.add_argument("-c", dest="no_color", action="store_true")
    p.add_argument("-sV", dest="sv", action="store_true")
    p.add_argument("--banner-wait", dest="banner_wait", type=float, default=2.0)
    p.add_argument("-h", "--help", dest="help", action="store_true")
    return p


HELP = """\
USAGE
  venomscanner [options] <target>

TARGET
  Single IP (192.168.1.10), CIDR (192.168.1.0/24), or hostname

OPTIONS
  -p <ports>        Ports: list and/or ranges, e.g. 22,80,443 or 1-1024
                    (default: common ports)
  -sV               Service/version detection via banner grabbing (like nmap -sV)
  -t <secs>         Timeout per probe in seconds (default: 1)
  -j <num>          Concurrent connections (default: 200)
  -n                No ping; treat every host as up (for hosts blocking ICMP)
  -o <file>         Save results; format from extension: .txt  .json  .csv
  -c                Disable colors and animations
  --banner-wait <s> How long to wait for a service banner (default: 2)
  -h                Show this help

EXAMPLES
  venomscanner 192.168.1.0/24
  venomscanner -sV -p 1-1024 192.168.1.57
  venomscanner -n -p 22,80,443 -o results.json 10.0.0.0/28
"""


def main():
    parser = build_parser()
    args, unknown = parser.parse_known_args()
    tty = sys.stdout.isatty() and not args.no_color
    c = Colors(tty)

    if args.help:
        banner(c, tty)
        print(HELP)
        return 0
    if unknown:
        die(c, f"Unknown option(s): {' '.join(unknown)}")
    # friendly: "venomscanner -p 192.168.1.57" -> treat the IP given to -p as the target
    if not args.target and "." in args.ports:
        args.target, args.ports = args.ports, DEFAULT_PORTS
    if not args.target:
        banner(c, tty)
        print(HELP)
        return 1
    if args.timeout <= 0 or args.jobs < 1:
        die(c, "Timeout and jobs must be positive")

    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        args.jobs = max(10, min(args.jobs, soft - 64))
    except Exception:
        pass

    hosts = expand_target(args.target, c)
    ports = parse_ports(args.ports, c)

    banner(c, tty)
    typewrite(f"{c.G}[+]{c.X} target     : {args.target}", tty)
    typewrite(f"{c.G}[+]{c.X} hosts      : {len(hosts)}", tty)
    typewrite(f"{c.G}[+]{c.X} ports/host : {len(ports)}", tty)
    typewrite(
        f"{c.G}[+]{c.X} workers    : {args.jobs}   timeout: {args.timeout:g}s   "
        f"ping: {0 if args.no_ping else 1}   version-scan: {int(args.sv)}", tty)
    print()

    if sys.stdout.isatty():
        sys.stdout.write("\x1b[?25l")
    start = time.time()
    try:
        data = asyncio.run(run_scan(args, hosts, ports, c, sys.stdout.isatty()))
    except KeyboardInterrupt:
        print(f"\n{c.R}[!] Interrupted.{c.X}")
        return 130
    finally:
        if sys.stdout.isatty():
            sys.stdout.write("\x1b[?25h")
    elapsed = time.time() - start

    if tty:
        print(f"{c.G}[✔] scan complete{c.X}\n")
    report = build_report(args, data, len(hosts), len(ports), elapsed, c)
    print(report)

    if args.outfile:
        try:
            save_output(args.outfile, args, data, report, elapsed)
            print(f"{c.G}[+] saved to {args.outfile}{c.X}")
        except OSError as e:
            die(c, f"Cannot write {args.outfile}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
