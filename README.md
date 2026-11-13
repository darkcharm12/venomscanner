# VenomScanner

A hacker-style network scanner for Linux, built with **Bash + Python**. It discovers live hosts, scans TCP ports concurrently and identifies service versions through banner grabbing (similar to `nmap -sV`), all with a colorful terminal interface.

> ⚠️ **For authorized security testing and education only.** Scan only networks and devices you own or have explicit written permission to test. You are responsible for how you use this tool.

## Features

- Host discovery by ping sweep (single IP, hostname or CIDR such as `192.168.1.0/24`)
- Fast, concurrent TCP port scanning (asyncio Python engine, up to hundreds of parallel connections)
- Service/version detection with `-sV` (SSH, HTTP/HTTPS, FTP, SMTP, POP3, IMAP, MySQL, Redis and more)
- Port-based guesses for silent services such as SMB and RDP, clearly marked as guesses
- Highlights risky exposed services (Telnet, FTP, SMB, RDP, VNC)
- Live progress bar and a summary report
- Export results to `.txt`, `.json` or `.csv`
- Hybrid design: Python engine by default, with an automatic pure-Bash fallback
- No third-party dependencies

## Files

| File | Purpose |
|---|---|
| `venomscanner` | Bash launcher that picks the Python or Bash engine |
| `venomscanner.py` | Python (asyncio) scanning engine |
| `venomscanner.sh` | Pure-Bash scanning engine (fallback) |
| `install.sh` | Installer / uninstaller |

## Install

```bash
git clone https://github.com/darkcharm/venomscanner.git
cd venomscanner
chmod +x install.sh
./install.sh
```

Requirements: Linux, Bash 4+, and optionally Python 3.8+ (for the fast engine). `ping` is needed for host discovery unless you use `-n`.

Uninstall with `./install.sh --uninstall`.

## Usage

```bash
venomscanner [--py | --bash] [options] <target>
```

| Option | Description |
|---|---|
| `-p <ports>` | Ports, e.g. `22,80,443` or `1-1024` (default: common ports) |
| `-sV` | Service/version detection |
| `-t <secs>` | Timeout per probe (default 1) |
| `-j <num>` | Concurrent connections (default 200 Python, 50 Bash) |
| `-n` | Skip ping, treat every host as up |
| `-o <file>` | Save results (`.txt`, `.json`, `.csv`) |
| `-c` | Disable colors and animations |
| `--py` / `--bash` | Force an engine |
| `-h` | Help |

### Examples

```bash
venomscanner 192.168.1.0/24
venomscanner -sV 192.168.1.57
venomscanner -sV -p 1-1024 192.168.1.57
venomscanner -n -sV -o results.json 10.0.0.0/28
venomscanner --bash -sV 192.168.1.57
```

### Example output

```
┌─[ 192.168.1.57 ]──────── ● ALIVE
│  PORT      STATE   SERVICE        VERSION
│  22/tcp    open    ssh            OpenSSH 8.9p1 Ubuntu-3ubuntu0.1 (protocol 2.0)
│  80/tcp    open    http           Apache/2.4.52 (Ubuntu)
│  445/tcp   open    microsoft-ds   SMB file sharing, Windows/Samba (guessed from port)
```

## Limitations

VenomScanner identifies services from their banners, so services that hide or fake a banner may show as unidentified or incorrect. It performs full TCP connect checks only (no SYN or UDP scanning). For deeper analysis, use [nmap](https://nmap.org).

## License

MIT License. See [LICENSE](LICENSE).
