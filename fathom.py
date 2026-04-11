#!/usr/bin/env python3
"""
fathom.py - Automated enumeration script
Runs nmap, parses results, and chains service-specific tools.
"""

import argparse
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
#  DEFAULT WORDLISTS (Kali paths)
# ─────────────────────────────────────────────
DEFAULT_PASS_WORDLIST  = "/usr/share/wordlists/rockyou.txt"
DEFAULT_USER_WORDLIST  = "/usr/share/wordlists/metasploit/unix_users.txt"
DEFAULT_DIR_WORDLIST   = "/usr/share/wordlists/dirb/common.txt"
DEFAULT_RECURSE_DEPTH  = 2


# ─────────────────────────────────────────────
#  ANSI COLORS
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
    〜〜〜〜〜〜〜〜〜〜〜〜〜〜〜〜〜〜
            F A T H O M  v1.0
          Cast wide. Dive deep.
    〜〜〜〜〜〜〜〜〜〜〜〜〜〜〜〜〜〜{C.RESET}
""")

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": C.GREEN, "WARN": C.YELLOW, "ERROR": C.RED, "TASK": C.CYAN}
    color = colors.get(level, C.RESET)
    print(f"{C.BOLD}[{ts}]{C.RESET} {color}[{level}]{C.RESET} {msg}")

def run(cmd, logfile=None, shell=False):
    """Run a command, tee output to terminal + optional logfile."""
    log(f"Running: {C.YELLOW}{cmd if isinstance(cmd, str) else ' '.join(cmd)}{C.RESET}", "TASK")
    try:
        proc = subprocess.Popen(
            cmd, shell=shell,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        lines = []
        for line in proc.stdout:
            print(f"  {line}", end="")
            lines.append(line)
        proc.wait()
        if logfile:
            Path(logfile).parent.mkdir(parents=True, exist_ok=True)
            with open(logfile, "w") as f:
                f.writelines(lines)
        return proc.returncode, "".join(lines)
    except FileNotFoundError:
        tool = cmd.split()[0] if isinstance(cmd, str) else cmd[0]
        log(f"Tool not found: {tool} — skipping", "WARN")
        return 1, ""

def tool_exists(name):
    return subprocess.run(["which", name], capture_output=True).returncode == 0


# ─────────────────────────────────────────────
#  OUTPUT DIRECTORY SETUP
# ─────────────────────────────────────────────
def make_dirs(base, ip):
    root = Path(base) / ip
    dirs = {
        "root":  root,
        "nmap":  root / "nmap",
        "web":   root / "web",
        "smb":   root / "smb",
        "ssh":   root / "ssh",
        "ftp":   root / "ftp",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


# ─────────────────────────────────────────────
#  NMAP
# ─────────────────────────────────────────────
def nmap_quick(ip, dirs):
    """Fast SYN scan across all ports to find open ones."""
    log(f"Phase 1 — quick port sweep on {ip}", "INFO")
    xml_out = str(dirs["nmap"] / "quick.xml")
    cmd = ["nmap", "-p-", "--min-rate=2000", "-T4",
           "-oX", xml_out, "-oN", str(dirs["nmap"] / "quick.txt"), ip]
    run(cmd, logfile=None)  # nmap writes its own files
    return xml_out

def nmap_deep(ip, ports, dirs):
    """Version + script scan on discovered open ports."""
    log(f"Phase 2 — deep scan on ports: {ports}", "INFO")
    xml_out = str(dirs["nmap"] / "deep.xml")
    cmd = ["nmap", "-p", ports, "-sV", "-sC", "-O",
           "--version-intensity=7",
           "-oX", xml_out, "-oN", str(dirs["nmap"] / "deep.txt"), ip]
    run(cmd, logfile=None)
    return xml_out

def parse_nmap_xml(xml_file):
    """
    Returns a dict:  { port_number(int): {"service": str, "product": str, "version": str} }
    """
    services = {}
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = int(port_el.get("portid"))
                svc_el = port_el.find("service")
                services[portid] = {
                    "service": svc_el.get("name", "unknown") if svc_el is not None else "unknown",
                    "product": svc_el.get("product", "") if svc_el is not None else "",
                    "version": svc_el.get("version", "") if svc_el is not None else "",
                }
    except (ET.ParseError, FileNotFoundError) as e:
        log(f"Failed to parse nmap XML: {e}", "ERROR")
    return services


# ─────────────────────────────────────────────
#  SERVICE HANDLERS
# ─────────────────────────────────────────────

# ── WEB ──────────────────────────────────────
def _parse_gobuster_dirs(output):
    """Return directory paths found in gobuster output (3xx responses only)."""
    dirs = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "(Status:" not in line:
            continue
        parts = line.split()
        if parts and "Status: 30" in line:
            dirs.append(parts[0])
    return dirs


def _gobuster_recurse(url, wl, outdir, port, depth, visited=None):
    """Run gobuster on url, then recurse into discovered directories."""
    if visited is None:
        visited = set()
    url = url.rstrip("/")
    if url in visited or depth < 0:
        return
    visited.add(url)

    label = url.replace("://", "_").replace("/", "_").strip("_")[:60]
    outfile = str(outdir / f"gobuster_{port}_{label}.txt")
    _, output = run(["gobuster", "dir", "-u", url, "-w", wl,
                     "-o", outfile, "-t", "40", "--no-error", "-q"])

    if depth > 0:
        for path in _parse_gobuster_dirs(output):
            _gobuster_recurse(url + path, wl, outdir, port, depth - 1, visited)


def enum_web(ip, port, dirs, args):
    proto = "https" if port == 443 or port == 8443 else "http"
    url   = f"{proto}://{ip}:{port}"
    log(f"Web enumeration → {url}", "INFO")

    # whatweb
    if tool_exists("whatweb"):
        run(["whatweb", "-a", "3", url],
            logfile=str(dirs["web"] / f"whatweb_{port}.txt"))

    # gobuster / ffuf — with subdirectory recursion
    wl    = args.dir_wordlist
    depth = args.recurse_depth
    if tool_exists("ffuf"):
        cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wl,
               "-o", str(dirs["web"] / f"ffuf_{port}.json"),
               "-of", "json", "-t", "40", "-ac", "-mc","200,204,301,302,307,401,403"]
        if depth > 0:
            cmd += ["-recursion", "-recursion-depth", str(depth)]
        run(cmd)
    elif tool_exists("gobuster"):
        _gobuster_recurse(url, wl, dirs["web"], port, depth)
    else:
        log("Neither ffuf nor gobuster found — skipping dir brute-force", "WARN")


# ── SMB ──────────────────────────────────────
def enum_smb(ip, dirs, args):
    log(f"SMB enumeration → {ip}", "INFO")

    # enum4linux
    if tool_exists("enum4linux"):
        run(["enum4linux", "-a", ip],
            logfile=str(dirs["smb"] / "enum4linux.txt"))

    # smbclient share list
    if tool_exists("smbclient"):
        run(["smbclient", "-L", f"//{ip}/", "-N"],
            logfile=str(dirs["smb"] / "smbclient_shares.txt"))

    # crackmapexec
    if tool_exists("crackmapexec"):
        run(["crackmapexec", "smb", ip],
            logfile=str(dirs["smb"] / "cme_smb.txt"))
        # spider shares anonymously
        run(["crackmapexec", "smb", ip, "--shares", "-u", "", "-p", ""],
            logfile=str(dirs["smb"] / "cme_shares.txt"))


# ── SSH ──────────────────────────────────────
def enum_ssh(ip, port, dirs, args):
    log(f"SSH enumeration → {ip}:{port}", "INFO")

    # ssh-audit
    if tool_exists("ssh-audit"):
        run(["ssh-audit", f"{ip}:{port}"],
            logfile=str(dirs["ssh"] / f"ssh_audit_{port}.txt"))

    # nmap ssh scripts
    run(["nmap", "-p", str(port), "--script",
         "ssh-hostkey,ssh2-enum-algos,ssh-auth-methods",
         "-oN", str(dirs["ssh"] / f"nmap_ssh_{port}.txt"), ip])

    # hydra — only if --brute flag set
    if args.brute:
        if tool_exists("hydra"):
            run(["hydra", "-L", args.user_wordlist, "-P", args.pass_wordlist,
                 "-s", str(port), "-t", "4", "-f",
                 ip, "ssh"],
                logfile=str(dirs["ssh"] / f"hydra_ssh_{port}.txt"))
        else:
            log("hydra not found — skipping SSH brute-force", "WARN")


# ── FTP ──────────────────────────────────────
def enum_ftp(ip, port, dirs, args):
    log(f"FTP enumeration → {ip}:{port}", "INFO")

    # nmap ftp scripts (anon login, version, bounce)
    run(["nmap", "-p", str(port),
         "--script", "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,banner",
         "-sV", "-oN", str(dirs["ftp"] / f"nmap_ftp_{port}.txt"), ip])

    # manual anon check via curl
    if tool_exists("curl"):
        run(["curl", "--connect-timeout", "5", "-v",
             f"ftp://anonymous:anonymous@{ip}:{port}/"],
            logfile=str(dirs["ftp"] / f"curl_anon_{port}.txt"))

    # hydra ftp brute — only if --brute flag set
    if args.brute:
        if tool_exists("hydra"):
            run(["hydra", "-L", args.user_wordlist, "-P", args.pass_wordlist,
                 "-s", str(port), "-t", "8", "-f",
                 ip, "ftp"],
                logfile=str(dirs["ftp"] / f"hydra_ftp_{port}.txt"))
        else:
            log("hydra not found — skipping FTP brute-force", "WARN")


# ─────────────────────────────────────────────
#  SERVICE DISPATCHER
# ─────────────────────────────────────────────
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888}
SMB_PORTS = {139, 445}
SSH_PORTS = {22, 2222}
FTP_PORTS = {21}

def dispatch(ip, services, dirs, args):
    """Route each open port to its handler."""
    smb_done = False

    for port, info in sorted(services.items()):
        svc  = info["service"].lower()
        prod = info["product"].lower()

        # Identify by port number first, fall back to service name
        if port in WEB_PORTS or "http" in svc:
            enum_web(ip, port, dirs, args)

        elif port in SMB_PORTS or "smb" in svc or "netbios" in svc or "microsoft-ds" in svc:
            if not smb_done:
                enum_smb(ip, dirs, args)
                smb_done = True  # run SMB suite once regardless of 139/445 both open

        elif port in SSH_PORTS or "ssh" in svc:
            enum_ssh(ip, port, dirs, args)

        elif port in FTP_PORTS or "ftp" in svc:
            enum_ftp(ip, port, dirs, args)

        else:
            log(f"Port {port}/{svc} — no handler configured, skipping", "WARN")


# ─────────────────────────────────────────────
#  SUMMARY REPORT
# ─────────────────────────────────────────────
def write_summary(ip, services, dirs):
    summary_path = dirs["root"] / "summary.txt"
    lines = [
        f"autoenum.py — Summary Report",
        f"Target : {ip}",
        f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Output : {dirs['root']}",
        "",
        "Open Ports / Services",
        "─" * 40,
    ]
    for port, info in sorted(services.items()):
        lines.append(
            f"  {port:>5}/tcp  {info['service']:<20} {info['product']} {info['version']}"
        )
    lines += ["", "Output Files", "─" * 40]
    for f in sorted(dirs["root"].rglob("*")):
        if f.is_file():
            lines.append(f"  {f.relative_to(dirs['root'])}")

    with open(summary_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    log(f"Summary written → {summary_path}", "INFO")
    print(f"\n{'─'*50}")
    for l in lines:
        print(f"  {l}")
    print(f"{'─'*50}\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="autoenum.py — nmap-driven automated enumeration",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("target",
        help="IP address or hostname to enumerate")
    p.add_argument("-o", "--output", default="./recon",
        help="Base output directory  (default: ./recon)")
    p.add_argument("--brute", action="store_true",
        help="Enable hydra brute-force for SSH and FTP\n(off by default — use responsibly)")
    p.add_argument("--user-wordlist", default=DEFAULT_USER_WORDLIST,
        dest="user_wordlist",
        help=f"Username list for hydra\n(default: {DEFAULT_USER_WORDLIST})")
    p.add_argument("--pass-wordlist", default=DEFAULT_PASS_WORDLIST,
        dest="pass_wordlist",
        help=f"Password list for hydra\n(default: {DEFAULT_PASS_WORDLIST})")
    p.add_argument("--dir-wordlist", default=DEFAULT_DIR_WORDLIST,
        dest="dir_wordlist",
        help=f"Directory list for gobuster/ffuf\n(default: {DEFAULT_DIR_WORDLIST})")
    p.add_argument("--recurse-depth", type=int, default=DEFAULT_RECURSE_DEPTH,
        dest="recurse_depth",
        help=f"Subdirectory recursion depth for ffuf/gobuster\n(default: {DEFAULT_RECURSE_DEPTH}, 0 = top-level only)")
    return p.parse_args()


def main():
    banner()
    args = parse_args()
    ip   = args.target

    # Verify nmap exists — hard requirement
    if not tool_exists("nmap"):
        log("nmap is required but not found. Exiting.", "ERROR")
        sys.exit(1)

    dirs = make_dirs(args.output, ip)
    log(f"Target: {C.BOLD}{ip}{C.RESET}", "INFO")
    log(f"Output root: {dirs['root']}", "INFO")
    log(f"Brute-force: {'ENABLED' if args.brute else 'disabled (pass --brute to enable)'}", "INFO")
    log(f"Dir recursion depth: {args.recurse_depth}", "INFO")
    print()

    # ── Phase 1: quick scan ──────────────────
    quick_xml = nmap_quick(ip, dirs)

    # Parse quick XML to extract open ports
    quick_services = parse_nmap_xml(quick_xml)
    if not quick_services:
        log("No open ports found in quick scan. Exiting.", "WARN")
        sys.exit(0)

    open_ports = ",".join(str(p) for p in sorted(quick_services.keys()))
    log(f"Open ports found: {C.BOLD}{open_ports}{C.RESET}", "INFO")

    # ── Phase 2: deep scan on open ports ────
    deep_xml = nmap_deep(ip, open_ports, dirs)
    services = parse_nmap_xml(deep_xml)

    # Fall back to quick results if deep parse fails
    if not services:
        log("Deep XML parse failed — using quick scan results", "WARN")
        services = quick_services

    # ── Phase 3: service enumeration ────────
    print()
    log("Starting service enumeration phase", "INFO")
    print()
    dispatch(ip, services, dirs, args)

    # ── Summary ──────────────────────────────
    write_summary(ip, services, dirs)


if __name__ == "__main__":
    main()