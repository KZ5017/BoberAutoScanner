<p align="center">
  <img width="600" src="https://github.com/user-attachments/assets/d10d8902-0c60-4a44-ac51-ba3592eb33ab" />
</p>

<h1 align="center">BoberAutoScanner</h1>

<p align="center">
  <b>Automated recon wrapper for CTF · HTB · OSCP environments</b><br/>
  <sub>RustScan · Nmap · NetExec · ffuf · Nuclei · BloodHound · SNMP</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-cyan?style=flat-square"/>
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Kali%20Linux-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/OSCP-compatible-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
</p>

---

> BoberAutoScanner is a Python-based recon wrapper that chains together the best offensive security tools into a single, semi-automated workflow.  
> Built for **CTF competitions, Hack The Box, and OSCP practice** — not for production red team engagements.

---

## ⚡ Quickstart

```bash
# Install
pipx install git+https://github.com/KZ5017/BoberAutoScanner.git

# Basic scan
bober-autoscanner 10.10.11.1

# With credentials
bober-autoscanner 10.10.11.1 -u admin -p Password1

# Pass-the-Hash
bober-autoscanner 10.10.11.1 -u administrator -H aad3b435b51404ee:ntlmhash

# Skip Nmap (reuse existing scan files)
bober-autoscanner 10.10.11.1 --skip-nmap

# Full combo: nuclei + CVE + fuzzing
bober-autoscanner 10.10.11.1 --nuclei --cve -wfe /usr/share/seclists/Discovery/Web-Content/common.txt

# SNMP with known community string
bober-autoscanner 10.10.11.1 --snmp-community public
```

---

## 🔁 Workflow

```
TARGET IP
    │
    ▼
┌──────────────────────────────────────┐
│  1. TCP SCAN                         │
│  RustScan (fast) → Nmap -sV → -A     │
└───────────────────┬──────────────────┘
                    │
                    ▼
┌──────────────────────────────────────┐
│  2. UDP SCAN                         │
│  Nmap -sU -sV -sC --open             │
│  ports: 53,161,162,500,5353...       │
└───────────────────┬──────────────────┘
                    │
                    ▼
┌──────────────────────────────────────┐
│  3. DOMAIN & TARGET DISCOVERY        │
│  LDAP · SSL CN/SAN · HTTP redirects  │
│  NTLM · /etc/hosts auto-update       │
└──────┬─────────────────────┬─────────┘
       │                     │
       ▼                     ▼
┌─────────────────┐  ┌──────────────────────────────────┐
│  4. AD / WIN    │  │  5. WEB ENUMERATION              │
│                 │  │                                  │
│  LDAP block     │  │  Fingerprint                     │
│  SMB block      │  │  → Server / X-Powered-By         │
│  ASREPRoast     │  │  → Tech stack (React/Laravel...) │
│  Kerberoasting  │  │  → Cookie security flags         │
│  BloodHound     │  │  → JWT detection                 │
│  gMSA dump      │  │                                  │
│  PtH / -H hash  │  │                                  │
│  Spray          │  │  Nuclei (--nuclei)               │
│  SMB cred scan  │  │  CVE lookup (--cve)              │
│                 │  │  vHost fuzzing                   │
│                 │  │  Endpoint fuzzing                │
│                 │  │  Web crawler (Burp proxy opt.)   │
└─────────────────┘  └──────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│  6. SNMP ENUMERATION                 │
│  Only if UDP 161/162 confirmed open  │
│  Community brute · snmpwalk          │
│  snmp-check · OID enum · cred hunt   │
└──────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────┐
│  7. OUTPUT                           │
│  scan_summary.json                   │
│  cve_hints.txt · nuclei findings     │
│  ldap/smb/snmp reports               │
│  BloodHound zip · hash files         │
└──────────────────────────────────────┘
```

---

## 🧰 Features

### Port Discovery
| Tool | Role |
|------|------|
| **RustScan** | Fast full TCP port discovery |
| **Nmap `-sV`** | Service version detection |
| **Nmap `-A`** | OS detection, scripts, traceroute |
| **Nmap `-sU -sV -sC --open`** | UDP scan — only confirmed open ports |

---

### Active Directory & Windows
| Feature | Description |
|---------|-------------|
| **Credential rounds** | Provided → Anonymous → Guest, auto Kerberos retry |
| **Pass-the-Hash** (`-H`) | Full NTLM hash support across all modules |
| **LDAP enumeration** | DC list, Domain Admins, Admin Count, delegations, ADCS, PSO, gMSA |
| **ASREPRoast** | Auto-dumps hashes + prints `hashcat -m 18200` command |
| **Kerberoasting** | Auto-dumps hashes + prints `hashcat -m 13100 / 19700` command |
| **BloodHound** | Runs `--bloodhound --collection All`, moves ZIP to output dir |
| **SMB enumeration** | Shares, RID brute, user export, password policy |
| **SMB spider** | Downloads readable shares via `spider_plus` |
| **Credential scan** | Scans downloaded share files for passwords/secrets/API keys |
| **Password spray** | Auto-spray against collected `users.txt` with common passwords |
| **Suspicious descriptions** | Flags AD user descriptions containing embedded credentials |
| **Extended SMB report** (`-csr`) | 30+ modules: DPAPI, LSA, SAM, NTDS, lsassy, KeePass, WinSCP... |
| **Time sync** | Auto-syncs with DC to prevent `KRB_AP_ERR_SKEW` errors |

---

### SNMP Enumeration
| Feature | Description |
|---------|-------------|
| **UDP gate** | Only runs if Nmap confirms UDP 161 or 162 **open** (not open\|filtered) |
| **Community brute** | `onesixtyone` + sequential fallback against common strings |
| **Full MIB walk** | `snmpwalk` full dump per valid community |
| **snmp-check** | Structured enumeration output |
| **Targeted OIDs** | Users, interfaces, processes, software, uptime, network |
| **Credential hunt** | Greps SNMP dump for passwords, API keys, connection strings |
| **Manual override** | `--snmp` force flag or `--snmp-community <string>` |

---

### Web Enumeration
| Feature                  | Description                                                              |
| ------------------------ | ------------------------------------------------------------------------ |
| **Service validation**   | curl-based HTTP/HTTPS confirmation with vhost + redirect support         |
| **Server fingerprint**   | Extracts `Server:`, `X-Powered-By:`, tech stack from response            |
| **Technology detection** | React, Angular, Vue, Laravel, Django, Flask, ASP.NET, WordPress...       |
| **Cookie analysis**      | Flags missing `HttpOnly`, `Secure`, `SameSite`                           |
| **JWT detection**        | Finds JWT tokens (`eyJ...`) in headers and cookies                       |
| **CMS detection**        | WordPress, Drupal, Joomla (header + body + path evidence)                |
| **Nuclei** (`--nuclei`)  | Scans with `cves/`, `misconfiguration/`, `exposures/`, `default-logins/` |
| **CVE lookup** (`--cve`) | `searchsploit` + NVD API with ExploitDB + MITRE links                    |
| **vHost fuzzing**        | `ffuf` with smart baseline — redirect codes never filtered               |
| **Endpoint fuzzing**     | `ffuf` with word-count baseline filtering                                |
| **Web crawler**          | `bober-crawler` with optional Burp Suite proxy integration               |

---

### Output & Reporting
| Output | Description |
|--------|-------------|
| `scan_summary.json` | Structured JSON: ports, domains, web targets, loot files |
| `cve_hints.txt` | CVE findings with ExploitDB + NVD + MITRE links |
| `ldap_<user>_output.txt` | Full LDAP enumeration report |
| `smb_<user>_report.txt` | Extended SMB module report |
| `smb_cred_scan.txt` | Credentials found in downloaded SMB shares |
| `smb_spray_hits.txt` | Successful password spray results |
| `asreproast.txt` / `kerberoasting.txt` | Hash files ready for hashcat |
| `ldap_suspicious_descriptions.txt` | AD descriptions with possible embedded creds |
| `snmp_<community>_full.txt` | Full SNMP MIB walk |
| `snmp_<community>_cred_hints.txt` | Credentials found in SNMP dump |
| `<host>_<port>_nuclei.txt` | Nuclei findings per target |
| `<host>_<port>_endpoint.txt` | Discovered endpoints (wordlist format) |
| `BloodHound_*.zip` | BloodHound collection, moved to output directory |
| `nmap_udp_scan.txt` | UDP scan results |

All files are written to `<target_ip>_scan/` (or custom `-o` path).

---

## 🚩 Flags

```
bober-autoscanner <target_ip> [options]

Authentication:
  -u, --username              Username
  -p, --password              Password
  -H, --hash                  NTLM hash (:NT or LM:NT)

Scan control:
  -sn, --skip-nmap            Skip RustScan/Nmap, use existing scan files
  -spu, --skip-passwordless-users
                              Skip anonymous and guest auth rounds

Modules:
  --nuclei                    Run Nuclei against web targets
  --cve                       CVE lookup via searchsploit + NVD API
  --snmp                      Force SNMP enumeration (no UDP scan needed)
  --snmp-community <string>   Use specific community string (skips brute)
  -wfs, --wordlist-for-subdomain
                              Wordlist for vHost fuzzing
  -wfe, --wordlist-for-endpoints
                              Wordlist for endpoint fuzzing
  -csr, --create-smb-report   Extended SMB report (needs high privileges)

Output:
  -o, --output-dir            Custom output directory (default: <ip>_scan/)
  --no-auto                   Fully interactive (disable auto-timeouts)
```

---

## 📦 Required Tools

```bash
# Core
apt install nmap curl ffuf nuclei hashcat snmp snmp-mibs-downloader onesixtyone

# RustScan
https://github.com/RustScan/RustScan/releases

# NetExec
pipx install netexec

# snmp-check
apt install snmpcheck

# Wordlists
apt install seclists

# Custom (Bober ecosystem)
bober-crawler    # separate repo
bober-exec       # separate repo
```

---

## 💡 Usage Examples

```bash
# First scan — auto-updates /etc/hosts
bober-autoscanner 10.10.11.1

# Subsequent runs — skip nmap, reuse files
bober-autoscanner 10.10.11.1 --skip-nmap --nuclei --cve

# AD box with hash
bober-autoscanner 10.10.11.1 -u administrator -H :ntlmhash -csr

# SNMP box
bober-autoscanner 10.10.11.1 --snmp-community public

# Full web box
bober-autoscanner 10.10.11.1 --skip-nmap --nuclei --cve \
  -wfs /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -wfe /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Update nuclei templates before first --nuclei run
nuclei -update-templates
```

---

## 📁 Output Structure

```
10.10.11.1_scan/
├── rustscan_all-ports_TCP.txt
├── nmap_all-ports_basic-info_TCP.txt
├── nmap_all-ports_all-info_TCP.txt
├── nmap_udp_scan.txt
├── nmap_LDAP.txt
│
├── ldap_<user>_output.txt
├── ldap_suspicious_descriptions.txt
├── smb_<user>_shares.txt
├── smb_<user>_rid_brute.txt
├── smb_<user>_pass_pol.txt
├── smb_<user>_report.txt          ← only with -csr
├── smb_cred_scan.txt
├── smb_spray_hits.txt
│
├── asreproast.txt
├── kerberoasting.txt
├── users.txt
├── BloodHound_<timestamp>.zip
│
├── snmp_public_full.txt
├── snmp_public_check.txt
├── snmp_public_targeted.txt
├── snmp_public_cred_hints.txt
│
├── <host>_<port>_vhost.json
├── <host>_<port>_endpoint.json
├── <host>_<port>_endpoint.txt
├── <host>_<port>_nuclei.txt
├── cve_hints.txt
│
├── nxc_logs/
├── smb_share_dumps/
└── scan_summary.json
```

---

## ⚠️ Disclaimer

BoberAutoScanner is intended for:
- CTF competitions
- Hack The Box / TryHackMe / OSCP lab environments
- Authorized penetration testing

**Not designed for:** stealth, evasion, production red team engagements, or unauthorized scanning.  
Always ensure you have explicit permission before scanning any system.

---

## Design Philosophy

BoberAutoScanner does not reinvent scanning logic.  
Instead, it acts as an **automation wrapper** around existing industry-standard tools.

It connects scan results across phases, extracts structured information from tool output, and builds a correlated picture of the target — so you can spend time on exploitation instead of copy-pasting commands.

The goal is practical automation for controlled environments — not stealth or OPSEC.

---

## 📄 License

MIT — free to use, modify, and redistribute.
