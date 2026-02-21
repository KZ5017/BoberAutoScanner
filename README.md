# BoberAutoScanner

BoberAutoScanner is a Python-based reconnaissance wrapper that orchestrates multiple well-known offensive security tools into a semi-automated workflow.

It is primarily designed for **CTF environments, labs, and training scenarios**, where automation and rapid service correlation are useful.  
It is **not intended to replace professional real-world penetration testing methodologies**.

The tool focuses on:

- Port discovery
    
- Service fingerprinting
    
- Active Directory discovery
    
- Windows service validation
    
- Web service validation and enumeration
    
- Virtual host and endpoint fuzzing
    
- Controlled web crawling
    

---

## ⚠️ Disclaimer

BoberAutoScanner is intended for:

- Capture The Flag (CTF) competitions
    
- Lab environments (e.g., Hack The Box, TryHackMe, local labs)
    
- Educational use
    

It is **not a full-featured enterprise-grade pentesting framework** and does not replace manual analysis, reporting discipline, or professional tradecraft.

Always ensure you have proper authorization before scanning any system.

---

## Design Philosophy

BoberAutoScanner does not reinvent scanning logic.  
Instead, it acts as an **automation wrapper** around existing industry-standard tools.

It:

- Connects scan results across phases
    
- Extracts structured information from Nmap output
    
- Builds domain mappings automatically
    
- Optionally updates `/etc/hosts`
    
- Validates real web services before attacking them
    
- Applies baseline-aware fuzzing logic to reduce noise
    

The goal is practical automation for controlled environments — not stealth or OPSEC.

---

# Architecture Overview

The workflow consists of the following major phases:

## 1️⃣ Nmap Phase

- RustScan for fast full TCP port discovery
    
- Nmap service detection (`-sV`)
    
- Nmap aggressive scan (`-A`)
    

Outputs:

- `rustscan_all-ports_TCP.txt`
    
- `nmap_all-ports_basic-info_TCP.txt`
    
- `nmap_all-ports_all-info_TCP.txt`
    

---

## 2️⃣ Domain & Target Discovery

From Nmap output, the tool:

- Extracts LDAP naming contexts
    
- Extracts SSL CN and SAN values
    
- Extracts HTTP redirect targets
    
- Extracts structured NTLM/DNS domain data
    
- Aggregates discovered domains
    
- Optionally updates `/etc/hosts`
    

This allows:

- Correct web vhost resolution
    
- Accurate AD environment mapping
    
- Cleaner follow-up scans
    

---

## 3️⃣ Active Directory & Windows Enumeration

If Windows-related ports are detected (e.g. 389, 445, 3389, 5985, etc.), the tool:

- Performs credential validation rounds
    
- Tests:
    
    - Provided credentials
        
    - Anonymous login
        
    - Guest login (unless disabled)
        
- Executes service-specific modules:
    
    - SMB
        
    - RPC
        
    - LDAP
        

### LDAP Block

Executed via `nxc ldap` with modules such as:

- Domain Controllers
    
- Domain Admins
    
- ASREPRoast
    
- Kerberoasting
    
- gMSA
    
- BloodHound collection
    
- Delegation analysis
    

Outputs consolidated LDAP reports.

---

### SMB Block

Executed via `nxc smb`, including:

- Share enumeration
    
- RID brute force
    
- User export
    
- Password policy
    
- Optional extended SMB report (`--create-smb-report`)
    

Readable shares are automatically dumped using `smbclient`.

---

## 4️⃣ Web Service Validation

The tool:

- Detects HTTP/HTTPS services from Nmap
    
- Validates real web responses via `curl`
    
- Maps domain → port → scheme
    
- Avoids Windows internal HTTP services
    

Only confirmed web services move to the next stage.

---

## 5️⃣ Web Enumeration

For validated web targets:

- CMS detection (WordPress, Drupal, Joomla)
    
- Optional web crawling (via `bober-crawler`)
    
- Virtual host fuzzing (`ffuf`)
    
- Endpoint fuzzing (`ffuf`)
    
- Baseline-aware filtering to reduce wildcard noise
    

The crawler supports optional Burp proxy integration.

---

# Required External Tools

BoberAutoScanner depends heavily on external binaries.

You must install the following tools manually:

### Core Scanning

- `rustscan`
    
- `nmap`
    

### Windows / AD Enumeration

- `nxc` (NetExec)
    
- `rpcclient`
    
- `smbclient`
    

### Web Enumeration

- `curl`
    
- `ffuf`
    
- `bober-crawler` (custom tool)
    

### Optional

- `sudo` (for Nmap -A and hosts updates)
    
- Burp Suite (for proxy-based crawling)
    

---

# Installation

Install via pipx (recommended):

```bash
pipx install git+https://github.com/KZ5017/BoberAutoScanner.git
```

Ensure Python 3.9+ is installed.

Install required system tools separately (not bundled).

---

# Usage

Basic usage:

```bash
python3 BoberAutoScanner.py <target_ip>
```

With credentials:

```bash
python3 BoberAutoScanner.py <target_ip> -u user -p password
```

Skip Nmap phase (use existing scan files):

```bash
python3 BoberAutoScanner.py <target_ip> --skip-nmap
```

Enable extended SMB report:

```bash
python3 BoberAutoScanner.py <target_ip> -csr
```

Enable virtual host fuzzing:

```bash
python3 BoberAutoScanner.py <target_ip> -wfs subdomains.txt
```

Enable endpoint fuzzing:

```bash
python3 BoberAutoScanner.py <target_ip> -wfe endpoints.txt
```

Fully interactive mode (disable auto-timeouts):

```bash
python3 BoberAutoScanner.py <target_ip> --no-auto
```

---

# Output Structure

The tool generates structured output files such as:

- `ldap_<user>_output.txt`
    
- `smb_<user>_shares.txt`
    
- `rpc_<user>_enumdomusers.txt`
    
- `domain_port_endpoint.json`
    
- BloodHound ZIP files
    
- Dumped SMB share directories
    

Files are named consistently using:

```
<service>_<username>_<module>.txt
```

---

# Strengths

- Automates repetitive CTF workflows
    
- Reduces manual parsing of Nmap output
    
- Correlates AD + Web + Service data
    
- Handles vhost and endpoint baselining
    
- Structured output organization
    

---

# Limitations

- Not stealthy
    
- No rate control sophistication
    
- No evasion logic
    
- Not optimized for production engagements
    
- Assumes Linux environment
    
- Requires many external tools
    
- Requires sudo for certain features
    

---

# Intended Use Cases

✔ CTF competitions  
✔ Lab environments  
✔ Active Directory attack labs  
✔ Web + AD mixed challenge boxes

Not recommended for:

✘ Corporate production testing without modification  
✘ Red team engagements requiring stealth  
✘ Environments with strict logging/IDS

---

# Final Notes

BoberAutoScanner is a workflow accelerator, not an exploitation framework.

It works best when:

- You understand what each underlying tool does.
    
- You review all generated output manually.
    
- You treat it as an assistant — not a replacement for analysis.
    

