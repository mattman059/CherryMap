# Nmap to CherryTree Converter

A Python script that takes Nmap XML output and turns it into a CherryTree (`.ctd`) file. Hosts, ports, and services are organized in a tree format, with suggested tools for follow-up testing.

---

## Overview

- Reads Nmap XML scans
- Creates a CherryTree document with hosts and ports structured in a hierarchy
- Includes basic tool suggestions based on detected services and OS when possible

---

## Features

### Filtering Results

- Closed and filtered ports are ignored
- Hosts with no open ports are skipped
- If OS detection is present, hosts are labeled (e.g., `192.168.1.10-W` for Windows, `192.168.1.20-L` for Linux)

### Tool Recommendations

- Suggestions are based on services and OS when known
- Windows hosts: tools like `crackmapexec`, `evil-winrm`, RDP clients
- Linux hosts: tools like `enum4linux` for Samba
- Web services are detected separately from WinRM/Microsoft HTTPAPI to avoid confusion

### Output Structure

The generated file is organized for quick navigation:

```
192.168.1.10-W (DC01.domain.local)
  └── Port Scan
      ├── 445/tcp
      │   ├── Service Info
      │   └── Tool Recommendations
      └── 3389/tcp
          ├── Service Info
          └── Tool Recommendations
```

---

## Requirements

- Python 3.6+
- Nmap (for scans)
- CherryTree (for viewing/editing the `.ctd` file)

---

## Installation

1. Download the script:

```bash
wget https://raw.githubusercontent.com/mattman059/CherryMap/main/cherrymap.py
chmod +x cherrymap.py
```

2. Install CherryTree if needed:

```bash
# Debian/Ubuntu
sudo apt install cherrytree

# Arch
sudo pacman -S cherrytree

# Or download from https://www.giuspen.com/cherrytree/
```

---

## Usage

### Step 1: Run an Nmap scan
Save results in XML format:

```bash
nmap -sV -oX scan_results.xml 192.168.1.0/24
nmap -sV -sC -O -oX scan_results.xml 192.168.1.0/24
nmap -A -oX scan_results.xml 192.168.1.1-254
```

Common flags:

- `-sV`: service version detection (needed for recommendations)
- `-O`: OS detection (enables OS-specific filtering)
- `-sC`: default NSE scripts
- `-oX`: XML output (required for this script)

### Step 2: Convert results

```bash
python3 cherrymap.py -i scan_results.xml -o pentest_notes.ctd
```

### Step 3: Open in CherryTree

```bash
cherrytree pentest_notes.ctd
```

---

## Command Line Options

```
usage: cherrymap.py [-h] -i INPUT -o OUTPUT

Convert Nmap XML output to CherryTree format

options:
  -h, --help         show this help message and exit
  -i INPUT           Input Nmap XML file
  -o OUTPUT          Output CherryTree file (.ctd)
```

---

## Output Details

### Host Level

```
192.168.1.100-W (webserver.local)
├── IP Address: 192.168.1.100
├── Hostname: webserver.local
├── OS: Windows Server 2019 (Accuracy: 95%)
└── Open Ports: 3
```

### Port Level

Each open port includes:

- Port number/protocol
- State
- Service info (name, product, version)
- NSE script output (if available)
- Tool suggestions

---

## Supported Services & Tools (Examples)

- **Web (HTTP/HTTPS):** gobuster, ffuf, nikto, whatweb
- **SMB/NetBIOS:** smbclient, smbmap, netexec, enum4linux
- **SSH:** ssh client, brute force tools
- **RDP (Windows):** xfreerdp, rdesktop, hydra
- **Databases:** mysql, psql, mongo client, impacket-mssqlclient
- **LDAP/Kerberos:** ldapsearch, ldapdomaindump, kerbrute
- **DNS:** dig, host, dnsenum, fierce
- **SNMP:** snmpwalk, onesixtyone

---

## Notes on Detection

- Web service detection attempts to skip false positives like WinRM or Microsoft HTTPAPI
- OS-aware recommendations filter Windows vs Linux tools where possible

---

## Typical Workflow

1. Run an Nmap scan and save XML
2. Convert with the script
3. Open the `.ctd` file in CherryTree
4. Navigate to a host, check suggested tools, and run what’s useful
5. Add notes and keep track of credentials or working commands

---

## Troubleshooting

- **No hosts in output:** Make sure the scan found live hosts and was saved in XML (`-oX`)
- **Missing recommendations:** Use `-sV` in Nmap to capture service info
- **OS not detected:** Add `-O` (requires sudo). OS detection isn’t always reliable, but the script still works without it

---

## License

For security testing and research only. Make sure you have permission before scanning any system.

---


