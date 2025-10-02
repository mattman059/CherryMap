#!/usr/bin/env python3
"""
NMAP XML to CherryTree Converter
Converts NMAP XML scan results to CherryTree (.ctd) format
"""

import xml.etree.ElementTree as ET
import argparse
import time
from datetime import datetime


def get_timestamp():
    """Generate timestamp for CherryTree nodes"""
    return str(int(time.time()))


def escape_xml(text):
    """Escape special XML characters"""
    if text is None:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&gt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;"))


def is_real_web_service(port_data):
    """
    Determine if the service is actually a web server and not WinRM or other Windows HTTP APIs
    """
    service_name = port_data['service_name'].lower()
    service_product = port_data['service_product'].lower()
    
    # Exclude Windows services that aren't real web servers
    excluded_services = [
        'winrm',
        'microsoft httpapi',
        'windows remote management',
        '.net remoting',
        'microsoft-httpapi',
        'ms-httpapi'
    ]
    
    for excluded in excluded_services:
        if excluded in service_name or excluded in service_product:
            return False
    
    # Check if it's actually a web service
    web_indicators = [
        'http', 'https', 'www', 'web', 'apache', 'nginx', 
        'iis', 'lighttpd', 'tomcat', 'jetty', 'websphere',
        'weblogic', 'jboss', 'flask', 'django', 'node.js',
        'express', 'gunicorn', 'unicorn', 'cherrypy'
    ]
    
    return any(indicator in service_name or indicator in service_product for indicator in web_indicators)


def get_os_type(os_info):
    """
    Determine if the OS is Linux, Windows, or Unknown
    Returns: 'linux', 'windows', or 'unknown'
    """
    if not os_info:
        return 'unknown'
    
    os_lower = os_info.lower()
    
    # Check for Windows indicators
    windows_indicators = ['windows', 'microsoft', 'win32', 'win64', 'win 7', 'win 8', 'win 10', 'win 11', 'win xp', 'win vista', 'win 2000', 'win 2003', 'win 2008', 'win 2012', 'win 2016', 'win 2019', 'win 2022']
    if any(indicator in os_lower for indicator in windows_indicators):
        return 'windows'
    
    # Check for Linux indicators
    linux_indicators = ['linux', 'ubuntu', 'debian', 'centos', 'rhel', 'red hat', 'fedora', 'kali', 'arch', 'suse', 'mint', 'unix', 'bsd', 'freebsd', 'openbsd']
    if any(indicator in os_lower for indicator in linux_indicators):
        return 'linux'
    
    return 'unknown'


def get_tool_recommendations(port_data, ip, os_type='unknown'):
    """
    Determine which tools should be run based on the service detected
    Returns a list of tool command strings
    """
    tools = []
    port = port_data['port']
    service_name = port_data['service_name'].lower()
    service_product = port_data['service_product'].lower()
    
    # Web Services (HTTP/HTTPS)
    if is_real_web_service(port_data):
        protocol = 'https' if 'ssl' in service_name or 'https' in service_name or 'tls' in service_product else 'http'
        
        tools.extend([
            f"# Directory/File Enumeration",
            f"gobuster dir -u {protocol}://{ip}:{port}/ -w /usr/share/wordlists/dirb/common.txt",
            f"gobuster dir -u {protocol}://{ip}:{port}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            f"feroxbuster -u {protocol}://{ip}:{port}/ -w /usr/share/wordlists/dirb/common.txt",
            f"ffuf -u {protocol}://{ip}:{port}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
            f"dirb {protocol}://{ip}:{port}/ /usr/share/wordlists/dirb/common.txt",
            f"dirsearch -u {protocol}://{ip}:{port}/ -w /usr/share/wordlists/dirb/common.txt",
            "",
            f"# Web Vulnerability Scanning",
            f"nikto -h {protocol}://{ip}:{port}/",
            f"whatweb {protocol}://{ip}:{port}/",
            f"wapiti -u {protocol}://{ip}:{port}/",
            "",
            f"# Manual Inspection",
            f"firefox {protocol}://{ip}:{port}/",
            f"curl -i {protocol}://{ip}:{port}/",
            f"curl -X OPTIONS -i {protocol}://{ip}:{port}/",
        ])
        
        # Add subdomain/vhost fuzzing if it seems like a virtual host setup
        tools.extend([
            "",
            f"# Virtual Host/Subdomain Fuzzing",
            f"gobuster vhost -u {protocol}://{ip}:{port}/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            f"ffuf -u {protocol}://{ip}:{port}/ -H 'Host: FUZZ.{ip}' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ])
    
    # FTP
    elif 'ftp' in service_name:
        tools.extend([
            f"# FTP Enumeration",
            f"ftp {ip} {port}",
            f"# Try anonymous login: anonymous / anonymous",
            f"nmap -p {port} --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 {ip}",
            "",
            f"# Brute Force (use cautiously)",
            f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ftp://{ip}:{port}",
            f"medusa -h {ip} -n {port} -U /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -M ftp",
        ])
    
    # SSH
    elif 'ssh' in service_name:
        tools.extend([
            f"# SSH Enumeration",
            f"ssh {ip} -p {port}",
            f"nc {ip} {port}",
            "",
            f"# Check for user enumeration vulnerabilities",
            f"nmap -p {port} --script ssh-auth-methods,ssh-hostkey,ssh-publickey-acceptance {ip}",
            "",
            f"# Brute Force (use cautiously)",
            f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://{ip}:{port}",
            f"medusa -h {ip} -n {port} -U /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -M ssh",
        ])
    
    # SMB/NetBIOS
    elif 'netbios' in service_name or 'microsoft-ds' in service_name or 'smb' in service_name:
        tools.extend([
            f"# SMB Enumeration",
        ])
        
        if os_type == 'windows':
            tools.extend([
                f"smbclient -L //{ip}/ -N",
                f"smbmap -H {ip}",
                f"crackmapexec smb {ip} --shares",
                f"nmap -p {port} --script smb-vuln* {ip}",
                f"nmap -p {port} --script smb-enum-shares,smb-enum-users,smb-enum-domains {ip}",
                "",
                f"# Brute Force (use cautiously)",
                f"crackmapexec smb {ip} -u users.txt -p passwords.txt",
                f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt smb://{ip}",
            ])
        elif os_type == 'linux':
            tools.extend([
                f"smbclient -L //{ip}/ -N",
                f"smbmap -H {ip}",
                f"enum4linux -a {ip}",
                f"enum4linux-ng -A {ip}",
                f"nmap -p {port} --script smb-enum-shares,smb-enum-users {ip}",
            ])
        else:
            # Unknown OS - show both
            tools.extend([
                f"smbclient -L //{ip}/ -N",
                f"smbmap -H {ip}",
                f"crackmapexec smb {ip} --shares",
                f"enum4linux -a {ip}",
                f"enum4linux-ng -A {ip}",
                "",
                f"# Vulnerability Scanning",
                f"nmap -p {port} --script smb-vuln* {ip}",
                f"nmap -p {port} --script smb-enum-shares,smb-enum-users,smb-enum-domains {ip}",
                "",
                f"# Brute Force (use cautiously)",
                f"crackmapexec smb {ip} -u users.txt -p passwords.txt",
                f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt smb://{ip}",
            ])
    
    # MSSQL
    elif 'ms-sql' in service_name or 'mssql' in service_name or 'microsoft sql' in service_product:
        if os_type == 'windows' or os_type == 'unknown':
            tools.extend([
                f"# MSSQL Enumeration",
                f"nmap -p {port} --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config {ip}",
                f"sqsh -S {ip}:{port} -U sa",
                "",
                f"# Impacket",
                f"impacket-mssqlclient {ip} -port {port}",
                "",
                f"# Brute Force (use cautiously)",
                f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt mssql://{ip}:{port}",
            ])
    
    # MySQL/MariaDB
    elif 'mysql' in service_name or 'mariadb' in service_name:
        tools.extend([
            f"# MySQL Enumeration",
            f"mysql -h {ip} -P {port} -u root",
            f"nmap -p {port} --script mysql-enum,mysql-databases,mysql-variables {ip}",
            "",
            f"# Brute Force (use cautiously)",
            f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt mysql://{ip}:{port}",
        ])
    
    # PostgreSQL
    elif 'postgresql' in service_name or 'postgres' in service_name:
        tools.extend([
            f"# PostgreSQL Enumeration",
            f"psql -h {ip} -p {port} -U postgres",
            f"nmap -p {port} --script pgsql-brute {ip}",
            "",
            f"# Brute Force (use cautiously)",
            f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt postgres://{ip}:{port}",
        ])
    
    # RDP
    elif 'rdp' in service_name or 'ms-wbt-server' in service_name or 'terminal' in service_name:
        if os_type == 'windows' or os_type == 'unknown':
            tools.extend([
                f"# RDP Enumeration",
                f"xfreerdp /v:{ip}:{port} /u:Administrator",
                f"rdesktop {ip}:{port}",
                f"nmap -p {port} --script rdp-enum-encryption,rdp-vuln-ms12-020 {ip}",
                "",
                f"# Brute Force (use cautiously)",
                f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt rdp://{ip}:{port}",
                f"crowbar -b rdp -s {ip}:{port} -U users.txt -C /usr/share/wordlists/rockyou.txt",
            ])
    
    # WinRM
    elif 'winrm' in service_name or 'windows remote management' in service_product:
        if os_type == 'windows' or os_type == 'unknown':
            tools.extend([
                f"# WinRM Enumeration",
                f"crackmapexec winrm {ip} -u users.txt -p passwords.txt",
                f"evil-winrm -i {ip} -u administrator -p password",
                "",
                f"# Brute Force (use cautiously)",
                f"crackmapexec winrm {ip} -u users.txt -p /usr/share/wordlists/rockyou.txt",
            ])
    
    # SNMP
    elif 'snmp' in service_name:
        tools.extend([
            f"# SNMP Enumeration",
            f"snmpwalk -v2c -c public {ip}",
            f"snmpwalk -v2c -c private {ip}",
            f"onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt {ip}",
            f"snmp-check {ip}",
            f"nmap -p {port} --script snmp-* {ip}",
        ])
    
    # DNS
    elif 'dns' in service_name or 'domain' in service_name:
        tools.extend([
            f"# DNS Enumeration",
            f"dig @{ip} -p {port} domain.com ANY",
            f"host -t any domain.com {ip}",
            f"nslookup domain.com {ip}",
            f"dnsenum --dnsserver {ip} domain.com",
            f"fierce --dns-servers {ip} --domain domain.com",
            "",
            f"# Zone Transfer",
            f"dig @{ip} -p {port} domain.com AXFR",
            f"host -l domain.com {ip}",
        ])
    
    # LDAP
    elif 'ldap' in service_name:
        tools.extend([
            f"# LDAP Enumeration",
            f"ldapsearch -x -h {ip} -p {port} -s base",
            f"ldapsearch -x -h {ip} -p {port} -b 'dc=domain,dc=com'",
            f"nmap -p {port} --script ldap-search,ldap-rootdse {ip}",
            f"ldapdomaindump {ip}:{port}",
        ])
    
    # Redis
    elif 'redis' in service_name:
        tools.extend([
            f"# Redis Enumeration",
            f"redis-cli -h {ip} -p {port}",
            f"# Try: INFO, CONFIG GET *, KEYS *",
            f"nmap -p {port} --script redis-info {ip}",
        ])
    
    # MongoDB
    elif 'mongodb' in service_name or 'mongo' in service_name:
        tools.extend([
            f"# MongoDB Enumeration",
            f"mongo {ip}:{port}",
            f"# Try: show dbs, use dbname, show collections",
            f"nmap -p {port} --script mongodb-databases,mongodb-info {ip}",
        ])
    
    # Telnet
    elif 'telnet' in service_name:
        tools.extend([
            f"# Telnet Enumeration",
            f"telnet {ip} {port}",
            f"nc {ip} {port}",
            "",
            f"# Brute Force (use cautiously)",
            f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt telnet://{ip}:{port}",
        ])
    
    # SMTP
    elif 'smtp' in service_name:
        tools.extend([
            f"# SMTP Enumeration",
            f"telnet {ip} {port}",
            f"nc {ip} {port}",
            f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {ip} -p {port}",
            f"nmap -p {port} --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344 {ip}",
        ])
    
    # POP3/IMAP
    elif 'pop3' in service_name or 'imap' in service_name:
        tools.extend([
            f"# {service_name.upper()} Enumeration",
            f"telnet {ip} {port}",
            f"nc {ip} {port}",
            "",
            f"# Brute Force (use cautiously)",
            f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {service_name}://{ip}:{port}",
        ])
    
    # VNC
    elif 'vnc' in service_name:
        tools.extend([
            f"# VNC Enumeration",
            f"vncviewer {ip}:{port}",
            f"nmap -p {port} --script vnc-info,realvnc-auth-bypass {ip}",
            "",
            f"# Brute Force (use cautiously)",
            f"hydra -P /usr/share/wordlists/rockyou.txt vnc://{ip}:{port}",
        ])
    
    # NFS
    elif 'nfs' in service_name or 'rpcbind' in service_name:
        tools.extend([
            f"# NFS Enumeration",
            f"showmount -e {ip}",
            f"nmap -p {port} --script nfs-ls,nfs-showmount,nfs-statfs {ip}",
            f"# Mount: mkdir /mnt/nfs && mount -t nfs {ip}:/share /mnt/nfs",
        ])
    
    # Kerberos
    elif 'kerberos' in service_name or 'krb5' in service_name:
        if os_type == 'windows' or os_type == 'unknown':
            tools.extend([
                f"# Kerberos Enumeration",
                f"nmap -p {port} --script krb5-enum-users --script-args krb5-enum-users.realm='domain.com' {ip}",
                f"kerbrute userenum -d domain.com --dc {ip} /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt",
                f"# AS-REP Roasting",
                f"impacket-GetNPUsers domain.com/ -dc-ip {ip} -usersfile users.txt -format hashcat",
            ])
    
    # Generic/Unknown service
    else:
        tools.extend([
            f"# Generic Enumeration",
            f"nc {ip} {port}",
            f"telnet {ip} {port}",
            f"nmap -p {port} -sV -sC {ip}",
            f"# Check for banner grabbing",
            f"# Try connecting and sending basic commands",
        ])
    
    return tools


def create_cherrytree_node(name, unique_id, content="", children=None):
    """Create a CherryTree node element"""
    ts = get_timestamp()
    node = ET.Element("node", {
        "name": escape_xml(name),
        "unique_id": str(unique_id),
        "prog_lang": "custom-colors",
        "tags": "",
        "readonly": "0",
        "custom_icon_id": "0",
        "is_bold": "0",
        "foreground": "",
        "ts_creation": ts,
        "ts_lastsave": ts
    })
    
    if content:
        rich_text = ET.SubElement(node, "rich_text")
        rich_text.text = escape_xml(content)
    
    if children:
        for child in children:
            node.append(child)
    
    return node


def parse_nmap_xml(nmap_file):
    """Parse NMAP XML file and extract host information"""
    tree = ET.parse(nmap_file)
    root = tree.getroot()
    
    hosts_data = []
    
    for host in root.findall('.//host'):
        # Get host status
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        
        # Get IP address
        address = host.find('address')
        if address is None:
            continue
        ip = address.get('addr')
        
        # Get hostname if available
        hostnames = host.find('hostnames')
        hostname = ""
        if hostnames is not None:
            hostname_elem = hostnames.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', '')
        
        # Get ports information
        ports_data = []
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                
                state = port.find('state')
                port_state = state.get('state') if state is not None else 'unknown'
                
                # Only process open ports
                if port_state != 'open':
                    continue
                
                service = port.find('service')
                service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                service_product = service.get('product', '') if service is not None else ''
                service_version = service.get('version', '') if service is not None else ''
                service_extrainfo = service.get('extrainfo', '') if service is not None else ''
                
                # Get script output if available
                scripts = []
                for script in port.findall('script'):
                    script_id = script.get('id')
                    script_output = script.get('output', '')
                    scripts.append({'id': script_id, 'output': script_output})
                
                ports_data.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': port_state,
                    'service_name': service_name,
                    'service_product': service_product,
                    'service_version': service_version,
                    'service_extrainfo': service_extrainfo,
                    'scripts': scripts
                })
        
        # Get OS information if available
        os_info = ""
        os_elem = host.find('.//osmatch')
        if os_elem is not None:
            os_info = f"{os_elem.get('name', '')} (Accuracy: {os_elem.get('accuracy', '')}%)"
        
        # Determine OS type
        os_type = get_os_type(os_info)
        
        # Skip hosts with no open ports
        if not ports_data:
            continue
        
        hosts_data.append({
            'ip': ip,
            'hostname': hostname,
            'ports': ports_data,
            'os': os_info,
            'os_type': os_type
        })
    
    return hosts_data


def create_cherrytree_document(hosts_data):
    """Create CherryTree XML document from NMAP data"""
    root = ET.Element("cherrytree")
    node_id = 1
    
    for host in hosts_data:
        # Create host node
        os_suffix = ""
        if host['os_type'] == 'windows':
            os_suffix = "-W"
        elif host['os_type'] == 'linux':
            os_suffix = "-L"
        
        host_name = f"{host['ip']}{os_suffix}"
        if host['hostname']:
            host_name += f" ({host['hostname']})"
        
        host_content = f"IP Address: {host['ip']}\n"
        if host['hostname']:
            host_content += f"Hostname: {host['hostname']}\n"
        if host['os']:
            host_content += f"OS: {host['os']}\n"
        host_content += f"Open Ports: {len(host['ports'])}"
        
        # Create Port Scan child node
        port_scan_children = []
        
        for port_data in host['ports']:
            # Create port node
            port_name = f"Port {port_data['port']}/{port_data['protocol']}"
            
            port_content = f"Port: {port_data['port']}\n"
            port_content += f"Protocol: {port_data['protocol']}\n"
            port_content += f"State: {port_data['state']}\n"
            
            # Children for this port
            port_children = []
            
            # Create service info child
            service_content = f"Service: {port_data['service_name']}\n"
            if port_data['service_product']:
                service_content += f"Product: {port_data['service_product']}\n"
            if port_data['service_version']:
                service_content += f"Version: {port_data['service_version']}\n"
            if port_data['service_extrainfo']:
                service_content += f"Extra Info: {port_data['service_extrainfo']}\n"
            
            # Add script output if available
            if port_data['scripts']:
                service_content += "\nScript Output:\n"
                for script in port_data['scripts']:
                    service_content += f"\n[{script['id']}]\n{script['output']}\n"
            
            service_node = create_cherrytree_node("Service Info", node_id, service_content)
            node_id += 1
            port_children.append(service_node)
            
            # Create tool recommendations child
            tool_recommendations = get_tool_recommendations(port_data, host['ip'], host['os_type'])
            if tool_recommendations:
                tools_content = "\n".join(tool_recommendations)
                tools_node = create_cherrytree_node("Tool Recommendations", node_id, tools_content)
                node_id += 1
                port_children.append(tools_node)
            
            port_node = create_cherrytree_node(port_name, node_id, port_content, port_children)
            node_id += 1
            port_scan_children.append(port_node)
        
        port_scan_node = create_cherrytree_node("Port Scan", node_id, "", port_scan_children)
        node_id += 1
        
        host_node = create_cherrytree_node(host_name, node_id, host_content, [port_scan_node])
        node_id += 1
        
        root.append(host_node)
    
    return root


def main():
    parser = argparse.ArgumentParser(
        description='Convert NMAP XML output to CherryTree format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python cherrymap.py -i scan_results.xml -o output.ctd
        """
    )
    parser.add_argument('-i', '--input', required=True, help='Input NMAP XML file')
    parser.add_argument('-o', '--output', required=True, help='Output CherryTree file (.ctd)')
    
    args = parser.parse_args()
    
    try:
        print(f"[+] Parsing NMAP XML file: {args.input}")
        hosts_data = parse_nmap_xml(args.input)
        print(f"[+] Found {len(hosts_data)} hosts")
        
        print(f"[+] Creating CherryTree document...")
        cherrytree_root = create_cherrytree_document(hosts_data)
        
        print(f"[+] Writing to {args.output}")
        tree = ET.ElementTree(cherrytree_root)
        ET.indent(tree, space="  ")
        tree.write(args.output, encoding='UTF-8', xml_declaration=True)
        
        print(f"[+] Done! CherryTree document created successfully.")
        
    except FileNotFoundError:
        print(f"[-] Error: File '{args.input}' not found")
    except ET.ParseError as e:
        print(f"[-] Error parsing XML: {e}")
    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    main()
