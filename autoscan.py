import socket
import subprocess
import requests
import nmap
from impacket import smb

def scan_ports(host, start_port, end_port):
    open_ports = []
    nmap_args = ["nmap", "-p", f"{start_port}-{end_port}", "-sV", host]
    try:
        output = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT)
        output_str = output.decode()
        lines = output_str.split("\n")
        for line in lines:
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = parts[0].split("/")[0]
                service = parts[2]
                version = parts[3]
                open_ports.append((int(port), service, version))
    except subprocess.CalledProcessError as e:
        print("Error executing Nmap:", e.output)
    return open_ports

def identify_services(open_ports):
    services = []
    for port in open_ports:
        try:
            service = socket.getservbyport(port)
            services.append((port, service))
        except socket.error:
            services.append((port, 'unknown'))
    return services

def nmap_http_scan(host, port):
    nmap_args = ["nmap", "-p", str(port), "--script", "http-title", host]
    try:
        output = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        print("Error executing Nmap:", e.output)
        return None

def directory_bust(url):
    wordlist = ["admin", "login", "secret", "backup"]  # Add more words as needed
    for word in wordlist:
        try_url = url + "/" + word
        response = requests.get(try_url)
        if response.status_code == 200:
            print(f"Found directory: {try_url}")

def run_nikto_scan(url):
    nikto_args = ["nikto", "-h", url]
    try:
        output = subprocess.check_output(nikto_args, stderr=subprocess.STDOUT)
        print("Nikto scan result:")
        print(output.decode())
    except subprocess.CalledProcessError as e:
        print("Error executing Nikto:", e.output)

def identify_os(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-O')
    if 'osclass' in nm[host]:
        osclass = nm[host]['osclass']
        if osclass:
            print(f"OS Identification for {host}:")
            for os in osclass:
                print(f"OS Name: {os['name']}\tAccuracy: {os['accuracy']}")

def smb_enumeration(host):
    username = ''
    password = ''
    try:
        smb_client = smb.SMB(host, host)
        smb_client.login(username, password)
        shares = smb_client.listShares()
        print("Enumerating SMB shares:")
        for share in shares:
            print(f"Share Name: {share['shi1_netname']}\tShare Type: {share['shi1_type']}")
    except smb.SessionError as e:
        print("Error authenticating to SMB:", e)

def check_ftp_anonymous(host):
    nmap_args = ["nmap", "-p", "21", "--script", "ftp-anon", host]
    try:
        output = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT)
        output_str = output.decode()
        if "Anonymous FTP login allowed" in output_str:
            print("Anonymous FTP login is allowed")
        else:
            print("Anonymous FTP login is not allowed")
    except subprocess.CalledProcessError as e:
        print("Error executing Nmap:", e.output)

def nmap_scan_all_ports(host):
    nmap_args = ["nmap", "-p-", host]
    try:
        output = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        print("Error executing Nmap:", e.output)
        return None

def ldap_enumeration(host):
    nmap_args = ["nmap", "-p", "389", "--script", "ldap-search", host]
    try:
        output = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT)
        print("LDAP enumeration result:")
        print(output.decode())
    except subprocess.CalledProcessError as e:
        print("Error executing Nmap:", e.output)

def rpc_enumeration(host):
    nmap_args = ["nmap", "-p", "135", "--script", "rpcinfo", host]
    try:
        output = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT)
        print("RPC enumeration result:")
        print(output.decode())
    except subprocess.CalledProcessError as e:
        print("Error executing Nmap:", e.output)

def smtp_enumeration(host):
    nmap_args = ["nmap", "-p", "25", "--script", "smtp-enum-users", host]
    try:
        output = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT)
        print("SMTP enumeration result:")
        print(output.decode())
    except subprocess.CalledProcessError as e:
        print("Error executing Nmap:", e.output)

def run_openvas_vuln_scan(target):
    openvas_args = ["gvm-cli", "ssh", "--hostname", target, "--xml", "~/.config/gvm/my_scan_config.xml"]
    try:
        output = subprocess.check_output(openvas_args, stderr=subprocess.STDOUT)
        print("OpenVAS vulnerability scan result:")
        print(output.decode())
    except subprocess.CalledProcessError as e:
        print("Error executing OpenVAS:", e.output)

# Example usage
target_host = '127.0.0.1'  # Replace with the IP address or hostname you want to scan
start_port = 1
end_port = 65535

open_ports = scan_ports(target_host, start_port, end_port)
services = identify_services(open_ports)

if services:
    print("Open ports and identified services:")
    for port, service in services:
        print(f"Port: {port}, Service: {service}")
        if service == "http":
            output = nmap_http_scan(target_host, port)
            if output:
                print("Nmap HTTP scan result:")
                print(output)
            url = f"http://{target_host}:{port}"
            directory_bust(url)
            run_nikto_scan(url)
        elif service == "https":
            output = nmap_http_scan(target_host, port)
            if output:
                print("Nmap HTTPS scan result:")
                print(output)
            url = f"https://{target_host}:{port}"
            directory_bust(url)
            run_nikto_scan(url)
        elif port in [139, 445] and service == "unknown":
            smb_enumeration(target_host)
        elif service == "ldap":
            ldap_enumeration(target_host)
        elif service == "rpcbind":
            rpc_enumeration(target_host)
        elif service == "smtp":
            smtp_enumeration(target_host)

check_ftp_anonymous(target_host)
identify_os(target_host)
nmap_output = nmap_scan_all_ports(target_host)
if nmap_output:
    print("Nmap scan on all ports result:")
    print(nmap_output)

run_openvas_vuln_scan(target_host)
