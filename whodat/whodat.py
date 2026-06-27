import os
import sys
import time
import datetime
import argparse

import vt
import ssl
import socket
import ipinfo
import requests

import cryptography.x509
from cryptography.hazmat.backends import default_backend

from dotenv import load_dotenv

PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443]
PADDING = 100

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def sanitize(obj):
    if hasattr(obj, 'items'):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(i) for i in obj]
    return obj

# (Reverse) DNS lookup
def get_domain_info(domain: str) -> tuple | None:
    try: return socket.gethostbyaddr(domain)
    except socket.herror as e:
        print(f"[!] DNS lookup failed: {e}")
        return None
    
# Geolocation
def get_geo(ip_addr: str) -> object | None:
    token = os.getenv("IPINFO_TOKEN")
    if not token:
        print("[!] IPINFO_TOKEN not set in environment — skipping geolocation.")
        return None
    try:
        handler = ipinfo.getHandler(token)
        return handler.getDetails(ip_addr)
    except Exception as e:
        print(f"[!] Geolocation lookup failed: {e}")
        return None

# Headers info 
def get_headers(hostname: str) -> dict | None:
    for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{hostname}"
                response = requests.get(url, timeout=5)
                return dict(response.headers)
            except requests.exceptions.SSLError: continue
            except Exception as e: print(f"[!] Could not fetch headers from {scheme}://{hostname}: {e}")
    return None

# VirusTotal URL Scan
def get_vt_scan(hostname: str) -> dict | None:
    key = os.getenv("VT_KEY")
    if not key:
        print("[!] VT_KEY not set in environment — skipping VirusTotal scan.")
        return None
    try:
        with vt.Client(key) as client:
            analysis = client.scan_url(f"https://{hostname}")
            while True:
                analysis = client.get_object(f"/analyses/{analysis.id}")
                if analysis.status == "completed": break
                time.sleep(3)
            return sanitize(analysis.stats)
    except Exception as e:
        print(f"[!] VirusTotal scan failed: {e}")
        return None

# Port scanner
def scan_port(hostname: str, ports: list) -> list | None:
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((hostname, port))
                open_ports.append(port)
        except OSError: continue
    return open_ports

# SSL Info
def get_ssl_info(hostname: str) -> dict | None:
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            der_cert = s.getpeercert(binary_form=True)
            cert = cryptography.x509.load_der_x509_certificate(der_cert, default_backend())
            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "issued": cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
                "expires": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
                "san": [v.value for v in cert.extensions.get_extension_for_class(
                    cryptography.x509.SubjectAlternativeName).value],
            }
    except Exception as e:
        print(f"[!] SSL lookup failed: {e}")
        return None

def json_export(target, domain_info, geo, headers, open_ports, vt_scan, ssl_info):
    import json
    TIME = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
    FILE = f"{target}_Analysis_{TIME}"

    results = {
        "target": target,
        "timestamp": TIME,
        "dns": {
            "hostname": domain_info[0],
            "aliases": domain_info[1],
            "ips": domain_info[2],
        },
        "geo": sanitize(dict(geo.all)) if geo else None,
        "headers": sanitize(headers),
        "open_ports": sanitize(open_ports),
        "virustotal": sanitize(vt_scan),
        "ssl_info" : ssl_info,
    }
    with open(FILE, "w") as f: json.dump(results, f, indent=2)
    print(f"[+] Report saved to {FILE}")

def check_date(cert_exp_date):
    try:
        expiry_dt = datetime.datetime.strptime(cert_exp_date, "%b %d %H:%M:%S %Y %Z")
        return expiry_dt < datetime.datetime.now()
    except (ValueError, TypeError): return False



def format_output(domain_info, geo, headers, vt_scan, open_ports, ssl_info) -> str:
    lines = ["=" * PADDING]
 
    # DNS info
    lines.append(f" {bcolors.BOLD}DNS INFO{bcolors.ENDC}")
    lines.append("-" * PADDING)
    lines.append(f"  Hostname : {domain_info[0]}")
    lines.append(f"  Aliases  : {', '.join(domain_info[1]) or 'none'}")
    lines.append(f"  IPs      : {', '.join(domain_info[2])}")
    lines.append("")
 
    # Geo info
    lines.append(f" {bcolors.BOLD}GEOLOCATION{bcolors.ENDC}")
    lines.append("-" * PADDING)
    if geo:
        lines.append(f"  Country  : {getattr(geo, 'country_name', 'N/A')}")
        lines.append(f"  City     : {getattr(geo, 'city', 'N/A')}")
        lines.append(f"  Region   : {getattr(geo, 'region', 'N/A')}")
        lines.append(f"  Location : {getattr(geo, 'loc', 'N/A')}")
        lines.append(f"  Org      : {getattr(geo, 'org', 'N/A')}")
    else: lines.append("  (unavailable)")
    lines.append("")
 
    # Headers info
    lines.append(f" {bcolors.BOLD}HTTP HEADERS{bcolors.ENDC}")
    lines.append("-" * PADDING)
    if headers:
        for key, value in headers.items():
            lines.append(f"  {key:<30}: {value}")
    else: lines.append("  (unavailable)")
    lines.append("")

    # VirusTotal info
    lines.append(f" {bcolors.BOLD}VIRUSTOTAL{bcolors.ENDC}")    
    lines.append("-" * PADDING)
    if vt_scan:
        total = sum(vt_scan.values())
        lines.append(f"  Malicious  : {bcolors.FAIL}{vt_scan.get('malicious', 0)}{bcolors.ENDC}")
        lines.append(f"  Suspicious : {bcolors.WARNING}{vt_scan.get('suspicious', 0)}{bcolors.ENDC}")
        lines.append(f"  Harmless   : {bcolors.OKGREEN}{vt_scan.get('harmless', 0)}{bcolors.ENDC}")
        lines.append(f"  Undetected : {vt_scan.get('undetected', 0)}")
        lines.append(f"  Total      : {total} engines")
    else: lines.append("  (unavailable)")
    lines.append("")

    # Open ports
    lines.append(f" {bcolors.BOLD}OPEN PORTS{bcolors.ENDC}")
    lines.append("-" * PADDING)
    for port in PORTS_TO_SCAN:
        if port in open_ports:
            lines.append(f"  PORT {port}: {bcolors.OKGREEN}OPEN{bcolors.ENDC}")
        else: lines.append(f"  PORT {port}: {bcolors.FAIL}CLOSED{bcolors.ENDC}")
    lines.append("")

    # SSL info
    lines.append(f" {bcolors.BOLD}SSL INFO{bcolors.ENDC}")
    lines.append("-" * PADDING)
    if ssl_info:
        lines.append(f"  Subject : {ssl_info.get('subject')}")
        lines.append(f"  Issuer  : {ssl_info.get('issuer')}")
        lines.append(f"  Issued  : {ssl_info.get('issued')}")

        expired = check_date(ssl_info.get('expires'))
        lines.append(f"  Expires : {bcolors.FAIL}{ssl_info.get('expires')}{bcolors.ENDC}") if expired else lines.append(f"  Expires : {ssl_info.get('expires')}")

        lines.append(f"  SAN     : {', '.join(ssl_info.get('san', []))}")
    else: lines.append("  (unavailable)")


    lines.append("=" * PADDING)
    return "\n".join(lines)
 
 
def main() -> int:
    parser = argparse.ArgumentParser(
        description="WHOIS-like tool with a some more features"
    )
    parser.add_argument("domain", help="Domain name or IP address to look up")
    parser.add_argument("--json", action="store_true", help="Export the analysis result to a JSON file")
    parsed_args = parser.parse_args()
 
    target = parsed_args.domain

    load_dotenv()
 
    domain_info = get_domain_info(target)
    if domain_info is None:
        print(f"[!] Could not resolve '{target}'. Exiting.")
        return 1
 
    primary_ip = domain_info[2][0]
    hostname = domain_info[0]
 
    geo = get_geo(primary_ip)
    headers = get_headers(hostname)
    vt_scan = get_vt_scan(hostname)
    open_ports = scan_port(hostname, PORTS_TO_SCAN)
    ssl_info = get_ssl_info(hostname)

    if parsed_args.json: json_export(target, domain_info, geo, headers, open_ports, vt_scan, ssl_info)
 
    print(format_output(domain_info, geo, headers, vt_scan, open_ports, ssl_info))
    return 0
 
 
if __name__ == "__main__":
    sys.exit(main())
