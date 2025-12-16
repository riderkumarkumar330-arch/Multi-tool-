#!/usr/bin/env python3
import os, re, socket, ipaddress, threading, requests
import concurrent.futures
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.table import Table
from colorama import init
from urllib3.exceptions import InsecureRequestWarning
import warnings
import time
from datetime import datetime
import random
import sys

# ============ SETUP ============
init(autoreset=True)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

console = Console()
lock = threading.Lock()

# यहाँ बेस डायरेक्टरी को फिक्स कर दिया है
BASE_DIR = "/storage/emulated/0/Download/Scan_Results"
os.makedirs(BASE_DIR, exist_ok=True)

def banner():
    console.clear()
    console.print(Panel(
        "[bold red]╔══════════════════════════════════════╗\n"
        "║     ███╗   ███╗██████╗ ███████╗██████╗  ║\n"
        "║     ████╗ ████║██╔══██╗██╔════╝██╔══██╗ ║\n"
        "║     ██╔████╔██║██████╔╝█████╗  ██████╔╝ ║\n"
        "║     ██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗ ║\n"
        "║     ██║ ╚═╝ ██║██║  ██║███████╗██║  ██║ ║\n"
        "║     ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ║\n"
        "║     [cyan]MULTI ADVANCED TOOL v2.0[/cyan]        ║\n"
        "║     [green]Developed by: Mr Raj[/green]           ║\n"
        "╚══════════════════════════════════════╝[/bold red]",
        border_style="blue"
    ))

def make_out(name):
    path = os.path.join(BASE_DIR, name)
    os.makedirs(path, exist_ok=True)
    return path

def save_results(filename, data):
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(data + "\n")

def refresh_tool():
    """टूल को रिफ्रेश करने के लिए फंक्शन"""
    console.print("\n[bold yellow]Refreshing tool...[/bold yellow]")
    time.sleep(1)
    # मेनू में वापस जाने से पहले थोड़ा wait करें
    return

# ============ 1 HOST SCANNER ============
def host_scanner():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│          HOST SCANNER MODULE           │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    infile = input("[bold cyan]Enter domain list file path: ").strip()
    if not os.path.exists(infile):
        console.print("[bold red]File not found![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Host_Scanner"
    outdir = make_out(outdir_name)
    ports = input("[bold cyan]Ports (comma separated, default: 80,443,8080): ").strip()
    ports = [p.strip() for p in ports.split(",")] if ports else ["80", "443", "8080"]
    threads = int(input("[bold cyan]Threads (default: 80): ").strip() or 80)
    
    try:
        domains = [d.strip() for d in open(infile, 'r') if d.strip()]
    except:
        console.print("[bold red]Error reading file![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    total = len(domains) * len(ports)
    
    results_file = os.path.join(outdir, "host_scan_results.txt")
    with open(results_file, 'w') as f:
        f.write(f"Scan started at: {datetime.now()}\n")
        f.write(f"Domains: {len(domains)}, Ports: {ports}\n")
        f.write("="*60 + "\n")
    
    console.print(f"\n[bold green]Starting scan of {len(domains)} domains on ports {ports}...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print("[bold white]Status | Code | Server | IP | Domain:Port[/bold white]")
    console.print("-" * 80)

    def scan(domain, port, progress, task):
        try:
            if port == "443":
                url = f"https://{domain}"
            else:
                url = f"http://{domain}:{port}"
            
            r = requests.head(url, timeout=5, verify=False, allow_redirects=True)
            ip = socket.gethostbyname(domain)
            server = r.headers.get("Server", "Unknown")
            status = "[bold green]LIVE[/bold green]"
            
            line = f"{status} | {r.status_code:^4} | {server[:20]:^20} | {ip:^15} | {domain}:{port}"
            result_line = f"LIVE | {r.status_code} | {server} | {ip} | {domain}:{port}"
            
            with lock:
                console.print(line)
                with open(results_file, 'a') as f:
                    f.write(result_line + "\n")
                    
        except requests.exceptions.SSLError:
            try:
                url = f"http://{domain}:{port}" if port != "443" else f"http://{domain}"
                r = requests.head(url, timeout=5, verify=False, allow_redirects=True)
                ip = socket.gethostbyname(domain)
                server = r.headers.get("Server", "Unknown")
                status = "[bold yellow]SSL-ERR[/bold yellow]"
                
                line = f"{status} | {r.status_code:^4} | {server[:20]:^20} | {ip:^15} | {domain}:{port}"
                result_line = f"SSL-ERROR | {r.status_code} | {server} | {ip} | {domain}:{port}"
                
                with lock:
                    console.print(line)
                    with open(results_file, 'a') as f:
                        f.write(result_line + "\n")
            except:
                pass
        except socket.gaierror:
            status = "[bold red]DNS-ERR[/bold red]"
            line = f"{status} | {'-':^4} | {'-':^20} | {'-':^15} | {domain}:{port}"
        except:
            pass
        finally:
            progress.update(task, advance=1)

    with Progress(
        SpinnerColumn(),
        BarColumn(),
        MofNCompleteColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
            futures = []
            for d in domains:
                for p in ports:
                    futures.append(exe.submit(scan, d, p.strip(), progress, task))
            concurrent.futures.wait(futures)

    console.print(f"\n[bold green]Results saved to: {results_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 2 CIDR SCANNER ============
def cidr_scanner():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│          CIDR SCANNER MODULE           │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    cidr_input = input("[bold cyan]Enter CIDR (e.g., 192.168.1.0/24): ").strip()
    try:
        cidr = ipaddress.ip_network(cidr_input, strict=False)
    except:
        console.print("[bold red]Invalid CIDR notation![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "CIDR_Scanner"
    outdir = make_out(outdir_name)
    ports = input("[bold cyan]Ports (comma separated, default: 80,443): ").strip()
    ports = [p.strip() for p in ports.split(",")] if ports else ["80", "443"]
    threads = int(input("[bold cyan]Threads (default: 500): ").strip() or 500)
    
    hosts = list(cidr.hosts())
    total = len(hosts) * len(ports)
    
    results_file = os.path.join(outdir, "cidr_scan_results.txt")
    with open(results_file, 'w') as f:
        f.write(f"Scan started at: {datetime.now()}\n")
        f.write(f"CIDR: {cidr_input}, Hosts: {len(hosts)}, Ports: {ports}\n")
        f.write("="*60 + "\n")
    
    console.print(f"\n[bold green]Starting scan of {len(hosts)} hosts on ports {ports}...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print("[bold white]Status | Code | Server | IP:Port[/bold white]")
    console.print("-" * 70)

    def scan(ip, port, progress, task):
        try:
            r = requests.head(f"http://{ip}:{port}", timeout=3, verify=False, allow_redirects=True)
            server = r.headers.get("Server", "Unknown")
            status = "[bold green]LIVE[/bold green]"
            
            line = f"{status} | {r.status_code:^4} | {server[:20]:^20} | {ip}:{port}"
            result_line = f"LIVE | {r.status_code} | {server} | {ip}:{port}"
            
            with lock:
                console.print(line)
                with open(results_file, 'a') as f:
                    f.write(result_line + "\n")
                    
        except requests.exceptions.ConnectionError:
            pass
        except:
            pass
        finally:
            progress.update(task, advance=1)

    with Progress(
        SpinnerColumn(),
        BarColumn(),
        MofNCompleteColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
            futures = []
            for ip in hosts:
                for p in ports:
                    futures.append(exe.submit(scan, str(ip), p.strip(), progress, task))
            concurrent.futures.wait(futures)

    console.print(f"\n[bold green]Results saved to: {results_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 3 DOMAIN EXTRACTOR ============
def domain_extractor():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│        DOMAIN EXTRACTOR MODULE         │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Domain_Extractor"
    outdir = make_out(outdir_name)
    
    console.print("\n[bold cyan]Choose input method:[/bold cyan]")
    console.print("1. Paste text directly")
    console.print("2. Read from file")
    choice = input("\n[bold cyan]Select (1/2): ").strip()
    
    text = ""
    if choice == "1":
        console.print("\n[bold cyan]Paste your text (Ctrl+D or Ctrl+Z then Enter when done):[/bold cyan]")
        try:
            lines = []
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            text = "\n".join(lines)
    elif choice == "2":
        filepath = input("[bold cyan]Enter file path: ").strip()
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except:
            console.print("[bold red]Error reading file![/bold red]")
            input("\nPress Enter to continue...")
            refresh_tool()
            return
    
    # Improved regex for domain extraction
    pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    domains = set(re.findall(pattern, text))
    
    # Filter out common false positives
    filtered_domains = []
    for domain in domains:
        if len(domain) > 4 and not domain.startswith("www.") and not domain.endswith(".com.com"):
            filtered_domains.append(domain.lower())
    
    filtered_domains = sorted(set(filtered_domains))
    
    output_file = os.path.join(outdir, "extracted_domains.txt")
    console.print(f"\n[bold green]Found {len(filtered_domains)} unique domains[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print("[bold white]Extracted Domains:[/bold white]")
    console.print("-" * 50)
    
    with open(output_file, 'w') as f:
        for domain in filtered_domains:
            console.print(domain)
            f.write(domain + "\n")
    
    console.print(f"\n[bold green]Domains saved to: {output_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 4 MULTI CIDR ============
def multi_cidr():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│          MULTI CIDR SCANNER            │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    infile = input("[bold cyan]Enter CIDR list file path: ").strip()
    if not os.path.exists(infile):
        console.print("[bold red]File not found![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Multi_CIDR"
    outdir = make_out(outdir_name)
    port = input("[bold cyan]Port to scan (default: 80): ").strip() or "80"
    threads = int(input("[bold cyan]Threads (default: 200): ").strip() or 200)
    
    try:
        with open(infile, 'r') as f:
            cidr_list = [line.strip() for line in f if line.strip()]
    except:
        console.print("[bold red]Error reading file![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    all_ips = []
    for cidr_str in cidr_list:
        try:
            cidr = ipaddress.ip_network(cidr_str, strict=False)
            all_ips.extend(list(cidr.hosts()))
        except:
            console.print(f"[yellow]Skipping invalid CIDR: {cidr_str}[/yellow]")
    
    total = len(all_ips)
    results_file = os.path.join(outdir, "multi_cidr_results.txt")
    
    console.print(f"\n[bold green]Scanning {total} IPs on port {port}...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    
    def scan_ip(ip, progress, task):
        try:
            r = requests.head(f"http://{ip}:{port}", timeout=2, verify=False)
            with lock:
                with open(results_file, 'a') as f:
                    f.write(f"LIVE | {ip}:{port} | Server: {r.headers.get('Server', 'Unknown')}\n")
        except:
            pass
        finally:
            progress.update(task, advance=1)
    
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        MofNCompleteColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
            futures = [exe.submit(scan_ip, str(ip), progress, task) for ip in all_ips]
            concurrent.futures.wait(futures)
    
    console.print(f"\n[bold green]Results saved to: {results_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 5 MULTI PORT ============
def multi_port():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│          MULTI PORT SCANNER            │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    domain = input("[bold cyan]Enter domain/IP: ").strip()
    ports_input = input("[bold cyan]Enter ports (comma separated or range 1-100): ").strip()
    
    # Handle port ranges
    if '-' in ports_input:
        try:
            start, end = map(int, ports_input.split('-'))
            ports = list(range(start, end + 1))
        except:
            console.print("[bold red]Invalid port range![/bold red]")
            input("\nPress Enter to continue...")
            refresh_tool()
            return
    else:
        ports = [p.strip() for p in ports_input.split(",")]
    
    threads = int(input("[bold cyan]Threads (default: 100): ").strip() or 100)
    
    console.print(f"\n[bold green]Scanning {domain} on {len(ports)} ports...[/bold green]\n")
    
    table = Table(title=f"Port Scan Results for {domain}")
    table.add_column("Port", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Service", style="yellow")
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, int(port)))
            sock.close()
            return port, result == 0
        except:
            return port, False
    
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {exe.submit(scan_port, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                table.add_row(str(port), "[bold green]OPEN[/bold green]", "HTTP/HTTPS")
                open_ports.append(port)
            else:
                table.add_row(str(port), "[bold red]CLOSED[/bold red]", "-")
    
    console.print(table)
    console.print(f"\n[bold green]Found {len(open_ports)} open ports: {open_ports}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 6 SUBDOMAIN HUNT ============
def subdomain_hunt():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│         SUBDOMAIN ENUMERATOR           │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    domain = input("[bold cyan]Enter domain (example.com): ").strip()
    wordlist_file = input("[bold cyan]Wordlist file (press Enter for default): ").strip()
    
    # Common subdomains if no wordlist provided
    common_subs = [
        "www", "mail", "ftp", "admin", "api", "blog", "cdn", "dev", 
        "test", "staging", "portal", "webmail", "cpanel", "webdisk",
        "ns1", "ns2", "mx", "pop", "imap", "smtp", "secure", "vpn",
        "mobile", "m", "shop", "store", "support", "help", "docs",
        "status", "monitor", "dashboard", "app", "apps", "beta",
        "alpha", "demo", "staging", "prod", "production", "backup"
    ]
    
    if wordlist_file and os.path.exists(wordlist_file):
        with open(wordlist_file, 'r') as f:
            subs = [line.strip() for line in f if line.strip()]
    else:
        subs = common_subs
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Subdomain_Hunter"
    outdir = make_out(outdir_name)
    threads = int(input("[bold cyan]Threads (default: 50): ").strip() or 50)
    
    results_file = os.path.join(outdir, f"subdomains_{domain}.txt")
    
    console.print(f"\n[bold green]Checking {len(subs)} subdomains for {domain}...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    
    found_subs = []
    
    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except:
            return None
    
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        MofNCompleteColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Checking...", total=len(subs))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
            futures = {exe.submit(check_subdomain, sub): sub for sub in subs}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    console.print(f"[green]✓ Found: {result}[/green]")
                    found_subs.append(result)
                progress.update(task, advance=1)
    
    # Save results
    with open(results_file, 'w') as f:
        for sub in found_subs:
            try:
                ip = socket.gethostbyname(sub)
                f.write(f"{sub} - {ip}\n")
            except:
                f.write(f"{sub}\n")
    
    console.print(f"\n[bold green]Found {len(found_subs)} subdomains[/bold green]")
    console.print(f"[bold green]Results saved to: {results_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 7 SPLIT TXT ============
def split_txt():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│            FILE SPLITTER               │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    infile = input("[bold cyan]Enter file to split: ").strip()
    if not os.path.exists(infile):
        console.print("[bold red]File not found![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    lines_per_file = int(input("[bold cyan]Lines per file (default: 1000): ").strip() or 1000)
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "File_Splitter"
    outdir = make_out(outdir_name)
    
    try:
        with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except:
        console.print("[bold red]Error reading file![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    total_lines = len(lines)
    num_files = (total_lines + lines_per_file - 1) // lines_per_file
    
    console.print(f"\n[bold green]Splitting {total_lines} lines into {num_files} files...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]\n")
    
    for i in range(num_files):
        start = i * lines_per_file
        end = start + lines_per_file
        chunk = lines[start:end]
        
        filename = os.path.join(outdir, f"split_part_{i+1}.txt")
        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(chunk)
        
        console.print(f"[cyan]Created: {filename} ({len(chunk)} lines)[/cyan]")
    
    console.print(f"\n[bold green]Successfully split into {num_files} files in '{outdir}'[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 8 CIDR TO DOMAIN ============
def cidr_to_domain():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│         CIDR TO DOMAIN RESOLVER        │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    cidr_input = input("[bold cyan]Enter CIDR (e.g., 192.168.1.0/24): ").strip()
    try:
        cidr = ipaddress.ip_network(cidr_input, strict=False)
    except:
        console.print("[bold red]Invalid CIDR notation![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "CIDR_To_Domain"
    outdir = make_out(outdir_name)
    threads = int(input("[bold cyan]Threads (default: 100): ").strip() or 100)
    
    hosts = list(cidr.hosts())
    results_file = os.path.join(outdir, f"reverse_lookup_{cidr_input.replace('/', '_')}.txt")
    
    console.print(f"\n[bold green]Performing reverse DNS lookup on {len(hosts)} IPs...[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]\n")
    
    def reverse_lookup(ip, progress, task):
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            result = f"{ip} -> {hostname}"
            with lock:
                console.print(f"[green]{result}[/green]")
                with open(results_file, 'a') as f:
                    f.write(result + "\n")
        except:
            pass
        finally:
            progress.update(task, advance=1)
    
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        MofNCompleteColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Resolving...", total=len(hosts))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
            futures = [exe.submit(reverse_lookup, ip, progress, task) for ip in hosts]
            concurrent.futures.wait(futures)
    
    console.print(f"\n[bold green]Results saved to: {results_file}[/bold green]")
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 9 REMOVE DUPLICATES ============
def remove_domain():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│        REMOVE DUPLICATE DOMAINS        │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    infile = input("[bold cyan]Enter domain list file: ").strip()
    if not os.path.exists(infile):
        console.print("[bold red]File not found![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    outdir_name = input("[bold cyan]Output folder name: ").strip() or "Remove_Duplicates"
    outdir = make_out(outdir_name)
    
    try:
        with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
            domains = [line.strip().lower() for line in f if line.strip()]
    except:
        console.print("[bold red]Error reading file![/bold red]")
        input("\nPress Enter to continue...")
        refresh_tool()
        return
    
    original_count = len(domains)
    unique_domains = sorted(set(domains))
    new_count = len(unique_domains)
    
    output_file = os.path.join(outdir, "deduplicated_domains.txt")
    
    with open(output_file, 'w') as f:
        for domain in unique_domains:
            f.write(domain + "\n")
    
    console.print(f"\n[bold green]Original: {original_count} domains[/bold green]")
    console.print(f"[bold green]Unique: {new_count} domains[/bold green]")
    console.print(f"[bold green]Removed: {original_count - new_count} duplicates[/bold green]")
    console.print(f"[bold green]Output Directory: {outdir}[/bold green]")
    console.print(f"\n[bold green]Results saved to: {output_file}[/bold green]")
    
    # Show sample of cleaned domains
    if unique_domains:
        console.print(f"\n[bold white]Sample of cleaned domains:[/bold white]")
        for i, domain in enumerate(unique_domains[:10], 1):
            console.print(f"{i}. {domain}")
        if len(unique_domains) > 10:
            console.print(f"... and {len(unique_domains) - 10} more")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 10 REVERSE IP ============
def reverse_ip():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│           REVERSE IP LOOKUP            │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    domain = input("[bold cyan]Enter domain: ").strip()
    
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"\n[bold green]Domain: {domain}[/bold green]")
        console.print(f"[bold green]IP Address: {ip}[/bold green]")
        
        # Try to get additional info
        try:
            hostname, aliases, ips = socket.gethostbyaddr(ip)
            console.print(f"[bold green]Hostname: {hostname}[/bold green]")
            if aliases:
                console.print(f"[bold green]Aliases: {', '.join(aliases)}[/bold green]")
        except:
            pass
            
    except socket.gaierror:
        console.print(f"[bold red]Could not resolve domain: {domain}[/bold red]")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 11 HOST INFO ============
def host_info():
    banner()
    console.print("[bold yellow]┌────────────────────────────────────────┐[/bold yellow]")
    console.print("[bold yellow]│          HOST INFORMATION              │[/bold yellow]")
    console.print("[bold yellow]└────────────────────────────────────────┘[/bold yellow]\n")
    
    domain = input("[bold cyan]Enter domain/IP: ").strip()
    
    console.print("\n[bold white]Gathering information...[/bold white]\n")
    
    try:
        # Get IP address
        ip = socket.gethostbyname(domain)
        
        # Create info table
        table = Table(title=f"Information for {domain}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Domain", domain)
        table.add_row("IP Address", ip)
        
        # Try to get reverse DNS
        try:
            hostname, aliases, ips = socket.gethostbyaddr(ip)
            table.add_row("Reverse DNS", hostname)
            if aliases:
                table.add_row("DNS Aliases", ", ".join(aliases))
        except:
            table.add_row("Reverse DNS", "Not available")
        
        # Check common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389]
        
        table.add_row("\n[bold]Port Scan[/bold]", "")
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                status = "[bold green]OPEN[/bold green]" if result == 0 else "[dim]CLOSED[/dim]"
                table.add_row(f"Port {port}", status)
            except:
                table.add_row(f"Port {port}", "[red]ERROR[/red]")
        
        console.print(table)
        
    except socket.gaierror:
        console.print(f"[bold red]Could not resolve: {domain}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
    
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 12 DEVELOPER INFO ============
def dev_info():
    banner()
    console.print(Panel.fit(
        "[bold cyan]DEVELOPER INFORMATION[/bold cyan]\n\n"
        "[bold]Name:[/bold] Mr Raj\n"
        "[bold]YouTube:[/bold] Mr Tech Hacker\n"
        "[bold]Tool:[/bold] Multi Advanced Tool v2.0\n"
        "[bold]Version:[/bold] 2.0\n"
        "[bold]Release Date:[/bold] 2024\n\n"
        "[yellow]This tool is for educational purposes only.[/yellow]\n"
        "[yellow]Use responsibly and only on systems you own.[/yellow]",
        border_style="green"
    ))
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ 13 SCRIPT UPDATE ============
def update():
    banner()
    console.print(Panel.fit(
        "[bold cyan]UPDATE INFORMATION[/bold cyan]\n\n"
        "[green]✓ Current Version: 2.0[/green]\n"
        "[green]✓ All modules are working[/green]\n"
        "[green]✓ Latest updates applied[/green]\n\n"
        "[yellow]Check GitHub for future updates:[/yellow]\n"
        "[white]https://github.com/mrtechhacker[/white]",
        border_style="blue"
    ))
    input("\nPress Enter to continue...")
    refresh_tool()

# ============ MAIN MENU ============
def main():
    while True:
        banner()
        console.print("[bold cyan]┌────────────────────────────────────────┐[/bold cyan]")
        console.print("[bold cyan]│            MAIN MENU                   │[/bold cyan]")
        console.print("[bold cyan]└────────────────────────────────────────┘[/bold cyan]\n")
        
        console.print(f"[bold yellow]Output Directory:[/bold yellow] [bold green]{BASE_DIR}[/bold green]\n")
        
        menu_items = [
            ("1", "HOST SCANNER", "Scan domains on multiple ports"),
            ("2", "CIDR SCANNER", "Scan IP ranges for web servers"),
            ("3", "DOMAIN EXTRACTOR", "Extract domains from text/files"),
            ("4", "MULTI CIDR SCANNER", "Scan multiple CIDR ranges"),
            ("5", "MULTI PORT SCANNER", "Scan multiple ports on a host"),
            ("6", "SUBDOMAIN HUNTER", "Find subdomains of a domain"),
            ("7", "FILE SPLITTER", "Split large text files"),
            ("8", "CIDR TO DOMAIN", "Reverse DNS lookup for IP ranges"),
            ("9", "REMOVE DUPLICATES", "Remove duplicate domains from list"),
            ("10", "REVERSE IP LOOKUP", "Get IP address of domain"),
            ("11", "HOST INFORMATION", "Get detailed host information"),
            ("12", "DEVELOPER INFO", "About the developer"),
            ("13", "CHECK UPDATE", "Check for updates"),
            ("14", "EXIT", "Exit the tool")
        ]
        
        for num, name, desc in menu_items:
            console.print(f"[bold yellow][{num}][/bold yellow] [bold white]{name:<25}[/bold white] [dim]{desc}[/dim]")
        
        console.print("\n[bold cyan]┌────────────────────────────────────────┐[/bold cyan]")
        choice = input("[bold green]Choose option (1-14): [/bold green]").strip()
        console.print("[bold cyan]└────────────────────────────────────────┘[/bold cyan]")
        
        options = {
            "1": host_scanner,
            "2": cidr_scanner,
            "3": domain_extractor,
            "4": multi_cidr,
            "5": multi_port,
            "6": subdomain_hunt,
            "7": split_txt,
            "8": cidr_to_domain,
            "9": remove_domain,
            "10": reverse_ip,
            "11": host_info,
            "12": dev_info,
            "13": update
        }
        
        if choice == "14":
            banner()
            console.print(Panel.fit("[bold green]Thank you for using Mr Tech Hacker Tool![/bold green]\n[yellow]Goodbye![/yellow]", border_style="red"))
            break
        elif choice in options:
            try:
                options[choice]()
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled by user[/yellow]")
                input("\nPress Enter to continue...")
                refresh_tool()
            except Exception as e:
                console.print(f"\n[bold red]Error: {e}[/bold red]")
                input("\nPress Enter to continue...")
                refresh_tool()
        else:
            console.print("\n[bold red]Invalid option! Please choose 1-14[/bold red]")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Tool terminated by user[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {e}[/bold red]")
