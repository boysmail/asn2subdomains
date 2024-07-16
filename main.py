import argparse
import io
import os
import re
import pyasn
import requests
import rich
import zipfile
parser = argparse.ArgumentParser(description='Asn2Subdomains - A tool to extract subdomains from ASN information')
parser.add_argument('-a', '--asn', required=True, type=int, help='ASN number')
parser.add_argument('--skip-update', action='store_true', help='Don\'t update the tools')
parser.add_argument('-i', '--interact', action='store_true', help='Interact with the hosts - httpx + gowitness')
parser.add_argument('-p', '--proxy',  help='Proxy to pass to each tool')
parser.add_argument('-c', '--config', help='Subfinder config file')
parser.add_argument('-whxml', '--whoisxml', help='WhoisXML API key for reverse whois')
parser.add_argument('-n', '--name', help='Company dns ORG name for reverse whois')


args = parser.parse_args()
asn = args.asn
# check if ipasn.dat exists
if not os.path.exists('ipasn.dat'):
    rich.print("[bold yellow]ASN database not found, downloading...[/bold yellow]")
    os.system('pyasn_util_download.py --latest --filename ipasn.dat.temp')
    os.system("pyasn_util_convert.py --single ipasn.dat.temp ipasn.dat")
    os.remove('ipasn.dat.temp')
    rich.print("[bold green]ASN database updated![/bold green]")


if not args.skip_update:
    rich.print("[bold yellow]Updating tools...[/bold yellow]")
    # Project discovery tools
    tools = ['projectdiscovery/dnsx', 'projectdiscovery/httpx', 'projectdiscovery/subfinder']

    if os.name == 'nt':
        rich.print(f"Detected Windows")
        windows = True
    else:
        rich.print(f"Detected Linux")
        windows = False

    for tool in tools:
        links = requests.get(f'https://api.github.com/repos/{tool}/releases/latest').json()
        if windows:
            # match name "dnsx_x.x.x_windows_amd64.zip" in assets
            for asset in links["assets"]:
                if re.search(r'windows_amd', asset['name']):
                    rich.print(f"Downloading {tool.split('/')[1]}.exe version {links['tag_name'][1:]}")
                    r = requests.get(asset["browser_download_url"], stream=True)
                    #open(f'{tool.split("/")[1]}.zip', 'wb').write(r.content)
                    with zipfile.ZipFile(io.BytesIO(r.content)) as zip_ref:
                        zip_ref.extractall()
                    break
        else:
            for asset in links["assets"]:
                if re.search(r'linux_amd', asset['name']):
                    rich.print(f"Downloading {tool.split('/')[1]} version {links['tag_name'][1:]}")
                    r = requests.get(asset["browser_download_url"], stream=True)
                    with zipfile.ZipFile(io.BytesIO(r.content)) as zip_ref:
                        zip_ref.extractall()
                    break

    # gowitness
    links = requests.get(f'https://api.github.com/repos/sensepost/gowitness/releases/latest').json()
    if windows:
        for asset in links["assets"]:
            if re.search(r'windows-amd', asset['name']):
                rich.print(f"Downloading gowitness.exe version {links['tag_name']}")
                r = requests.get(asset["browser_download_url"], stream=True)
                open('gowitness.exe', 'wb').write(r.content)
                break
    else:
        for asset in links["assets"]:
            if re.search(r'linux-amd', asset['name']):
                rich.print(f"Downloading gowitness version {links['tag_name']}")
                r = requests.get(asset["browser_download_url"], stream=True)
                open('gowitness', 'wb').write(r.content)
                break

    # nameservers
    r = requests.get("https://public-dns.info/nameservers.txt", stream=True)
    open('nameservers.txt', 'wb').write(r.content)
    r = requests.get("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt", stream=True)
    open('nameservers-trusted.txt', 'wb').write(r.content)


    rich.print("[bold green]ASN database updated![/bold green]")
else:
    rich.print("[bold yellow]Skipping tools update...[/bold yellow]")

rich.print(f"[bold yellow]Getting subnets for asn {asn}...[/bold yellow]")
asndb = pyasn.pyasn('ipasn.dat')
prefixes = asndb.get_as_prefixes(asn)
rich.print(f"[bold green]Found {len(prefixes)} subnets - subnets.txt[/bold green]")
with open(f'{asn}_subnets.txt', 'w') as f:
    for prefix in prefixes:
        f.write(f"{prefix}\n")

# dnsx
rich.print("[bold yellow]Running dnsx...[/bold yellow]")
os.system(f'dnsx -l {asn}_subnets.txt -ptr -ro -o {asn}_dnsx.txt -r nameservers.txt')
# get only second level domains
with open(f'{asn}_dnsx.txt', 'r') as f:
    with open(f'{asn}_dnsx_basedomains.txt', 'w') as f2:
        base = set()
        for line in f:
            base.add(line.split('.')[-2] + '.' + line.split('.')[-1])
        for domain in base:
            f2.write(f"{domain}")


rich.print(f"[bold green]Found hosts - {asn}_hosts.txt[/bold green]")

# reverse whois
if args.whoisxml:
    rich.print("[bold yellow]Running reverse whois...[/bold yellow]")
    data = {
        "apiKey": args.whoisxml,
        "searchType": "current",
        "mode": "purchase",
        "punycode": True,
        "basicSearchTerms": {
            "include": [
                args.name
            ]
        }
    }
    r = requests.post("https://reverse-whois.whoisxmlapi.com/api/v2", json=data)
    with open(f'{asn}_reversewhois.txt', 'w') as f:
        for domain in r.json()['domainsList']:
            f.write(f"{domain['domainName']}\n")
    rich.print(f"[bold green]Found domains - {asn}_reversewhois.txt[/bold green]")

rich.print("[bold yellow]Combining dnsx and reverse whois for subfinder...[/bold yellow]")
subdomains = set()
with open(f'{asn}_dnsx_basedomains.txt', 'r') as f:
    for line in f:
        subdomains.add(line.strip())
if args.whoisxml:
    with open(f'{asn}_reversewhois.txt', 'r') as f:
        for line in f:
            subdomains.add(line.strip())
with open(f'{asn}_dnsx_reversewhois.txt', 'w') as f:
    for subdomain in subdomains:
        f.write(f"{subdomain}\n")

# subfinder
# check config and proxy
cmd = f'subfinder -dL {asn}_dnsx_reversewhois.txt -o {asn}_subfinder.txt'
text = "[bold yellow]Running subfinder"
if args.config:
    cmd += f' -config {args.config}'
    text += f" with config {args.config}"
if args.proxy:
    cmd += f' -proxy {args.proxy}'
    text += f" with proxy {args.proxy}"
rich.print(f"{text}...[/bold yellow]")
os.system(cmd)
rich.print(f"[bold green]Found subdomains - {asn}_subfinder.txt[/bold green]")

# Combine all subdomains
rich.print("[bold yellow]Combining all subdomains...[/bold yellow]")
subdomains = set()
with open(f'{asn}_dnsx.txt', 'r') as f:
    for line in f:
        subdomains.add(line.strip())
with open(f'{asn}_subfinder.txt', 'r') as f:
    for line in f:
        subdomains.add(line.strip())
if args.whoisxml:
    with open(f'{asn}_reversewhois.txt', 'r') as f:
        for line in f:
            subdomains.add(line.strip())
with open(f'{asn}_hosts.txt', 'w') as f:
    for subdomain in subdomains:
        f.write(f"{subdomain}\n")
rich.print(f"[bold green]All subdomains - {asn}_hosts.txt[/bold green]")

# resolve all subdomains and write in subdomain:ip format
rich.print("[bold yellow]Resolving all subdomains...[/bold yellow]")
os.system(f'dnsx -a -re -nc -l {asn}_hosts.txt -o {asn}_hosts_resolved.txt -r nameservers-trusted.txt')
# turn google.com [A] [216.58.206.46] into google.com:216.58.206.46
with open(f'{asn}_hosts_resolved.txt', 'r') as f:
    with open(f'{asn}_hosts_resolved_final.txt', 'w') as f2:
        for line in f:
            f2.write(f"{line.split(' [A] [')[0]}:{line.split(' [A] [')[-1][:-3]}\n")
rich.print(f"[bold green]Resolved subdomains - {asn}_hosts_resolved_final.txt[/bold green]")


if args.interact:
    rich.print("[bold yellow]Interacting with hosts...[/bold yellow]")
    if args.proxy:
        os.system(f'httpx -l {asn}_hosts.txt -random-agent -o {asn}_httpx.txt -proxy {args.proxy}')
        os.system(f'gowitness file -f {asn}_httpx.txt --user-agent Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 --proxy {args.proxy}')
    else:
        os.system(f'httpx -l {asn}_hosts.txt -random-agent -o {asn}_httpx.txt')
        os.system(f'gowitness file -f {asn}_httpx.txt --user-agent Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36')

    rich.print(f"[bold green]Screenshots saved in gowitness/{asn}_httpx[/bold green]")
rich.print("[bold green]Done![/bold green]")
