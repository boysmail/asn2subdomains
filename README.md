# asn2subdomains
Combining multiple Project Discovery's tools to make osint easier.

## Tools used
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [gowitness](https://github.com/sensepost/gowitness)
- [WhoisXML](https://www.whoisxmlapi.com/)

Nameservers:
- [nameservers.txt](https://public-dns.info/nameservers.txt)
- [resolvers-trusted.txt](https://github.com/trickest/resolvers)

## Installation
1. Clone repo
2. Create venv (optional), install requirements from requirements.txt or pyproject.toml
3. Run main.py
```
# requirements.txt
pip install -r requirements.txt
# pyproject.toml
python -m pip install .
# Run
python main.py
```

## Usage
```
> python main.py -h
usage: main.py [-h] [-a ASN] [--skip-update] [-i] [-p PROXY] [-c CONFIG] [-whxml WHOISXML] [-n NAME]

Asn2Subdomains - A tool to extract subdomains from ASN information

options:
  -h, --help            show this help message and exit
  -a ASN, --asn ASN     ASN number
  --skip-update         Don't update the tools
  -i, --interact        Interact with the hosts - httpx + gowitness
  -p PROXY, --proxy PROXY
                        Proxy to pass to each tool
  -c CONFIG, --config CONFIG
                        Subfinder config file
  -whxml WHOISXML, --whoisxml WHOISXML
                        WhoisXML API key for reverse whois
  -n NAME, --name NAME  Company dns ORG name for reverse whois

```

## Example
Run the tool with the ASN number 15169 and interact with the hosts.
```
> python main.py -a 15169 -i
```

Skip the update and pass a subfinder config file.
```
> python main.py -a 15169 --skip-update -c subfinder.yaml
```

Reverse whois lookup using WhoisXML API key and ORG.
```
> python main.py -a 13238 -whxml <API_KEY> -n "YANDEX, LLC."
```

## Flow
Here is the general flow of the tool along with the produced files:

## Future
- [ ] Add more tools
- [ ] Add user-agent switch 
