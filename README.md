# Country Prefix Enumerator

A Python-based network reconnaissance and IP prefix enumeration tool for discovering IPv4 network ranges associated with a specific country.

The tool combines data from **RIPE NCC** and **BGP/HE.net** to collect IPv4 prefixes, optionally validates BGP prefixes through IRR data, performs WHOIS-based organization identification, filters common CDN/cloud infrastructure, expands CIDR ranges into individual IPv4 addresses, and can split large output files into multiple parts.

---

## Features

- Retrieve IPv4 prefixes associated with a country from RIPE NCC
- Discover ASNs associated with a country using BGP/HE.net
- Retrieve IPv4 prefixes originated by discovered ASNs
- Optional IRR validation of BGP prefixes
- WHOIS organization lookup for prefixes
- CDN/cloud provider filtering
- Remove duplicate prefixes
- Sort prefixes automatically
- Expand CIDR ranges into individual IPv4 addresses
- Split large IP/prefix lists into multiple files
- Support custom output filenames
- IPv4-focused enumeration
- Uses standard Python libraries together with `requests`

---

## Data Sources

The tool uses multiple public network data sources.

### RIPE NCC

RIPE country resource information is used to retrieve IPv4 resources associated with the selected country.

The RIPE data may contain:

- IPv4 CIDR prefixes
- IPv4 start/end ranges
- Country-associated address resources

Start/end IPv4 ranges are converted to CIDR notation using Python's `ipaddress` module.

---

### BGP / HE.net

The tool uses BGP information from:

```text
https://bgp.he.net