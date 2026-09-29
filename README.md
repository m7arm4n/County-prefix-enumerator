# Country Prefix Enumerator

A Python tool for discovering IPv4 network prefixes associated with a specific country. It combines RIPE NCC and BGP / HE.net data to collect prefixes, optionally validates BGP routes using IRR, filters common CDN/cloud networks using WHOIS information, and can convert CIDR ranges into individual IP addresses.

## Features

- Discover country-associated IPv4 prefixes from RIPE NCC
- Discover ASNs associated with a country through BGP / HE.net
- Collect prefixes originated by discovered ASNs
- Optional IRR validation
- WHOIS-based organization lookup
- Filter common CDN/cloud providers
- Convert CIDR prefixes to individual IPv4 addresses
- Split large output lists into multiple files
- Export results as simple text files

## Data Sources

The tool uses the following public network data sources:

- RIPE NCC — Country-based Internet resource information
- BGP / HE.net — ASN and originated BGP prefix information
- HE.net IRR — Optional route validation
- HE.net WHOIS — Organization information used for filtering

Main BGP source:

https://bgp.he.net

The collected data from these sources is combined, deduplicated, sorted, and written to the output file.

## Installation

Install Python 3 and the required dependency:

pip install requests

Clone the repository:
```
git clone https://github.com/YOUR_USERNAME/country-prefix-enumerator.git
cd country-prefix-enumerator
```
Run the tool:
```
python3 country_prefix_enumerator.py -c AE
```
## Usage

Basic country prefix enumeration:
```
python3 country_prefix_enumerator.py -c AE
```
Specify an output file:
```
python3 country_prefix_enumerator.py -c AE -o ae.txt
```
Enable IRR validation:
```
python3 country_prefix_enumerator.py -c AE --cidr
```
Expand CIDR prefixes into individual IPv4 addresses:
```
python3 country_prefix_enumerator.py -c AE --ip-list
```
Split a large result into multiple files:
```
python3 country_prefix_enumerator.py -c AE --ip-list --split 10
```
### Command Options

| Option | Description |
|---|---|
| -c, --country | Two-letter country code such as AE, SA, or KW |
| -o, --output | Output filename |
| --cidr | Enable IRR validation for BGP prefixes |
| --ip-list | Expand CIDR ranges into individual IPv4 addresses |
| --split | Split the output into the specified number of files |

Example:
```
python3 country_prefix_enumerator.py \
    -c AE \
    -o ae.txt \
    --cidr \
    --ip-list \
    --split 10
```