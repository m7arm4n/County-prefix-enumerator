import requests
import re
import argparse
import time
import ipaddress
import math
import ipaddress

BASE = "https://bgp.he.net"

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json, text/plain, */*",
    "Referer": BASE
}

CDN_BLOCKLIST = [
    "cloudflare", "akamai", "fastly", "amazon", "aws",
    "google", "azure", "microsoft", "edgecast",
    "stackpath", "limelight", "bunny", "cdn77",
    "gcore", "imperva", "quantil", "cachefly"
]


# ---------------- ASN ----------------

def bgp_get_asns(country):
    url = f"{BASE}/country/{country.upper()}"
    r = requests.get(url, headers=HEADERS)
    r.raise_for_status()
    return sorted(set(re.findall(r'AS(\d+)', r.text)))


# ---------------- PREFIXES ----------------

def bgp_get_prefixes(asn):
    url = f"{BASE}/super-lg/report/api/v1/prefixes/originated/{asn}"
    r = requests.get(url, headers=HEADERS)
    r.raise_for_status()

    data = r.json()
    prefixes = []

    for item in data.get("prefixes", []):
        p = item.get("Prefix")

        if p and "." in p and p != "0.0.0.0/0":
            prefixes.append(p)

    return prefixes

import ipaddress

def rip_get_prefixes(country):
    url = f"https://stat.ripe.net/data/country-resource-list/data.json?resource={country}"

    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()

    ipv4_list = (
        r.json()
         .get("data", {})
         .get("resources", {})
         .get("ipv4", [])
    )

    prefixes = []

    for item in ipv4_list:

        # CIDR
        if "/" in item:
            prefixes.append(item)

        # Start-End Range
        elif "-" in item:
            start, end = item.split("-")

            try:
                nets = ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(start.strip()),
                    ipaddress.IPv4Address(end.strip())
                )

                prefixes.extend(str(n) for n in nets)

            except Exception:
                pass

    return sorted(set(prefixes))


# ---------------- VALIDATION ----------------

def chunked(lst, size=50):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def validate_prefixes(asn, prefixes):
    url = f"{BASE}/super-lg/report/api/v1/irr/prefixes"
    valid = []

    for chunk in chunked(prefixes, 50):
        payload = {
            "prefixes": chunk,
            "origin": int(asn)
        }

        r = requests.post(url, json=payload, headers=HEADERS)
        r.raise_for_status()

        data = r.json()

        for item in data.get("response", []):
            if item.get("RouteValid") == "valid":
                p = item.get("Prefix")
                if p and "." in p:
                    valid.append(p)

        time.sleep(0.5)

    return valid


# ---------------- WHOIS ----------------

def whois_prefixes(prefixes):
    url = f"{BASE}/super-lg/report/api/v1/whois/prefixes"
    enriched = []

    for chunk in chunked(prefixes, 50):
        payload = {"prefixes": chunk}

        r = requests.post(url, json=payload, headers=HEADERS)
        r.raise_for_status()

        data = r.json()

        for item in data.get("response", []):
            enriched.append({
                "prefix": item.get("Prefix"),
                "org": (item.get("Org") or "").lower()
            })

        time.sleep(0.5)

    return enriched


def is_cdn(org):
    return any(cdn in org for cdn in CDN_BLOCKLIST)


def filter_clean_prefixes(whois_data):
    clean = []

    for item in whois_data:
        if item["prefix"] and not is_cdn(item["org"]):
            clean.append(item["prefix"])

    return sorted(set(clean))


# ---------------- CIDR -> IP ----------------

def cidr_to_ips(prefixes):
    ips = []

    for cidr in prefixes:
        try:
            net = ipaddress.ip_network(cidr, strict=False)

            # IPv4 only
            if net.version == 4:
                for ip in net.hosts():
                    ips.append(str(ip))

        except Exception:
            continue

    return ips


# ---------------- SPLIT FILES ----------------

def split_output(data, parts, base_name):
    total = len(data)
    if total == 0:
        return

    chunk_size = math.ceil(total / parts)

    for i in range(parts):
        chunk = data[i * chunk_size:(i + 1) * chunk_size]
        if not chunk:
            continue

        filename = f"{base_name}_part{i+1}.txt"

        with open(filename, "w") as f:
            for line in chunk:
                f.write(line + "\n")

        print(f"[+] Saved {len(chunk)} lines -> {filename}")


# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--country",
        required=True,
        help="Two-letter country code, for example AE, SA, KW"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output file name"
    )

    parser.add_argument(
        "--cidr",
        action="store_true",
        help="Validate BGP prefixes using IRR validation"
    )

    parser.add_argument(
        "--ip-list",
        action="store_true",
        help="Expand CIDR prefixes into individual IPv4 addresses"
    )

    parser.add_argument(
        "--split",
        type=int,
        help="Split the output into the specified number of files"
    )

    args = parser.parse_args()

    results = set()

    # ---------------- RIPE ----------------
    try:
        print("[+] Fetching RIPE prefixes...")
        ripe_prefixes = rip_get_prefixes(args.country)

        print(f"[+] RIPE returned {len(ripe_prefixes)} prefixes")
        results.update(ripe_prefixes)

    except Exception as e:
        print(f"[!] RIPE error: {e}")

    # ---------------- BGP HE ----------------
    try:
        asns = bgp_get_asns(args.country)

        print(f"[+] Found {len(asns)} ASNs")

        for asn in asns:
            print(f"[+] Processing AS{asn}")

            try:
                prefixes = bgp_get_prefixes(asn)

                if args.cidr:
                    prefixes = validate_prefixes(asn, prefixes)

                whois_data = whois_prefixes(prefixes)
                prefixes = filter_clean_prefixes(whois_data)

                results.update(prefixes)

            except Exception as e:
                print(f"[!] Error AS{asn}: {e}")

    except Exception as e:
        print(f"[!] ASN discovery error: {e}")

    # ---------------- Final ----------------
    results = sorted(results)

    print(f"[+] Total unique prefixes: {len(results)}")

    if args.ip_list:
        print("[+] Expanding CIDRs to IPs...")
        results = cidr_to_ips(results)

    if args.output:
        if args.split and args.split > 1:
            split_output(results, args.split, args.output)
        else:
            with open(args.output, "w") as f:
                for r in results:
                    f.write(r + "\n")

            print(f"[+] Saved {len(results)} lines -> {args.output}")
    else:
        for r in results:
            print(r)

if __name__ == "__main__":
    main()
