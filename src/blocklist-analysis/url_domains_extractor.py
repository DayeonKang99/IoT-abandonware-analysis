import ipaddress
import json
import os
from urllib.parse import urlparse
import tldextract

def extract_domain(urls=None):
    if not urls:
        return []

    unique_domains = set()
    for url in urls:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:  # ensure it's a valid domain
            unique_domains.add(f"{ext.domain}.{ext.suffix}")
    return list(unique_domains)

def extract_domain_ips(urls=None):
    if not urls:
        return []
    
    unique_ips = set()
    for url in urls:
        netloc = urlparse(url).hostname
        if netloc:
            try:
                ipaddress.ip_address(netloc)  # validate if hostname is an IP
                unique_ips.add(netloc)
            except ValueError:
                continue  # not an IP
    return list(unique_ips)

def merge_json_files(directory):
    merged_data = {}
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            with open(os.path.join(directory, filename), 'r') as f:
                data = json.load(f)
                for app, urls in data.items():
                    if app not in merged_data:
                        merged_data[app] = []
                    merged_data[app].extend(urls)
    return merged_data

if __name__ == "__main__":
    apps_urls = "urls"  # run from the blocklist-analysis/ directory

    merged_urls = merge_json_files(apps_urls)
    with open("urls/urls_merged.json", 'w') as f:
        json.dump(merged_urls, f, indent=4)

    os.makedirs("results", exist_ok=True)

    unique_app_domains = {}
    unique_app_domains_ips = {}

    # extract unique domains for each app
    for app, urls in merged_urls.items():
        print(f"App: {app}")
        domains = extract_domain(urls)
        if domains:
            unique_app_domains[app] = domains
            print(f"Extracted Domains: {domains}")
        else:
            print(f"No URLs provided or no domains extracted for {app}. Skipping ...")
           
    output_file = "results/unique_app_domains.json"
    with open(output_file, 'w') as f:
        json.dump(unique_app_domains, f, indent=4)

    print(f"Unique app domains saved to {output_file}")

    # Extract unique app domain IPs
    for app, urls in merged_urls.items():
        print(f"App: {app}")
        domain_ips = extract_domain_ips(urls)
        if domain_ips:
            unique_app_domains_ips[app] = domain_ips
            print(f"Extracted Domain IPs: {domain_ips}")
        else:
            print(f"No URLs provided or no domain IPs extracted for {app}. Skipping ...")

    output_file_ips = "results/unique_app_domains_ips.json"
    with open(output_file_ips, 'w') as f:
        json.dump(unique_app_domains_ips, f, indent=4)

    print(f"Unique app domain IPs saved to {output_file_ips}")

    # combine all unique domains into a single list (no duplicates)
    all_unique_domains = set()
    for domains in unique_app_domains.values():
        all_unique_domains.update(domains)

    output_all_domains = "results/unique_app_domains_all.json"
    with open(output_all_domains, 'w') as f:
        json.dump(list(all_unique_domains), f, indent=4)
    print(f"All unique domains saved to {output_all_domains}")
    
    # combine all unique domain IPs into a single list (no duplicates)
    all_unique_domain_ips = set()
    for ips in unique_app_domains_ips.values():
        all_unique_domain_ips.update(ips)

    output_all_domain_ips = "results/unique_app_domains_ips_all.json"
    with open(output_all_domain_ips, 'w') as f:
        json.dump(list(all_unique_domain_ips), f, indent=4)
    print(f"All unique domain IPs saved to {output_all_domain_ips}")

