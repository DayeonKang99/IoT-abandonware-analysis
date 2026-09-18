

import os
import ipaddress
from urllib.parse import urlparse
import tldextract
import json


def load_known_malicious_urls(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f.readlines()]

def load_app_domains(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

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



def main(only_domains=True):
    # Load known malicious URLs from a file
    known_malicious_urls = "data/urlhauze.txt"
    malicious_urls = load_known_malicious_urls(known_malicious_urls)

     # Load app domain json file
    apps_domains_file = "../urls/urls_merged.json"
    app_domains = load_app_domains(apps_domains_file)
    
    # # Load app domain ips json file
    # apps_domain_ips_file = "results/unique_app_domains_ips.json"
    # app_domain_ips = load_app_domains(apps_domain_ips_file)
        # Merge app domains and app domain ips
    # for app, ips in app_domain_ips.items():
    #     if app in app_domains:
    #         app_domains[app].extend(ips)
    #     else:
    #         app_domains[app] = ips

    if only_domains:
        # Extract only domains from the malicious URLs
        malicious_domains = set(extract_domain(malicious_urls))
        malicious_domain_ips = set(extract_domain_ips(malicious_urls))

        # check each app's domains against known malicious domains
        results = {}
        for app, domains in app_domains.items():
            results[app] = {"malicious": []}
            for domain in domains:
                if domain in malicious_domains or domain in malicious_domain_ips:
                    print(f"[Malicious] App: {app}, Domain: {domain}")
                    results[app]["malicious"].append(domain)
    
    else:
        # check each app's urls against known malicious urls
        results = {}
        for app, urls in app_domains.items():
            results[app] = {"malicious": []}
            for url in urls:
                if url in malicious_urls:
                    print(f"[Malicious] App: {app}, URL: {url}")
                    results[app]["malicious"].append(url)

    # save results to a file
    output_file = "results/apps_with_malicious_urls.json"
    os.makedirs("results", exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    
    # for domain only checks
    # main()

    # for full url checks
    main(only_domains=False)