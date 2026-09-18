#!/usr/bin/env python3

import pandas as pd
import json
import sys
import time
import whois
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List
import requests
import tldextract


class WHOISHistoryFetcher:
    
    def __init__(self, api_key: str, cache_file: str = "whois_history_cache.json"):
        self.api_key = api_key
        self.cache_file = Path(cache_file)
        self.api_url = "https://whois-history.whoisxmlapi.com/api/v1"
        
        self.cache = self._load_cache()
        
        # Track hostname -> registered domain mappings
        self.domain_mappings = {}
        
        self.stats = {
            'total_hostnames': 0,
            'unique_domains': 0,
            'cache_hits': 0,
            'validation_passed': 0,
            'validation_failed': 0,
            'api_calls_made': 0,
            'api_calls_successful': 0,
            'api_calls_failed': 0,
            'credits_used': 0
        }
    
    def extract_registered_domain(self, hostname: str) -> Optional[str]:
        try:
            extracted = tldextract.extract(hostname)
            
            # Handle invalid/empty results
            if not extracted.domain or not extracted.suffix:
                return None
            
            # Registered domain is domain + suffix
            registered_domain = f"{extracted.domain}.{extracted.suffix}"
            
            return registered_domain.lower()
            
        except Exception as e:
            print(f"  Warning: Failed to extract domain from '{hostname}': {e}")
            return None
    
    def _load_cache(self) -> Dict:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                print(f"Loaded cache from {self.cache_file}")
                print(f"  Cached domains: {len(cache)}")
                return cache
            except Exception as e:
                print(f"Warning: Could not load cache: {e}")
                return {}
        return {}
    
    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
            print(f"\nCache saved to {self.cache_file}")
            print(f"  Total cached domains: {len(self.cache)}")
        except Exception as e:
            print(f"Error saving cache: {e}")
    
    def validate_domain_whois(self, domain: str) -> bool:
       
        try:
            # Try to fetch basic WHOIS info
            w = whois.whois(domain)
            
            # Check if we got meaningful data
            # A valid WHOIS record should have at least domain_name
            if w.domain_name:
                return True
            
            return False
            
        except whois.parser.WhoisDomainNotFoundError:
            # Domain doesn't exist or no WHOIS data
            return False
        except Exception as e:
            # Other errors (network, timeout, etc.)
            print(f"  Warning: WHOIS validation error for {domain}: {e}")
            # Be conservative - assume it might have data
            return True
    
    def fetch_history_from_api(self, domain: str) -> Optional[Dict]:
    
        try:
            params = {
                'apiKey': self.api_key,
                'domainName': domain,
                'mode': 'purchase',
                'outputFormat': 'JSON'
            }
            
            print(f"  Calling API for {domain}...")
            response = requests.get(self.api_url, params=params, timeout=30)
            
            self.stats['api_calls_made'] += 1
            
            if response.status_code == 200:
                data = response.json()
                self.stats['api_calls_successful'] += 1
                
                # Check if we got history data
                if 'WhoisRecord' in data or 'records' in data:
                    return data
                else:
                    print(f"  No history data returned for {domain}")
                    return None
            
            elif response.status_code == 403:
                print(f"  API Error 403: Authentication failed or credits exhausted")
                self.stats['api_calls_failed'] += 1
                return None
            
            elif response.status_code == 422:
                print(f"  API Error 422: Invalid domain name: {domain}")
                self.stats['api_calls_failed'] += 1
                return None
            
            else:
                print(f"  API Error {response.status_code}: {response.text}")
                self.stats['api_calls_failed'] += 1
                return None
                
        except requests.exceptions.Timeout:
            print(f"  Timeout fetching {domain}")
            self.stats['api_calls_failed'] += 1
            return None
        
        except requests.exceptions.RequestException as e:
            print(f"  Request error fetching {domain}: {e}")
            self.stats['api_calls_failed'] += 1
            sys.exit(1)
        
        except Exception as e:
            print(f"  Error fetching {domain}: {e}")
            self.stats['api_calls_failed'] += 1
            return None
    
    def get_whois_history(self, domain: str, skip_validation: bool = False) -> Optional[Dict]:
    
        domain = domain.lower().strip()
        
        # Check cache first
        if domain in self.cache:
            print(f"✓ Cache hit: {domain}")
            self.stats['cache_hits'] += 1
            return self.cache[domain]
        
        # Validate domain has WHOIS records (unless skipped)
        if not skip_validation:
            print(f"Validating: {domain}")
            if not self.validate_domain_whois(domain):
                print(f"  ✗ Validation failed: No WHOIS records found")
                self.stats['validation_failed'] += 1
                # Cache the failure to avoid re-checking
                self.cache[domain] = None
                return None
            else:
                print(f"  ✓ Validation passed")
                self.stats['validation_passed'] += 1
        
        # Fetch from API
        history = self.fetch_history_from_api(domain)
        
        # Cache the result (even if None)
        self.cache[domain] = history
        
        # Save cache after each successful fetch
        if history is not None:
            self._save_cache()
        
        return history
    
    def process_domains_from_csv(
        self, 
        csv_file: str, 
        hostname_column: str = 'hostname',
        max_domains: int = None,
        delay_seconds: float = 1.0,
        skip_validation: bool = False
    ) -> List[Dict]:
       
        print(f"\nLoading hostnames from: {csv_file}")
        df = pd.read_csv(csv_file)
        
        if hostname_column not in df.columns:
            raise ValueError(f"Column '{hostname_column}' not found in CSV")
        
        hostnames = df[hostname_column].tolist()
        
        if max_domains:
            hostnames = hostnames[:max_domains]
        
        self.stats['total_hostnames'] = len(hostnames)
        
        # Extract registered domains and deduplicate
        print(f"\nExtracting registered domains from {len(hostnames)} hostnames...")
        hostname_to_domain = {}
        unique_domains = set()
        
        for hostname in hostnames:
            domain = self.extract_registered_domain(hostname)
            if domain:
                hostname_to_domain[hostname] = domain
                unique_domains.add(domain)
                self.domain_mappings[hostname] = domain
            else:
                print(f"  Warning: Could not extract domain from '{hostname}'")
        
        domains_list = sorted(unique_domains)
        self.stats['unique_domains'] = len(domains_list)
        
        print(f"  Extracted {len(domains_list)} unique registered domains")
        print(f"  Example mappings:")
        for hostname in list(hostname_to_domain.keys())[:5]:
            print(f"    {hostname} → {hostname_to_domain[hostname]}")
        
        print(f"\nProcessing {len(domains_list)} unique domains...")
        print(f"Validation: {'Disabled' if skip_validation else 'Enabled'}")
        print(f"API delay: {delay_seconds}s between calls")
        print("="*60)
        
        # Process each unique domain
        domain_results = {}
        
        for idx, domain in enumerate(domains_list, 1):
            print(f"\n[{idx}/{len(domains_list)}] Processing: {domain}")
            
            history = self.get_whois_history(domain, skip_validation=skip_validation)
            
            domain_results[domain] = {
                'domain': domain,
                'rank': idx,
                'has_history': history is not None,
                'history': history,
                'fetched_at': datetime.now().isoformat()
            }
            
            # Rate limiting: delay between API calls (not for cache hits)
            if history is not None and domain not in self.cache:
                time.sleep(delay_seconds)
            
            # Periodic cache saves (every 10 domains)
            if idx % 10 == 0:
                self._save_cache()
                self._print_progress()
        
        # Final cache save
        self._save_cache()
        
        # Map results back to original hostnames
        results = []
        for hostname in hostnames:
            domain = hostname_to_domain.get(hostname)
            if domain and domain in domain_results:
                result = domain_results[domain].copy()
                result['original_hostname'] = hostname
                results.append(result)
            else:
                # Hostname had no valid domain
                results.append({
                    'original_hostname': hostname,
                    'domain': None,
                    'has_history': False,
                    'history': None,
                    'fetched_at': datetime.now().isoformat()
                })
        
        return results
    
    def _print_progress(self):
        """Print progress statistics."""
        print("\n" + "-"*60)
        print("PROGRESS UPDATE")
        print("-"*60)
        processed = self.stats['cache_hits'] + self.stats['validation_passed'] + self.stats['validation_failed']
        print(f"Unique domains processed: {processed}/{self.stats['unique_domains']}")
        print(f"Cache hits: {self.stats['cache_hits']}")
        print(f"Validation passed: {self.stats['validation_passed']}")
        print(f"Validation failed: {self.stats['validation_failed']}")
        print(f"API calls made: {self.stats['api_calls_made']}")
        print(f"API calls successful: {self.stats['api_calls_successful']}")
        print(f"API calls failed: {self.stats['api_calls_failed']}")
        print("-"*60)
    
    def print_final_stats(self):
        """Print final statistics."""
        print("\n" + "="*60)
        print("FINAL STATISTICS")
        print("="*60)
        print(f"Total hostnames: {self.stats['total_hostnames']}")
        print(f"Unique registered domains: {self.stats['unique_domains']}")
        print(f"Deduplication savings: {self.stats['total_hostnames'] - self.stats['unique_domains']} domains")
        print(f"\nCache performance:")
        print(f"  Cache hits: {self.stats['cache_hits']}")
        if self.stats['unique_domains'] > 0:
            print(f"  Cache hit rate: {self.stats['cache_hits']/self.stats['unique_domains']*100:.1f}%")
        print(f"\nValidation results:")
        print(f"  Passed: {self.stats['validation_passed']}")
        print(f"  Failed: {self.stats['validation_failed']}")
        if self.stats['validation_passed'] + self.stats['validation_failed'] > 0:
            pass_rate = self.stats['validation_passed']/(self.stats['validation_passed']+self.stats['validation_failed'])*100
            print(f"  Pass rate: {pass_rate:.1f}%")
        print(f"\nAPI usage:")
        print(f"  Total API calls: {self.stats['api_calls_made']}")
        print(f"  Successful: {self.stats['api_calls_successful']}")
        print(f"  Failed: {self.stats['api_calls_failed']}")
        if self.stats['api_calls_made'] > 0:
            success_rate = self.stats['api_calls_successful']/self.stats['api_calls_made']*100
            print(f"  Success rate: {success_rate:.1f}%")
        print(f"\nTotal credits saved:")
        dedup_savings = self.stats['total_hostnames'] - self.stats['unique_domains']
        validation_savings = self.stats['validation_failed']
        cache_savings = self.stats['cache_hits']
        total_savings = dedup_savings + validation_savings + cache_savings
        print(f"  By deduplication: {dedup_savings}")
        print(f"  By validation: {validation_savings}")
        print(f"  By caching: {cache_savings}")
        print(f"  TOTAL SAVED: {total_savings} credits")
        print(f"  Actual API calls: {self.stats['api_calls_made']}")
        if self.stats['total_hostnames'] > 0:
            efficiency = (1 - self.stats['api_calls_made']/self.stats['total_hostnames']) * 100
            print(f"  Efficiency: {efficiency:.1f}% reduction in API calls")
        print("="*60)


def save_results_to_json(results: List[Dict], output_file: str):
    """Save results to JSON file."""
    print(f"\nSaving results to: {output_file}")
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"  Saved {len(results)} records")
    
    # Also create a summary CSV
    summary_data = []
    for r in results:
        summary_data.append({
            'original_hostname': r.get('original_hostname'),
            'registered_domain': r.get('domain'),
            'has_history': r['has_history'],
            'fetched_at': r['fetched_at']
        })
    
    summary_df = pd.DataFrame(summary_data)
    summary_csv = Path(output_file).parent / f"{Path(output_file).stem}_summary.csv"
    summary_df.to_csv(summary_csv, index=False)
    print(f"  Saved summary to: {summary_csv}")


def main():
    """Main execution function."""
    # if len(sys.argv) < 3:
    #     print("Usage: python fetch_whois_history.py <api_key> <domains_csv> [options]")
    #     print("\nExample:")
    #     print("  python fetch_whois_history.py YOUR_API_KEY selected_urls.csv")
    #     print("  python fetch_whois_history.py YOUR_API_KEY selected_urls.csv --max 100 --delay 2")
    #     print("\nOptions:")
    #     print("  --max N              Process only first N domains (default: all)")
    #     print("  --delay N            Delay N seconds between API calls (default: 1.0)")
    #     print("  --column NAME        Column name for hostnames (default: hostname)")
    #     print("  --output FILE        Output JSON file (default: whois_history_results.json)")
    #     print("  --cache FILE         Cache file path (default: whois_history_cache.json)")
    #     print("  --skip-validation    Skip WHOIS validation (not recommended)")
    #     sys.exit(1)
    
    # Only needed if you want to fetch/extend WHOIS history yourself — the
    # curated results already in results/ (whois_history_cache.json etc.)
    # work with no key at all. Get your own key at
    # https://whois-history.whoisxmlapi.com/api/documentation/making-requests
    api_key = "" #sys.argv[1]
    csv_file = "data/sampled_urls_4_domain_analysis-III.csv" #sys.argv[2]

    # Parse optional arguments
    max_domains =  300 #None # default: process all
    delay = 0.5
    hostname_column = 'hostname'
    output_file = 'results/whois_history_results.json'
    cache_file = 'results/whois_history_cache.json'
    skip_validation = False
    
    # i = 3
    # while i < len(sys.argv):
    #     if sys.argv[i] == '--max' and i + 1 < len(sys.argv):
    #         max_domains = int(sys.argv[i + 1])
    #         i += 2
    #     elif sys.argv[i] == '--delay' and i + 1 < len(sys.argv):
    #         delay = float(sys.argv[i + 1])
    #         i += 2
    #     elif sys.argv[i] == '--column' and i + 1 < len(sys.argv):
    #         hostname_column = sys.argv[i + 1]
    #         i += 2
    #     elif sys.argv[i] == '--output' and i + 1 < len(sys.argv):
    #         output_file = sys.argv[i + 1]
    #         i += 2
    #     elif sys.argv[i] == '--cache' and i + 1 < len(sys.argv):
    #         cache_file = sys.argv[i + 1]
    #         i += 2
    #     elif sys.argv[i] == '--skip-validation':
    #         skip_validation = True
    #         i += 1
    #     else:
    #         i += 1
    
    try:
        # Initialize fetcher
        fetcher = WHOISHistoryFetcher(api_key, cache_file)
        
        # Process domains
        results = fetcher.process_domains_from_csv(
            csv_file,
            hostname_column=hostname_column,
            max_domains=max_domains,
            delay_seconds=delay,
            skip_validation=skip_validation
        )
        
        # Save results
        save_results_to_json(results, output_file)
        
        # Print final statistics
        fetcher.print_final_stats()
        
        print("\n" + "="*60)
        print("WHOIS HISTORY FETCH COMPLETED")
        print("="*60)
        print(f"\nOutputs:")
        print(f"  Full results: {output_file}")
        print(f"  Summary CSV: {Path(output_file).stem}_summary.csv")
        print(f"  Cache file: {cache_file}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
