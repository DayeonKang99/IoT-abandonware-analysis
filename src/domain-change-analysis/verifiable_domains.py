#!/usr/bin/env python3
"""
Verifiable Domain Filter and Analysis

Filters dataset to include ONLY domains with sufficient non-redacted 
registrant information in BOTH first and last records for ground truth 
validation. Performs comprehensive analysis on this verifiable subset.

This script addresses the fundamental limitation: we can only validate 
ownership change detection on domains where actual ownership is determinable.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, asdict
import re


@dataclass
class VerificationStatus:
    """Status of domain verification"""
    domain: str
    verifiable: bool
    reason: str
    first_has_pii: bool
    last_has_pii: bool
    pii_fields_first: List[str]
    pii_fields_last: List[str]
    confidence: str  # 'high', 'medium', 'low', 'insufficient'


def is_redacted(value: Optional[str]) -> bool:
    """Check if a value is redacted/privacy-protected"""
    if not value or value.strip() == '':
        return True
    
    value_lower = value.lower()
    
    # Explicit redaction indicators
    redaction_indicators = [
        'redacted', 'privacy', 'whoisguard', 'private registration',
        'proxy', 'data protected', 'domains by proxy', 'perfect privacy',
        'contact privacy', 'privacy protect', 'not disclosed',
        'data redacted', 'redacted for privacy'
    ]
    
    for indicator in redaction_indicators:
        if indicator in value_lower:
            return True
    
    return False


def extract_email_domain(email: Optional[str]) -> Optional[str]:
    """Extract domain from email address"""
    if not email or '@' not in email:
        return None
    
    # Handle privacy URLs
    if 'http' in email.lower():
        return None
    
    try:
        domain = email.split('@')[1].lower().strip()
        
        # Filter out privacy service domains
        privacy_domains = [
            'privacy.com', 'whoisguard.com', 'privacyprotect.org',
            'contactprivacy.com', 'domainsbyproxy.com', 'withheldforprivacy.com',
            'redacted.com', 'proxy.com'
        ]
        
        if domain in privacy_domains:
            return None
        
        return domain
    except (IndexError, AttributeError):
        return None


def extract_pii_fields(record: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    Extract all potentially identifying information from WHOIS record.
    
    Returns dict of field_name -> value (or None if redacted/missing)
    """
    registrant = record.get('registrantContact', {})
    
    pii = {
        'organization': None,
        'email_domain': None,
        'name': None,
        'street': None,
        'city': None,
        'state': None,
        'postal_code': None,
        'country': None,
        'phone': None,
    }
    
    # Organization
    org = registrant.get('organization', '')
    if org and not is_redacted(org):
        pii['organization'] = org.lower().strip()
    
    # Email domain
    email = registrant.get('email', '')
    if email and not is_redacted(email):
        pii['email_domain'] = extract_email_domain(email)
    
    # Name
    name = registrant.get('name', '')
    if name and not is_redacted(name):
        pii['name'] = name.lower().strip()
    
    # Address fields
    street = registrant.get('street', '')
    if street and not is_redacted(street):
        pii['street'] = street.lower().strip()
    
    city = registrant.get('city', '')
    if city and not is_redacted(city):
        pii['city'] = city.lower().strip()
    
    state = registrant.get('state', '')
    if state and not is_redacted(state) and len(state) <= 3:
        pii['state'] = state.upper().strip()
    
    postal = registrant.get('postalCode', '')
    if postal and not is_redacted(postal):
        pii['postal_code'] = postal.strip()
    
    country = registrant.get('country', '')
    if country and not is_redacted(country):
        pii['country'] = country.upper().strip()
    
    # Phone
    phone = registrant.get('telephone', '')
    if phone and not is_redacted(phone):
        pii['phone'] = re.sub(r'\D', '', phone)  # Normalize to digits only
    
    return pii


def assess_pii_quality(pii: Dict[str, Optional[str]]) -> Tuple[str, List[str]]:
    """
    Assess the quality/confidence level of available PII.
    
    Returns:
        (confidence_level, available_fields)
    """
    available = [field for field, value in pii.items() if value is not None]
    
    # High confidence: Organization + (Email domain OR multiple address fields)
    if pii['organization']:
        if pii['email_domain']:
            return 'high', available
        if sum(1 for f in ['street', 'city', 'state', 'postal_code'] if pii[f]) >= 2:
            return 'high', available
    
    # Medium confidence: Email domain + (Name OR address fields)
    if pii['email_domain']:
        if pii['name'] or sum(1 for f in ['city', 'state', 'country'] if pii[f]) >= 2:
            return 'medium', available
    
    # Low confidence: Name + multiple address fields
    if pii['name']:
        if sum(1 for f in ['city', 'state', 'country', 'postal_code'] if pii[f]) >= 3:
            return 'low', available
    
    # Insufficient: Not enough data
    return 'insufficient', available


def is_verifiable(first_pii: Dict[str, Optional[str]], 
                  last_pii: Dict[str, Optional[str]]) -> Tuple[bool, str, str]:
    """
    Determine if domain ownership change can be verified.
    
    Returns:
        (verifiable, confidence, reason)
    """
    first_conf, first_fields = assess_pii_quality(first_pii)
    last_conf, last_fields = assess_pii_quality(last_pii)
    
    # Both records must have at least low confidence
    if first_conf == 'insufficient' or last_conf == 'insufficient':
        return False, 'insufficient', 'Insufficient PII in one or both records'
    
    # Check if we have comparable fields
    comparable_high = ['organization', 'email_domain']
    comparable_medium = ['name', 'phone']
    
    has_comparable_high = any(
        first_pii[f] and last_pii[f] 
        for f in comparable_high
    )
    
    has_comparable_medium = any(
        first_pii[f] and last_pii[f] 
        for f in comparable_medium
    )
    
    if has_comparable_high:
        confidence = min(first_conf, last_conf, key=['high', 'medium', 'low'].index)
        return True, confidence, f'Comparable high-confidence fields: {", ".join(comparable_high)}'
    
    if has_comparable_medium:
        confidence = 'low'
        return True, confidence, f'Comparable medium-confidence fields: {", ".join(comparable_medium)}'
    
    # Have PII but different fields in each record
    return False, 'insufficient', 'No comparable PII fields between records'


def determine_ownership_change(first_pii: Dict[str, Optional[str]],
                               last_pii: Dict[str, Optional[str]]) -> Tuple[bool, str]:
    """
    Determine if ownership actually changed based on PII comparison.
    
    Returns:
        (changed, reason)
    """
    # Priority 1: Organization comparison (strongest signal)
    if first_pii['organization'] and last_pii['organization']:
        if first_pii['organization'] != last_pii['organization']:
            return True, f"Organization changed: '{first_pii['organization'][:50]}' → '{last_pii['organization'][:50]}'"
        # Same org - check email for confirmation
        if first_pii['email_domain'] and last_pii['email_domain']:
            if first_pii['email_domain'] != last_pii['email_domain']:
                return True, f"Organization same but email domain changed: {first_pii['email_domain']} → {last_pii['email_domain']}"
            return False, f"Organization and email domain unchanged: {first_pii['organization'][:50]}"
        return False, f"Organization unchanged: {first_pii['organization'][:50]}"
    
    # Priority 2: Email domain comparison
    if first_pii['email_domain'] and last_pii['email_domain']:
        if first_pii['email_domain'] != last_pii['email_domain']:
            return True, f"Email domain changed: {first_pii['email_domain']} → {last_pii['email_domain']}"
        return False, f"Email domain unchanged: {first_pii['email_domain']}"
    
    # Priority 3: Name comparison (weak signal)
    if first_pii['name'] and last_pii['name']:
        if first_pii['name'] != last_pii['name']:
            # Check supporting evidence
            supporting = []
            if (first_pii['phone'] and last_pii['phone'] and 
                first_pii['phone'] != last_pii['phone']):
                supporting.append('phone changed')
            if (first_pii['street'] and last_pii['street'] and 
                first_pii['street'] != last_pii['street']):
                supporting.append('address changed')
            
            if supporting:
                return True, f"Name changed with supporting evidence: {', '.join(supporting)}"
            return True, f"Name changed (low confidence): '{first_pii['name'][:50]}' → '{last_pii['name'][:50]}'"
        return False, f"Name unchanged: {first_pii['name'][:50]}"
    
    # Insufficient comparable data
    return False, "Insufficient comparable PII fields"


def filter_verifiable_domains(simplified_data: Dict[str, Any],
                              verbose: bool = True) -> Dict[str, Any]:
    """
    Filter dataset to include only verifiable domains.
    
    Returns:
        {
            'verifiable_domains': {...},
            'verification_status': [...],
            'statistics': {...}
        }
    """
    verifiable_domains = {}
    verification_status = []
    
    stats = {
        'total_domains': len(simplified_data),
        'verifiable': 0,
        'not_verifiable': 0,
        'insufficient_pii': 0,
        'no_comparable_fields': 0,
        'confidence_distribution': defaultdict(int),
        'pii_field_availability': defaultdict(int),
    }
    
    if verbose:
        print(f"Analyzing {len(simplified_data)} domains for verifiability...")
    
    for idx, (domain_name, domain_data) in enumerate(simplified_data.items(), 1):
        if verbose and idx % 100 == 0:
            print(f"  Processed: {idx}/{len(simplified_data)}")
        
        first_record = domain_data['first_record']
        last_record = domain_data['last_record']
        
        # Extract PII
        first_pii = extract_pii_fields(first_record)
        last_pii = extract_pii_fields(last_record)
        
        # Track PII availability
        for field, value in first_pii.items():
            if value is not None:
                stats['pii_field_availability'][f'first_{field}'] += 1
        for field, value in last_pii.items():
            if value is not None:
                stats['pii_field_availability'][f'last_{field}'] += 1
        
        # Check verifiability
        first_conf, first_fields = assess_pii_quality(first_pii)
        last_conf, last_fields = assess_pii_quality(last_pii)
        
        verifiable, confidence, reason = is_verifiable(first_pii, last_pii)
        
        # Create verification status
        status = VerificationStatus(
            domain=domain_name,
            verifiable=verifiable,
            reason=reason,
            first_has_pii=(first_conf != 'insufficient'),
            last_has_pii=(last_conf != 'insufficient'),
            pii_fields_first=first_fields,
            pii_fields_last=last_fields,
            confidence=confidence if verifiable else 'insufficient'
        )
        
        verification_status.append(asdict(status))
        
        # Update statistics
        if verifiable:
            stats['verifiable'] += 1
            stats['confidence_distribution'][confidence] += 1
            
            # Determine actual ownership change
            changed, change_reason = determine_ownership_change(first_pii, last_pii)
            
            # Add to verifiable dataset with ground truth
            verifiable_domains[domain_name] = {
                **domain_data,
                'ground_truth': {
                    'ownership_changed': changed,
                    'reason': change_reason,
                    'confidence': confidence
                },
                'pii_first': {k: v for k, v in first_pii.items() if v is not None},
                'pii_last': {k: v for k, v in last_pii.items() if v is not None},
            }
        else:
            stats['not_verifiable'] += 1
            if confidence == 'insufficient':
                if not status.first_has_pii or not status.last_has_pii:
                    stats['insufficient_pii'] += 1
                else:
                    stats['no_comparable_fields'] += 1
    
    return {
        'verifiable_domains': verifiable_domains,
        'verification_status': verification_status,
        'statistics': stats
    }


def analyze_verifiable_subset(verifiable_data: Dict[str, Any]) -> Dict[str, Any]:
    """Perform detailed analysis on verifiable domains"""
    
    domains = verifiable_data['verifiable_domains']
    stats = verifiable_data['statistics']
    
    analysis = {
        'ownership_changes': {
            'total_changed': 0,
            'total_unchanged': 0,
            'by_confidence': defaultdict(lambda: {'changed': 0, 'unchanged': 0}),
            'change_reasons': defaultdict(int),
        },
        'temporal_analysis': {
            'avg_years_span_changed': [],
            'avg_years_span_unchanged': [],
        },
        'pii_patterns': {
            'most_discriminative_fields': defaultdict(int),
        }
    }
    
    for domain_name, domain_data in domains.items():
        gt = domain_data['ground_truth']
        changed = gt['ownership_changed']
        confidence = gt['confidence']
        
        # Ownership change statistics
        if changed:
            analysis['ownership_changes']['total_changed'] += 1
            analysis['ownership_changes']['by_confidence'][confidence]['changed'] += 1
            analysis['temporal_analysis']['avg_years_span_changed'].append(domain_data['years_span'])
            
            # Categorize change reason
            reason = gt['reason'].lower()
            if 'organization' in reason:
                analysis['ownership_changes']['change_reasons']['organization_change'] += 1
            elif 'email domain' in reason:
                analysis['ownership_changes']['change_reasons']['email_domain_change'] += 1
            elif 'name' in reason:
                analysis['ownership_changes']['change_reasons']['name_change'] += 1
            else:
                analysis['ownership_changes']['change_reasons']['other'] += 1
        else:
            analysis['ownership_changes']['total_unchanged'] += 1
            analysis['ownership_changes']['by_confidence'][confidence]['unchanged'] += 1
            analysis['temporal_analysis']['avg_years_span_unchanged'].append(domain_data['years_span'])
        
        # Track which PII fields were used for determination
        if 'organization' in domain_data['pii_first'] and 'organization' in domain_data['pii_last']:
            analysis['pii_patterns']['most_discriminative_fields']['organization'] += 1
        if 'email_domain' in domain_data['pii_first'] and 'email_domain' in domain_data['pii_last']:
            analysis['pii_patterns']['most_discriminative_fields']['email_domain'] += 1
        if 'name' in domain_data['pii_first'] and 'name' in domain_data['pii_last']:
            analysis['pii_patterns']['most_discriminative_fields']['name'] += 1
    
    # Calculate averages
    if analysis['temporal_analysis']['avg_years_span_changed']:
        analysis['temporal_analysis']['avg_years_changed'] = \
            sum(analysis['temporal_analysis']['avg_years_span_changed']) / \
            len(analysis['temporal_analysis']['avg_years_span_changed'])
    
    if analysis['temporal_analysis']['avg_years_span_unchanged']:
        analysis['temporal_analysis']['avg_years_unchanged'] = \
            sum(analysis['temporal_analysis']['avg_years_span_unchanged']) / \
            len(analysis['temporal_analysis']['avg_years_span_unchanged'])
    
    return analysis


def print_analysis_report(verifiable_data: Dict[str, Any], analysis: Dict[str, Any]):
    """Print comprehensive analysis report"""
    
    stats = verifiable_data['statistics']
    
    print("\n" + "="*70)
    print("VERIFIABLE DOMAIN ANALYSIS REPORT")
    print("="*70)
    
    # Overall statistics
    print("\n📊 DATASET OVERVIEW")
    print("-"*70)
    print(f"Total domains in dataset:      {stats['total_domains']:,}")
    print(f"Verifiable domains:            {stats['verifiable']:,} ({stats['verifiable']/stats['total_domains']*100:.1f}%)")
    print(f"Not verifiable:                {stats['not_verifiable']:,} ({stats['not_verifiable']/stats['total_domains']*100:.1f}%)")
    print(f"  ├─ Insufficient PII:         {stats['insufficient_pii']:,}")
    print(f"  └─ No comparable fields:     {stats['no_comparable_fields']:,}")
    
    # Confidence distribution
    print("\n📈 VERIFIABLE DOMAINS BY CONFIDENCE")
    print("-"*70)
    for conf in ['high', 'medium', 'low']:
        count = stats['confidence_distribution'][conf]
        if count > 0:
            pct = count / stats['verifiable'] * 100 if stats['verifiable'] > 0 else 0
            print(f"{conf.capitalize():10s} confidence: {count:4,} ({pct:5.1f}%)")
    
    # Ownership changes
    print("\n🔄 OWNERSHIP CHANGE ANALYSIS")
    print("-"*70)
    oc = analysis['ownership_changes']
    total = oc['total_changed'] + oc['total_unchanged']
    print(f"Total verifiable domains:      {total:,}")
    print(f"Ownership changed:             {oc['total_changed']:,} ({oc['total_changed']/total*100:.1f}%)")
    print(f"Ownership unchanged:           {oc['total_unchanged']:,} ({oc['total_unchanged']/total*100:.1f}%)")
    
    print("\nBy confidence level:")
    for conf in ['high', 'medium', 'low']:
        if conf in oc['by_confidence']:
            conf_data = oc['by_confidence'][conf]
            conf_total = conf_data['changed'] + conf_data['unchanged']
            if conf_total > 0:
                print(f"  {conf.capitalize()} (n={conf_total}):")
                print(f"    Changed:   {conf_data['changed']:3,} ({conf_data['changed']/conf_total*100:.1f}%)")
                print(f"    Unchanged: {conf_data['unchanged']:3,} ({conf_data['unchanged']/conf_total*100:.1f}%)")
    
    print("\nChange reasons:")
    for reason, count in sorted(oc['change_reasons'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {reason:25s}: {count:3,}")
    
    # Temporal patterns
    print("\n⏱️  TEMPORAL PATTERNS")
    print("-"*70)
    ta = analysis['temporal_analysis']
    if 'avg_years_changed' in ta:
        print(f"Avg time span (changed):       {ta['avg_years_changed']:.2f} years")
    if 'avg_years_unchanged' in ta:
        print(f"Avg time span (unchanged):     {ta['avg_years_unchanged']:.2f} years")
    
    # PII field availability
    print("\n🔍 PII FIELD AVAILABILITY (Verifiable Subset)")
    print("-"*70)
    pii_fields = ['organization', 'email_domain', 'name', 'street', 'city', 
                  'state', 'postal_code', 'country', 'phone']
    
    for field in pii_fields:
        first_key = f'first_{field}'
        last_key = f'last_{field}'
        first_count = stats['pii_field_availability'].get(first_key, 0)
        last_count = stats['pii_field_availability'].get(last_key, 0)
        
        if first_count > 0 or last_count > 0:
            first_pct = first_count / stats['total_domains'] * 100
            last_pct = last_count / stats['total_domains'] * 100
            print(f"{field:20s}: First={first_count:4,} ({first_pct:5.1f}%)  Last={last_count:4,} ({last_pct:5.1f}%)")
    
    print("\n" + "="*70)


def main():
    """Command-line interface"""
    # if len(sys.argv) < 3:
    #     print("Usage: python filter_verifiable_domains.py <simplified_data.json> <output_prefix>")
    #     print("\nExample:")
    #     print("  python filter_verifiable_domains.py simplified.json verifiable")
    #     print("\nOutputs:")
    #     print("  - verifiable_domains.json:     Filtered verifiable domains only")
    #     print("  - verifiable_analysis.json:    Detailed analysis results")
    #     print("  - verification_status.json:    Status of all domains")
    #     sys.exit(1)
    
    input_file = "results/whois_history_cache_simplified.json" #sys.argv[1]
    output_prefix = "results/verified" #sys.argv[2]
    
    # Validate input
    if not Path(input_file).exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)
    
    print(f"Loading simplified dataset from: {input_file}")
    with open(input_file, 'r', encoding='utf-8') as f:
        simplified_data = json.load(f)
    
    print(f"Total domains: {len(simplified_data)}")
    
    # Filter verifiable domains
    print("\n" + "="*70)
    print("STEP 1: Filtering Verifiable Domains")
    print("="*70)
    verifiable_data = filter_verifiable_domains(simplified_data, verbose=True)
    
    # Analyze verifiable subset
    print("\n" + "="*70)
    print("STEP 2: Analyzing Verifiable Subset")
    print("="*70)
    analysis = analyze_verifiable_subset(verifiable_data)
    
    # Print report
    print_analysis_report(verifiable_data, analysis)
    
    # Save outputs
    print("\n" + "="*70)
    print("STEP 3: Saving Results")
    print("="*70)
    
    # 1. Verifiable domains dataset
    domains_file = f"{output_prefix}_domains.json"
    with open(domains_file, 'w', encoding='utf-8') as f:
        json.dump(verifiable_data['verifiable_domains'], f, indent=2, ensure_ascii=False)
    print(f"✓ Verifiable domains saved to: {domains_file}")
    
    # 2. Analysis results
    analysis_file = f"{output_prefix}_analysis.json"
    full_results = {
        'statistics': verifiable_data['statistics'],
        'analysis': analysis
    }
    with open(analysis_file, 'w', encoding='utf-8') as f:
        json.dump(full_results, f, indent=2, ensure_ascii=False)
    print(f"✓ Analysis results saved to: {analysis_file}")
    
    # 3. Verification status for all domains
    status_file = f"{output_prefix}_verification_status.json"
    with open(status_file, 'w', encoding='utf-8') as f:
        json.dump(verifiable_data['verification_status'], f, indent=2, ensure_ascii=False)
    print(f"✓ Verification status saved to: {status_file}")
    
    print("\n✓ All results saved successfully!")
    print("="*70)


if __name__ == "__main__":
    main()