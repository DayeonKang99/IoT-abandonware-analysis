#!/usr/bin/env python3


import json
import sys
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib


@dataclass
class OwnershipFeatures:
    # Ground truth features (from non-redacted data)
    registrant_org: Optional[str] = None
    registrant_email_domain: Optional[str] = None
    registrant_name: Optional[str] = None
    
    # GDPR-compliant features (always available)
    reseller: Optional[str] = None
    registrar: Optional[str] = None
    nameserver_pattern: Optional[str] = None
    nameserver_category: Optional[str] = None
    nameservers_hash: Optional[str] = None
    state_province: Optional[str] = None
    country: Optional[str] = None
    dnssec: Optional[str] = None
    whois_server: Optional[str] = None
    registration_service_provider: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class GroundTruthResult:
    domain: str
    changed: bool
    confidence: str  # 'high', 'medium', 'low'
    reason: str
    first_date: str
    last_date: str
    years_span: float


@dataclass
class PredictionResult:
    domain: str
    predicted_change: bool
    score: float
    features_changed: Dict[str, bool]
    first_date: str
    last_date: str


# Nameserver category patterns
NAMESERVER_CATEGORIES = {
    'cloud_infrastructure': [
        'awsdns', 'azure', 'googledomains', 'oraclecloud', 
        'cloudfront', 'googleapis'
    ],
    'domain_parking': [
        'parkingcrew', 'sedo', 'bodis', 'sedoparking', 
        'parklogic', 'parked'
    ],
    'shared_hosting': [
        'hostgator', 'bluehost', 'godaddy', 'namecheap',
        'hostinger', 'dreamhost', 'siteground'
    ],
    'cdn_security': [
        'cloudflare', 'akamai', 'fastly', 'incapsula',
        'sucuri', 'imperva'
    ],
    'expired_seized': [
        'registrar-servers', 'suspended', 'expired',
        'seized', 'hold'
    ],
    'privacy_generic': [
        'dnsmadeeasy', 'dnsimple', 'ultradns', 'nsone'
    ],
}


# Privacy service indicators
PRIVACY_SERVICES = [
    'privacy', 'whoisguard', 'private registration', 'proxy',
    'redacted', 'data protected', 'domains by proxy',
    'perfect privacy', 'contact privacy', 'privacy protect'
]


def normalize_string(s: Optional[str]) -> Optional[str]:
    if not s or s.strip() == '':
        return None
    
    s = s.lower().strip() 
    s = re.sub(r'[,.\(\)]', '', s)
    s = re.sub(r'\s+', ' ', s)
    
    return s if s else None


def is_redacted(value: Optional[str]) -> bool:
    if not value:
        return True
    
    value_lower = value.lower()
    
    if 'redacted' in value_lower:
        return True
    
    # Check for privacy service indicators
    for indicator in PRIVACY_SERVICES:
        if indicator in value_lower:
            return True
    
    return False


def extract_email_domain(email: Optional[str]) -> Optional[str]:
    if not email or '@' not in email:
        return None
    
    # Handle privacy URLs like https://tieredaccess.com/contact/...
    if 'http' in email.lower():
        return None
    
    try:
        domain = email.split('@')[1].lower().strip()
        
        # Filter out privacy service domains
        privacy_domains = [
            'privacy.com', 'whoisguard.com', 'privacyprotect.org',
            'contactprivacy.com', 'domainsbyproxy.com'
        ]
        
        if domain in privacy_domains:
            return None
        
        return domain
    except (IndexError, AttributeError):
        return None


def categorize_nameserver(ns: str) -> Optional[str]:
    ns_lower = ns.lower()
    
    for category, patterns in NAMESERVER_CATEGORIES.items():
        for pattern in patterns:
            if pattern in ns_lower:
                return category
    
    return 'custom'  # Self-hosted or unknown


def get_nameserver_pattern(nameservers: List[str]) -> Tuple[Optional[str], Optional[str]]:
    if not nameservers:
        return None, None
    
    ns = nameservers[0].lower()
    ns_clean = re.sub(r'^ns\d+\.', '', ns)
    category = categorize_nameserver(ns)
    
    return ns_clean, category


def hash_nameservers(nameservers: List[str]) -> str:
    if not nameservers:
        return ""
    
    # Sort and normalize
    ns_sorted = sorted([ns.lower().strip() for ns in nameservers])
    ns_string = '|'.join(ns_sorted)
    
    return hashlib.md5(ns_string.encode()).hexdigest()


def extract_reseller_from_raw_text(raw_text: str) -> Optional[str]:
    if not raw_text:
        return None
    
    # Look for "Reseller:" line
    reseller_match = re.search(r'Reseller:\s*(.+?)(?:\n|$)', raw_text, re.IGNORECASE)
    if reseller_match:
        reseller = reseller_match.group(1).strip()
        if reseller and not is_redacted(reseller):
            return normalize_string(reseller)
    
    return None


def extract_registration_service_provider(raw_text: str) -> Optional[str]:
    if not raw_text:
        return None
    
    rsp_match = re.search(
        r'Registration Service Provider:\s*(.+?)(?:\n|$)', 
        raw_text, 
        re.IGNORECASE
    )
    if rsp_match:
        rsp = rsp_match.group(1).strip()
        # Remove email and phone if included
        rsp = re.split(r'[,\n]', rsp)[0].strip()
        if rsp and not is_redacted(rsp):
            return normalize_string(rsp)
    
    return None


def extract_features(record: Dict[str, Any]) -> OwnershipFeatures:
    features = OwnershipFeatures()
    
    registrant = record.get('registrantContact', {})
    
    # Ground truth features
    org = registrant.get('organization', '')
    if org and not is_redacted(org):
        features.registrant_org = normalize_string(org)
    
    email = registrant.get('email', '')
    if email and not is_redacted(email):
        features.registrant_email_domain = extract_email_domain(email)
    
    name = registrant.get('name', '')
    if name and not is_redacted(name):
        features.registrant_name = normalize_string(name)
    
    # GDPR-compliant features
    raw_text = record.get('rawText', '')
    
    features.reseller = extract_reseller_from_raw_text(raw_text)
    features.registration_service_provider = extract_registration_service_provider(raw_text)
    features.registrar = normalize_string(record.get('registrarName'))
    features.whois_server = normalize_string(record.get('whoisServer'))
    
    # Nameserver analysis
    nameservers = record.get('nameServers', [])
    if nameservers:
        pattern, category = get_nameserver_pattern(nameservers)
        features.nameserver_pattern = pattern
        features.nameserver_category = category
        features.nameservers_hash = hash_nameservers(nameservers)
    
    # State and country (sometimes not fully redacted)
    state = registrant.get('state', '')
    if state and not is_redacted(state) and len(state) <= 3:  # Valid state codes
        features.state_province = normalize_string(state)
    
    country = registrant.get('country', '')
    if country and not is_redacted(country):
        features.country = normalize_string(country)
    
    # DNSSEC status
    if raw_text and 'DNSSEC:' in raw_text:
        dnssec_match = re.search(r'DNSSEC:\s*(\w+)', raw_text, re.IGNORECASE)
        if dnssec_match:
            features.dnssec = dnssec_match.group(1).lower()
    
    return features


def has_ground_truth_data(features: OwnershipFeatures) -> bool:
    return bool(
        features.registrant_org or 
        features.registrant_email_domain or
        features.registrant_name
    )


def determine_ground_truth_ownership_change(
    first_features: OwnershipFeatures,
    last_features: OwnershipFeatures
) -> Tuple[bool, str, str]:
    # High confidence signals (organization and email domain)
    if first_features.registrant_org and last_features.registrant_org:
        if first_features.registrant_org != last_features.registrant_org:
            return True, 'high', 'Organization changed' # Always strong signal
        else:
            # Same org - check email domain for confirmation
            if (first_features.registrant_email_domain and 
                last_features.registrant_email_domain):
                if first_features.registrant_email_domain != last_features.registrant_email_domain:
                    return True, 'medium', 'Organization same but email domain changed'
                else:
                    return False, 'high', 'Organization and email domain unchanged'
            return False, 'high', 'Organization unchanged'
    
    # Medium confidence signals (email domain only)
    if (first_features.registrant_email_domain and 
        last_features.registrant_email_domain):
        if first_features.registrant_email_domain != last_features.registrant_email_domain:
            return True, 'medium', 'Email domain changed'
        else:
            return False, 'medium', 'Email domain unchanged'
    
    # Low confidence signals (name only)
    if first_features.registrant_name and last_features.registrant_name:
        if first_features.registrant_name != last_features.registrant_name:
            return True, 'low', 'Name changed (low confidence)'
        else:
            return False, 'low', 'Name unchanged (low confidence)'
    
    # Insufficient data
    return False, 'insufficient', 'No comparable ground truth fields'


def compute_ownership_change_score(
    first_features: OwnershipFeatures,
    last_features: OwnershipFeatures
) -> Tuple[float, Dict[str, bool]]:
    score = 0.0
    features_changed = {}
    
    # Reseller change (weight: 0.35) - strongest signal
    if first_features.reseller and last_features.reseller:
        reseller_changed = first_features.reseller != last_features.reseller
        features_changed['reseller'] = reseller_changed
        if reseller_changed:
            score += 0.35
    
    # Registration Service Provider (weight: 0.30) - very strong
    if (first_features.registration_service_provider and 
        last_features.registration_service_provider):
        rsp_changed = (first_features.registration_service_provider != 
                      last_features.registration_service_provider)
        features_changed['registration_service_provider'] = rsp_changed
        if rsp_changed:
            score += 0.30
    
    # Nameserver category change (weight: 0.25) - strong behavioral signal
    if (first_features.nameserver_category and 
        last_features.nameserver_category):
        ns_cat_changed = (first_features.nameserver_category != 
                         last_features.nameserver_category)
        features_changed['nameserver_category'] = ns_cat_changed
        if ns_cat_changed:
            score += 0.25
            
            # Extra weight for parking transition (very suspicious)
            if (last_features.nameserver_category == 'domain_parking' or
                first_features.nameserver_category == 'expired_seized'):
                score += 0.15
    
    # Nameserver hash change (weight: 0.15) - captures exact NS changes
    elif first_features.nameservers_hash and last_features.nameservers_hash:
        ns_hash_changed = (first_features.nameservers_hash != 
                          last_features.nameservers_hash)
        features_changed['nameservers'] = ns_hash_changed
        if ns_hash_changed:
            score += 0.15
    
    # Registrar change (weight: 0.10) - weak signal
    if first_features.registrar and last_features.registrar:
        registrar_changed = first_features.registrar != last_features.registrar
        features_changed['registrar'] = registrar_changed
        if registrar_changed:
            score += 0.10
    
    # State/Province change (weight: 0.08)
    if first_features.state_province and last_features.state_province:
        state_changed = first_features.state_province != last_features.state_province
        features_changed['state_province'] = state_changed
        if state_changed:
            score += 0.08
    
    # DNSSEC status change (weight: 0.05)
    if first_features.dnssec and last_features.dnssec:
        dnssec_changed = first_features.dnssec != last_features.dnssec
        features_changed['dnssec'] = dnssec_changed
        if dnssec_changed:
            score += 0.05
    
    # Country change (weight: 0.05) - very weak, lots of false positives
    if first_features.country and last_features.country:
        country_changed = first_features.country != last_features.country
        features_changed['country'] = country_changed
        if country_changed:
            score += 0.05
    
    return score, features_changed


def validate_ownership_detection(
    simplified_data: Dict[str, Any],
    threshold: float = 0.5,
    verbose: bool = True
) -> Dict[str, Any]:
    results = {
        'ground_truth': [],
        'predictions': [],
        'statistics': {
            'total_domains': len(simplified_data),
            'ground_truth_available': 0,
            'ground_truth_high_confidence': 0,
            'ground_truth_medium_confidence': 0,
            'ground_truth_low_confidence': 0,
            'no_ground_truth': 0,
        },
        'feature_availability': defaultdict(int),
        'threshold': threshold
    }
    
    processed = 0
    
    for domain_name, domain_data in simplified_data.items():
        processed += 1
        
        if verbose and processed % 100 == 0:
            print(f"Validating: {processed}/{len(simplified_data)}")
        
        first_record = domain_data['first_record']
        last_record = domain_data['last_record']
        
        # Extract features
        first_features = extract_features(first_record)
        last_features = extract_features(last_record)
        
        # Track feature availability
        for feature, value in first_features.to_dict().items():
            if value is not None:
                results['feature_availability'][f'first_{feature}'] += 1
        for feature, value in last_features.to_dict().items():
            if value is not None:
                results['feature_availability'][f'last_{feature}'] += 1
        
        # Check if we have ground truth
        has_ground_truth = (has_ground_truth_data(first_features) and 
                           has_ground_truth_data(last_features))
        
        if has_ground_truth:
            results['statistics']['ground_truth_available'] += 1
            
            # Determine ground truth
            changed, confidence, reason = determine_ground_truth_ownership_change(
                first_features, last_features
            )
            
            # Count by confidence
            if confidence == 'high':
                results['statistics']['ground_truth_high_confidence'] += 1
            elif confidence == 'medium':
                results['statistics']['ground_truth_medium_confidence'] += 1
            elif confidence == 'low':
                results['statistics']['ground_truth_low_confidence'] += 1
            
            ground_truth = GroundTruthResult(
                domain=domain_name,
                changed=changed,
                confidence=confidence,
                reason=reason,
                first_date=domain_data['first_date'],
                last_date=domain_data['last_date'],
                years_span=domain_data['years_span']
            )
            results['ground_truth'].append(asdict(ground_truth))
            
            # Compute algorithm prediction (GDPR-compliant only)
            score, features_changed = compute_ownership_change_score(
                first_features, last_features
            )
            
            predicted_change = score >= threshold
            
            prediction = PredictionResult(
                domain=domain_name,
                predicted_change=predicted_change,
                score=score,
                features_changed=features_changed,
                first_date=domain_data['first_date'],
                last_date=domain_data['last_date']
            )
            results['predictions'].append(asdict(prediction))
        else:
            results['statistics']['no_ground_truth'] += 1
    
    # Calculate performance metrics
    if results['predictions']:
        y_true = [gt['changed'] for gt in results['ground_truth']]
        y_pred = [pred['predicted_change'] for pred in results['predictions']]
        
        # Confusion matrix
        tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
        tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
        fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
        
        total = len(y_true)
        
        results['statistics']['confusion_matrix'] = {
            'true_positive': tp,
            'true_negative': tn,
            'false_positive': fp,
            'false_negative': fn
        }
        
        # Metrics
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        results['statistics']['metrics'] = {
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'false_positive_rate': round(fpr, 4)
        }
        
        # Break down by confidence level
        for conf_level in ['high', 'medium', 'low']:
            conf_indices = [i for i, gt in enumerate(results['ground_truth']) 
                          if gt['confidence'] == conf_level]
            
            if conf_indices:
                conf_true = [y_true[i] for i in conf_indices]
                conf_pred = [y_pred[i] for i in conf_indices]
                
                tp_conf = sum(1 for t, p in zip(conf_true, conf_pred) if t and p)
                tn_conf = sum(1 for t, p in zip(conf_true, conf_pred) if not t and not p)
                fp_conf = sum(1 for t, p in zip(conf_true, conf_pred) if not t and p)
                fn_conf = sum(1 for t, p in zip(conf_true, conf_pred) if t and not p)
                
                total_conf = len(conf_true)
                acc_conf = (tp_conf + tn_conf) / total_conf
                prec_conf = tp_conf / (tp_conf + fp_conf) if (tp_conf + fp_conf) > 0 else 0
                rec_conf = tp_conf / (tp_conf + fn_conf) if (tp_conf + fn_conf) > 0 else 0
                f1_conf = 2 * (prec_conf * rec_conf) / (prec_conf + rec_conf) if (prec_conf + rec_conf) > 0 else 0
                
                results['statistics'][f'metrics_{conf_level}_confidence'] = {
                    'count': total_conf,
                    'accuracy': round(acc_conf, 4),
                    'precision': round(prec_conf, 4),
                    'recall': round(rec_conf, 4),
                    'f1_score': round(f1_conf, 4)
                }
    
    return results


def print_validation_summary(results: Dict[str, Any]):
    """Print human-readable summary of validation results"""
    stats = results['statistics']
    
    print("\n" + "="*70)
    print("DOMAIN OWNERSHIP CHANGE VALIDATION SUMMARY")
    print("="*70)
    
    print("\nDATASET STATISTICS")
    print("-" * 70)
    print(f"Total domains analyzed:        {stats['total_domains']:,}")
    print(f"Ground truth available:        {stats['ground_truth_available']:,} "
          f"({stats['ground_truth_available']/stats['total_domains']*100:.1f}%)")
    print(f"  ├─ High confidence:          {stats['ground_truth_high_confidence']:,}")
    print(f"  ├─ Medium confidence:        {stats['ground_truth_medium_confidence']:,}")
    print(f"  └─ Low confidence:           {stats['ground_truth_low_confidence']:,}")
    print(f"No ground truth:               {stats['no_ground_truth']:,} "
          f"({stats['no_ground_truth']/stats['total_domains']*100:.1f}%)")
    
    if 'metrics' in stats:
        print("\n ALGORITHM PERFORMANCE (All Confidence Levels)")
        print("-" * 70)
        metrics = stats['metrics']
        print(f"Accuracy:                      {metrics['accuracy']:.1%}")
        print(f"Precision:                     {metrics['precision']:.1%}")
        print(f"Recall:                        {metrics['recall']:.1%}")
        print(f"F1 Score:                      {metrics['f1_score']:.3f}")
        print(f"False Positive Rate:           {metrics['false_positive_rate']:.1%}")
        
        cm = stats['confusion_matrix']
        print(f"\nConfusion Matrix:")
        print(f"  True Positives:              {cm['true_positive']:,}")
        print(f"  True Negatives:              {cm['true_negative']:,}")
        print(f"  False Positives:             {cm['false_positive']:,}")
        print(f"  False Negatives:             {cm['false_negative']:,}")
        
        # Performance by confidence level
        print("\nPERFORMANCE BY CONFIDENCE LEVEL")
        print("-" * 70)
        for conf_level in ['high', 'medium', 'low']:
            key = f'metrics_{conf_level}_confidence'
            if key in stats:
                conf_metrics = stats[key]
                print(f"\n{conf_level.upper()} Confidence (n={conf_metrics['count']})")
                print(f"  Accuracy:  {conf_metrics['accuracy']:.1%}  |  "
                      f"Precision: {conf_metrics['precision']:.1%}  |  "
                      f"Recall: {conf_metrics['recall']:.1%}  |  "
                      f"F1: {conf_metrics['f1_score']:.3f}")
    
    print("\nFEATURE AVAILABILITY")
    print("-" * 70)
    
    # Group features by type
    gdpr_features = [
        'reseller', 'registration_service_provider', 'registrar',
        'nameserver_category', 'nameserver_pattern', 'state_province'
    ]
    gt_features = [
        'registrant_org', 'registrant_email_domain', 'registrant_name'
    ]
    
    print("GDPR-Compliant Features (First Record):")
    for feature in gdpr_features:
        key = f'first_{feature}'
        if key in results['feature_availability']:
            count = results['feature_availability'][key]
            pct = count / stats['total_domains'] * 100
            print(f"  {feature:30s}: {count:5,} ({pct:5.1f}%)")
    
    print("\nGround Truth Features (First Record):")
    for feature in gt_features:
        key = f'first_{feature}'
        if key in results['feature_availability']:
            count = results['feature_availability'][key]
            pct = count / stats['total_domains'] * 100
            print(f"  {feature:30s}: {count:5,} ({pct:5.1f}%)")
    
    print("\n" + "="*70)
    
    # Assessment
    if 'metrics' in stats:
        f1 = stats['metrics']['f1_score']
        print("\n ASSESSMENT")
        print("-" * 70)
        if f1 >= 0.77:
            print(" EXCELLENT: Results are strong enough for top-tier publication")
        elif f1 >= 0.67:
            print("✓ GOOD: Results are publishable with appropriate caveats")
        elif f1 >= 0.55:
            print("⚠ MARGINAL: Consider refinement or additional validation")
        else:
            print(" WEAK: Significant refinement needed")
        print("="*70)


def main():
    # if len(sys.argv) < 3:
    #     print("Usage: python validate_ownership_detection.py <simplified_data.json> <output_results.json> [threshold]")
    #     print("\nExample:")
    #     print("  python validate_ownership_detection.py simplified.json validation_results.json 0.5")
    #     print("\nThreshold (optional): Score threshold for ownership change (default: 0.5)")
    #     sys.exit(1)
    
    input_file = "results/whois_history_cache_simplified.json" #sys.argv[1]
    output_file = "results/validation_results.json" #sys.argv[2]
    threshold = 0.5 #float(sys.argv[3]) if len(sys.argv) > 3 else 0.5
    
    # Validate input
    if not Path(input_file).exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)
    
    if not 0 < threshold < 1:
        print(f"Error: Threshold must be between 0 and 1 (got {threshold})")
        sys.exit(1)
    
    print(f"Loading simplified dataset from: {input_file}")
    print(f"Ownership change threshold: {threshold}")
    
    # Load data
    with open(input_file, 'r', encoding='utf-8') as f:
        simplified_data = json.load(f)
    
    print(f"Loaded {len(simplified_data)} domains")
    
    # Run validation
    print("\nRunning validation...")
    results = validate_ownership_detection(
        simplified_data, 
        threshold=threshold,
        verbose=True
    )
    
    print_validation_summary(results)

    print(f"\nSaving detailed results to: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print("\n✓ Validation complete!")
    
    output_path = Path(output_file)
    
    # Save ground truth separately
    gt_file = output_path.parent / f"{output_path.stem}_ground_truth.json"
    with open(gt_file, 'w', encoding='utf-8') as f:
        json.dump(results['ground_truth'], f, indent=2, ensure_ascii=False)
    print(f"  Ground truth saved to: {gt_file}")
    
    # Save predictions separately
    pred_file = output_path.parent / f"{output_path.stem}_predictions.json"
    with open(pred_file, 'w', encoding='utf-8') as f:
        json.dump(results['predictions'], f, indent=2, ensure_ascii=False)
    print(f"  Predictions saved to: {pred_file}")


if __name__ == "__main__":
    main()
