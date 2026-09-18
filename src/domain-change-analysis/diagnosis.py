#!/usr/bin/env python3
"""
Diagnostic Analysis: Why is recall so low?

Analyzes the false negatives to understand what features changed
in actual ownership transfers that the algorithm missed.
"""

import json
import sys
from collections import defaultdict


def analyze_false_negatives(results_file: str):
    """Analyze why the algorithm missed actual ownership changes"""
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    ground_truth = {gt['domain']: gt for gt in results['ground_truth']}
    predictions = {pred['domain']: pred for pred in results['predictions']}
    
    # Find false negatives (actual changes that were missed)
    false_negatives = []
    for domain, gt in ground_truth.items():
        if gt['changed'] and domain in predictions:
            pred = predictions[domain]
            if not pred['predicted_change']:
                false_negatives.append({
                    'domain': domain,
                    'ground_truth': gt,
                    'prediction': pred
                })
    
    print("="*70)
    print(f"FALSE NEGATIVE ANALYSIS ({len(false_negatives)} cases)")
    print("="*70)
    
    if not false_negatives:
        print("No false negatives found!")
        return
    
    # Analyze what features changed (or didn't)
    feature_change_stats = defaultdict(lambda: {'changed': 0, 'not_changed': 0, 'missing': 0})
    
    for fn in false_negatives:
        print(f"\n{'─'*70}")
        print(f"Domain: {fn['domain']}")
        print(f"Ground Truth: {fn['ground_truth']['reason']}")
        print(f"Confidence: {fn['ground_truth']['confidence']}")
        print(f"Predicted Score: {fn['prediction']['score']:.3f}")
        print(f"Date Range: {fn['ground_truth']['first_date']} → {fn['ground_truth']['last_date']}")
        
        features_changed = fn['prediction']['features_changed']
        
        print(f"\nFeatures that changed:")
        if features_changed:
            for feature, changed in features_changed.items():
                feature_change_stats[feature]['changed' if changed else 'not_changed'] += 1
                if changed:
                    print(f"  ✓ {feature}")
        else:
            print("  (No GDPR features changed)")
        
        print(f"\nFeatures that did NOT change:")
        if features_changed:
            for feature, changed in features_changed.items():
                if not changed:
                    print(f"  ✗ {feature}")
    
    # Summary statistics
    print(f"\n{'='*70}")
    print("FEATURE CHANGE STATISTICS (False Negatives)")
    print("="*70)
    print(f"{'Feature':<30} {'Changed':<10} {'Unchanged':<10} {'Change %'}")
    print("-"*70)
    
    for feature in sorted(feature_change_stats.keys()):
        stats = feature_change_stats[feature]
        total = stats['changed'] + stats['not_changed']
        if total > 0:
            pct = stats['changed'] / total * 100
            print(f"{feature:<30} {stats['changed']:<10} {stats['not_changed']:<10} {pct:>6.1f}%")
    
    # Check if ANY features changed
    print(f"\n{'='*70}")
    print("FEATURE AVAILABILITY IN FALSE NEGATIVES")
    print("="*70)
    
    no_features_changed = sum(1 for fn in false_negatives 
                             if not any(fn['prediction']['features_changed'].values()))
    
    print(f"Cases with NO GDPR features changed: {no_features_changed}/{len(false_negatives)} "
          f"({no_features_changed/len(false_negatives)*100:.1f}%)")
    
    some_features = len(false_negatives) - no_features_changed
    print(f"Cases with SOME features changed:    {some_features}/{len(false_negatives)} "
          f"({some_features/len(false_negatives)*100:.1f}%)")


def analyze_true_positives(results_file: str):
    """Analyze what made the algorithm correctly identify changes"""
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    ground_truth = {gt['domain']: gt for gt in results['ground_truth']}
    predictions = {pred['domain']: pred for pred in results['predictions']}
    
    # Find true positives
    true_positives = []
    for domain, gt in ground_truth.items():
        if gt['changed'] and domain in predictions:
            pred = predictions[domain]
            if pred['predicted_change']:
                true_positives.append({
                    'domain': domain,
                    'ground_truth': gt,
                    'prediction': pred
                })
    
    print("\n" + "="*70)
    print(f"TRUE POSITIVE ANALYSIS ({len(true_positives)} cases)")
    print("="*70)
    
    if not true_positives:
        print("No true positives found!")
        return
    
    for tp in true_positives:
        print(f"\n{'─'*70}")
        print(f"Domain: {tp['domain']}")
        print(f"Ground Truth: {tp['ground_truth']['reason']}")
        print(f"Predicted Score: {tp['prediction']['score']:.3f}")
        
        features_changed = tp['prediction']['features_changed']
        
        print(f"\nFeatures that changed:")
        for feature, changed in features_changed.items():
            if changed:
                print(f"  ✓ {feature}")


def analyze_score_distribution(results_file: str):
    """Analyze the distribution of scores"""
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    ground_truth = {gt['domain']: gt for gt in results['ground_truth']}
    predictions = {pred['domain']: pred for pred in results['predictions']}
    
    changed_scores = []
    unchanged_scores = []
    
    for domain, pred in predictions.items():
        if domain in ground_truth:
            gt = ground_truth[domain]
            if gt['changed']:
                changed_scores.append(pred['score'])
            else:
                unchanged_scores.append(pred['score'])
    
    print("\n" + "="*70)
    print("SCORE DISTRIBUTION")
    print("="*70)
    
    print(f"\nActual Ownership Changes (n={len(changed_scores)}):")
    if changed_scores:
        print(f"  Min:    {min(changed_scores):.3f}")
        print(f"  Max:    {max(changed_scores):.3f}")
        print(f"  Mean:   {sum(changed_scores)/len(changed_scores):.3f}")
        print(f"  Median: {sorted(changed_scores)[len(changed_scores)//2]:.3f}")
    
    print(f"\nNo Ownership Change (n={len(unchanged_scores)}):")
    if unchanged_scores:
        print(f"  Min:    {min(unchanged_scores):.3f}")
        print(f"  Max:    {max(unchanged_scores):.3f}")
        print(f"  Mean:   {sum(unchanged_scores)/len(unchanged_scores):.3f}")
        print(f"  Median: {sorted(unchanged_scores)[len(unchanged_scores)//2]:.3f}")
    
    # Suggest optimal threshold
    print("\n" + "="*70)
    print("THRESHOLD OPTIMIZATION")
    print("="*70)
    
    all_scores = [(score, True) for score in changed_scores] + \
                 [(score, False) for score in unchanged_scores]
    all_scores.sort(reverse=True)
    
    best_f1 = 0
    best_threshold = 0.5
    
    for threshold in [0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5]:
        tp = sum(1 for s, changed in all_scores if s >= threshold and changed)
        fp = sum(1 for s, changed in all_scores if s >= threshold and not changed)
        fn = sum(1 for s, changed in all_scores if s < threshold and changed)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"Threshold {threshold:.2f}: Precision={precision:.1%}, Recall={recall:.1%}, F1={f1:.3f}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
    
    print(f"\n✓ Optimal threshold: {best_threshold:.2f} (F1={best_f1:.3f})")


def main():
    # if len(sys.argv) < 2:
    #     print("Usage: python diagnose_results.py <validation_results.json>")
    #     sys.exit(1)
    
    results_file = "results/validation_results.json"  #sys.argv[1]
    
    analyze_false_negatives(results_file)
    analyze_true_positives(results_file)
    analyze_score_distribution(results_file)


if __name__ == "__main__":
    main()