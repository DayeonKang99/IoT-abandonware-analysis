#!/usr/bin/env python3
"""
Comprehensive Analysis and Visualization of Verifiable Domain Ground Truth

Analyzes ownership change patterns, confidence distributions, temporal trends,
and generates publication-ready visualizations.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from collections import Counter
import re

# Set publication-quality style
plt.style.use('seaborn-v0_8-paper')
sns.set_palette("husl")
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9


def load_and_prepare_data(csv_file):
    """Load CSV and prepare for analysis"""
    df = pd.read_csv(csv_file)
    
    # Parse boolean column
    df['changed'] = df['changed'].map({'True': True, 'False': False, True: True, False: False})
    
    # Categorize change reasons
    def categorize_reason(reason):
        reason_lower = str(reason).lower()
        if 'organization changed' in reason_lower and 'email' not in reason_lower:
            return 'Organization change'
        elif 'email domain changed' in reason_lower and 'organization same' in reason_lower:
            return 'Email change (org unchanged)'
        elif 'email domain changed' in reason_lower:
            return 'Email domain change'
        elif 'name changed' in reason_lower:
            return 'Name change'
        elif 'organization unchanged' in reason_lower or 'email domain unchanged' in reason_lower:
            return 'No change detected'
        elif 'name unchanged' in reason_lower:
            return 'No change (name only)'
        else:
            return 'Other/Insufficient'
    
    df['reason_category'] = df['reason'].apply(categorize_reason)
    
    return df


def basic_statistics(df):
    """Generate basic statistical summary"""
    total = len(df)
    changed = df['changed'].sum()
    unchanged = total - changed
    
    stats = {
        'total': total,
        'changed': changed,
        'unchanged': unchanged,
        'change_rate': changed / total * 100,
        'by_confidence': df.groupby(['confidence', 'changed']).size().to_dict(),
    }
    
    return stats


def analyze_ownership_changes(df):
    """Detailed analysis of ownership changes"""
    changed_df = df[df['changed'] == True]
    
    if len(changed_df) == 0:
        return None
    
    analysis = {
        'total': len(changed_df),
        'by_confidence': changed_df['confidence'].value_counts().to_dict(),
        'by_reason': changed_df['reason_category'].value_counts().to_dict(),
        'avg_years_span': changed_df['years_span'].mean(),
        'median_years_span': changed_df['years_span'].median(),
        'min_years_span': changed_df['years_span'].min(),
        'max_years_span': changed_df['years_span'].max(),
    }
    
    return analysis


def analyze_unchanged_domains(df):
    """Detailed analysis of unchanged domains"""
    unchanged_df = df[df['changed'] == False]
    
    if len(unchanged_df) == 0:
        return None
    
    analysis = {
        'total': len(unchanged_df),
        'by_confidence': unchanged_df['confidence'].value_counts().to_dict(),
        'by_reason': unchanged_df['reason_category'].value_counts().to_dict(),
        'avg_years_span': unchanged_df['years_span'].mean(),
        'median_years_span': unchanged_df['years_span'].median(),
        'min_years_span': unchanged_df['years_span'].min(),
        'max_years_span': unchanged_df['years_span'].max(),
    }
    
    return analysis


def temporal_analysis(df):
    """Analyze temporal patterns"""
    df['first_year'] = pd.to_datetime(df['first_date']).dt.year
    df['last_year'] = pd.to_datetime(df['last_date']).dt.year
    
    # Changes by year range
    changed_by_year = df[df['changed'] == True].groupby('first_year').size()
    
    # Years span distribution
    span_bins = [0, 0.5, 1.0, 1.5, 2.0, 3.0]
    df['span_category'] = pd.cut(df['years_span'], bins=span_bins, 
                                   labels=['<6mo', '6mo-1yr', '1-1.5yr', '1.5-2yr', '>2yr'])
    
    return df, changed_by_year


def confidence_analysis(df):
    """Analyze confidence level distributions"""
    # Cross-tabulation of confidence vs changed status
    crosstab = pd.crosstab(df['confidence'], df['changed'], normalize='index') * 100
    
    # Confidence distribution overall
    conf_dist = df['confidence'].value_counts()
    
    return crosstab, conf_dist


def tld_analysis(df):
    """Analyze by Top-Level Domain"""
    df['tld'] = df['domain'].str.split('.').str[-1]
    
    # Change rate by TLD (for TLDs with 5+ domains)
    tld_counts = df['tld'].value_counts()
    common_tlds = tld_counts[tld_counts >= 5].index
    
    tld_change_rate = df[df['tld'].isin(common_tlds)].groupby('tld').apply(
        lambda x: (x['changed'].sum() / len(x) * 100)
    ).sort_values(ascending=False)
    
    return tld_change_rate


def print_comprehensive_report(df, stats, changed_analysis, unchanged_analysis):
    """Print detailed text report"""
    print("\n" + "="*80)
    print("VERIFIABLE DOMAIN GROUND TRUTH ANALYSIS")
    print("="*80)
    
    # Overview
    print("\n📊 OVERVIEW")
    print("-"*80)
    print(f"Total verifiable domains:      {stats['total']:,}")
    print(f"Ownership changed:             {stats['changed']:,} ({stats['change_rate']:.1f}%)")
    print(f"Ownership unchanged:           {stats['unchanged']:,} ({100-stats['change_rate']:.1f}%)")
    
    # Ownership changes
    if changed_analysis:
        print("\n🔄 OWNERSHIP CHANGES (n={:,})".format(changed_analysis['total']))
        print("-"*80)
        
        print("\nBy Confidence Level:")
        for conf in ['high', 'medium', 'low']:
            count = changed_analysis['by_confidence'].get(conf, 0)
            pct = count / changed_analysis['total'] * 100 if changed_analysis['total'] > 0 else 0
            print(f"  {conf.capitalize():10s}: {count:3,} ({pct:5.1f}%)")
        
        print("\nBy Change Type:")
        for reason, count in sorted(changed_analysis['by_reason'].items(), 
                                    key=lambda x: x[1], reverse=True):
            pct = count / changed_analysis['total'] * 100
            print(f"  {reason:35s}: {count:3,} ({pct:5.1f}%)")
        
        print("\nTemporal Characteristics:")
        print(f"  Average time span:   {changed_analysis['avg_years_span']:.2f} years")
        print(f"  Median time span:    {changed_analysis['median_years_span']:.2f} years")
        print(f"  Range:               {changed_analysis['min_years_span']:.2f} - "
              f"{changed_analysis['max_years_span']:.2f} years")
    
    # Unchanged domains
    if unchanged_analysis:
        print("\n✓ UNCHANGED OWNERSHIP (n={:,})".format(unchanged_analysis['total']))
        print("-"*80)
        
        print("\nBy Confidence Level:")
        for conf in ['high', 'medium', 'low', 'insufficient']:
            count = unchanged_analysis['by_confidence'].get(conf, 0)
            pct = count / unchanged_analysis['total'] * 100 if unchanged_analysis['total'] > 0 else 0
            print(f"  {conf.capitalize():10s}: {count:3,} ({pct:5.1f}%)")
        
        print("\nBy Evidence Type:")
        for reason, count in sorted(unchanged_analysis['by_reason'].items(), 
                                    key=lambda x: x[1], reverse=True):
            pct = count / unchanged_analysis['total'] * 100
            print(f"  {reason:35s}: {count:3,} ({pct:5.1f}%)")
        
        print("\nTemporal Characteristics:")
        print(f"  Average time span:   {unchanged_analysis['avg_years_span']:.2f} years")
        print(f"  Median time span:    {unchanged_analysis['median_years_span']:.2f} years")
        print(f"  Range:               {unchanged_analysis['min_years_span']:.2f} - "
              f"{unchanged_analysis['max_years_span']:.2f} years")
    
    # Confidence vs Change Rate
    print("\n📈 CHANGE RATE BY CONFIDENCE LEVEL")
    print("-"*80)
    for conf in ['high', 'medium', 'low']:
        conf_df = df[df['confidence'] == conf]
        if len(conf_df) > 0:
            n_total = len(conf_df)
            n_changed = conf_df['changed'].sum()
            change_rate = n_changed / n_total * 100
            print(f"  {conf.capitalize():10s} (n={n_total:3,}): {n_changed:2,} changed "
                  f"({change_rate:5.1f}%)")
    
    # Domain insights
    print("\n🌐 DOMAIN INSIGHTS")
    print("-"*80)
    
    # Notable changed domains
    changed_high_conf = df[(df['changed'] == True) & (df['confidence'] == 'high')]
    if len(changed_high_conf) > 0:
        print(f"\nHigh-confidence ownership changes ({len(changed_high_conf)} domains):")
        for _, row in changed_high_conf.head(10).iterrows():
            print(f"  • {row['domain']:30s} - {row['reason'][:50]}")
    
    print("\n" + "="*80)


def create_visualizations(df, stats, changed_analysis, unchanged_analysis, output_dir):
    """Generate comprehensive visualizations"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # 1. Overview: Changed vs Unchanged (Pie Chart)
    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ['#ff6b6b', '#51cf66']
    sizes = [stats['changed'], stats['unchanged']]
    labels = [f"Changed\n({stats['changed']}, {stats['change_rate']:.1f}%)", 
              f"Unchanged\n({stats['unchanged']}, {100-stats['change_rate']:.1f}%)"]
    
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, 
                                        autopct='', startangle=90,
                                        textprops={'fontsize': 12, 'weight': 'bold'})
    
    ax.set_title('Ownership Change Distribution\n(Verifiable Domains)', 
                 fontsize=14, weight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path / '1_overview_pie.png', bbox_inches='tight')
    plt.close()
    
    # 2. Changed Domains: Confidence Distribution
    if changed_analysis and changed_analysis['by_confidence']:
        fig, ax = plt.subplots(figsize=(10, 6))
        
        conf_order = ['high', 'medium', 'low']
        conf_counts = [changed_analysis['by_confidence'].get(c, 0) for c in conf_order]
        conf_labels = [c.capitalize() for c in conf_order]
        colors_conf = ['#20c997', '#ffd43b', '#ff8787']
        
        bars = ax.bar(conf_labels, conf_counts, color=colors_conf, edgecolor='black', linewidth=1.5)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontsize=11, weight='bold')
        
        ax.set_xlabel('Confidence Level', fontsize=12, weight='bold')
        ax.set_ylabel('Number of Domains', fontsize=12, weight='bold')
        ax.set_title('Ownership Changes by Confidence Level', fontsize=14, weight='bold', pad=15)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        plt.tight_layout()
        plt.savefig(output_path / '2_changed_confidence.png', bbox_inches='tight')
        plt.close()
    
    # 3. Changed Domains: Reason Distribution
    if changed_analysis and changed_analysis['by_reason']:
        fig, ax = plt.subplots(figsize=(12, 6))
        
        reasons = list(changed_analysis['by_reason'].keys())
        counts = list(changed_analysis['by_reason'].values())
        
        # Sort by count
        sorted_pairs = sorted(zip(reasons, counts), key=lambda x: x[1], reverse=True)
        reasons, counts = zip(*sorted_pairs)
        
        bars = ax.barh(reasons, counts, color='#ff6b6b', edgecolor='black', linewidth=1.5)
        
        # Add value labels
        for i, (bar, count) in enumerate(zip(bars, counts)):
            ax.text(count + 0.1, i, f'{int(count)}', 
                   va='center', fontsize=10, weight='bold')
        
        ax.set_xlabel('Number of Domains', fontsize=12, weight='bold')
        ax.set_title('Ownership Change Reasons', fontsize=14, weight='bold', pad=15)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        plt.tight_layout()
        plt.savefig(output_path / '3_changed_reasons.png', bbox_inches='tight')
        plt.close()
    
    # 4. Unchanged Domains: Confidence Distribution
    if unchanged_analysis and unchanged_analysis['by_confidence']:
        fig, ax = plt.subplots(figsize=(10, 6))
        
        conf_order = ['high', 'medium', 'low', 'insufficient']
        conf_counts = [unchanged_analysis['by_confidence'].get(c, 0) for c in conf_order]
        conf_labels = [c.capitalize() for c in conf_order]
        colors_conf = ['#20c997', '#ffd43b', '#ff8787', '#adb5bd']
        
        bars = ax.bar(conf_labels, conf_counts, color=colors_conf, edgecolor='black', linewidth=1.5)
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontsize=11, weight='bold')
        
        ax.set_xlabel('Confidence Level', fontsize=12, weight='bold')
        ax.set_ylabel('Number of Domains', fontsize=12, weight='bold')
        ax.set_title('Unchanged Ownership by Confidence Level', fontsize=14, weight='bold', pad=15)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        plt.tight_layout()
        plt.savefig(output_path / '4_unchanged_confidence.png', bbox_inches='tight')
        plt.close()
    
    # 5. Unchanged Domains: Evidence Type Distribution
    if unchanged_analysis and unchanged_analysis['by_reason']:
        fig, ax = plt.subplots(figsize=(12, 7))
        
        reasons = list(unchanged_analysis['by_reason'].keys())
        counts = list(unchanged_analysis['by_reason'].values())
        
        # Sort by count
        sorted_pairs = sorted(zip(reasons, counts), key=lambda x: x[1], reverse=True)
        reasons, counts = zip(*sorted_pairs)
        
        bars = ax.barh(reasons, counts, color='#51cf66', edgecolor='black', linewidth=1.5)
        
        # Add value labels
        for i, (bar, count) in enumerate(zip(bars, counts)):
            ax.text(count + 0.5, i, f'{int(count)}', 
                   va='center', fontsize=10, weight='bold')
        
        ax.set_xlabel('Number of Domains', fontsize=12, weight='bold')
        ax.set_title('Unchanged Ownership: Evidence Types', fontsize=14, weight='bold', pad=15)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        plt.tight_layout()
        plt.savefig(output_path / '5_unchanged_evidence.png', bbox_inches='tight')
        plt.close()
    
    # 6. Confidence vs Change Rate
    fig, ax = plt.subplots(figsize=(10, 6))
    
    conf_order = ['high', 'medium', 'low']
    change_rates = []
    conf_labels = []
    sample_sizes = []
    
    for conf in conf_order:
        conf_df = df[df['confidence'] == conf]
        if len(conf_df) > 0:
            rate = conf_df['changed'].sum() / len(conf_df) * 100
            change_rates.append(rate)
            conf_labels.append(f"{conf.capitalize()}\n(n={len(conf_df)})")
            sample_sizes.append(len(conf_df))
    
    colors_gradient = ['#20c997', '#ffd43b', '#ff8787'][:len(change_rates)]
    bars = ax.bar(conf_labels, change_rates, color=colors_gradient, 
                   edgecolor='black', linewidth=1.5)
    
    # Add percentage labels
    for bar, rate in zip(bars, change_rates):
        ax.text(bar.get_x() + bar.get_width()/2., rate + 0.5,
               f'{rate:.1f}%',
               ha='center', va='bottom', fontsize=11, weight='bold')
    
    ax.set_ylabel('Ownership Change Rate (%)', fontsize=12, weight='bold')
    ax.set_xlabel('Confidence Level', fontsize=12, weight='bold')
    ax.set_title('Ownership Change Rate by Confidence Level', fontsize=14, weight='bold', pad=15)
    ax.set_ylim(0, max(change_rates) * 1.15)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(output_path / '6_change_rate_by_confidence.png', bbox_inches='tight')
    plt.close()
    
    # 7. Time Span Distribution
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Changed domains
    if changed_analysis:
        changed_spans = df[df['changed'] == True]['years_span']
        ax1.hist(changed_spans, bins=15, color='#ff6b6b', edgecolor='black', alpha=0.7)
        ax1.axvline(changed_spans.mean(), color='darkred', linestyle='--', linewidth=2, 
                   label=f'Mean: {changed_spans.mean():.2f}yr')
        ax1.axvline(changed_spans.median(), color='orange', linestyle='--', linewidth=2,
                   label=f'Median: {changed_spans.median():.2f}yr')
        ax1.set_xlabel('Years Span', fontsize=11, weight='bold')
        ax1.set_ylabel('Frequency', fontsize=11, weight='bold')
        ax1.set_title('Time Span: Ownership Changed', fontsize=12, weight='bold')
        ax1.legend()
        ax1.spines['top'].set_visible(False)
        ax1.spines['right'].set_visible(False)
    
    # Unchanged domains
    if unchanged_analysis:
        unchanged_spans = df[df['changed'] == False]['years_span']
        ax2.hist(unchanged_spans, bins=15, color='#51cf66', edgecolor='black', alpha=0.7)
        ax2.axvline(unchanged_spans.mean(), color='darkgreen', linestyle='--', linewidth=2,
                   label=f'Mean: {unchanged_spans.mean():.2f}yr')
        ax2.axvline(unchanged_spans.median(), color='lime', linestyle='--', linewidth=2,
                   label=f'Median: {unchanged_spans.median():.2f}yr')
        ax2.set_xlabel('Years Span', fontsize=11, weight='bold')
        ax2.set_ylabel('Frequency', fontsize=11, weight='bold')
        ax2.set_title('Time Span: Ownership Unchanged', fontsize=12, weight='bold')
        ax2.legend()
        ax2.spines['top'].set_visible(False)
        ax2.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(output_path / '7_time_span_distribution.png', bbox_inches='tight')
    plt.close()
    
    # 8. Combined Stacked Bar: Confidence × Change Status
    fig, ax = plt.subplots(figsize=(10, 6))
    
    conf_order = ['high', 'medium', 'low']
    changed_counts = []
    unchanged_counts = []
    
    for conf in conf_order:
        conf_df = df[df['confidence'] == conf]
        changed_counts.append(conf_df['changed'].sum())
        unchanged_counts.append((~conf_df['changed']).sum())
    
    x = np.arange(len(conf_order))
    width = 0.6
    
    p1 = ax.bar(x, changed_counts, width, label='Changed', color='#ff6b6b', edgecolor='black')
    p2 = ax.bar(x, unchanged_counts, width, bottom=changed_counts, 
               label='Unchanged', color='#51cf66', edgecolor='black')
    
    # Add labels
    for i, (changed, unchanged) in enumerate(zip(changed_counts, unchanged_counts)):
        if changed > 0:
            ax.text(i, changed/2, str(changed), ha='center', va='center', 
                   fontsize=11, weight='bold', color='white')
        if unchanged > 0:
            ax.text(i, changed + unchanged/2, str(unchanged), ha='center', va='center',
                   fontsize=11, weight='bold', color='white')
    
    ax.set_ylabel('Number of Domains', fontsize=12, weight='bold')
    ax.set_xlabel('Confidence Level', fontsize=12, weight='bold')
    ax.set_title('Ownership Status by Confidence Level', fontsize=14, weight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels([c.capitalize() for c in conf_order])
    ax.legend(loc='upper right', fontsize=11)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(output_path / '8_stacked_confidence.png', bbox_inches='tight')
    plt.close()
    
    print(f"\n✓ Generated 8 visualization plots in: {output_path}")


def main():
    import sys
    
    # if len(sys.argv) < 2:
    #     print("Usage: python analyze_ground_truth.py <ground_truth.csv> [output_dir]")
    #     print("\nExample:")
    #     print("  python analyze_ground_truth.py verifiable_ground_truth.csv analysis_output/")
    #     sys.exit(1)
    
    csv_file = "results/validation_results_ground_truth.csv" #sys.argv[1]
    output_dir = "results/analysis_output" #sys.argv[2] if len(sys.argv) > 2 else 'analysis_output'
    
    print(f"Loading ground truth data from: {csv_file}")
    df = load_and_prepare_data(csv_file)
    
    print("Performing statistical analysis...")
    stats = basic_statistics(df)
    changed_analysis = analyze_ownership_changes(df)
    unchanged_analysis = analyze_unchanged_domains(df)
    
    # Print comprehensive report
    print_comprehensive_report(df, stats, changed_analysis, unchanged_analysis)
    
    # Additional analyses
    print("\n" + "="*80)
    print("ADDITIONAL INSIGHTS")
    print("="*80)
    
    # TLD analysis
    print("\n🌐 CHANGE RATE BY TLD (domains with n≥5)")
    print("-"*80)
    tld_rates = tld_analysis(df)
    for tld, rate in tld_rates.head(10).items():
        tld_count = len(df[df['domain'].str.endswith(f'.{tld}')])
        print(f"  .{tld:10s}: {rate:5.1f}% changed (n={tld_count})")
    
    # Temporal analysis
    df_temporal, _ = temporal_analysis(df)
    
    # Years span categories
    print("\n⏱️  TIME SPAN CATEGORIES")
    print("-"*80)
    span_dist = df_temporal['span_category'].value_counts().sort_index()
    for span, count in span_dist.items():
        change_rate = df_temporal[df_temporal['span_category'] == span]['changed'].mean() * 100
        print(f"  {span:10s}: {count:3,} domains ({change_rate:5.1f}% changed)")
    
    # Generate visualizations
    print("\n" + "="*80)
    print("GENERATING VISUALIZATIONS")
    print("="*80)
    create_visualizations(df, stats, changed_analysis, unchanged_analysis, output_dir)
    
    # Export summary statistics to JSON
    import json

    def json_safe(obj):
        """Recursively convert numpy scalars and non-string dict keys (e.g.
        tuple keys from groupby) into plain JSON-serializable equivalents."""
        if isinstance(obj, dict):
            return {
                (str(k) if not isinstance(k, str) else k): json_safe(v)
                for k, v in obj.items()
            }
        if isinstance(obj, (list, tuple)):
            return [json_safe(v) for v in obj]
        if isinstance(obj, np.generic):
            return obj.item()
        return obj

    summary = {
        'overview': stats,
        'changed_domains': changed_analysis,
        'unchanged_domains': unchanged_analysis,
    }

    summary_file = Path(output_dir) / 'summary_statistics.json'
    with open(summary_file, 'w') as f:
        json.dump(json_safe(summary), f, indent=2, default=str)
    
    print(f"✓ Summary statistics saved to: {summary_file}")
    print("\n✓ Analysis complete!")


if __name__ == "__main__":
    main()