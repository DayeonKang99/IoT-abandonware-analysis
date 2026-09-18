#!/usr/bin/env python3
"""
Domain History Simplifier: Extract First and Last Records

Given a JSON dataset of domain WHOIS history, extract only the first 
record after a start date and the last record before an end date for 
each domain.

Input Format:
{
  "domain.com": {
    "recordsCount": N,
    "records": [
      {
        "domainName": "domain.com",
        "createdDateISO8601": "...",
        "updatedDateISO8601": "...",
        ...
      },
      ...
    ]
  },
  ...
}

Output Format:
{
  "domain.com": {
    "first_record": {...},
    "last_record": {...},
    "first_date": "2020-01-15",
    "last_date": "2024-12-01",
    "years_span": 4.9
  },
  ...
}
"""

import json
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path


def parse_iso_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse ISO8601 date string to datetime object (timezone-aware).
    
    Args:
        date_str: ISO8601 formatted date string
        
    Returns:
        timezone-aware datetime object or None if parsing fails
    """
    if not date_str:
        return None
    
    try:
        # Parse ISO8601 with timezone
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        
        # Ensure it's timezone-aware (default to UTC if naive)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        return dt
    except (ValueError, AttributeError):
        return None


def parse_date_string(date_str: str) -> datetime:
    """
    Parse command-line date string (YYYY-MM-DD) to timezone-aware datetime.
    
    Args:
        date_str: Date string in YYYY-MM-DD format
        
    Returns:
        timezone-aware datetime object at midnight UTC
    """
    dt = datetime.strptime(date_str, '%Y-%m-%d')
    # Make it timezone-aware (UTC)
    return dt.replace(tzinfo=timezone.utc)


def get_record_date(record: Dict[str, Any]) -> Optional[datetime]:
    """
    Extract the most relevant date from a WHOIS record.
    Priority: updatedDateISO8601 > createdDateISO8601
    
    Args:
        record: WHOIS record dictionary
        
    Returns:
        timezone-aware datetime object representing the record's timestamp
    """
    # Try updatedDate first (most recent activity)
    updated = parse_iso_date(record.get('updatedDateISO8601'))
    if updated:
        return updated
    
    # Fall back to createdDate
    created = parse_iso_date(record.get('createdDateISO8601'))
    if created:
        return created
    
    # Last resort: check audit dates
    audit = record.get('audit', {})
    audit_updated = parse_iso_date(audit.get('updatedDate'))
    if audit_updated:
        return audit_updated
    
    return None


def find_first_record_after(
    records: List[Dict[str, Any]], 
    start_date: datetime
) -> Optional[Dict[str, Any]]:
    """
    Find the first record on or after the start date.
    
    Args:
        records: List of WHOIS records
        start_date: Start date threshold (timezone-aware)
        
    Returns:
        First record after start_date, or None if not found
    """
    candidates = []
    
    for record in records:
        record_date = get_record_date(record)
        if record_date and record_date >= start_date:
            candidates.append((record_date, record))
    
    if not candidates:
        return None
    
    # Sort by date and return earliest
    candidates.sort(key=lambda x: x[0])
    return candidates[0][1]


def find_last_record_before(
    records: List[Dict[str, Any]], 
    end_date: datetime
) -> Optional[Dict[str, Any]]:
    """
    Find the last record on or before the end date.
    
    Args:
        records: List of WHOIS records
        end_date: End date threshold (timezone-aware)
        
    Returns:
        Last record before end_date, or None if not found
    """
    candidates = []
    
    for record in records:
        record_date = get_record_date(record)
        if record_date and record_date <= end_date:
            candidates.append((record_date, record))
    
    if not candidates:
        return None
    
    # Sort by date and return latest
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def simplify_domain_history(
    domain_data: Dict[str, Any],
    start_date: datetime,
    end_date: datetime
) -> Optional[Dict[str, Any]]:
    """
    Extract first and last records for a single domain.
    
    Args:
        domain_data: Domain history data
        start_date: Start date for first record (timezone-aware)
        end_date: End date for last record (timezone-aware)
        
    Returns:
        Simplified domain data with first and last records
    """
    records = domain_data.get('records', [])
    
    if not records:
        return None
    
    # Find first and last records
    first_record = find_first_record_after(records, start_date)
    last_record = find_last_record_before(records, end_date)
    
    # Skip if we don't have both records
    if not first_record or not last_record:
        return None
    
    # Get dates
    first_date = get_record_date(first_record)
    last_date = get_record_date(last_record)
    
    # Skip if same record (no temporal span)
    if first_date == last_date:
        return None
    
    # Calculate time span
    time_delta = last_date - first_date
    years_span = time_delta.days / 365.25
    
    return {
        'domain': domain_data.get('domainName', first_record.get('domainName')),
        'first_record': first_record,
        'last_record': last_record,
        'first_date': first_date.strftime('%Y-%m-%d'),
        'last_date': last_date.strftime('%Y-%m-%d'),
        'years_span': round(years_span, 2),
        'original_record_count': domain_data.get('recordsCount', len(records))
    }


def process_dataset(
    input_file: str,
    output_file: str,
    start_date: str,
    end_date: str,
    verbose: bool = True
) -> Dict[str, int]:
    """
    Process entire domain history dataset and extract simplified records.
    
    Args:
        input_file: Path to input JSON file
        output_file: Path to output JSON file
        start_date: Start date (YYYY-MM-DD format)
        end_date: End date (YYYY-MM-DD format)
        verbose: Print progress information
        
    Returns:
        Statistics dictionary
    """
    # Parse dates (timezone-aware)
    start_dt = parse_date_string(start_date)
    end_dt = parse_date_string(end_date)
    
    if verbose:
        print(f"Loading dataset from: {input_file}")
        print(f"Date range: {start_date} to {end_date}")
    
    # Load input data
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    total_domains = len(data)
    if verbose:
        print(f"Total domains in dataset: {total_domains}")
    
    # Process each domain
    simplified_data = {}
    stats = {
        'total_domains': total_domains,
        'processed': 0,
        'skipped_no_records': 0,
        'skipped_missing_dates': 0,
        'skipped_same_record': 0,
        'successful': 0
    }
    
    for domain_name, domain_data in data.items():
        stats['processed'] += 1
        
        if domain_data is None or 'records' not in domain_data:
            stats['skipped_no_records'] += 1
            continue
        
        simplified = simplify_domain_history(domain_data, start_dt, end_dt)
        
        if simplified is None:
            # Determine why it was skipped
            records = domain_data.get('records', [])
            first_record = find_first_record_after(records, start_dt)
            last_record = find_last_record_before(records, end_dt)
            
            if not first_record or not last_record:
                stats['skipped_missing_dates'] += 1
            else:
                stats['skipped_same_record'] += 1
            continue
        
        simplified_data[domain_name] = simplified
        stats['successful'] += 1
        
        # Progress indicator
        if verbose and stats['processed'] % 100 == 0:
            print(f"Processed: {stats['processed']}/{total_domains} "
                  f"(Success: {stats['successful']})")
    
    # Write output
    if verbose:
        print(f"\nWriting simplified dataset to: {output_file}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(simplified_data, f, indent=2, ensure_ascii=False)
    
    # Print summary
    if verbose:
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Total domains:           {stats['total_domains']}")
        print(f"Successfully processed:  {stats['successful']}")
        print(f"Skipped (no records):    {stats['skipped_no_records']}")
        print(f"Skipped (missing dates): {stats['skipped_missing_dates']}")
        print(f"Skipped (same record):   {stats['skipped_same_record']}")
        print(f"Success rate:            {stats['successful']/stats['total_domains']*100:.1f}%")
        print("="*60)
    
    return stats


def main():
    """Command-line interface"""
    # if len(sys.argv) < 5:
    #     print("Usage: python simplify_domain_history.py <input_file> <output_file> <start_date> <end_date>")
    #     print("\nExample:")
    #     print("  python simplify_domain_history.py whois_history.json simplified.json 2020-01-01 2024-12-31")
    #     print("\nDates should be in YYYY-MM-DD format")
    #     sys.exit(1)
    
    input_file = "results/whois_history_cache.json" # sys.argv[1]
    output_file = "results/whois_history_cache_simplified.json" #sys.argv[2]
    start_date = "2024-01-01" #sys.argv[3]
    end_date = "2026-01-05" #sys.argv[4]

    # Validate input file
    if not Path(input_file).exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)
    
    # Validate date formats
    try:
        datetime.strptime(start_date, '%Y-%m-%d')
        datetime.strptime(end_date, '%Y-%m-%d')
    except ValueError:
        print("Error: Dates must be in YYYY-MM-DD format")
        sys.exit(1)
    
    # Process dataset
    try:
        stats = process_dataset(input_file, output_file, start_date, end_date)
        
        # Exit with appropriate code
        if stats['successful'] == 0:
            print("\nWarning: No domains were successfully processed!")
            sys.exit(1)
        
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
