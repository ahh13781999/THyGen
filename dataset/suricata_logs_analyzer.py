import json
from collections import defaultdict
import argparse
import os
import glob

def analyze_suricata_file(log_file):
    """Analyze a single Suricata log file"""
    event_counts = defaultdict(int)
    line_count = 0
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line_count += 1
            try:
                log_entry = json.loads(line.strip())
                event_type = log_entry.get('event_type', 'unknown')
                event_counts[event_type] += 1
            except json.JSONDecodeError:
                continue
    
    return event_counts, line_count

def analyze_suricata_folder(folder_path):
    """Analyze all .log files in a folder"""
    total_counts = defaultdict(int)
    processed_files = 0
    total_lines = 0
    skipped_files = 0
    
    # Find all .log files in the folder
    pattern = os.path.join(folder_path, '*.log')
    log_files = glob.glob(pattern)
    
    if not log_files:
        print(f"No .log files found in {folder_path}")
        return None, 0
    
    print(f"Found {len(log_files)} .log files to process...")
    
    for log_file in log_files:
        try:
            file_counts, lines_processed = analyze_suricata_file(log_file)
            for event_type, count in file_counts.items():
                total_counts[event_type] += count
            processed_files += 1
            total_lines += lines_processed
        except Exception as e:
            print(f"Error processing {log_file}: {str(e)}")
            skipped_files += 1
            continue
    
    print(f"\nProcessing summary:")
    print(f"- Files found: {len(log_files)}")
    print(f"- Files processed successfully: {processed_files}")
    print(f"- Files skipped: {skipped_files}")
    print(f"- Total log entries analyzed: {total_lines}")
    return total_counts

def main():
    parser = argparse.ArgumentParser(
        description='Analyze Suricata logs from a folder (with .log extension) and count event types',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('folder_path', help='Path to the folder containing Suricata log files (.log)')
    parser.add_argument('--output', help='Optional output file to save results')
    parser.add_argument('--min-count', type=int, default=1,
                       help='Minimum count threshold for reporting event types')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.folder_path):
        print(f"Error: {args.folder_path} is not a valid directory")
        return
    
    event_counts = analyze_suricata_folder(args.folder_path)
    
    if not event_counts:
        return
    
    # Sort by count (descending) and apply minimum count threshold
    sorted_counts = sorted(
        [(et, count) for et, count in event_counts.items() if count >= args.min_count],
        key=lambda x: x[1],
        reverse=True
    )
    
    # Calculate percentages
    total_events = sum(event_counts.values())
    
    # Print results
    print("\nSuricata Event Type Frequency:")
    print("=" * 60)
    print(f"{'Event Type':<20} {'Count':>10} {'Percentage':>15}")
    print("-" * 60)
    for event_type, count in sorted_counts:
        percentage = (count / total_events) * 100
        print(f"{event_type:<20} {count:>10,} {percentage:>14.2f}%")
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write("Suricata Event Type Frequency Report\n")
            f.write(f"Directory: {args.folder_path}\n")
            f.write(f"Minimum count threshold: {args.min_count}\n")
            f.write("=" * 60 + "\n")
            f.write(f"{'Event Type':<20} {'Count':>10} {'Percentage':>15}\n")
            f.write("-" * 60 + "\n")
            for event_type, count in sorted_counts:
                percentage = (count / total_events) * 100
                f.write(f"{event_type:<20} {count:>10,} {percentage:>14.2f}%\n")
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()