import re
import sys
import random
import os
from collections import defaultdict

def parse_datasets(file_paths):
    """Parse multiple dataset files, extract mitre_tactic values, and add log_type"""
    tactic_counts = defaultdict(int)
    total_entries = 0
    all_lines = []
    
    for file_path in file_paths:
        try:
            # Extract filename without extension
            filename_with_ext = os.path.basename(file_path)
            filename = os.path.splitext(filename_with_ext)[0]
            
            for encoding in ['utf-8', 'latin-1', 'utf-16', 'cp1252']:
                try:
                    with open(file_path, 'r', encoding=encoding) as file:
                        for line in file:
                            try:
                                stripped_line = line.strip()
                                match = re.search(r"mitre_tactic='([^']*)'", stripped_line)
                                if match:
                                    tactic = match.group(1)
                                    # Skip if tactic is empty or 'null' (case-insensitive)
                                    if not tactic or tactic.lower() == 'null':
                                        continue
                                    tactic_counts[tactic] += 1
                                    total_entries += 1
                                    # Prepend log_type to the line
                                    modified_line = f"log_type='{filename}', {stripped_line}"
                                    all_lines.append((tactic, modified_line))
                            except UnicodeDecodeError:
                                continue
                    break  # Break if encoding succeeded
                except UnicodeDecodeError:
                    continue
        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}", file=sys.stderr)
                    
    return tactic_counts, total_entries, all_lines

# The rest of the functions (generate_report, process_dataset, main) remain unchanged

def generate_report(tactic_counts, total_entries, title="MITRE Tactic Report"):
    """Generate a report with counts and percentages"""
    if total_entries == 0:
        print("No valid entries found.", file=sys.stderr)
        return
    
    print(f"\n{title}")
    print("=" * len(title))
    print(f"{'Tactic':<25} | {'Count':<10} | {'Percentage':<10}")
    print("-" * 50)
    
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_entries) * 100
        print(f"{tactic:<25} | {count:<10} | {percentage:.2f}%")
    
    print("\n" + "-" * 50)
    print(f"{'Total':<25} | {total_entries:<10} | 100.00%")

def process_dataset(all_lines):
    """Process dataset according to frequency rules"""
    # Calculate initial statistics
    tactic_counts = defaultdict(int)
    for tactic, _ in all_lines:
        tactic_counts[tactic] += 1
    total_entries = len(all_lines)
    
    # Generate initial report
    generate_report(tactic_counts, total_entries, "Initial Dataset Report")
    
    # Categorize tactics
    high_freq = []
    low_freq = []
    normal_freq = []
    
    for tactic, count in tactic_counts.items():
        percentage = (count / total_entries) * 100
        if percentage > 3:
            high_freq.append(tactic)
        elif percentage < 2:
            low_freq.append(tactic)
        else:
            normal_freq.append(tactic)
    
    # Process lines according to rules
    processed_lines = []
    
    # For high frequency (>3%): deduplicate (keep only one per unique line)
    high_freq_lines = [line for tactic, line in all_lines if tactic in high_freq]
    deduplicated_high = list(set(high_freq_lines))  # Remove duplicates
    
    # For low frequency (<2%): keep as is
    low_freq_lines = [line for tactic, line in all_lines if tactic in low_freq]
    
    # For normal frequency (2%-3%): keep as is
    normal_freq_lines = [line for tactic, line in all_lines if tactic in normal_freq]
    
    # Combine all lines and shuffle
    processed_lines = deduplicated_high + normal_freq_lines + low_freq_lines
    random.shuffle(processed_lines)
    
    # Calculate new statistics
    new_tactic_counts = defaultdict(int)
    for line in processed_lines:
        match = re.search(r"mitre_tactic='([^']*)'", line)
        if match:
            tactic = match.group(1)
            new_tactic_counts[tactic] += 1
    new_total = len(processed_lines)
    
    # Generate final report
    generate_report(new_tactic_counts, new_total, "Processed Dataset Report")
    
    # Return processed lines
    return processed_lines

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py dataset1.txt [dataset2.txt ...]", file=sys.stderr)
        sys.exit(1)
    
    dataset_files = sys.argv[1:]
    print(f"Processing {len(dataset_files)} files...", file=sys.stderr)
    
    # Parse files and get all lines with their tactics
    _, _, all_lines = parse_datasets(dataset_files)
    
    if not all_lines:
        print("No valid entries found in input files.", file=sys.stderr)
        sys.exit(1)
    
    # Process dataset according to rules
    processed_lines = process_dataset(all_lines)
    
    # Save processed dataset
    output_file = "processed_dataset.csv"
    with open(output_file, 'w', encoding='utf-8') as f:
        for line in processed_lines:
            f.write(line + "\n")
    
    print(f"\nProcessed dataset saved to {output_file}")

if __name__ == "__main__":
    main()