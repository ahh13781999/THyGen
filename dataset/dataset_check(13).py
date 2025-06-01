import re
import sys
import argparse
from collections import defaultdict

def analyze_line(line, line_number):
    """Analyze a single log line and return MITRE tactic or error"""
    try:
        # Try standard pattern first
        match = re.search(
            r"mitre_tactic\s*=\s*['\"]([^'\"]+)['\"]",
            line,
            re.IGNORECASE
        )
        if match:
            return match.group(1).strip().lower(), None
        
        # Try alternative patterns if standard fails
        alternative_patterns = [
            r"mitre_tactic=([^,\s]+)",            # Unquoted values
            r"'mitre_tactic':\s*['\"]([^'\"]+)",  # JSON-style
            r"mitre_attack=['\"]([^'\"]+)",       # Alternate field name
        ]
        
        for pattern in alternative_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1).strip().lower(), None
        
        return None, "No MITRE tactic pattern found"
    
    except Exception as e:
        return None, f"Parsing error: {str(e)}"

def process_log_file(input_file, debug=False):
    """Process log file and return counts, errors, and statistics"""
    label_counts = defaultdict(int)
    error_log = []
    total_lines = 0
    processed_lines = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as file:
            for line_number, line in enumerate(file, 1):
                total_lines += 1
                
                if not line.strip():
                    if debug:
                        error_log.append((line_number, "Empty line skipped"))
                    continue
                
                tactic, error = analyze_line(line, line_number)
                
                if error:
                    error_log.append((line_number, error))
                    continue
                
                label_counts[tactic] += 1
                processed_lines += 1
    
    except Exception as e:
        return None, None, [(0, f"File error: {str(e)}")]
    
    return label_counts, processed_lines, error_log

def write_report(output_file, counts, total_processed, total_lines, errors):
    """Generate comprehensive report"""
    with open(output_file, 'w', encoding='utf-8') as f:
        # Header section
        f.write("MITRE ATT&CK TACTIC ANALYSIS REPORT\n")
        f.write("=" * 50 + "\n\n")
        
        # Summary statistics
        f.write(f"Total lines processed: {total_lines}\n")
        f.write(f"Successfully parsed lines: {total_processed}\n")
        f.write(f"Lines with issues: {len(errors)}\n")
        f.write(f"Success rate: {(total_processed/total_lines)*100:.2f}%\n\n")
        
        # MITRE tactic distribution
        if total_processed > 0:
            f.write("TACTIC DISTRIBUTION:\n")
            f.write("{:<25} {:<15} {:<15}\n".format(
                "Tactic", "Count", "Percentage"))
            f.write("-" * 55 + "\n")
            
            sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
            for tactic, count in sorted_counts:
                percentage = (count / total_processed) * 100
                f.write("{:<25} {:<15} {:<15.2f}\n".format(
                    tactic, count, percentage))
        
        # Error details
        if errors:
            f.write("\nPROCESSING ISSUES:\n")
            f.write("{:<10} {:<50}\n".format("Line", "Issue"))
            f.write("-" * 60 + "\n")
            for line_num, error in errors[:20]:  # Show first 20 errors
                f.write("{:<10} {:<50}\n".format(line_num, error))
            if len(errors) > 20:
                f.write(f"\n... and {len(errors)-20} more issues not shown\n")

def main():
    parser = argparse.ArgumentParser(
        description='Robust MITRE ATT&CK analyzer with error handling',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--input', required=True,
                       help='Input log file path')
    parser.add_argument('-o', '--output', required=True,
                       help='Output report file path')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Show detailed processing information')
    
    args = parser.parse_args()
    
    print(f"\nProcessing {args.input}...")
    counts, processed_count, errors = process_log_file(args.input, args.debug)
    
    if counts is None:
        print("Fatal error processing file:")
        for _, error in errors:
            print(f"- {error}")
        sys.exit(1)
    
    total_lines = processed_count + len(errors)
    write_report(args.output, counts, processed_count, total_lines, errors)
    
    print(f"\nReport generated: {args.output}")
    print(f"\nSummary:")
    print(f"- Total lines: {total_lines}")
    print(f"- Successfully processed: {processed_count}")
    print(f"- Lines with issues: {len(errors)}")
    
    if processed_count > 0:
        print("\nTop MITRE tactics:")
        for tactic, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            percentage = (count / processed_count) * 100
            print(f"- {tactic}: {count} ({percentage:.2f}%)")
    
    if errors and args.debug:
        print("\nFirst 5 problematic lines:")
        for line_num, error in errors[:5]:
            print(f"Line {line_num}: {error}")

if __name__ == "__main__":
    main()