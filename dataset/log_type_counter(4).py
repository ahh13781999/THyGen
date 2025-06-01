import os
from collections import defaultdict

def analyze_common_subfolders(root_path):
    """Analyze common subfolders across multiple parent folders"""
    subfolder_stats = defaultdict(lambda: {'count': 0, 'files': 0, 'paths': []})
    
    # Get all immediate subdirectories of the root path
    parent_folders = [d for d in os.listdir(root_path) 
                     if os.path.isdir(os.path.join(root_path, d))]
    
    if not parent_folders:
        print(f"No subfolders found in {root_path}")
        return None
    
    print(f"Analyzing {len(parent_folders)} parent folders...")
    
    for parent in parent_folders:
        parent_path = os.path.join(root_path, parent)
        for root, dirs, files in os.walk(parent_path):
            # Only process immediate subfolders of the parent folders
            if root == parent_path:
                for subfolder in dirs:
                    subfolder_path = os.path.join(root, subfolder)
                    file_count = sum(len(files) for _, _, files in os.walk(subfolder_path))
                    
                    subfolder_stats[subfolder]['count'] += 1
                    subfolder_stats[subfolder]['files'] += file_count
                    subfolder_stats[subfolder]['paths'].append(subfolder_path)
    
    return subfolder_stats

def save_to_text_file(report_data, root_dir, output_file):
    """Save the analysis results to a text file"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=== COMMON SUBFOLDER ANALYSIS REPORT ===\n\n")
        f.write(f"Root directory: {root_dir}\n")
        f.write(f"Total parent folders analyzed: {len([d for d in os.listdir(root_dir) if os.path.isdir(os.path.join(root_dir, d))])}\n\n")
        
        f.write("SUBFOLDER STATISTICS:\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Subfolder Name':<20} | {'Occurrences':>12} | {'Total Files':>12}\n")
        f.write("-" * 80 + "\n")
        
        for subfolder, data in sorted(report_data.items(), key=lambda x: -x[1]['files']):
            f.write(f"{subfolder:<20} | {data['count']:>12} | {data['files']:>12}\n")
        
        f.write("\n\nDETAILED PATH INFORMATION:\n")
        f.write("-" * 80 + "\n")
        for subfolder, data in sorted(report_data.items(), key=lambda x: -x[1]['files']):
            f.write(f"\n[{subfolder}]\n")
            f.write(f"Found in {data['count']} locations with {data['files']} total files:\n")
            for path in data['paths']:
                f.write(f"  • {path}\n")

def main():
    root_dir = input("Enter the directory path containing your folders: ").strip()
    
    if not os.path.isdir(root_dir):
        print("Error: Invalid directory path")
        return
    
    stats = analyze_common_subfolders(root_dir)
    
    if not stats:
        return
    
    # Generate output filename based on root directory name
    dir_name = os.path.basename(root_dir) if os.path.basename(root_dir) else "analysis"
    output_file = f"{dir_name}_subfolder_report.txt"
    
    save_to_text_file(stats, root_dir, output_file)
    print(f"\nReport successfully saved to: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    main()