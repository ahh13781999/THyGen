import os
import shutil
import json

# Configuration
SOURCE_DIR = "../attack_techniques"  
DEST_DIR = "../labelled_logs"  
MAPPING_FILE = "mitre_mapping.json"  # Generated in Step 1
ALLOWED_EXTENSIONS = {'.log', '.json'}

def sanitize_tactic_name(tactic):
    """Convert tactic names to filesystem-friendly format (e.g., 'Defense Evasion' -> 'Defense_Evasion')"""
    return tactic.replace(' ', '_')

def get_unique_filename(dest_dir, filename):
    """Generate a unique filename by appending a counter if duplicates exist (e.g., file_1.log)"""
    base, ext = os.path.splitext(filename)
    counter = 1
    unique_name = filename
    while os.path.exists(os.path.join(dest_dir, unique_name)):
        unique_name = f"{base}_{counter}{ext}"
        counter += 1
    return unique_name

# Load MITRE technique-to-tactic mapping
with open(MAPPING_FILE, "r") as f:
    tech_to_tactic = json.load(f)

# Process all technique folders (including nested files)
for tech_folder in os.listdir(SOURCE_DIR):
    tech_path = os.path.join(SOURCE_DIR, tech_folder)
    if not os.path.isdir(tech_path):
        continue  # Skip non-folders

    # Get tactic from mapping (case-insensitive)
    tactic = tech_to_tactic.get(tech_folder.upper())
    if not tactic:
        print(f"Skipping unmapped technique: {tech_folder}")
        continue

    tactic_dir = os.path.join(DEST_DIR, sanitize_tactic_name(tactic))
    os.makedirs(tactic_dir, exist_ok=True)

    # Walk through all nested subdirectories in the technique folder
    for root, _, files in os.walk(tech_path):
        for file in files:
            src_file = os.path.join(root, file)
            if not os.path.isfile(src_file):
                continue

            # Check file extension
            ext = os.path.splitext(file)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                continue

            # Generate unique filename for destination
            dest_filename = get_unique_filename(tactic_dir, file)
            dest_file = os.path.join(tactic_dir, dest_filename)

            # Copy file
            shutil.copy2(src_file, dest_file)
            print(f"Copied {file} to {dest_file}")
    tech_path = os.path.join(SOURCE_DIR, tech_folder)
    if not os.path.isdir(tech_path):
        continue

    # Get tactic from mapping (e.g., T1003 -> Credential Access)
    tactic = tech_to_tactic.get(tech_folder.upper())
    if not tactic:
        print(f"Skipping unmapped technique: {tech_folder}")
        continue

    tactic_dir = os.path.join(DEST_DIR, sanitize_tactic_name(tactic))
    os.makedirs(tactic_dir, exist_ok=True)

    # Copy .log and .json files to tactic directory
    for file in os.listdir(tech_path):
        src_file = os.path.join(tech_path, file)
        if not os.path.isfile(src_file):
            continue

        ext = os.path.splitext(file)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            continue

        dest_file = os.path.join(tactic_dir, file)
        shutil.copy2(src_file, dest_file)
        print(f"Copied {file} to {dest_file}")